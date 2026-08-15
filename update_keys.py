#!/usr/bin/env python3
"""Final - SG/JP/TH/HK 20 each, single quick pass"""
import base64,json,socket,ssl,time,random
import urllib.parse
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime
from collections import defaultdict
import pytz,requests

TARGET={"SG":"🇸🇬","JP":"🇯🇵","TH":"🇹🇭","HK":"🇭🇰"}
MAX=10
PRIO={2096,8443,8388}
OK_PORTS=set(range(1,65536))-{443}  # All ports except 443
BLK_SNI=["cloudflare.com","speedtest.net","co.uk","127.0.0.1","localhost","example.com","0.0.0.0","google.com"]
PROTOS=("vless://","vmess://","trojan://","ss://","hysteria2://","hy2://","tuic://")
FB="block_domains=an.facebook.com,graph.facebook.com/adnw,pixel.facebook.com,connect.facebook.net/adnw"

CSRC={
    "SG":"https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/all.txt",
    "JP":"https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/jp/all.txt",
    "TH":"https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/th/all.txt",
    "HK":"https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/hk/all.txt",
}
GSRC=[
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/sub/Mix",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/sub/mix",
]

def P(line):
    d={"p":"?","t":"tcp","s":"none","f":"none","ty":None,"h":None,"pt":None,"sn":None,"pa":"/","u":None,"fp":None,"pk":None,"r":line,"g":0,"ft":[]}
    try:
        if line.startswith("vmess://"):
            d["p"]="vmess";b=line[8:];b+="="*((4-len(b)%4)%4);dc=json.loads(base64.b64decode(b).decode())
            d.update({"ty":"vmess","data":dc,"h":dc.get("add"),"pt":int(dc.get("port",0)),"sn":dc.get("sni") or dc.get("host"),"pa":dc.get("path","/"),"u":dc.get("id"),"t":dc.get("net","tcp"),"s":dc.get("tls","none")})
            if dc.get("tls")=="tls":d["g"]+=3
            n=dc.get("net","tcp")
            if n=="grpc":d["g"]+=7
            elif n=="ws":d["g"]+=5
            elif n=="h2":d["g"]+=5
            else:d["g"]+=3
        elif line.startswith("vless://"):
            d["p"]="vless";p=urllib.parse.urlparse(line);q=urllib.parse.parse_qs(p.query)
            d.update({"ty":"url","h":p.hostname,"pt":int(p.port or 443),"u":p.username,"sn":q.get("sni",[None])[0] or q.get("host",[None])[0],"pa":q.get("path",["/"])[0],"s":q.get("security",["none"])[0],"t":q.get("type",["tcp"])[0],"f":q.get("flow",["none"])[0],"fp":q.get("fp",[None])[0],"pk":q.get("pbk",[None])[0]})
            if d["s"]=="reality":d["g"]+=10;d["ft"].append("🛡️REALITY")
            elif d["s"]=="tls":d["g"]+=4
            if d["f"] and "xtls-rprx-vision" in d["f"]:d["g"]+=8;d["ft"].append("🔥XTLS")
            tp=d["t"]
            if tp=="grpc":d["g"]+=7
            elif tp=="ws":d["g"]+=5
            elif tp in("httpupgrade","splithttp"):d["g"]+=6
            else:d["g"]+=3
            if d["fp"]:d["g"]+=2
        elif line.startswith("trojan://"):
            d["p"]="trojan";p=urllib.parse.urlparse(line);q=urllib.parse.parse_qs(p.query)
            d.update({"ty":"url","h":p.hostname,"pt":int(p.port or 443),"u":p.username,"sn":q.get("sni",[None])[0] or q.get("host",[None])[0],"pa":q.get("path",["/"])[0],"s":"tls","t":q.get("type",["tcp"])[0],"fp":q.get("fp",[None])[0]})
            d["g"]+=6;d["ft"].append("🐴Trojan")
            if d["t"]=="grpc":d["g"]+=6
            elif d["t"]=="ws":d["g"]+=4
            if d["fp"]:d["g"]+=2
        elif line.startswith("ss://"):
            d["p"]="ss";bu=line.split("#")[0];p=urllib.parse.urlparse(bu);h,pt=p.hostname,p.port
            if not h or not pt:
                raw=bu[5:]
                if"@"in raw:_,hp=raw.split("@",1)
                else:
                    try:dc=base64.b64decode(raw+"==").decode();_,hp=dc.split("@",1)
                    except:return None
                if":"in hp:h,pt=hp.rsplit(":",1);pt=int(pt)
            if not h or not pt:return None
            d.update({"ty":"ss","h":h,"pt":int(pt),"s":"ss","g":2})
        elif line.startswith(("hysteria2://","hy2://")):
            d["p"]="hy2";p=urllib.parse.urlparse(line);q=urllib.parse.parse_qs(p.query)
            d.update({"ty":"url","h":p.hostname,"pt":int(p.port or 443),"sn":q.get("sni",[None])[0],"g":5})
        elif line.startswith("tuic://"):
            d["p"]="tuic";p=urllib.parse.urlparse(line);q=urllib.parse.parse_qs(p.query)
            d.update({"ty":"url","h":p.hostname,"pt":int(p.port or 443),"sn":q.get("sni",[None])[0],"g":6})
        else:return None
    except:return None
    return d if d.get("h") and d.get("pt") else None

def fetch(url):
    try:
        r=requests.get(url,timeout=10);c=r.text.strip()
        try:return base64.b64decode(c).decode().splitlines()
        except:return c.splitlines()
    except:return[]

def resolve(h):
    try:return socket.getaddrinfo(h,None,socket.AF_INET)[0][4][0]
    except:return None

def test(n):
    h,pt=n["h"],n["pt"];sn=n.get("sn")
    if pt==443:return None
    if sn and any(b in sn.lower() for b in BLK_SNI):n["g"]-=5
    # Single TCP test
    try:
        s=socket.socket();s.settimeout(2.5);t=time.time()
        s.connect((h,pt));lat=(time.time()-t)*1000;s.close()
    except:return None
    # TLS test for TLS ports/protocols
    tls_ports={2096,8443,2053,2083,2087}
    need_tls=pt in tls_ports or n["p"] in("vless","trojan","vmess","tuic","hy2")
    tls_lat=-1
    if need_tls:
        try:
            s=socket.socket();s.settimeout(3.5)
            ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
            t2=time.time();s.connect((h,pt))
            with ctx.wrap_socket(s,server_hostname=sn or h) as ts:
                tls_lat=(time.time()-t2)*1000;ts.close()
        except:return None
    avg=tls_lat if tls_lat>0 else lat
    sc=n.get("g",0)
    if pt in PRIO:sc+=5;n["ft"].append(f"✅{pt}")
    if 0<avg<100:sc+=6
    elif 0<avg<200:sc+=4
    elif 0<avg<400:sc+=2
    elif avg>800:sc-=4
    sc+=3
    return{"n":n,"tcp":round(lat,1),"tls":round(tls_lat,1) if tls_lat>0 else -1,"sc":sc,
           "v":"🟢" if sc>=15 else "🟡" if sc>=10 else "🟠" if sc>=5 else "🔴"}

def fmt(n,name):
    raw=n["r"]
    if n["ty"]=="vmess":
        dc=n["data"];dc["ps"]=name;dc["fb_block"]=FB
        return f"vmess://{base64.b64encode(json.dumps(dc).encode()).decode()}"
    base=raw.split("#")[0];d="&" if"?"in base else"?"
    return f"{base}{d}{FB}#{urllib.parse.quote(name)}"

def main():
    tz=pytz.timezone("Asia/Yangon");now=datetime.now(tz)
    t0=time.time()
    print(f"{'='*60}\n  🔑 Final | {now.strftime('%H:%M MMT')} | {', '.join(TARGET)} × {MAX}\n{'='*60}")
    
    bc=defaultdict(list);seen=set()
    
    # Fetch ALL sources in parallel
    print(f"  📥 Fetching {len(CSRC)+len(GSRC)} sources...")
    all_fetch = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        for cc,url in CSRC.items():
            all_fetch[ex.submit(fetch,url)] = ("country",cc)
        for url in GSRC:
            all_fetch[ex.submit(fetch,url)] = ("global",None)
        
        for f in as_completed(all_fetch):
            typ,arg = all_fetch[f]
            try:
                lines = f.result()
            except:continue
            for l in lines:
                l=l.strip()
                if l and any(l.startswith(p) for p in PROTOS):
                    n=P(l)
                    if n and n["pt"]!=443:
                        key=f"{n['h']}:{n['pt']}:{n.get('u','')}"
                        if key not in seen:
                            seen.add(key)
                            if typ=="country":
                                n["_cc"]=arg
                                bc[arg].append(n)
                            else:
                                n["_cc"]="?"
                                bc["?"].append(n)
    
    for cc in TARGET:
        print(f"     {TARGET[cc]} {cc}: {len(bc[cc])} (from country source)")
    print(f"     🌍 Global: {len(bc.get('?',[]))} (need GeoIP)")
    print(f"  ⏱️ Fetch: {time.time()-t0:.1f}s")
    
    # GeoIP for global nodes
    gnodes=bc.get("?",[])
    if gnodes:
        t1=time.time()
        hosts=list(set(n["h"] for n in gnodes))
        print(f"  🌍 GeoIP: resolving {len(hosts)} hosts...")
        hip={}
        with ThreadPoolExecutor(max_workers=60) as ex:
            futs={ex.submit(resolve,h):h for h in hosts}
            for f in as_completed(futs):
                try:hip[futs[f]]=f.result()
                except:pass
        
        ips=list(set(v for v in hip.values() if v))
        icc={}
        for i in range(0,len(ips),100):
            batch=ips[i:i+100]
            try:
                r=requests.post("http://ip-api.com/batch",json=[{"query":ip,"fields":"query,countryCode"} for ip in batch],timeout=10)
                for item in r.json():icc[item["query"]]=item.get("countryCode","")
                time.sleep(0.3)
            except:pass
        
        for n in gnodes:
            ip=hip.get(n["h"])
            cc=icc.get(ip,"") if ip else""
            if cc in TARGET:bc[cc].append(n)
        
        print(f"  🌍 GeoIP done: {time.time()-t1:.1f}s")
        for cc in TARGET:
            print(f"     {TARGET[cc]} {cc}: {len(bc[cc])} total")
    
    # Test each country
    print(f"\n  🧪 Testing...")
    t2=time.time()
    all_out=[]
    
    for cc in TARGET:
        flag=TARGET[cc];cands=bc[cc]
        if not cands:
            print(f"  {flag} {cc}: 0 configs ❌");continue
        
        results=[]
        with ThreadPoolExecutor(max_workers=40) as ex:
            futs={ex.submit(test,n):n for n in cands}
            for f in as_completed(futs):
                try:
                    r=f.result()
                    if r:results.append(r)
                except:pass
        
        results.sort(key=lambda x:(-x["sc"],x["tls"] if x["tls"]>0 else 9999))
        top=results[:MAX]
        
        print(f"  {flag} {cc}: {len(cands)} tested → {len(results)} passed → {len(top)} saved")
        for i,r in enumerate(top,1):
            n=r["n"];lat=r["tls"] if r["tls"]>0 else r["tcp"]
            ft=" | ".join(n["ft"][:2]) if n["ft"] else""
            print(f"    {flag} {cc} {i:>2} | {n['p'].upper():8} | {str(n['h'])[:28]:28}:{n['pt']} | {r['v']} {r['sc']:2} | {lat:.0f}ms {ft}")
        
        for i,r in enumerate(top,1):
            all_out.append(fmt(r["n"],f"{flag} {cc} {i}"))
    
    # Save
    print(f"\n  ⏱️ Total: {time.time()-t0:.1f}s")
    print(f"{'='*60}")
    print(f"  📊 {len(all_out)} keys saved")
    for cc in TARGET:
        c=sum(1 for l in all_out if f"%20{cc}%20" in l)
        print(f"     {TARGET[cc]} {cc}: {c}")
    print(f"{'='*60}")
    
    title=f"#profile-title: {now.strftime('%I:%M %p')} Updated"
    plain=title+"\n"+"\n".join(all_out)
    with open("servers","w") as f:f.write(base64.b64encode(plain.encode()).decode())
    with open("servers_plain.txt","w") as f:f.write(plain)
    print(f"  💾 Done!")

if __name__=="__main__":
    main()
