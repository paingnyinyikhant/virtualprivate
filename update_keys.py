#!/usr/bin/env python3
"""
SG-only Checker - Working Pattern Analysis Based
=================================================
Working patterns identified from user's configs:

Pattern A: VLESS Reality + XTLS Vision + fp=chrome (Score: 30+)
  → security=reality, flow=xtls-rprx-vision, fp=chrome
  → SNI: legitimate domains (zoom.us, apple.com, etc.)
  → Port: any (443, 12972, etc.)

Pattern B: Trojan TLS + fp=chrome (Score: 25+)
  → trojan://, security=tls, fp=chrome
  → SNI matches host (rooster465.autos family)
  → Port: 443

Pattern C: VLESS WS+TLS (Score: 20+)
  → security=tls, type=ws, sni=...
  → Port: 2096, 443

Pattern D: VLESS TLS + fp spoofing (Score: 18+)
  → security=tls, fp=chrome/firefox
  → Port: 443
"""
import base64, json, socket, ssl, time, random, sys, re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import pytz, requests

SOURCE = "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/all.txt"
MAX = 20
PROTOS = ("vless://", "ss://")  # VLESS နဲ့ SS ပဲ ယူမယ်
FB = "block_domains=an.facebook.com,graph.facebook.com/adnw,pixel.facebook.com,connect.facebook.net/adnw"

# Known working SNI domains (from user's configs)
GOOD_SNI_DOMAINS = [
    "zoom.us", "apple.com", "rooster465.autos", "techsonic.dev",
    "csmaster.ggff.net", "ariyuz.org", "sahanwickramasinghevip.shop"
]

# Known BAD SNIs
BAD_SNIS = ["cloudflare.com", "speedtest.net", "127.0.0.1", "localhost", "example.com", "0.0.0.0"]


def analyze_and_score(line):
    """Parse config and score based on working patterns"""
    d = {"raw": line, "protocol": "?", "host": None, "port": None, "type": None,
         "security": "none", "transport": "tcp", "flow": "none", "sni": None,
         "fp": None, "pbk": None, "uuid": None, "path": "/",
         "score": 0, "pattern": None, "features": [], "issues": []}
    
    try:
        if line.startswith("vless://"):
            d["protocol"] = "vless"
            p = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(p.query)
            d.update({
                "type": "url", "host": p.hostname, "port": int(p.port or 443),
                "uuid": p.username,
                "sni": q.get("sni", [None])[0] or q.get("host", [None])[0],
                "path": q.get("path", ["/"])[0],
                "security": q.get("security", ["none"])[0],
                "transport": q.get("type", ["tcp"])[0],
                "flow": q.get("flow", ["none"])[0],
                "fp": q.get("fp", [None])[0],
                "pbk": q.get("pbk", [None])[0],
                "sid": q.get("sid", [None])[0],
            })
            
            # Pattern A: VLESS Reality + XTLS Vision
            if d["security"] == "reality":
                d["score"] += 15
                d["pattern"] = "A:VLESS-Reality"
                d["features"].append("🛡️ REALITY")
                if d["flow"] and "xtls-rprx-vision" in d["flow"]:
                    d["score"] += 10
                    d["features"].append("🔥 XTLS Vision")
                if d["pbk"]:
                    d["score"] += 3
                if d["fp"]:
                    d["score"] += 2
                    d["features"].append(f"fp={d['fp']}")
                # Check SNI legitimacy
                if d["sni"]:
                    for good in GOOD_SNI_DOMAINS:
                        if good in d["sni"].lower():
                            d["score"] += 5
                            d["features"].append(f"SNI:{d['sni']}")
                            break
            
            # Pattern C: VLESS WS+TLS
            elif d["security"] == "tls" and d["transport"] == "ws":
                d["score"] += 12
                d["pattern"] = "C:VLESS-WS-TLS"
                d["features"].append("WS+TLS")
                if d["fp"]:
                    d["score"] += 3
                if d["sni"]:
                    d["score"] += 3
                    d["features"].append(f"SNI:{d['sni'][:30]}")
            
            # Pattern D: VLESS TLS + fp
            elif d["security"] == "tls":
                d["score"] += 8
                d["pattern"] = "D:VLESS-TLS"
                d["features"].append("TLS")
                if d["fp"]:
                    d["score"] += 5
                    d["features"].append(f"fp={d['fp']}")
                if d["transport"] == "tcp":
                    d["score"] += 2
            
            # Fallback pattern for VLESS with no security
            else:
                d["score"] += 3
                d["pattern"] = "G:VLESS-Plain"
                d["features"].append("No TLS")
            
            # Check bad SNI
            if d["sni"]:
                for bad in BAD_SNIS:
                    if bad in d["sni"].lower():
                        d["score"] -= 8
                        d["issues"].append(f"Bad SNI: {d['sni']}")
                        break
        
        elif line.startswith("trojan://"):
            d["protocol"] = "trojan"
            p = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(p.query)
            d.update({
                "type": "url", "host": p.hostname, "port": int(p.port or 443),
                "uuid": p.username,
                "sni": q.get("sni", [None])[0] or q.get("host", [None])[0],
                "path": q.get("path", ["/"])[0],
                "security": "tls",
                "transport": q.get("type", ["tcp"])[0],
                "fp": q.get("fp", [None])[0],
            })
            
            # Pattern B: Trojan TLS
            d["score"] += 12
            d["pattern"] = "B:Trojan-TLS"
            d["features"].append("🐴 Trojan")
            
            if d["fp"]:
                d["score"] += 5
                d["features"].append(f"fp={d['fp']}")
            
            # Check if SNI matches known working domains
            if d["sni"]:
                for good in GOOD_SNI_DOMAINS:
                    if good in d["sni"].lower():
                        d["score"] += 8
                        d["features"].append(f"SNI:{d['sni'][:30]}")
                        break
            
            if d["transport"] == "tcp":
                d["score"] += 2
            
            # Check bad SNI
            if d["sni"]:
                for bad in BAD_SNIS:
                    if bad in d["sni"].lower():
                        d["score"] -= 8
                        d["issues"].append(f"Bad SNI")
                        break
        
        elif line.startswith("vmess://"):
            d["protocol"] = "vmess"
            b = line[8:]
            b += "=" * ((4 - len(b) % 4) % 4)
            dc = json.loads(base64.b64decode(b).decode("utf-8"))
            d.update({
                "type": "vmess", "data": dc, "host": dc.get("add"),
                "port": int(dc.get("port", 0)),
                "sni": dc.get("sni") or dc.get("host"),
                "path": dc.get("path", "/"),
                "uuid": dc.get("id"),
                "transport": dc.get("net", "tcp"),
                "security": dc.get("tls", "none"),
            })
            if dc.get("tls") == "tls": d["score"] += 8
            if dc.get("net") == "ws": d["score"] += 5
            if dc.get("net") == "grpc": d["score"] += 7
            d["score"] += 3
            d["pattern"] = "E:VMess"
        
        elif line.startswith("ss://"):
            d["protocol"] = "ss"
            bu = line.split("#")[0]
            p = urllib.parse.urlparse(bu)
            h, pt = p.hostname, p.port
            if not h or not pt:
                raw = bu[5:]
                if "@" in raw:
                    _, hp = raw.split("@", 1)
                else:
                    try:
                        dc = base64.b64decode(raw + "==").decode()
                        _, hp = dc.split("@", 1)
                    except:
                        return None
                if ":" in hp:
                    h, pt = hp.rsplit(":", 1)
                    pt = int(pt)
            if not h or not pt: return None
            d.update({"type": "ss", "host": h, "port": int(pt), "security": "ss"})
            d["score"] += 5
            d["pattern"] = "F:SS"
        else:
            return None
    except:
        return None
    
    if not d.get("host") or not d.get("port"):
        return None
    if not d.get("pattern"):
        d["pattern"] = f"X:{d['protocol'].upper()}"
    return d


def tcp_test(host, port, timeout=3.0):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        t = time.time()
        s.connect((host, port))
        lat = (time.time() - t) * 1000
        s.close()
        return True, round(lat, 1)
    except:
        return False, -1


def tls_test(host, port, sni=None, timeout=4.0):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = time.time()
        s.connect((host, port))
        with ctx.wrap_socket(s, server_hostname=sni or host) as ts:
            lat = (time.time() - t) * 1000
            proto = ts.version()
            ts.close()
            return True, round(lat, 1), proto
    except Exception as e:
        return False, -1, str(e)[:60]


def test_config(d):
    """Test a config - 2x TCP + TLS with strict validation"""
    h, pt = d["host"], d["port"]
    sni = d.get("sni")
    
    # Test 1: TCP
    ok1, tcp_lat1 = tcp_test(h, pt)
    if not ok1:
        return None
    
    # Test 2: TCP again (stability check)
    time.sleep(0.1)
    ok2, tcp_lat2 = tcp_test(h, pt)
    if not ok2:
        return None  # Unstable - reject
    
    # TLS test for TLS-based protocols
    need_tls = d["security"] in ("tls", "reality") or d["protocol"] == "trojan"
    tls_lat = -1
    tls_proto = None
    
    if need_tls:
        tok, tlat, tproto = tls_test(h, pt, sni)
        if not tok:
            return None
        tls_lat = tlat
        tls_proto = tproto
        
        # Second TLS test for stability
        time.sleep(0.1)
        tok2, tlat2, _ = tls_test(h, pt, sni)
        if not tok2:
            return None  # TLS unstable - reject
        tls_lat = round((tlat + tlat2) / 2, 1)
    
    avg_tcp = round((tcp_lat1 + tcp_lat2) / 2, 1)
    avg = tls_lat if tls_lat > 0 else avg_tcp
    
    # Reject very high latency (probably won't work well)
    if avg > 2000:
        return None
    
    # Latency scoring (stricter)
    if 0 < avg < 50: d["score"] += 10
    elif 0 < avg < 100: d["score"] += 8
    elif 0 < avg < 200: d["score"] += 5
    elif 0 < avg < 400: d["score"] += 3
    elif 0 < avg < 600: d["score"] += 1
    elif avg > 1000: d["score"] -= 8
    
    # Port bonus
    if pt == 443: d["score"] += 5
    
    # Stability bonus (both tests passed)
    d["score"] += 5
    
    if tls_proto and isinstance(tls_proto, str) and "TLSv1.3" in tls_proto:
        d["features"].append("TLSv1.3")
    
    return {
        "d": d, "tcp": avg_tcp, "tls": tls_lat,
        "score": d["score"],
        "verdict": "🟢" if d["score"] >= 25 else "🟡" if d["score"] >= 15 else "🟠" if d["score"] >= 8 else "🔴"
    }


def format_config(d, name):
    raw = d["raw"]
    if d["type"] == "vmess":
        dc = d["data"]
        dc["ps"] = name
        dc["fb_block"] = FB
        return f"vmess://{base64.b64encode(json.dumps(dc).encode()).decode()}"
    else:
        base = raw.split("#")[0]
        delim = "&" if "?" in base else "?"
        return f"{base}{delim}{FB}#{urllib.parse.quote(name)}"


def main():
    tz = pytz.timezone("Asia/Yangon")
    now = datetime.now(tz)
    t0 = time.time()
    
    print("=" * 65)
    print(f"  🔑 SG Pattern-Based Checker | {now.strftime('%H:%M:%S MMT')}")
    print(f"  📥 Source: {SOURCE[:60]}...")
    print("=" * 65)
    
    # Step 1: Fetch
    print(f"\n  📥 Fetching...")
    try:
        r = requests.get(SOURCE, timeout=15)
        content = r.text.strip()
        try:
            lines = base64.b64decode(content).decode().splitlines()
        except:
            lines = content.splitlines()
    except Exception as e:
        print(f"  ❌ Fetch failed: {e}")
        return
    
    # Step 2: Parse and score
    configs = []
    seen = set()
    proto_counts = {}
    pattern_counts = {}
    
    for l in lines:
        l = l.strip()
        if l and any(l.startswith(p) for p in PROTOS):
            d = analyze_and_score(l)
            if d:
                key = f"{d['host']}:{d['port']}:{d.get('uuid', '')}"
                if key not in seen:
                    seen.add(key)
                    configs.append(d)
                    proto_counts[d["protocol"]] = proto_counts.get(d["protocol"], 0) + 1
                    pat = d.get("pattern", "?")
                    pattern_counts[pat] = pattern_counts.get(pat, 0) + 1
    
    print(f"  📊 Total: {len(configs)} configs (deduped from {len(lines)} lines)")
    print(f"\n  📦 Protocols:")
    for p, c in sorted(proto_counts.items(), key=lambda x: -x[1]):
        print(f"     {p.upper():10} {c}")
    
    print(f"\n  🎯 Patterns detected:")
    for p, c in sorted(pattern_counts.items(), key=lambda x: -x[1]):
        print(f"     {str(p):25} {c}")
    
    # Step 3: Pre-sort by score (test highest scored first)
    configs.sort(key=lambda x: -x["score"])
    
    # Step 4: Test (only test configs with score > 5 to save time)
    testable = [c for c in configs if c["score"] > 5]
    print(f"\n  🧪 Testing {len(testable)} configs...")
    
    results = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(test_config, d): d for d in testable}
        for f in as_completed(futs):
            try:
                r = f.result()
                if r:
                    results.append(r)
            except:
                pass
    
    # Step 5: Sort by final score
    results.sort(key=lambda x: (-x["score"], x["tls"] if x["tls"] > 0 else 9999))
    top = results[:MAX]
    
    print(f"\n  ✅ Passed: {len(results)} | Saved: {len(top)}")
    print(f"\n  {'─'*63}")
    print(f"  {'#':>3} {'Pattern':20} {'Host':30} {'Port':>5} {'Score':>5} {'Lat':>6} Features")
    print(f"  {'─'*63}")
    
    for i, r in enumerate(top, 1):
        d = r["d"]
        lat = r["tls"] if r["tls"] > 0 else r["tcp"]
        ft = " | ".join(d["features"][:4]) if d["features"] else ""
        print(f"  {i:>3} {d.get('pattern','?'):20} {str(d['host'])[:30]:30} {d['port']:>5} {r['score']:>5} {lat:>5.0f}ms {ft}")
    
    # Save
    all_out = []
    flag = "🇸🇬"
    for i, r in enumerate(top, 1):
        all_out.append(format_config(r["d"], f"{flag} SG {i}"))
    
    print(f"\n{'='*65}")
    print(f"  ⏱️ Total: {time.time()-t0:.1f}s")
    print(f"  📊 {len(all_out)} keys saved")
    
    # Pattern breakdown of saved keys
    pat_saved = {}
    for r in top:
        p = r["d"].get("pattern", "?")
        pat_saved[p] = pat_saved.get(p, 0) + 1
    print(f"\n  📊 Saved by pattern:")
    for p, c in sorted(pat_saved.items(), key=lambda x: -x[1]):
        print(f"     {p:25} {c}")
    
    print(f"{'='*65}")
    
    title = f"#profile-title: {now.strftime('%I:%M %p')} Updated"
    plain = title + "\n" + "\n".join(all_out)
    with open("servers", "w") as f:
        f.write(base64.b64encode(plain.encode()).decode())
    with open("servers_plain.txt", "w") as f:
        f.write(plain)
    
    print(f"\n  💾 servers + servers_plain.txt | ✅ Done!")


if __name__ == "__main__":
    main()
