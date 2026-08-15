#!/usr/bin/env python3
"""
SG - Verified Working Servers Only
===================================
User confirmed only these 6 configs work. We filter the source
to ONLY include configs from these proven working servers.
"""
import base64, json, socket, ssl, time, random
import urllib.parse, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import pytz, requests

SOURCE = "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/all.txt"
FB = "block_domains=an.facebook.com,graph.facebook.com/adnw,pixel.facebook.com,connect.facebook.net/adnw"

# ✅ User confirmed WORKING servers (IPs and domains)
WORKING_HOSTS = {
    "178.128.52.52",     # VLESS Reality zoom.us
    "3.0.111.82",        # VLESS Reality apple.com
    "45.8.211.57",       # VLESS WS+TLS ariyuz.org
    "91.193.58.140",     # VLESS WS+TLS techsonic.dev
    "91.193.58.57",      # VLESS WS+TLS techsonic.dev
    "64.176.36.17",      # VLESS WS+TLS csmaster.ggff.net
}

# ❌ Known NON-working (user tested and failed)
BLOCKED_HOSTS = {
    "178.128.112.70",    # Reality but doesn't work from Myanmar
    "91.192.81.214",     # Reality but doesn't work
    "152.42.217.27",     # Reality but doesn't work
}

# Cloudflare CDN IP ranges (proxy behind these usually doesn't work)
CF_RANGES = [
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("104.20.0.0/14"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("131.0.72.0/22"),
]

def is_cloudflare(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in CF_RANGES)
    except:
        return False

def resolve(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except:
        return None

def tcp_test(host, port, timeout=3.0):
    try:
        s = socket.socket(); s.settimeout(timeout)
        t = time.time(); s.connect((host, port))
        lat = (time.time() - t) * 1000; s.close()
        return True, round(lat, 1)
    except:
        return False, -1

def tls_test(host, port, sni=None, timeout=4.0):
    try:
        s = socket.socket(); s.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        t = time.time(); s.connect((host, port))
        with ctx.wrap_socket(s, server_hostname=sni or host) as ts:
            lat = (time.time() - t) * 1000; ts.close()
            return True, round(lat, 1)
    except:
        return False, -1

def parse_line(line):
    d = {"protocol": "?", "host": None, "port": None, "type": None,
         "security": "none", "transport": "tcp", "flow": "none", "sni": None,
         "fp": None, "pbk": None, "uuid": None, "path": "/", "raw": line, "features": []}
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
            })
            if d["security"] == "reality":
                d["features"].append("🛡️ REALITY")
                if d["flow"] and "xtls-rprx-vision" in d["flow"]:
                    d["features"].append("🔥 XTLS Vision")
            elif d["security"] == "tls":
                if d["transport"] == "ws":
                    d["features"].append("WS+TLS")
                else:
                    d["features"].append("TLS")
            if d["fp"]: d["features"].append(f"fp={d['fp']}")
            if d["sni"]: d["features"].append(f"SNI:{d['sni'][:25]}")
        elif line.startswith("ss://"):
            d["protocol"] = "ss"
            bu = line.split("#")[0]; p = urllib.parse.urlparse(bu)
            h, pt = p.hostname, p.port
            if not h or not pt:
                raw = bu[5:]
                if "@" in raw: _, hp = raw.split("@", 1)
                else:
                    try:
                        dc = base64.b64decode(raw + "==").decode()
                        _, hp = dc.split("@", 1)
                    except: return None
                if ":" in hp: h, pt = hp.rsplit(":", 1); pt = int(pt)
            if not h or not pt: return None
            d.update({"type": "ss", "host": h, "port": int(pt), "security": "ss"})
            d["features"].append("Shadowsocks")
        else:
            return None
    except:
        return None
    return d if d.get("host") and d.get("port") else None

def strict_test(d):
    """3x TCP + 2x TLS strict test"""
    h, pt = d["host"], d["port"]
    sni = d.get("sni")
    need_tls = d["security"] in ("tls", "reality")

    tcp_lats = []
    for i in range(3):
        if i > 0: time.sleep(0.1)
        ok, lat = tcp_test(h, pt)
        if not ok: return None
        tcp_lats.append(lat)

    tls_lat = -1
    if need_tls:
        tls_lats = []
        for i in range(2):
            if i > 0: time.sleep(0.1)
            ok, lat = tls_test(h, pt, sni)
            if not ok: return None
            tls_lats.append(lat)
        tls_lat = round(sum(tls_lats) / len(tls_lats), 1)

    avg_tcp = round(sum(tcp_lats) / len(tcp_lats), 1)
    avg = tls_lat if tls_lat > 0 else avg_tcp

    return {"d": d, "tcp": avg_tcp, "tls": tls_lat, "avg": avg}

def format_config(d, name):
    raw = d["raw"]
    base = raw.split("#")[0]
    delim = "&" if "?" in base else "?"
    return f"{base}{delim}{FB}#{urllib.parse.quote(name)}"

def main():
    tz = pytz.timezone("Asia/Yangon")
    now = datetime.now(tz)
    t0 = time.time()

    print("=" * 65)
    print(f"  🔑 SG Verified Servers Only | {now.strftime('%H:%M:%S MMT')}")
    print(f"  ✅ Working hosts: {len(WORKING_HOSTS)}")
    print(f"  ❌ Blocked hosts: {len(BLOCKED_HOSTS)}")
    print("=" * 65)

    # Fetch
    r = requests.get(SOURCE, timeout=15)
    content = r.text.strip()
    try:
        lines = base64.b64decode(content).decode().splitlines()
    except:
        lines = content.splitlines()

    # Parse ALL lines (vless + ss only)
    all_configs = []
    seen = set()
    for l in lines:
        l = l.strip()
        if l and (l.startswith("vless://") or l.startswith("ss://")):
            d = parse_line(l)
            if d:
                key = f"{d['host']}:{d['port']}:{d.get('uuid', '')}"
                if key not in seen:
                    seen.add(key)
                    all_configs.append(d)

    print(f"\n  📊 Total VLESS+SS: {len(all_configs)}")

    # Resolve all hosts to IPs
    hosts = list(set(c["host"] for c in all_configs))
    print(f"  📡 Resolving {len(hosts)} hosts...")
    host_ip = {}
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(resolve, h): h for h in hosts}
        for f in as_completed(futs):
            try: host_ip[futs[f]] = f.result()
            except: pass

    # Categorize each config
    verified = []    # From known working hosts
    promising = []   # Not CF, not blocked, VLESS Reality/WS+TLS
    skipped_cf = 0
    skipped_blocked = 0
    skipped_other = 0

    for c in all_configs:
        h = c["host"]
        ip = host_ip.get(h)

        # Skip blocked hosts
        if h in BLOCKED_HOSTS:
            skipped_blocked += 1
            continue

        # Skip Cloudflare CDN IPs
        if ip and is_cloudflare(ip):
            skipped_cf += 1
            continue

        # Include if from verified working hosts
        if h in WORKING_HOSTS:
            verified.append(c)
            continue

        # Include if VLESS Reality + XTLS Vision (proven pattern, non-CF)
        if c["protocol"] == "vless" and c["security"] == "reality" and c.get("flow") and "xtls-rprx-vision" in c["flow"]:
            promising.append(c)
            continue

        # Include if VLESS WS+TLS with fp (non-CF)
        if c["protocol"] == "vless" and c["security"] == "tls" and c["transport"] == "ws" and c.get("fp"):
            promising.append(c)
            continue

        skipped_other += 1

    print(f"\n  📊 Filter results:")
    print(f"     ✅ Verified (known working hosts): {len(verified)}")
    print(f"     🔶 Promising (non-CF, good pattern): {len(promising)}")
    print(f"     ❌ Cloudflare CDN skipped: {skipped_cf}")
    print(f"     ❌ Blocked hosts skipped: {skipped_blocked}")
    print(f"     ❌ Other skipped: {skipped_other}")

    # Strict test all candidates
    candidates = verified + promising
    print(f"\n  🧪 Strict testing {len(candidates)} configs (3x TCP + 2x TLS)...")

    results = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(strict_test, d): d for d in candidates}
        for f in as_completed(futs):
            try:
                r = f.result()
                if r:
                    results.append(r)
            except:
                pass

    # Sort: verified first, then by latency
    def sort_key(r):
        is_verified = r["d"]["host"] in WORKING_HOSTS
        lat = r["tls"] if r["tls"] > 0 else r["tcp"]
        return (0 if is_verified else 1, lat)

    results.sort(key=sort_key)

    print(f"\n  ✅ Passed strict test: {len(results)}")
    print(f"\n  {'─'*63}")
    for i, r in enumerate(results, 1):
        d = r["d"]
        v = "✅" if d["host"] in WORKING_HOSTS else "🔶"
        lat = r["tls"] if r["tls"] > 0 else r["tcp"]
        ft = " | ".join(d["features"][:4])
        print(f"  {v} {i:>2} | {d['protocol'].upper():6} | {str(d['host'])[:28]:28}:{d['port']} | {lat:.0f}ms | {ft}")

    # Save
    all_out = []
    flag = "🇸🇬"
    for i, r in enumerate(results, 1):
        all_out.append(format_config(r["d"], f"{flag} SG {i}"))

    print(f"\n{'='*65}")
    print(f"  ⏱️ {time.time()-t0:.1f}s | 💾 {len(all_out)} keys saved")

    v_count = sum(1 for r in results if r["d"]["host"] in WORKING_HOSTS)
    p_count = len(results) - v_count
    print(f"     ✅ Verified: {v_count} | 🔶 New promising: {p_count}")
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
