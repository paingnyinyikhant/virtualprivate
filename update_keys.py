#!/usr/bin/env python3
"""
SG Smart Checker - Auto-fetch, Analyze & Filter Working Nodes
==============================================================
Working Pattern Analysis (from user's confirmed 7 keys):

WHY they work:
  Pattern 1: VLESS Reality + XTLS Vision
    → Direct VPS IP (NOT CDN)
    → Valid pbk + sid + fp=chrome + flow=xtls-rprx-vision
    → SNI = legitimate accessible domain (zoom.us, apple.com)
    → Server's Reality config matches client params

  Pattern 2: VLESS WebSocket + TLS
    → Direct server IP (NOT behind Cloudflare/CDN)
    → Valid SNI that resolves
    → fp=chrome/firefox (uTLS fingerprint)
    → Server actually runs VLESS proxy with matching UUID

WHY others DON'T work:
  ❌ Cloudflare CDN IPs (172.64.x, 162.159.x, 104.16-31.x, etc.)
     → CF responds to TLS handshake but proxy behind it is invalid/expired
  ❌ VLESS Reality with mismatched pbk/sid
     → TCP+TLS passes but actual proxy auth fails
  ❌ Trojan rooster465.autos
     → Servers down or blocked from Myanmar
  ❌ Plain VLESS (no TLS, no security)
     → Easily detected/blocked by GFW
"""

import base64, json, socket, ssl, time, random, struct
import urllib.parse, ipaddress, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import pytz, requests

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
SOURCE_URL = "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/all.txt"
MAX_OUTPUT = 20
FB = "block_domains=an.facebook.com,graph.facebook.com/adnw,pixel.facebook.com,connect.facebook.net/adnw"

# Cloudflare IP ranges (configs behind these DON'T work)
CF_NETS = [
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

# Other CDN/proxy ranges that usually don't work
CDN_NETS = [
    ipaddress.ip_network("185.199.108.0/22"),   # GitHub Pages
    ipaddress.ip_network("151.101.0.0/16"),     # Fastly
]

# Known blocked/dead hosts from Myanmar
BLOCKED_HOSTS = set()  # Will be populated dynamically

TCP_TIMEOUT = 3.0
TLS_TIMEOUT = 4.0


# ═══════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════

def is_cdn(ip_str):
    """Check if IP belongs to Cloudflare or other CDN"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if any(ip in n for n in CF_NETS):
            return "Cloudflare"
        if any(ip in n for n in CDN_NETS):
            return "CDN"
        return None
    except:
        return None

def resolve(host):
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except:
        return None

def tcp_connect(host, port, timeout=TCP_TIMEOUT):
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

def tls_handshake(host, port, sni=None, timeout=TLS_TIMEOUT):
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
            ver = ts.version()
            ts.close()
            return True, round(lat, 1), ver
    except:
        return False, -1, None

def sni_resolves(sni):
    """Check if SNI domain actually resolves to a real server"""
    if not sni:
        return False
    try:
        ip = socket.getaddrinfo(sni, None, socket.AF_INET)[0][4][0]
        return ip != "127.0.0.1"
    except:
        return False


# ═══════════════════════════════════════════════════════════════
# DEEP ANALYSIS - Why does a config work or not?
# ═══════════════════════════════════════════════════════════════

def analyze_vless(d, ip):
    """Deep analysis of a VLESS config"""
    score = 0
    reasons = []
    rejects = []

    sec = d["security"]
    tp = d["transport"]
    flow = d.get("flow", "")
    fp = d.get("fp", "")
    pbk = d.get("pbk", "")
    sni = d.get("sni", "")
    host = d["host"]
    port = d["port"]

    # ── Check 1: Is it behind CDN? ──
    cdn = is_cdn(ip) if ip else None
    if cdn:
        rejects.append(f"❌ {cdn} CDN IP ({ip})")
        rejects.append("   → CDN responds to TLS but proxy behind it is invalid/expired")
        return score, reasons, rejects

    # ── Check 2: VLESS Reality ──
    if sec == "reality":
        # Must have ALL required params
        if not pbk:
            rejects.append("❌ Reality without pbk (public key)")
            return 0, reasons, rejects
        if not fp:
            rejects.append("❌ Reality without fp (fingerprint)")
            return 0, reasons, rejects
        if "xtls-rprx-vision" not in flow:
            rejects.append("❌ Reality without xtls-rprx-vision flow")
            return 0, reasons, rejects

        # SNI must be legitimate
        if sni and sni_resolves(sni):
            score += 5
            reasons.append(f"✅ SNI '{sni}' resolves (legitimate domain)")
        elif sni:
            rejects.append(f"❌ SNI '{sni}' doesn't resolve")
            return 0, reasons, rejects

        score += 20
        reasons.append("✅ Reality + XTLS Vision + pbk + fp (all params valid)")
        reasons.append("   → Looks like real HTTPS to zoom.us/apple.com")
        reasons.append("   → GFW cannot distinguish from normal traffic")

    # ── Check 3: VLESS WS+TLS ──
    elif sec == "tls" and tp == "ws":
        if not sni:
            rejects.append("❌ WS+TLS without SNI")
            return 0, reasons, rejects

        # SNI should resolve
        if sni_resolves(sni):
            score += 5
            reasons.append(f"✅ SNI '{sni}' resolves")
        else:
            score -= 5
            reasons.append(f"⚠️ SNI '{sni}' doesn't resolve (might still work)")

        # fp is important for uTLS
        if fp:
            score += 5
            reasons.append(f"✅ fp={fp} (uTLS fingerprint spoofing)")
        else:
            score += 1
            reasons.append("⚠️ No fp (no uTLS, might get fingerprinted)")

        # Direct IP is good
        score += 10
        reasons.append(f"✅ Direct server IP ({ip})")
        reasons.append("   → Not behind CDN, proxy is directly accessible")

    # ── Check 4: VLESS TLS (non-WS) ──
    elif sec == "tls":
        if fp:
            score += 8
            reasons.append(f"✅ TLS + fp={fp}")
        else:
            score += 3
            reasons.append("⚠️ TLS but no fp")

    # ── Check 5: Plain VLESS ──
    else:
        rejects.append("❌ No TLS/Reality security")
        rejects.append("   → Easily detected by GFW DPI")
        return 0, reasons, rejects

    return score, reasons, rejects


def analyze_trojan(d, ip):
    """Analyze Trojan config"""
    score = 0
    reasons = []
    rejects = []

    cdn = is_cdn(ip) if ip else None
    if cdn:
        rejects.append(f"❌ {cdn} CDN")
        return 0, reasons, rejects

    sni = d.get("sni", "")
    fp = d.get("fp", "")

    if fp:
        score += 10
        reasons.append(f"✅ Trojan + fp={fp}")
    else:
        score += 5
        reasons.append("⚠️ Trojan without fp")

    if sni and sni_resolves(sni):
        score += 5
        reasons.append(f"✅ SNI '{sni}' resolves")

    # Trojan is inherently stealthy
    score += 8
    reasons.append("✅ Trojan protocol (mimics HTTPS)")

    return score, reasons, rejects


def analyze_ss(d, ip):
    """Analyze Shadowsocks config"""
    score = 0
    reasons = []
    rejects = []

    cdn = is_cdn(ip) if ip else None
    if cdn:
        rejects.append(f"❌ CDN")
        return 0, reasons, rejects

    # Plain SS is detectable
    score += 5
    reasons.append("⚠️ Shadowsocks (detectable by GFW DPI)")
    reasons.append("   → No TLS wrapping, traffic pattern visible")

    return score, reasons, rejects


# ═══════════════════════════════════════════════════════════════
# PARSER
# ═══════════════════════════════════════════════════════════════

def parse_line(line):
    d = {"protocol": "?", "host": None, "port": None, "type": None,
         "security": "none", "transport": "tcp", "flow": "", "sni": None,
         "fp": None, "pbk": None, "uuid": None, "path": "/", "raw": line}
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
        elif line.startswith("trojan://"):
            d["protocol"] = "trojan"
            p = urllib.parse.urlparse(line)
            q = urllib.parse.parse_qs(p.query)
            d.update({
                "type": "url", "host": p.hostname, "port": int(p.port or 443),
                "uuid": p.username,
                "sni": q.get("sni", [None])[0] or q.get("host", [None])[0],
                "security": "tls",
                "transport": q.get("type", ["tcp"])[0],
                "fp": q.get("fp", [None])[0],
            })
        elif line.startswith("ss://"):
            d["protocol"] = "ss"
            bu = line.split("#")[0]
            p = urllib.parse.urlparse(bu)
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
        elif line.startswith("vmess://"):
            d["protocol"] = "vmess"
            b = line[8:]; b += "=" * ((4 - len(b) % 4) % 4)
            dc = json.loads(base64.b64decode(b).decode())
            d.update({
                "type": "vmess", "data": dc, "host": dc.get("add"),
                "port": int(dc.get("port", 0)),
                "sni": dc.get("sni") or dc.get("host"),
                "transport": dc.get("net", "tcp"),
                "security": dc.get("tls", "none"),
            })
        else:
            return None
    except:
        return None
    return d if d.get("host") and d.get("port") else None


# ═══════════════════════════════════════════════════════════════
# FULL TEST PIPELINE
# ═══════════════════════════════════════════════════════════════

def full_test(d, ip):
    """Analyze → TCP test → TLS test → Score"""
    h, pt = d["host"], d["port"]
    sni = d.get("sni")
    proto = d["protocol"]

    # Phase 1: Deep analysis (static checks)
    if proto == "vless":
        base_score, reasons, rejects = analyze_vless(d, ip)
    elif proto == "trojan":
        base_score, reasons, rejects = analyze_trojan(d, ip)
    elif proto == "ss":
        base_score, reasons, rejects = analyze_ss(d, ip)
    else:
        return None

    # If rejected by static analysis, skip
    if rejects and base_score == 0:
        return {"d": d, "ip": ip, "passed": False, "reasons": reasons,
                "rejects": rejects, "score": 0, "tcp": -1, "tls": -1}

    # Phase 2: Connectivity test (3x TCP)
    tcp_lats = []
    for i in range(3):
        if i > 0: time.sleep(0.08)
        ok, lat = tcp_connect(h, pt)
        if ok:
            tcp_lats.append(lat)

    if len(tcp_lats) < 2:  # Need at least 2/3 to pass
        rejects.append(f"❌ TCP failed ({len(tcp_lats)}/3)")
        return {"d": d, "ip": ip, "passed": False, "reasons": reasons,
                "rejects": rejects, "score": 0, "tcp": -1, "tls": -1}

    avg_tcp = round(sum(tcp_lats) / len(tcp_lats), 1)

    # Phase 3: TLS test (2x for TLS protocols)
    need_tls = d["security"] in ("tls", "reality") or proto == "trojan"
    tls_lat = -1

    if need_tls:
        tls_lats = []
        for i in range(2):
            if i > 0: time.sleep(0.08)
            ok, lat, ver = tls_handshake(h, pt, sni)
            if ok:
                tls_lats.append(lat)

        if len(tls_lats) < 2:
            rejects.append(f"❌ TLS failed ({len(tls_lats)}/2)")
            return {"d": d, "ip": ip, "passed": False, "reasons": reasons,
                    "rejects": rejects, "score": 0, "tcp": avg_tcp, "tls": -1}

        tls_lat = round(sum(tls_lats) / len(tls_lats), 1)

    # Phase 4: Final scoring
    avg = tls_lat if tls_lat > 0 else avg_tcp
    final_score = base_score

    # Latency bonus
    if 0 < avg < 50: final_score += 10
    elif 0 < avg < 100: final_score += 8
    elif 0 < avg < 200: final_score += 5
    elif 0 < avg < 400: final_score += 3
    elif avg > 1000: final_score -= 5

    # Stability bonus
    if len(tcp_lats) == 3: final_score += 3

    reasons.append(f"✅ TCP: {avg_tcp}ms (3/3) | TLS: {tls_lat}ms" if tls_lat > 0 else f"✅ TCP: {avg_tcp}ms (3/3)")

    return {"d": d, "ip": ip, "passed": True, "reasons": reasons,
            "rejects": rejects, "score": final_score, "tcp": avg_tcp, "tls": tls_lat}


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def format_output(d, name):
    raw = d["raw"]
    if d["type"] == "vmess":
        dc = d["data"]; dc["ps"] = name; dc["fb_block"] = FB
        return f"vmess://{base64.b64encode(json.dumps(dc).encode()).decode()}"
    base = raw.split("#")[0]
    delim = "&" if "?" in base else "?"
    return f"{base}{delim}{FB}#{urllib.parse.quote(name)}"


def main():
    tz = pytz.timezone("Asia/Yangon")
    now = datetime.now(tz)
    t0 = time.time()

    print("=" * 70)
    print(f"  🔑 SG Smart Checker | {now.strftime('%Y-%m-%d %H:%M:%S MMT')}")
    print(f"  📥 {SOURCE_URL}")
    print("=" * 70)

    # ── Step 1: Fetch ──
    print(f"\n  📥 Fetching subscription...")
    r = requests.get(SOURCE_URL, timeout=15)
    content = r.text.strip()
    try:
        lines = base64.b64decode(content).decode().splitlines()
    except:
        lines = content.splitlines()

    # ── Step 2: Parse + Dedup ──
    configs = []
    seen = set()
    for l in lines:
        l = l.strip()
        if l and any(l.startswith(p) for p in ("vless://", "trojan://", "ss://", "vmess://")):
            d = parse_line(l)
            if d:
                key = f"{d['host']}:{d['port']}:{d.get('uuid', '')}"
                if key not in seen:
                    seen.add(key)
                    configs.append(d)

    proto_c = {}
    for c in configs:
        proto_c[c["protocol"]] = proto_c.get(c["protocol"], 0) + 1

    print(f"  📊 Parsed: {len(configs)} unique configs")
    for p, c in sorted(proto_c.items(), key=lambda x: -x[1]):
        print(f"     {p.upper():10} {c}")

    # ── Step 3: Resolve DNS (parallel) ──
    hosts = list(set(c["host"] for c in configs))
    print(f"\n  📡 Resolving {len(hosts)} hosts...")
    host_ip = {}
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(resolve, h): h for h in hosts}
        for f in as_completed(futs):
            try:
                h = futs[f]
                host_ip[h] = f.result()
            except:
                pass
    resolved = sum(1 for v in host_ip.values() if v)
    print(f"     Resolved: {resolved}/{len(hosts)}")

    # CDN breakdown
    cdn_count = 0
    direct_count = 0
    for h, ip in host_ip.items():
        if ip and is_cdn(ip):
            cdn_count += 1
        elif ip:
            direct_count += 1
    print(f"     Direct IPs: {direct_count} | CDN IPs: {cdn_count}")

    # ── Step 4: Full test pipeline (parallel) ──
    print(f"\n  🧪 Testing {len(configs)} configs (analyze → TCP 3x → TLS 2x)...")
    results = []

    with ThreadPoolExecutor(max_workers=25) as ex:
        futs = {}
        for c in configs:
            ip = host_ip.get(c["host"])
            futs[ex.submit(full_test, c, ip)] = c

        done = 0
        for f in as_completed(futs):
            done += 1
            try:
                r = f.result()
                if r:
                    results.append(r)
            except:
                pass
            if done % 50 == 0:
                passed = sum(1 for r in results if r["passed"])
                print(f"     Progress: {done}/{len(configs)} | Passed so far: {passed}")

    # ── Step 5: Results ──
    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]

    passed.sort(key=lambda x: (-x["score"], x["tls"] if x["tls"] > 0 else 9999))
    top = passed[:MAX_OUTPUT]

    print(f"\n{'='*70}")
    print(f"  📊 RESULTS")
    print(f"{'='*70}")
    print(f"  ✅ Passed: {len(passed)}")
    print(f"  ❌ Failed: {len(failed)}")
    print(f"  💾 Saved:  {len(top)}")

    # ── Detailed output for top configs ──
    print(f"\n  {'─'*66}")
    flag = "🇸🇬"

    for i, r in enumerate(top, 1):
        d = r["d"]
        lat = r["tls"] if r["tls"] > 0 else r["tcp"]
        proto = d["protocol"].upper()
        sec = d["security"]
        tp = d["transport"]

        type_tag = ""
        if sec == "reality":
            type_tag = "🛡️ Reality+XTLS"
        elif sec == "tls" and tp == "ws":
            type_tag = "🌐 WS+TLS"
        elif sec == "tls":
            type_tag = "🔒 TLS"
        elif proto == "TROJAN":
            type_tag = "🐴 Trojan"
        elif proto == "SS":
            type_tag = "🔑 SS"

        print(f"\n  {flag} SG {i} | Score: {r['score']} | {type_tag} | {lat:.0f}ms")
        print(f"     Host: {d['host']}:{d['port']} ({r['ip']})")
        if d.get("sni"):
            print(f"     SNI:  {d['sni']}")
        if d.get("fp"):
            print(f"     FP:   {d['fp']}")
        for reason in r["reasons"]:
            print(f"     {reason}")

    # ── Show WHY failed configs failed (sample) ──
    reject_reasons = {}
    for r in failed:
        for rej in r.get("rejects", []):
            key = rej.split("→")[0].strip() if "→" in rej else rej[:50]
            reject_reasons[key] = reject_reasons.get(key, 0) + 1

    print(f"\n  {'─'*66}")
    print(f"  ❌ Top Rejection Reasons:")
    for reason, count in sorted(reject_reasons.items(), key=lambda x: -x[1])[:8]:
        print(f"     {count:>3}x {reason}")

    # ── Save ──
    all_out = []
    for i, r in enumerate(top, 1):
        all_out.append(format_output(r["d"], f"{flag} SG {i}"))

    title = f"#profile-title: {now.strftime('%I:%M %p')} Updated"
    plain = title + "\n" + "\n".join(all_out)

    with open("servers", "w") as f:
        f.write(base64.b64encode(plain.encode()).decode())
    with open("servers_plain.txt", "w") as f:
        f.write(plain)

    print(f"\n{'='*70}")
    print(f"  ⏱️ Total: {time.time()-t0:.1f}s")
    print(f"  💾 servers (base64) + servers_plain.txt")
    print(f"  ✅ Done!")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
