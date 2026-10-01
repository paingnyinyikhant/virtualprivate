#!/usr/bin/env python3
"""
V2Ray Auto Tester — GitHub Actions (Hourly)
- Multi-source fetch (base64 + plain, auto-detect)
- GeoIP pre-filter (SG/US/JP/TH/HK)
- Real-delay test via xray + curl
- Output: single file `servers` (base64 subscription)
"""
import os
import sys
import json
import base64
import re
import socket
import queue
import time
import subprocess
import shutil
import threading
import datetime
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ==================== SETTINGS ====================
TOP_COUNT = 30
ALLOWED_COUNTRIES = {"SG", "US", "JP", "TH", "HK"}
TEST_URL = "https://www.gstatic.com/generate_204"
BASE_PORT = 10808
WORKERS = 16
TIMEOUT_SEC = 5
TCP_PRECHECK = 1.5
DEBUG = False

# ✅ Working sources (verified)
SOURCE_URLS = [
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

SUPPORTED_SS_METHODS = {
    "aes-256-gcm", "aes-128-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
}
SS_METHOD_ALIAS = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
}

COUNTRY_NAMES = {
    "SG": "Singapore", "US": "United States", "JP": "Japan",
    "TH": "Thailand", "HK": "Hong Kong", "VN": "Vietnam",
    "KR": "Korea", "TW": "Taiwan", "IN": "India", "DE": "Germany",
    "FR": "France", "NL": "Netherlands", "GB": "United Kingdom",
    "CA": "Canada", "AU": "Australia", "MY": "Malaysia",
    "ID": "Indonesia", "PH": "Philippines", "CN": "China",
}


# ==================== COLORS ====================
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; CYAN = "\033[36m"


# ==================== HELPERS ====================
def find_xray():
    p = os.environ.get("XRAY_BIN")
    if p and os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    for name in ("xray", "xray-core"):
        w = shutil.which(name)
        if w:
            return w
    for cand in (
        os.path.expanduser("~/xray-bin/xray"),
        os.path.expanduser("~/bin/xray"),
        "/usr/local/bin/xray",
        "./xray",
    ):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def get_flag_emoji(cc):
    if not cc or len(cc) != 2:
        return ""
    try:
        return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + \
               chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))
    except Exception:
        return ""


def _safe(v):
    """Convert any value to a safe string (never crashes)."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def tcp_open(host, port, timeout=TCP_PRECHECK):
    host = str(host).strip("[]")
    try:
        infos = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
    except OSError:
        return False
    for family, socktype, proto, _, addr in infos[:2]:
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        try:
            s.connect(addr)
            s.close()
            return True
        except OSError:
            s.close()
    return False


def wait_port(port, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            s.close()
            time.sleep(0.05)
    return False


def _b64(s):
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _host_port(host_port, default=443):
    if host_port.startswith("["):
        host, rest = host_port[1:].split("]", 1)
        m = re.search(r"\d+", rest)
        return host, int(m.group()) if m else default
    if ":" in host_port:
        host, ps = host_port.rsplit(":", 1)
        m = re.search(r"\d+", ps)
        return host, int(m.group()) if m else default
    return host_port, default


# ==================== PARSERS ====================
def parse_vless(link):
    try:
        if not link.startswith("vless://"):
            return None
        remark = ""
        if "#" in link:
            link, remark = link.split("#", 1)
            remark = urllib.parse.unquote(remark)
        rest = link[len("vless://"):]
        uuid, rest = rest.split("@", 1)
        host_port, qs = rest.split("?", 1) if "?" in rest else (rest, "")
        host, port = _host_port(host_port, 443)
        q = dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))
        return {
            "proto": "vless",
            "uuid": _safe(uuid),
            "host": _safe(host),
            "port": int(port),
            "query": {k: _safe(v) for k, v in q.items()},
            "remark": remark,
        }
    except Exception:
        return None


def parse_ss(link):
    try:
        if not link.startswith("ss://"):
            return None
        remark = ""
        raw = link[len("ss://"):]
        if "#" in raw:
            raw, remark = raw.split("#", 1)
            remark = urllib.parse.unquote(remark)
        plugin = ""
        if "/?" in raw:
            raw, extra = raw.split("/?", 1)
            plugin = dict(urllib.parse.parse_qsl(extra)).get("plugin", "")
        elif "?" in raw:
            raw, extra = raw.split("?", 1)
            plugin = dict(urllib.parse.parse_qsl(extra)).get("plugin", "")

        if "@" in raw:
            userinfo, host_port = raw.split("@", 1)
            try:
                userinfo = _b64(urllib.parse.unquote(userinfo)).decode("utf-8")
            except Exception:
                userinfo = urllib.parse.unquote(userinfo)
            method, password = userinfo.split(":", 1)
            host, port = _host_port(host_port, 8388)
        else:
            decoded = _b64(raw).decode("utf-8")
            userinfo, host_port = decoded.split("@", 1)
            method, password = userinfo.split(":", 1)
            host, port = _host_port(host_port, 8388)

        method = SS_METHOD_ALIAS.get(method.lower(), method)
        return {
            "proto": "shadowsocks",
            "host": _safe(host),
            "port": int(port),
            "method": _safe(method),
            "password": _safe(password),
            "plugin": _safe(plugin),
            "remark": remark,
        }
    except Exception:
        return None


def parse_vmess(link):
    try:
        if not link.startswith("vmess://"):
            return None
        remark = ""
        raw = link[len("vmess://"):]
        if "#" in raw:
            raw, remark = raw.split("#", 1)
            remark = urllib.parse.unquote(remark)

        data = json.loads(_b64(raw).decode("utf-8"))
        host = data.get("add") or data.get("addr") or ""

        # ---- normalize tls (could be bool, str, or None) ----
        tls_raw = data.get("tls")
        if isinstance(tls_raw, bool):
            tls = "tls" if tls_raw else ""
        else:
            tls = _safe(tls_raw)

        def _i(v, default=0):
            try:
                return int(v)
            except (TypeError, ValueError):
                return default

        return {
            "proto": "vmess",
            "uuid": _safe(data.get("id")),
            "host": _safe(host),
            "port": _i(data.get("port"), 443),
            "aid": _i(data.get("aid"), 0),
            "scy": _safe(data.get("scy")) or "auto",
            "net": _safe(data.get("net")) or "tcp",
            "tls": tls,
            "sni": _safe(data.get("sni")) or _safe(data.get("host")) or _safe(host),
            "host_header": _safe(data.get("host")),
            "path": _safe(data.get("path")) or "/",
            "type": _safe(data.get("type")) or "none",
            "alpn": _safe(data.get("alpn")),
            "fp": _safe(data.get("fp")) or "chrome",
            "remark": remark or _safe(data.get("ps")),
        }
    except Exception:
        return None


def parse_link(link):
    try:
        if link.startswith("vless://"):
            return parse_vless(link)
        if link.startswith("ss://"):
            return parse_ss(link)
        if link.startswith("vmess://"):
            return parse_vmess(link)
    except Exception:
        return None
    return None


def node_key(link):
    """Build a dedupe key. Never raises."""
    try:
        p = parse_link(link)
        if not p:
            return link.split("#")[0].strip()

        if p["proto"] == "vless":
            q = p["query"]
            return "|".join([
                "vless",
                _safe(p.get("uuid")).lower(),
                _safe(p.get("host")).lower(),
                _safe(p.get("port")),
                _safe(q.get("type") or "tcp").lower(),
                urllib.parse.unquote(_safe(q.get("path") or "/")),
                _safe(q.get("security") or "none").lower(),
                _safe(q.get("sni") or q.get("host") or "").lower(),
            ])

        if p["proto"] == "vmess":
            return "|".join([
                "vmess",
                _safe(p.get("uuid")).lower(),
                _safe(p.get("host")).lower(),
                _safe(p.get("port")),
                _safe(p.get("net") or ""),
                _safe(p.get("path") or ""),
                _safe(p.get("tls") or ""),
            ])

        return "|".join([
            "ss",
            _safe(p.get("host")).lower(),
            _safe(p.get("port")),
            _safe(p.get("method")).lower(),
            _safe(p.get("password")),
            _safe(p.get("plugin") or ""),
        ])
    except Exception:
        return link.split("#")[0].strip()


def dedupe_links(links):
    seen, out, dropped = set(), [], 0
    for ln in links:
        try:
            k = node_key(ln)
        except Exception:
            k = ln.split("#")[0].strip() or ln
        if k in seen:
            dropped += 1
            continue
        seen.add(k)
        out.append(ln)
    return out, dropped


# ==================== XRAY CONFIG ====================
def create_xray_config(p, path, listen_port):
    if p.get("proto") == "shadowsocks":
        outbound = {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": p["host"],
                    "port": int(p["port"]),
                    "method": p["method"],
                    "password": p["password"],
                    "level": 0,
                }]
            },
        }
    elif p.get("proto") == "vmess":
        q = {
            "type": p.get("net") or "tcp",
            "security": "tls" if p.get("tls") in ("tls", "xtls") else (p.get("tls") or "none"),
            "sni": p.get("sni"),
            "host": p.get("host_header"),
            "path": p.get("path") or "/",
            "headerType": p.get("type") or "none",
            "alpn": p.get("alpn") or "",
            "fp": p.get("fp") or "chrome",
        }
        host, port, uuid = p["host"], int(p["port"]), p["uuid"]
        network, security = q["type"], q["security"]
        sni = q.get("sni") or q.get("host") or host
        raw_path = urllib.parse.unquote(q.get("path", "/")) or "/"
        header_host = q.get("host") or sni
        stream = {"network": network, "security": security}
        if network == "ws":
            stream["wsSettings"] = {"path": raw_path, "headers": {"Host": header_host}}
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
        else:
            stream["tcpSettings"] = {"header": {"type": q.get("headerType", "none")}}
        if security == "tls":
            stream["tlsSettings"] = {
                "serverName": sni,
                "allowInsecure": True,
                "fingerprint": q.get("fp") or "chrome",
            }
        outbound = {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "alterId": p.get("aid") or 0,
                        "security": p.get("scy") or "auto",
                        "level": 0,
                    }],
                }]
            },
            "streamSettings": stream,
        }
    else:  # vless
        q = p["query"]
        host, port, uuid = p["host"], int(p["port"]), p["uuid"]
        network = q.get("type", "tcp")
        security = q.get("security", "none")
        sni = q.get("sni") or q.get("host") or host
        raw_path = urllib.parse.unquote(q.get("path", "/")) or "/"
        header_host = q.get("host") or sni
        stream = {"network": network, "security": security}
        if network == "ws":
            stream["wsSettings"] = {"path": raw_path, "headers": {"Host": header_host}}
        elif network == "grpc":
            stream["grpcSettings"] = {
                "serviceName": q.get("serviceName", ""),
                "multiMode": q.get("mode") == "multi",
            }
        elif network in ("xhttp", "splithttp"):
            stream["xhttpSettings"] = {
                "path": raw_path,
                "host": header_host,
                "mode": q.get("mode") or "auto",
            }
        elif network == "tcp" and q.get("headerType") == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [raw_path],
                        "headers": {"Host": [header_host]},
                    },
                }
            }
        else:
            stream["tcpSettings"] = {"header": {"type": q.get("headerType", "none")}}

        if security == "tls":
            tls = {
                "serverName": sni,
                "allowInsecure": q.get("allowInsecure", "0") in ("1", "true", "True"),
                "fingerprint": q.get("fp") or "chrome",
            }
            alpn = q.get("alpn", "")
            if alpn:
                tls["alpn"] = [x.strip() for x in urllib.parse.unquote(alpn).split(",") if x.strip()]
            stream["tlsSettings"] = tls
        elif security == "reality":
            stream["realitySettings"] = {
                "serverName": sni,
                "fingerprint": q.get("fp") or "chrome",
                "publicKey": q.get("pbk", ""),
                "shortId": q.get("sid", ""),
                "spiderX": urllib.parse.unquote(q.get("spx", "/")) or "/",
            }

        user = {"id": uuid, "encryption": q.get("encryption") or "none", "level": 0}
        if q.get("flow"):
            user["flow"] = q["flow"]

        outbound = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream,
        }

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks",
            "port": listen_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [outbound],
    }

    with open(path, "w") as f:
        json.dump(config, f)


# ==================== DELAY TEST ====================
def curl_real_delay(url, listen_port):
    curl = shutil.which("curl") or "/usr/bin/curl"
    cmd = [
        curl, "-sS", "-o", "/dev/null",
        "-w", "%{http_code} %{time_starttransfer}",
        "--connect-timeout", str(TIMEOUT_SEC),
        "--max-time", str(TIMEOUT_SEC),
        "-x", f"socks5h://127.0.0.1:{listen_port}",
        url,
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=TIMEOUT_SEC + 1)
        text = out.decode("utf-8", "replace").strip().split()
        code, ttfb = int(text[0]), float(text[1])
        if code in (200, 204):
            return int(round(ttfb * 1000)), "ok"
        return None, f"http_{code}"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except Exception:
        return None, "curl_fail"


def test_one(link_data, xray_bin, port_q):
    link, parsed, cc = link_data

    if parsed.get("proto") == "shadowsocks":
        if parsed.get("plugin"):
            return None, "ss_plugin", parsed, link, cc
        if parsed["method"].lower() not in SUPPORTED_SS_METHODS:
            return None, "ss_legacy", parsed, link, cc

    if not tcp_open(parsed["host"], parsed["port"]):
        return None, "tcp_closed", parsed, link, cc

    listen_port = port_q.get()
    cfg_path = f"temp_config_{listen_port}.json"
    env = os.environ.copy()
    asset = os.environ.get("XRAY_LOCATION_ASSET")
    if asset and os.path.isdir(asset):
        env["XRAY_LOCATION_ASSET"] = asset

    proc = None
    try:
        try:
            create_xray_config(parsed, cfg_path, listen_port)
        except Exception:
            return None, "config_error", parsed, link, cc

        proc = subprocess.Popen(
            [xray_bin, "run", "-c", os.path.abspath(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        if not wait_port(listen_port, 3.0):
            return None, "xray_dead", parsed, link, cc

        delay, reason = curl_real_delay(TEST_URL, listen_port)
        return delay, reason, parsed, link, cc
    except Exception:
        return None, "test_error", parsed, link, cc
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        try:
            os.remove(cfg_path)
        except OSError:
            pass
        port_q.put(listen_port)


def fmt_bar(done, total, width=28):
    if total <= 0:
        return "[" + " " * width + "]"
    filled = int(width * done / total)
    return "[" + "█" * filled + "░" * (width - filled) + "]"


# ==================== MAIN ====================
def main():
    xray_bin = find_xray()
    if not xray_bin:
        print(f"{C.RED}❌ xray not found. Set XRAY_BIN.{C.RESET}")
        sys.exit(1)

    print(f"{C.CYAN}xray:{C.RESET} {xray_bin}")
    print(f"{C.CYAN}workers:{C.RESET} {WORKERS}  {C.CYAN}TOP:{C.RESET} {TOP_COUNT}")
    print(f"{C.CYAN}🎯 Target:{C.RESET} {', '.join(sorted(ALLOWED_COUNTRIES))}")

    # ---------- Fetch ----------
    print(f"\n{C.BOLD}Fetching from {len(SOURCE_URLS)} sources...{C.RESET}")
    raw_lines = []

    def fetch(url):
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            return url, r.text, None
        except Exception as e:
            return url, None, str(e)

    with ThreadPoolExecutor(max_workers=len(SOURCE_URLS)) as pool:
        for url, text, err in pool.map(fetch, SOURCE_URLS):
            if err:
                print(f"  {C.RED}✗ {url[:70]} → {err}{C.RESET}")
                continue

            # Auto-detect base64 vs plain
            decoded = text
            s = text.strip()
            if "://" not in s[:200] and " " not in s[:200]:
                try:
                    padded = s + "=" * ((4 - len(s) % 4) % 4)
                    if re.match(r"^[A-Za-z0-9+/=_\-\s]+$", padded):
                        cand = base64.b64decode(padded).decode("utf-8", "ignore")
                        if "://" in cand:
                            decoded = cand
                except Exception:
                    pass

            n = 0
            for ln in decoded.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                if ln.lower().startswith(("vless://", "vmess://", "ss://")):
                    raw_lines.append(ln)
                    n += 1
            print(f"  {C.GREEN}✓{C.RESET} {url[:70]} → {n} nodes")

    print(f"\n{C.GREEN}Total raw: {len(raw_lines)}{C.RESET}")
    if not raw_lines:
        print(f"{C.RED}❌ No configs.{C.RESET}")
        sys.exit(1)

    lines, dropped = dedupe_links(raw_lines)
    print(f"{C.GREEN}Unique: {len(lines)}{C.RESET} {C.DIM}(dropped {dropped}){C.RESET}")

    # ---------- Pre-filter ----------
    print(f"\n{C.BOLD}=== GeoIP Pre-filter ==={C.RESET}")
    link_parsed, hosts = [], set()
    for ln in lines:
        p = parse_link(ln)
        if p and p.get("host"):
            link_parsed.append((ln, p))
            hosts.add(p["host"])

    print(f"  Parsed: {C.GREEN}{len(link_parsed)}{C.RESET}  "
          f"Hosts: {C.CYAN}{len(hosts)}{C.RESET}")

    if not hosts:
        print(f"{C.RED}❌ No hosts parsed.{C.RESET}")
        sys.exit(1)

    host_ip = {}

    def resolve(h):
        try:
            return h, socket.gethostbyname(h.strip("[]"))
        except Exception:
            return h, None

    print(f"  {C.YELLOW}⏳ DNS...{C.RESET}")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=100) as pool:
        for h, ip in pool.map(resolve, hosts):
            if ip:
                host_ip[h] = ip
    print(f"  {C.GREEN}✓ DNS done{C.RESET} {time.time()-t0:.1f}s ({len(host_ip)})")

    uniq_ips = list(set(host_ip.values()))
    ip_cc = {}
    print(f"  {C.YELLOW}⏳ GeoIP ({len(uniq_ips)} IPs)...{C.RESET}")
    t0 = time.time()
    for i in range(0, len(uniq_ips), 100):
        chunk = uniq_ips[i:i+100]
        try:
            r = requests.post(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                json=[{"query": ip} for ip in chunk],
                timeout=10,
            ).json()
            for item in r:
                if item.get("status") == "success":
                    ip_cc[item["query"]] = item.get("countryCode", "").upper()
        except Exception as e:
            print(f"    {C.RED}GeoIP chunk: {e}{C.RESET}")
    print(f"  {C.GREEN}✓ GeoIP done{C.RESET} {time.time()-t0:.1f}s")

    filtered = []
    for ln, p in link_parsed:
        ip = host_ip.get(p["host"])
        if not ip:
            continue
        cc = ip_cc.get(ip, "")
        if cc in ALLOWED_COUNTRIES:
            filtered.append((ln, p, cc))

    print(f"\n{C.BOLD}{C.GREEN}🎯 Target: {len(filtered)} / {len(lines)}{C.RESET}\n")

    if not filtered:
        print(f"{C.RED}No matching nodes.{C.RESET}")
        sys.exit(1)

    # ---------- Test ----------
    print(f"{C.BOLD}=== Real Internet Test ==={C.RESET}\n")
    port_q = queue.Queue()
    for i in range(WORKERS):
        port_q.put(BASE_PORT + i)

    total = len(filtered)
    state = {"done": 0, "online": 0}
    results = []
    fails = {}
    t_start = time.time()
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {pool.submit(test_one, item, xray_bin, port_q): item for item in filtered}
        for fut in as_completed(futs):
            delay, reason, parsed, link, cc = fut.result()
            with lock:
                state["done"] += 1
                done = state["done"]

                if delay is not None:
                    state["online"] += 1
                    flag = get_flag_emoji(cc)
                    results.append((delay, link, cc, flag, parsed))
                    bar = fmt_bar(done, total)
                    print(f"{bar} {done:>3}/{total}  "
                          f"{C.GREEN}✓ {delay:>4}ms{C.RESET}  "
                          f"{flag} {cc:<2}  "
                          f"{C.DIM}{parsed['host']}:{parsed['port']}{C.RESET}",
                          flush=True)
                else:
                    fails[reason] = fails.get(reason, 0) + 1
                    if done % 20 == 0 or DEBUG:
                        bar = fmt_bar(done, total)
                        print(f"{bar} {done:>3}/{total}  "
                              f"{C.RED}✗ {reason}{C.RESET}  "
                              f"{C.DIM}{parsed['host']}:{parsed['port']}{C.RESET}",
                              flush=True)

    elapsed = time.time() - t_start
    print(f"\n{C.BOLD}=== Summary ==={C.RESET}")
    print(f"  {C.GREEN}ONLINE : {state['online']}{C.RESET} / {total}")
    print(f"  {C.RED}FAILED : {total - state['online']}{C.RESET}")
    print(f"  {C.CYAN}Time   : {elapsed:.1f}s{C.RESET}")

    if fails:
        print(f"  Reasons:")
        for r, c in sorted(fails.items(), key=lambda x: -x[1]):
            print(f"    {C.RED}{r:>15}{C.RESET} : {c}")

    if not results:
        print(f"\n{C.RED}❌ No ONLINE nodes.{C.RESET}")
        sys.exit(1)

    # ---------- Write single `servers` file ----------
    results.sort(key=lambda x: x[0])
    top = results[:TOP_COUNT]

    now = datetime.datetime.utcnow().strftime("%d-%b-%Y %H:%M UTC")
    out = [f"#profile-title: Main {now} ({len(top)} nodes)"]

    counter = {}
    for delay, link, cc, flag, _ in top:
        counter[cc] = counter.get(cc, 0) + 1
        name = f"{flag} {COUNTRY_NAMES.get(cc, cc)} {counter[cc]} - {delay}ms"
        base = link.split("#")[0]
        out.append(f"{base}#{urllib.parse.quote(name)}")

    with open("servers", "w") as f:
        f.write(base64.b64encode("\n".join(out).encode()).decode())

    print(f"\n{C.GREEN}✅ servers : {len(top)} nodes written{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Interrupted.{C.RESET}")
        sys.exit(130)
