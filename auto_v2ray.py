#!/usr/bin/env python3
"""
V2RayNG-style Real Delay.
vless / ss (AEAD via Xray, aes-*-cfb via pycryptodome)
"""
import base64
import datetime
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import queue
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    raise SystemExit("pip install requests")

SOURCE_URLS = [
    # SG list အရင် — duplicate ဖြစ်ရင် SG ဖိုင်က နိုင်
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/vless.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/all.txt",
]
WANT_COUNTRIES = ("SG", "JP", "US", "TH", "HK")
COUNTRY_PAT = re.compile(
    r"(🇸🇬|🇯🇵|🇺🇸|🇹🇭|🇭🇰)"
    r"|(?<![A-Za-z])(SG|JP|US|TH|HK)(?![A-Za-z])"
    r"|(singapore|japan|thailand|hong\s*kong|united\s*states|\busa\b)",
    re.I,
)
TEST_URL = "https://www.gstatic.com/generate_204"
BASE_PORT = 10808
WORKERS = 3
TIMEOUT_SEC = 5
TCP_PRECHECK = 1.2
XRAY_ASSET_PATH = os.path.expanduser("~/xray-bin")
XRAY_SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
STREAM_SS_METHODS = {
    "aes-128-cfb": (16, 16),
    "aes-192-cfb": (24, 16),
    "aes-256-cfb": (32, 16),
    "aes-128-ctr": (16, 16),
    "aes-192-ctr": (24, 16),
    "aes-256-ctr": (32, 16),
}
SS_METHOD_ALIAS = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
}

_print_lock = threading.Lock()


def find_xray():
    for name in ("xray", "xray-core"):
        p = shutil.which(name)
        if p:
            return p
    for p in (
        os.path.expanduser("~/xray-bin/xray"),
        os.path.expanduser("~/bin/xray"),
        "/data/data/com.termux/files/usr/bin/xray",
        "./xray",
    ):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def tcp_open(host, port, timeout=TCP_PRECHECK):
    host = str(host).strip("[]")
    result = []

    def _resolve():
        try:
            result.extend(socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM))
        except OSError:
            pass

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive() or not result:
        return False
    for family, socktype, proto, _, addr in result:
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        try:
            s.connect(addr)
            s.close()
            return True
        except OSError:
            s.close()
    return False


def wait_port(port, timeout=2.5):
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
        port = int(re.search(r"\d+", rest).group()) if re.search(r"\d+", rest) else default
        return host, port
    if ":" in host_port:
        host, ps = host_port.rsplit(":", 1)
        m = re.search(r"\d+", ps)
        return host, int(m.group()) if m else default
    return host_port, default


def evp_bytes_to_key(password, key_len):
    pw = password.encode("utf-8") if isinstance(password, str) else password
    m = b""
    out = b""
    while len(out) < key_len:
        m = hashlib.md5(m + pw).digest()
        out += m
    return out[:key_len]


def _aes_cipher(method, key, iv):
    from Crypto.Cipher import AES
    if method.endswith("-ctr"):
        from Crypto.Util import Counter
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        return AES.new(key, AES.MODE_CTR, counter=ctr)
    return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)


def ss_stream_real_delay(parsed, timeout=TIMEOUT_SEC):
    try:
        from Crypto.Cipher import AES  # noqa: F401
    except ImportError:
        return None, "pip_install_pycryptodome"

    method = parsed["method"].lower()
    if method not in STREAM_SS_METHODS:
        return None, f"ss_no_impl_{method}"
    key_len, iv_len = STREAM_SS_METHODS[method]
    key = evp_bytes_to_key(parsed["password"], key_len)

    host, port = "www.gstatic.com", 80
    req = (
        b"GET /generate_204 HTTP/1.1\r\n"
        b"Host: www.gstatic.com\r\n"
        b"Connection: close\r\n\r\n"
    )
    atyp = b"\x03" + bytes([len(host)]) + host.encode("ascii") + port.to_bytes(2, "big")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((parsed["host"], int(parsed["port"])))
        iv = os.urandom(iv_len)
        enc = _aes_cipher(method, key, iv)
        s.sendall(iv + enc.encrypt(atyp + req))

        buf = b""
        while len(buf) < iv_len + 8:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        if len(buf) < iv_len:
            return None, "ss_short"
        riv, rest = buf[:iv_len], buf[iv_len:]
        dec = _aes_cipher(method, key, riv)
        plain = dec.decrypt(rest) if rest else b""
        while b"\r\n" not in plain and time.time() - t0 < timeout:
            chunk = s.recv(4096)
            if not chunk:
                break
            plain += dec.decrypt(chunk)
        ms = int(round((time.time() - t0) * 1000))
        head = plain.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if "204" in head or "200" in head:
            return ms, "ok"
        if not plain:
            return None, "ss_empty"
        return None, f"ss_http:{head[:40]}"
    except socket.timeout:
        return None, "timeout"
    except Exception as e:
        return None, f"ss_py:{type(e).__name__}"
    finally:
        s.close()


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
        if "?" in rest:
            host_port, qs = rest.split("?", 1)
        else:
            host_port, qs = rest, ""
        host, port = _host_port(host_port, 443)
        q = dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))
        return {"proto": "vless", "uuid": uuid, "host": host, "port": port, "query": q, "remark": remark}
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
            "host": host,
            "port": port,
            "method": method,
            "password": password,
            "plugin": plugin,
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
        return {
            "proto": "vmess",
            "uuid": data.get("id", ""),
            "host": host,
            "port": int(data.get("port") or 443),
            "aid": int(data.get("aid") or 0),
            "scy": data.get("scy") or "auto",
            "net": data.get("net") or "tcp",
            "tls": data.get("tls") or "",
            "sni": data.get("sni") or data.get("host") or host,
            "host_header": data.get("host") or "",
            "path": data.get("path") or "/",
            "type": data.get("type") or "none",
            "alpn": data.get("alpn") or "",
            "fp": data.get("fp") or "chrome",
            "remark": remark or data.get("ps") or "",
        }
    except Exception:
        return None


def parse_link(link):
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("ss://"):
        return parse_ss(link)
    if link.startswith("vmess://"):
        return parse_vmess(link)
    return None


TLD_COUNTRY = (
    (".com.sg", "SG"), (".com.hk", "HK"), (".co.th", "TH"),
    (".sg", "SG"), (".jp", "JP"), (".hk", "HK"), (".th", "TH"),
)


def country_blob(link):
    parts = []
    if "#" in link:
        parts.append(urllib.parse.unquote(link.split("#", 1)[1]))
    p = parse_link(link)
    if p:
        parts.append(p.get("remark") or "")
        if p.get("proto") == "vless":
            q = p.get("query") or {}
            parts.append(q.get("sni") or "")
            parts.append(q.get("host") or "")
        elif p.get("proto") == "vmess":
            parts.append(p.get("sni") or "")
            parts.append(p.get("host_header") or "")
    return " ".join(parts)


def country_code(link, default=None):
    blob = country_blob(link)
    m = COUNTRY_PAT.search(blob)
    if m:
        g = m.group(0).upper()
        raw = m.group(0)
        if "🇸🇬" in raw or "SINGAPORE" in g or g == "SG":
            return "SG"
        if "🇯🇵" in raw or "JAPAN" in g or g == "JP":
            return "JP"
        if "🇺🇸" in raw or "UNITED STATES" in g or g in ("US", "USA"):
            return "US"
        if "🇹🇭" in raw or "THAILAND" in g or g == "TH":
            return "TH"
        if "🇭🇰" in raw or "HONG" in g or g == "HK":
            return "HK"
    low = blob.lower()
    for tld, cc in TLD_COUNTRY:
        if tld in low:
            return cc
    return default


def node_key(link):
    p = parse_link(link)
    if not p:
        return link.split("#")[0].strip()
    if p["proto"] == "vless":
        q = p["query"]
        return "|".join([
            "vless", p["uuid"].lower(), p["host"].lower(), str(p["port"]),
            (q.get("type") or "tcp").lower(),
            urllib.parse.unquote(q.get("path") or "/"),
            (q.get("security") or "none").lower(),
            (q.get("sni") or q.get("host") or "").lower(),
        ])
    if p["proto"] == "vmess":
        return "|".join([
            "vmess", p["uuid"].lower(), p["host"].lower(), str(p["port"]),
            p.get("net") or "", p.get("path") or "", p.get("tls") or "",
        ])
    return "|".join([
        "ss", p["host"].lower(), str(p["port"]),
        p["method"].lower(), p["password"], p.get("plugin") or "",
    ])


def dedupe_links(links):
    seen, out, dropped = set(), [], 0
    for ln in links:
        k = node_key(ln)
        if k in seen:
            dropped += 1
            continue
        seen.add(k)
        out.append(ln)
    return out, dropped


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
        p = {
            "proto": "vless",
            "host": p["host"],
            "port": p["port"],
            "uuid": p["uuid"],
            "query": q,
            "_as": "vmess",
            "scy": p.get("scy") or "auto",
            "aid": p.get("aid") or 0,
        }
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
    else:
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
                "path": raw_path, "host": header_host, "mode": q.get("mode") or "auto",
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


def curl_real_delay(url, listen_port):
    curl = shutil.which("curl")
    if not curl:
        return None, "no_curl"
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


def requests_real_delay(url, listen_port):
    try:
        import socks  # noqa: F401
    except ImportError:
        return None, "pip_install_pysocks"
    proxies = {
        "http": f"socks5h://127.0.0.1:{listen_port}",
        "https": f"socks5h://127.0.0.1:{listen_port}",
    }
    t0 = time.time()
    try:
        r = requests.get(url, proxies=proxies, timeout=TIMEOUT_SEC)
        if r.status_code in (200, 204):
            return int(round((time.time() - t0) * 1000)), "ok"
        return None, f"http_{r.status_code}"
    except Exception as e:
        return None, type(e).__name__


def test_one(idx, total, link, xray_bin, port_q):
    parsed = parse_link(link)
    if not parsed:
        return None, "parse_error", None, link, idx

    if parsed.get("proto") == "shadowsocks":
        if parsed.get("plugin"):
            return None, "ss_skip_plugin", parsed, link, idx
        m = parsed["method"].lower()
        if m in STREAM_SS_METHODS:
            if not tcp_open(parsed["host"], parsed["port"]):
                return None, "tcp_closed", parsed, link, idx
            delay, reason = ss_stream_real_delay(parsed)
            return delay, reason, parsed, link, idx

    if not tcp_open(parsed["host"], parsed["port"]):
        return None, "tcp_closed", parsed, link, idx

    listen_port = port_q.get()
    cfg_path = f"temp_config_{listen_port}.json"
    env = os.environ.copy()
    if os.path.isdir(XRAY_ASSET_PATH):
        env["XRAY_LOCATION_ASSET"] = XRAY_ASSET_PATH

    proc = None
    try:
        try:
            create_xray_config(parsed, cfg_path, listen_port)
        except Exception:
            return None, "config_error", parsed, link, idx
        proc = subprocess.Popen(
            [xray_bin, "run", "-c", os.path.abspath(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        if not wait_port(listen_port, 3.0):
            return None, "xray_dead", parsed, link, idx
        delay, reason = curl_real_delay(TEST_URL, listen_port)
        if reason == "no_curl":
            delay, reason = requests_real_delay(TEST_URL, listen_port)
        return delay, reason, parsed, link, idx
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


def process_configs():
    xray_bin = find_xray()
    if not xray_bin:
        print("ERROR: xray မတွေ့ပါ။ Termux:  pkg install xray", flush=True)
        return
    print(f"xray: {xray_bin} | workers={WORKERS}", flush=True)
    try:
        from Crypto.Cipher import AES  # noqa: F401
        print("aes-256-cfb: pycryptodome OK", flush=True)
    except ImportError:
        print("aes-256-cfb အတွက်:  pip install pycryptodome", flush=True)

    subprocess.run(
        ["pkill", "-f", f"{os.path.basename(xray_bin)} run"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)

    print("Fetching configs...", flush=True)
    skipped_trojan = 0
    raw_lines = []
    for url in SOURCE_URLS:
        print(f"  {url}", flush=True)
        try:
            raw = requests.get(url, timeout=15).text.strip()
        except Exception as e:
            print(f"  Fetch error: {e}", flush=True)
            continue
        try:
            decoded = base64.b64decode(raw).decode("utf-8")
            if "://" not in decoded:
                raise ValueError("plain")
        except Exception:
            decoded = raw
        force_sg = "/countries/sg/" in url
        n_keep = 0
        by = {c: 0 for c in WANT_COUNTRIES}
        for ln in decoded.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            low = ln.lower()
            if low.startswith("trojan://"):
                skipped_trojan += 1
                continue
            if not low.startswith(("vless://", "ss://", "vmess://")):
                continue
            if force_sg:
                ln = ln.split("#")[0] + "#" + urllib.parse.quote("🇸🇬 SG")
                raw_lines.append(ln)
                n_keep += 1
                by["SG"] += 1
                continue
            cc = country_code(ln)
            if cc:
                raw_lines.append(ln)
                n_keep += 1
                by[cc] = by.get(cc, 0) + 1
        print(
            f"    kept {n_keep}  "
            + " ".join(f"{k}={v}" for k, v in by.items() if v),
            flush=True,
        )
    lines, dropped = dedupe_links(raw_lines)
    print(
        f"total after merge: {len(raw_lines)} | -{dropped} dup → test {len(lines)} | "
        f"trojan dropped {skipped_trojan}",
        flush=True,
    )
    print("=== Real Delay ===", flush=True)
    print("starting tests...", flush=True)

    port_q = queue.Queue()
    for i in range(WORKERS):
        port_q.put(BASE_PORT + i)

    working, done = [], 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [
            pool.submit(test_one, i, len(lines), line, xray_bin, port_q)
            for i, line in enumerate(lines, 1)
        ]
        for fut in as_completed(futs):
            try:
                delay, reason, parsed, link, idx = fut.result()
            except Exception as e:
                done += 1
                print(f" [{done}/{len(lines)}]    - ms  FAIL (crash:{type(e).__name__})", flush=True)
                continue
            done += 1
            proto = (parsed or {}).get("proto") or "?"
            tag = (parsed or {}).get("remark") or (parsed or {}).get("host") or "?"
            with _print_lock:
                if delay is not None:
                    print(f" [{done}/{len(lines)}] {delay:4d} ms  [{proto}] {tag}", flush=True)
                    working.append((delay, link))
                else:
                    print(f" [{done}/{len(lines)}]    - ms  FAIL ({reason})  [{proto}] {tag}", flush=True)

    best = {}
    for delay, cfg in working:
        k = node_key(cfg)
        if k not in best or delay < best[k][0]:
            best[k] = (delay, cfg)
    working = sorted(best.values(), key=lambda x: x[0])
    print(f"\nWorking: {len(working)} / {len(lines)}", flush=True)

    now = datetime.datetime.now()
    title = f"#profile-title: {now.strftime('%I:%M %p').lstrip('0')} Updated"
    out_lines = [title]
    FLAG = {"SG": "🇸🇬", "JP": "🇯🇵", "US": "🇺🇸", "TH": "🇹🇭", "HK": "🇭🇰"}
    counts = {c: 0 for c in WANT_COUNTRIES}
    for _delay, cfg in working:
        cc = country_code(cfg, default="SG")
        counts[cc] = counts.get(cc, 0) + 1
        name = f"{FLAG.get(cc, '')} {cc} {counts[cc]}"
        base = cfg.split("#")[0]
        out_lines.append(f"{base}#{urllib.parse.quote(name)}")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(out_lines).encode()).decode())
    print(title, flush=True)
    print("Wrote servers  (country + delay order)", flush=True)


if __name__ == "__main__":
    process_configs()
