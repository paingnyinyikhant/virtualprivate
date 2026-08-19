#!/usr/bin/env python3
"""
V2RayNG-style Real Delay (safe parallel).
Xray-core -> SOCKS5h -> https://www.gstatic.com/generate_204
"""
import base64
import datetime
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

SOURCE_URL = "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/vless.txt"
TEST_URL = "https://www.gstatic.com/generate_204"
BASE_PORT = 10808
WORKERS = 3          # Termux RAM အတွက် 3 က လုံလောက် / အန္တရာယ်နည်း
TIMEOUT_SEC = 5      # V2RayNG 8s ထက်နည်းနည်းတို — dead node မစောင့်
TCP_PRECHECK = 1.2   # port မပွင့်ရင် xray မစ
XRAY_ASSET_PATH = os.path.expanduser("~/xray-bin")

_print_lock = threading.Lock()
_port_box = threading.local()


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
    try:
        infos = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for family, socktype, proto, _, addr in infos:
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
        if host_port.startswith("["):
            host, port_raw = host_port[1:].split("]", 1)
            port = int(re.search(r"\d+", port_raw).group()) if ":" in port_raw else 443
        elif ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            port = int(re.search(r"\d+", port_s).group())
        else:
            host, port = host_port, 443
        q = dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))
        return {"uuid": uuid, "host": host, "port": port, "query": q, "remark": remark}
    except Exception:
        return None


def create_xray_config(p, path, listen_port):
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
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": raw_path, "host": header_host}
    elif network == "h2":
        stream["httpSettings"] = {"path": raw_path, "host": [header_host]}
    elif network == "tcp" and q.get("headerType") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "version": "1.1",
                    "method": "GET",
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

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks",
            "port": listen_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": host, "port": port, "users": [user]}]
            },
            "streamSettings": stream,
        }],
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
        code = int(text[0])
        ttfb = float(text[1])
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
    parsed = parse_vless(link)
    if not parsed:
        return None, "parse_error", None, link, idx

    if not tcp_open(parsed["host"], parsed["port"]):
        return None, "tcp_closed", parsed, link, idx

    listen_port = port_q.get()
    cfg_path = f"temp_config_{listen_port}.json"
    try:
        create_xray_config(parsed, cfg_path, listen_port)
    except Exception:
        port_q.put(listen_port)
        return None, "config_error", parsed, link, idx

    env = os.environ.copy()
    if os.path.isdir(XRAY_ASSET_PATH):
        env["XRAY_LOCATION_ASSET"] = XRAY_ASSET_PATH

    proc = None
    try:
        proc = subprocess.Popen(
            [xray_bin, "run", "-c", os.path.abspath(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        if not wait_port(listen_port, 2.5):
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
        print("ERROR: xray မတွေ့ပါ။ Termux:  pkg install xray")
        return
    print(f"xray: {xray_bin} | workers={WORKERS} | timeout={TIMEOUT_SEC}s")

    subprocess.run(
        ["pkill", "-f", f"{os.path.basename(xray_bin)} run"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)

    print("Fetching configs...")
    try:
        raw = requests.get(SOURCE_URL, timeout=15).text.strip()
    except Exception as e:
        print(f"Fetch error: {e}")
        return

    try:
        decoded = base64.b64decode(raw).decode("utf-8")
        if "vless://" not in decoded:
            raise ValueError("plain")
    except Exception:
        decoded = raw

    lines = [ln.strip() for ln in decoded.splitlines() if ln.strip().startswith("vless://")]
    print(f"Nodes: {len(lines)}")
    print("=== Real Delay (parallel, safe) ===")

    port_q = queue.Queue()
    for i in range(WORKERS):
        port_q.put(BASE_PORT + i)

    working = []
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = [
            pool.submit(test_one, i, len(lines), line, xray_bin, port_q)
            for i, line in enumerate(lines, 1)
        ]

        for fut in as_completed(futs):
            delay, reason, parsed, link, idx = fut.result()
            done += 1
            tag = (parsed or {}).get("remark") or (parsed or {}).get("host") or "?"
            with _print_lock:
                if delay is not None:
                    print(f" [{done}/{len(lines)}] {delay:4d} ms  {tag}")
                    working.append((delay, link))
                else:
                    print(f" [{done}/{len(lines)}]    - ms  FAIL ({reason})  {tag}")

    working.sort(key=lambda x: x[0])
    print(f"\nWorking: {len(working)} / {len(lines)}")

    now = datetime.datetime.now()
    title = f"#profile-title: {now.strftime('%I:%M %p').lstrip('0')} Updated"
    out_lines = [title]
    for n, (_delay, cfg) in enumerate(working, 1):
        base = cfg.split("#")[0]
        out_lines.append(f"{base}#{urllib.parse.quote(f'🇸🇬 SG {n}')}")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(out_lines).encode()).decode())

    print(title)
    print("Wrote servers  (🇸🇬 SG 1 = fastest)")


if __name__ == "__main__":
    process_configs()
