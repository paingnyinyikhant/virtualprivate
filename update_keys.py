import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
import socket
import ssl
import time
import urllib.parse
import pytz
import requests
import sys
import re

# ==============================================================================
# ⚙️ CONFIGURATION - မြန်မာနိုင်ငံ GFW ကျော်လွှားရန် အထူးပြင်ဆင်ထားသည်
# ==============================================================================

SOURCES = {
    "SG": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/all.txt",
        "flag": "🇸🇬",
    },
    "JP": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/jp/all.txt",
        "flag": "🇯🇵",
    },
    "TH": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/th/all.txt",
        "flag": "🇹🇭",
    },
}

MAX_PER_COUNTRY = 30

# 🎯 Port 443 အပါအဝင် GFW ကျော်ရန် အကောင်းဆုံး Port များ
PRIORITY_PORTS = {443, 2096, 8443}
ALLOWED_PORTS = {443, 2096, 8388, 8443, 2053, 2083, 2087, 2052, 2082, 2086, 2095, 80, 8080}

# 🚫 GFW မှ ပိတ်ထားတတ်သော SNI များ
BLOCKED_SNIS = [
    "cloudflare.com", "speedtest.net", "co.uk", "127.0.0.1",
    "localhost", "example.com", "test.com", "0.0.0.0",
    "google.com",  # GFW fingerprint detection တွင် သုံးတတ်
]

# ✅ GFW ကျော်ရန် အကောင်းဆုံး Protocol Features
GFW_BYPASS_FEATURES = {
    "reality": 10,      # VLESS+Reality - အကောင်းဆုံး (TLS fingerprint ကို ဖုံးထား)
    "xtls-rprx-vision": 8,  # XTLS Vision flow
    "grpc": 7,          # gRPC transport - HTTP/2 multiplexing
    "ws": 5,            # WebSocket - HTTP upgrade ထဲ ဝင်
    "httpupgrade": 6,   # HTTPUpgrade
    "splithttp": 6,     # SplitHTTP
    "h2": 5,            # HTTP/2
    "tcp": 3,           # Raw TCP (အနည်းဆုံး)
}

SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")

# 🚫 Facebook Ads Blocking Parameters
FB_ADS_BLOCK_PARAMS = (
    "block_domains=an.facebook.com,graph.facebook.com/adnw,"
    "pixel.facebook.com,connect.facebook.net/adnw"
)

# Connection timeout settings (မြန်မာ့ network အတွက် adjusted)
TCP_TIMEOUT = 3.0        # TCP connect timeout
TLS_TIMEOUT = 4.0        # TLS handshake timeout
RESPONSE_TIMEOUT = 5.0   # HTTP response timeout


# ==============================================================================
# 🔍 DETAILED NODE ANALYSIS - Key တစ်ခုချင်း အသေးစိတ် စစ်ဆေးခြင်း
# ==============================================================================

def get_protocol_details(line):
    """Key တစ်ခုချင်းစီ၏ protocol details များကို အသေးစိတ် ခွဲခြမ်းစိတ်ဖြာသည်"""
    details = {
        "protocol": "unknown",
        "transport": "unknown",
        "security": "unknown",
        "flow": "none",
        "network": "tcp",
        "type": None,
        "host": None,
        "port": None,
        "sni": None,
        "path": "/",
        "uuid": None,
        "encryption": "none",
        "alpn": None,
        "fp": None,          # TLS fingerprint (uTLS)
        "pbk": None,         # Reality public key
        "sid": None,         # Reality short ID
        "servername": None,  # Reality dest server
        "raw": line,
        "gfw_score": 0,      # GFW bypass score (မြင့်လေ ကောင်းလေ)
        "issues": [],        # ပြဿနာများ
        "features": [],      # ကောင်းသော features များ
    }

    try:
        if line.startswith("vmess://"):
            details["protocol"] = "vmess"
            b64_str = line.replace("vmess://", "")
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            decoded = json.loads(base64.b64decode(b64_str).decode("utf-8"))
            
            details["type"] = "vmess"
            details["data"] = decoded
            details["host"] = decoded.get("add")
            details["port"] = int(decoded.get("port", 0))
            details["sni"] = decoded.get("sni") or decoded.get("host")
            details["path"] = decoded.get("path", "/")
            details["uuid"] = decoded.get("id")
            details["network"] = decoded.get("net", "tcp")
            details["transport"] = decoded.get("net", "tcp")
            details["security"] = decoded.get("tls", "none")
            details["encryption"] = decoded.get("scy", "auto")
            details["alpn"] = decoded.get("alpn")
            
            # VMess specific checks
            if decoded.get("tls") == "tls":
                details["gfw_score"] += 3
                details["features"].append("TLS encryption")
            if decoded.get("net") == "ws":
                details["gfw_score"] += 5
                details["features"].append("WebSocket transport")
            if decoded.get("net") == "grpc":
                details["gfw_score"] += 7
                details["features"].append("gRPC transport")
            if decoded.get("net") == "h2":
                details["gfw_score"] += 5
                details["features"].append("HTTP/2 transport")
                
        elif line.startswith("vless://"):
            details["protocol"] = "vless"
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            details["type"] = "url"
            details["host"] = parsed.hostname
            details["port"] = int(parsed.port or 443)
            details["uuid"] = parsed.username
            details["sni"] = query_params.get("sni", [None])[0] or query_params.get("host", [None])[0]
            details["path"] = query_params.get("path", ["/"])[0]
            details["security"] = query_params.get("security", ["none"])[0]
            details["transport"] = query_params.get("type", ["tcp"])[0]
            details["network"] = query_params.get("type", ["tcp"])[0]
            details["flow"] = query_params.get("flow", ["none"])[0]
            details["alpn"] = query_params.get("alpn", [None])[0]
            details["fp"] = query_params.get("fp", [None])[0]
            details["pbk"] = query_params.get("pbk", [None])[0]
            details["sid"] = query_params.get("sid", [None])[0]
            details["servername"] = query_params.get("sni", [None])[0]
            details["encryption"] = query_params.get("encryption", ["none"])[0]
            
            # GFW bypass scoring for VLESS
            security = details["security"]
            transport = details["transport"]
            flow = details["flow"]
            
            if security == "reality":
                details["gfw_score"] += 10
                details["features"].append("🛡️ REALITY (GFW ကျော်ရန် အကောင်းဆုံး)")
                if details["pbk"]:
                    details["features"].append("Reality Public Key ရှိ")
                if details["fp"]:
                    details["features"].append(f"uTLS Fingerprint: {details['fp']}")
            elif security == "tls":
                details["gfw_score"] += 4
                details["features"].append("TLS encryption")
                
            if flow and "xtls-rprx-vision" in flow:
                details["gfw_score"] += 8
                details["features"].append(f"🔥 XTLS Vision flow ({flow})")
                
            if transport in GFW_BYPASS_FEATURES:
                score = GFW_BYPASS_FEATURES[transport]
                details["gfw_score"] += score
                details["features"].append(f"Transport: {transport} (+{score})")
                
            if details["fp"]:
                details["gfw_score"] += 2
                details["features"].append(f"uTLS fingerprint spoofing: {details['fp']}")
                
        elif line.startswith("trojan://"):
            details["protocol"] = "trojan"
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            details["type"] = "url"
            details["host"] = parsed.hostname
            details["port"] = int(parsed.port or 443)
            details["uuid"] = parsed.username
            details["sni"] = query_params.get("sni", [None])[0] or query_params.get("host", [None])[0]
            details["path"] = query_params.get("path", ["/"])[0]
            details["security"] = query_params.get("security", ["tls"])[0]
            details["transport"] = query_params.get("type", ["tcp"])[0]
            details["network"] = query_params.get("type", ["tcp"])[0]
            details["fp"] = query_params.get("fp", [None])[0]
            
            # Trojan is inherently good for GFW bypass
            details["gfw_score"] += 6
            details["features"].append("🐴 Trojan protocol (HTTPS traffic ကဲ့သို့ မြင်ရ)")
            
            if details["transport"] == "ws":
                details["gfw_score"] += 4
                details["features"].append("WebSocket transport")
            if details["transport"] == "grpc":
                details["gfw_score"] += 6
                details["features"].append("gRPC transport")
            if details["fp"]:
                details["gfw_score"] += 2
                details["features"].append(f"uTLS fingerprint: {details['fp']}")
                
        elif line.startswith("ss://"):
            details["protocol"] = "ss"
            base_url = line.split("#")[0]
            parsed = urllib.parse.urlparse(base_url)
            host = parsed.hostname
            port = parsed.port
            
            if not host or not port:
                raw_ss = base_url.replace("ss://", "")
                if "@" in raw_ss:
                    user_info, host_port = raw_ss.split("@", 1)
                else:
                    decoded_ss = base64.b64decode(raw_ss + "==").decode("utf-8")
                    user_info, host_port = decoded_ss.split("@", 1)
                if ":" in host_port:
                    host, port = host_port.rsplit(":", 1)
                    port = int(port)
            
            details["type"] = "ss"
            details["host"] = host
            details["port"] = port if port else 443
            details["sni"] = None
            details["path"] = "/"
            details["security"] = "ss_encryption"
            
            # Shadowsocks - detect plugin
            query_params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
            plugin = query_params.get("plugin", [None])[0]
            if plugin:
                details["features"].append(f"Plugin: {plugin}")
                if "v2ray-plugin" in plugin or "obfs" in plugin:
                    details["gfw_score"] += 4
                    details["features"].append("Obfuscation plugin ရှိ")
            else:
                details["gfw_score"] += 2
                details["issues"].append("⚠️ Plain SS - GFW မှ ဖမ်းမိနိုင်")
                
        elif line.startswith(("hysteria2://", "hy2://")):
            details["protocol"] = "hysteria2"
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            details["type"] = "url"
            details["host"] = parsed.hostname
            details["port"] = int(parsed.port or 443)
            details["sni"] = query_params.get("sni", [None])[0]
            
            # Hysteria2 uses QUIC - can be good but may be blocked
            details["gfw_score"] += 5
            details["features"].append("🚀 Hysteria2 (QUIC-based, fast)")
            details["issues"].append("⚠️ QUIC/UDP - ISP မှ throttle လုပ်နိုင်")
            
        elif line.startswith("tuic://"):
            details["protocol"] = "tuic"
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            details["type"] = "url"
            details["host"] = parsed.hostname
            details["port"] = int(parsed.port or 443)
            details["sni"] = query_params.get("sni", [None])[0]
            
            details["gfw_score"] += 6
            details["features"].append("🚀 TUIC (QUIC+TLS, fast & stealthy)")
            details["issues"].append("⚠️ QUIC/UDP - ISP မှ throttle လုပ်နိုင်")

    except Exception as e:
        details["issues"].append(f"❌ Parse error: {str(e)}")

    return details


# ==============================================================================
# 🏓 ADVANCED CONNECTIVITY TEST - မြန်မာ့ Network အတွက် စစ်ဆေးခြင်း
# ==============================================================================

def dns_resolve(host):
    """DNS resolution check"""
    try:
        ip = socket.getaddrinfo(host, None)[0][4][0]
        return ip
    except Exception:
        return None


def tcp_connect_test(host, port, timeout=TCP_TIMEOUT):
    """TCP connection test with latency measurement"""
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        latency = (time.time() - start) * 1000  # ms
        sock.close()
        return True, round(latency, 1)
    except socket.timeout:
        return False, -1
    except ConnectionRefusedError:
        return False, -2
    except Exception:
        return False, -3


def tls_handshake_test(host, port, sni=None, timeout=TLS_TIMEOUT):
    """TLS handshake test - certificate and protocol check"""
    result = {
        "success": False,
        "protocol": None,
        "cipher": None,
        "cert_valid": False,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "alpn": None,
        "latency_ms": -1,
    }
    
    try:
        target_sni = sni if sni else host
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        start = time.time()
        sock.connect((host, port))
        
        with context.wrap_socket(sock, server_hostname=target_sni) as tls_sock:
            result["latency_ms"] = round((time.time() - start) * 1000, 1)
            result["protocol"] = tls_sock.version()
            result["cipher"] = tls_sock.cipher()
            result["success"] = True
            
            # Certificate details
            cert = tls_sock.getpeercert(binary_form=False)
            if cert:
                result["cert_valid"] = True
                subject = dict(x[0] for x in cert.get("subject", ()))
                result["cert_subject"] = subject.get("commonName", "unknown")
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                result["cert_issuer"] = issuer.get("organizationName", issuer.get("commonName", "unknown"))
                result["cert_expiry"] = cert.get("notAfter", "unknown")
            
            try:
                result["alpn"] = tls_sock.selected_alpn_protocol()
            except Exception:
                pass
                
            tls_sock.close()
            
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)[:80]}"
    except socket.timeout:
        result["error"] = "TLS timeout"
    except Exception as e:
        result["error"] = str(e)[:80]
        
    return result


def http_probe_test(host, port, path="/", sni=None, timeout=RESPONSE_TIMEOUT):
    """HTTP probe to check if server responds"""
    try:
        target_sni = sni if sni else host
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock.connect((host, port))
        
        with context.wrap_socket(sock, server_hostname=target_sni) as tls_sock:
            clean_path = path if path.startswith("/") else "/" + path
            request = (
                f"GET {clean_path} HTTP/1.1\r\n"
                f"Host: {target_sni}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Accept: text/html\r\n"
                f"Connection: close\r\n\r\n"
            )
            tls_sock.sendall(request.encode("utf-8"))
            response = tls_sock.recv(512)
            tls_sock.close()
            
            if len(response) > 0:
                resp_text = response.decode("utf-8", errors="ignore")
                status_code = None
                if resp_text.startswith("HTTP/"):
                    parts = resp_text.split(" ", 2)
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                        except ValueError:
                            pass
                return True, status_code, len(response)
            return False, None, 0
            
    except Exception:
        return False, None, 0


# ==============================================================================
# 🧪 COMPREHENSIVE NODE TEST - Key တစ်ခုချင်း အပြည့်အစုံ စစ်ဆေးခြင်း
# ==============================================================================

def comprehensive_test(node_info):
    """Key တစ်ခုချင်းစီကို အပြည့်အစုံ စစ်ဆေးသည်"""
    host = node_info["host"]
    port = node_info["port"]
    sni = node_info.get("sni")
    path = node_info.get("path", "/")
    protocol = node_info.get("protocol", "unknown")
    
    result = {
        "node": node_info,
        "passed": False,
        "dns_ok": False,
        "tcp_ok": False,
        "tls_ok": False,
        "http_ok": False,
        "tcp_latency": -1,
        "tls_latency": -1,
        "ip": None,
        "tls_details": {},
        "http_status": None,
        "final_score": 0,
        "verdict": "FAIL",
        "verdict_reason": "",
    }
    
    # Step 0: Basic validation
    if not host or not port:
        result["verdict_reason"] = "Host သို့ Port မရှိ"
        return result
        
    # Step 1: Port check
    if port not in ALLOWED_PORTS:
        result["verdict_reason"] = f"Port {port} ခွင့်မပြု"
        return result
    
    # Step 2: SNI block check
    if sni and any(b in sni.lower() for b in BLOCKED_SNIS):
        result["verdict_reason"] = f"SNI '{sni}' ပိတ်ထားသော domain"
        # Don't fully block, just penalize
        node_info["gfw_score"] -= 5
        node_info["issues"].append(f"⚠️ SNI '{sni}' သံသယရှိ")
    
    # Step 3: DNS Resolution
    ip = dns_resolve(host)
    if ip:
        result["dns_ok"] = True
        result["ip"] = ip
    else:
        # DNS fail might be temporary, don't block
        node_info["issues"].append("⚠️ DNS resolve မရ")
    
    # Step 4: TCP Connection
    tcp_ok, tcp_latency = tcp_connect_test(host, port)
    result["tcp_ok"] = tcp_ok
    result["tcp_latency"] = tcp_latency
    
    if not tcp_ok:
        if tcp_latency == -1:
            result["verdict_reason"] = f"TCP timeout (Port {port})"
        elif tcp_latency == -2:
            result["verdict_reason"] = f"TCP connection refused (Port {port})"
        else:
            result["verdict_reason"] = f"TCP connection failed (Port {port})"
        return result
    
    # Step 5: TLS Handshake (for TLS-based protocols or port 443/HTTPS ports)
    tls_ports = {443, 2096, 8443, 2053, 2083, 2087}
    is_tls_protocol = protocol in ("vless", "trojan", "vmess", "tuic", "hysteria2")
    
    if port in tls_ports or is_tls_protocol:
        tls_result = tls_handshake_test(host, port, sni=sni)
        result["tls_ok"] = tls_result["success"]
        result["tls_latency"] = tls_result["latency_ms"]
        result["tls_details"] = tls_result
        
        if tls_result["success"]:
            # Good TLS indicators
            if tls_result.get("protocol") in ("TLSv1.3", "TLSv1.2"):
                node_info["features"].append(f"TLS: {tls_result['protocol']}")
            if tls_result.get("cipher"):
                cipher_name = tls_result["cipher"][0] if isinstance(tls_result["cipher"], tuple) else str(tls_result["cipher"])
                node_info["features"].append(f"Cipher: {cipher_name[:40]}")
            if tls_result.get("cert_issuer"):
                node_info["features"].append(f"Cert issuer: {tls_result['cert_issuer']}")
        else:
            # TLS fail for TLS protocols is bad
            if is_tls_protocol and protocol not in ("ss",):
                node_info["issues"].append(f"TLS handshake fail: {tls_result.get('error', 'unknown')}")
    else:
        # Non-TLS port - just TCP is enough
        result["tls_ok"] = True
    
    # Step 6: HTTP Probe (optional - for websocket/http transports)
    transport = node_info.get("transport", "tcp")
    if transport in ("ws", "httpupgrade", "splithttp", "h2") and result["tls_ok"]:
        http_ok, http_status, resp_size = http_probe_test(host, port, path=path, sni=sni)
        result["http_ok"] = http_ok
        result["http_status"] = http_status
        
        if http_ok and http_status:
            node_info["features"].append(f"HTTP response: {http_status}")
    
    # Step 7: Calculate final score
    score = node_info.get("gfw_score", 0)
    
    # Port bonus
    if port == 443:
        score += 5  # Port 443 is best for GFW bypass
        node_info["features"].append("✅ Port 443 (HTTPS traffic ကဲ့သို့)")
    elif port in PRIORITY_PORTS:
        score += 3
    
    # Latency bonus (lower is better for Myanmar)
    latency = result["tls_latency"] if result["tls_latency"] > 0 else result["tcp_latency"]
    if 0 < latency < 100:
        score += 5
    elif 0 < latency < 200:
        score += 3
    elif 0 < latency < 400:
        score += 1
    elif latency > 800:
        score -= 3
        node_info["issues"].append("⚠️ Latency မြင့် (>800ms)")
    
    # Penalize issues
    score -= len([i for i in node_info.get("issues", []) if "❌" in i]) * 3
    
    result["final_score"] = score
    result["passed"] = result["tcp_ok"] and (result["tls_ok"] or port not in tls_ports)
    
    if result["passed"]:
        if score >= 15:
            result["verdict"] = "🟢 EXCELLENT"
        elif score >= 10:
            result["verdict"] = "🟡 GOOD"
        elif score >= 5:
            result["verdict"] = "🟠 FAIR"
        else:
            result["verdict"] = "🔴 WEAK"
    else:
        result["verdict"] = "❌ FAIL"
    
    return result


# ==============================================================================
# 📋 DETAILED REPORTING - ရလဒ်များကို အသေးစိတ် ပြသခြင်း
# ==============================================================================

def print_node_report(test_result, index):
    """Key တစ်ခုချင်း၏ စစ်ဆေးရလဒ်ကို အသေးစိတ် print"""
    node = test_result["node"]
    print(f"\n{'='*70}")
    print(f"  🔑 Key #{index}: {node['protocol'].upper()} | {node['host']}:{node['port']}")
    print(f"{'='*70}")
    
    # Connection Results
    print(f"  📡 DNS Resolution:  {'✅ ' + str(test_result['ip']) if test_result['dns_ok'] else '❌ Failed'}")
    print(f"  🔌 TCP Connect:     {'✅ OK' if test_result['tcp_ok'] else '❌ FAIL'} | Latency: {test_result['tcp_latency']}ms")
    print(f"  🔒 TLS Handshake:   {'✅ OK' if test_result['tls_ok'] else '⏭️ N/A'} | Latency: {test_result['tls_latency']}ms")
    if test_result.get("http_ok"):
        print(f"  🌐 HTTP Probe:      ✅ OK | Status: {test_result['http_status']}")
    
    # TLS Details
    tls = test_result.get("tls_details", {})
    if tls.get("success"):
        print(f"  📜 TLS Version:     {tls.get('protocol', 'N/A')}")
        if tls.get("cert_issuer"):
            print(f"  🏢 Cert Issuer:     {tls['cert_issuer']}")
    
    # Protocol Details
    print(f"  📦 Protocol:        {node['protocol'].upper()}")
    print(f"  🚀 Transport:       {node.get('transport', 'tcp')}")
    print(f"  🛡️ Security:        {node.get('security', 'unknown')}")
    if node.get("flow") and node["flow"] != "none":
        print(f"  🌊 Flow:            {node['flow']}")
    if node.get("sni"):
        print(f"  🏷️ SNI:             {node['sni']}")
    
    # GFW Score & Features
    print(f"\n  📊 GFW Bypass Score: {test_result['final_score']} | Verdict: {test_result['verdict']}")
    
    if node.get("features"):
        print(f"  ✨ Features:")
        for f in node["features"]:
            print(f"     • {f}")
    
    if node.get("issues"):
        print(f"  ⚠️ Issues:")
        for i in node["issues"]:
            print(f"     • {i}")
    
    print(f"{'─'*70}")
    return test_result["passed"]


# ==============================================================================
# 📥 FETCH & PROCESS
# ==============================================================================

def fetch_and_process_country(country_code, config, verbose=True):
    url = config["url"]
    flag = config["flag"]

    if verbose:
        print(f"\n{'#'*70}")
        print(f"  🌍 Country: {country_code} {flag}")
        print(f"  📥 Source: {url}")
        print(f"{'#'*70}")

    try:
        res = requests.get(url, timeout=15)
        content = res.text.strip()
        try:
            decoded = base64.b64decode(content).decode("utf-8")
            lines = decoded.splitlines()
        except Exception:
            lines = content.splitlines()

        # Parse all lines
        all_nodes = []
        for line in lines:
            line = line.strip()
            if line and any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                details = get_protocol_details(line)
                if details and details.get("host") and details.get("port"):
                    all_nodes.append(details)

        if verbose:
            print(f"\n  📊 Total keys found: {len(all_nodes)}")
            
            # Protocol breakdown
            proto_counts = {}
            for n in all_nodes:
                p = n["protocol"]
                proto_counts[p] = proto_counts.get(p, 0) + 1
            for p, c in sorted(proto_counts.items(), key=lambda x: -x[1]):
                print(f"     {p.upper()}: {c}")
            
            # Port distribution
            port_counts = {}
            for n in all_nodes:
                p = n["port"]
                port_counts[p] = port_counts.get(p, 0) + 1
            print(f"\n  📊 Port distribution:")
            for p, c in sorted(port_counts.items(), key=lambda x: -x[1]):
                marker = "⭐" if p in PRIORITY_PORTS else "  "
                print(f"     {marker} Port {p}: {c}")

        # Test each node
        if verbose:
            print(f"\n  🧪 Testing {len(all_nodes)} keys...\n")
        
        test_results = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(comprehensive_test, node): node for node in all_nodes}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    test_results.append(result)
                except Exception as e:
                    pass

        # Sort by score (descending)
        test_results.sort(key=lambda x: x["final_score"], reverse=True)
        
        # Print detailed reports
        passed_count = 0
        failed_count = 0
        key_index = 0
        
        for result in test_results:
            key_index += 1
            if result["passed"]:
                passed_count += 1
                if verbose:
                    print_node_report(result, key_index)
            else:
                failed_count += 1
                # Only show first few failures
                if verbose and failed_count <= 5:
                    print_node_report(result, key_index)

        if verbose:
            print(f"\n  📊 Results: ✅ {passed_count} passed | ❌ {failed_count} failed")

        # Format output for top nodes
        passed_results = [r for r in test_results if r["passed"]]
        top_results = passed_results[:MAX_PER_COUNTRY]
        
        formatted = []
        count = 1
        for result in top_results:
            node = result["node"]
            raw = node["raw"]
            score = result["final_score"]
            verdict = result["verdict"]
            
            # Build clean name with score indicator
            score_tag = ""
            if score >= 15:
                score_tag = "★"
            elif score >= 10:
                score_tag = "●"
            elif score >= 5:
                score_tag = "○"
            else:
                score_tag = "·"
            
            latency = result["tls_latency"] if result["tls_latency"] > 0 else result["tcp_latency"]
            latency_tag = f"{int(latency)}ms" if latency > 0 else ""
            
            clean_name = f"{flag} {country_code}-{count} {score_tag} {latency_tag}".strip()

            if node["type"] == "vmess":
                data = node["data"]
                data["ps"] = clean_name
                data["fb_block"] = FB_ADS_BLOCK_PARAMS
                new_b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
                formatted.append(f"vmess://{new_b64}")
            else:
                base_url = raw.split("#")[0]
                delimiter = "&" if "?" in base_url else "?"
                base_url = f"{base_url}{delimiter}{FB_ADS_BLOCK_PARAMS}"
                new_name = urllib.parse.quote(clean_name)
                formatted.append(f"{base_url}#{new_name}")
                
            count += 1

        return formatted, passed_count, failed_count

    except Exception as e:
        print(f"  ❌ Error processing {country_code}: {e}")
        return [], 0, 0


# ==============================================================================
# 🚀 MAIN
# ==============================================================================

def main():
    print("=" * 70)
    print("  🔑 Myanmar GFW-Bypass Key Checker v2.0")
    print("  📅 Date:", datetime.now(pytz.timezone("Asia/Yangon")).strftime("%Y-%m-%d %H:%M:%S MMT"))
    print("  🎯 Port 443 + GFW Bypass Optimized")
    print("=" * 70)
    print(f"\n  ✅ Allowed Ports: {sorted(ALLOWED_PORTS)}")
    print(f"  ⭐ Priority Ports: {sorted(PRIORITY_PORTS)}")
    print(f"  🚫 Blocked SNIs: {BLOCKED_SNIS}")
    print(f"  📦 Supported: {', '.join(SUPPORTED_PROTOCOLS)}")
    
    all_nodes = []
    total_passed = 0
    total_failed = 0
    
    for country_code, config in SOURCES.items():
        nodes, passed, failed = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        total_passed += passed
        total_failed += failed
        print(f"\n  💾 Saved {len(nodes)} nodes for {country_code}")

    # Summary
    print(f"\n{'='*70}")
    print(f"  📊 FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"  ✅ Total Passed: {total_passed}")
    print(f"  ❌ Total Failed: {total_failed}")
    print(f"  💾 Total Saved:  {len(all_nodes)}")
    
    # Save output
    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")
    
    profile_title = f"#profile-title: {current_date} GFW-Optimized Updated"
    plain_content = profile_title + "\n" + "\n".join(all_nodes)
    
    encoded_content = base64.b64encode(plain_content.encode("utf-8")).decode("utf-8")
    
    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)
    
    # Also save plain text version for easy review
    with open("servers_plain.txt", "w", encoding="utf-8") as f:
        f.write(plain_content)
    
    print(f"\n  💾 Encoded output: servers")
    print(f"  📄 Plain text output: servers_plain.txt")
    print(f"\n  ✅ Done! GFW-optimized keys with Port 443 support.")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
