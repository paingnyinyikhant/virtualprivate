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
import random

# ==============================================================================
# ⚙️ CONFIGURATION - မြန်မာနိုင်ငံ GFW ကျော်လွှားရန် အထူးပြင်ဆင်ထားသည်
# ==============================================================================

SOURCES = {
    # ─── Original Sources ───
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
    # ─── Additional Free Sources (Global/Mixed) ───
    "EPD": {
        "url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
        "flag": "🌍",
    },
    "EBR": {
        "url": "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
        "flag": "🌍",
    },
    "ROO": {
        "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
        "flag": "🌍",
    },
    "BRY": {
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
        "flag": "🌍",
    },
    "BRY2": {
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
        "flag": "🌍",
    },
    "BRY3": {
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
        "flag": "🌍",
    },
    "BRY4": {
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
        "flag": "🌍",
    },
    "MTG": {
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
        "flag": "🌍",
    },
    "MTG2": {
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
        "flag": "🌍",
    },
    "MTG3": {
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
        "flag": "🌍",
    },
    "MTG4": {
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",
        "flag": "🌍",
    },
    "FQF": {
        "url": "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
        "flag": "🌍",
    },
    "ZNG": {
        "url": "https://raw.githubusercontent.com/zengfr/free-vpn-subscribe/main/vpn_sub_raw_.txt",
        "flag": "🌍",
    },
    "SMK": {
        "url": "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
        "flag": "🌍",
    },
    "FR2": {
        "url": "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Vless",
        "flag": "🌍",
    },
    "FR3": {
        "url": "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
        "flag": "🌍",
    },
}

MAX_PER_COUNTRY = 20  # နိုင်ငံတစ်ခုကို Ping အကောင်းဆုံး 20

# 🎯 GFW ကျော်ရန် အကောင်းဆုံး Port များ (Port 443 မပါ)
PRIORITY_PORTS = {2096, 8443, 8388}
ALLOWED_PORTS = {2096, 8388, 8443, 2053, 2083, 2087, 2052, 2082, 2086, 2095, 80, 8080}

# 🚫 GFW မှ ပိတ်ထားတတ်သော SNI များ
BLOCKED_SNIS = [
    "cloudflare.com", "speedtest.net", "co.uk", "127.0.0.1",
    "localhost", "example.com", "test.com", "0.0.0.0",
    "google.com",
]

# ✅ GFW ကျော်ရန် အကောင်းဆုံး Protocol Features
GFW_BYPASS_FEATURES = {
    "reality": 10,
    "xtls-rprx-vision": 8,
    "grpc": 7,
    "ws": 5,
    "httpupgrade": 6,
    "splithttp": 6,
    "h2": 5,
    "tcp": 3,
}

SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")

# 🚫 Facebook Ads Blocking Parameters
FB_ADS_BLOCK_PARAMS = (
    "block_domains=an.facebook.com,graph.facebook.com/adnw,"
    "pixel.facebook.com,connect.facebook.net/adnw"
)

# Connection timeout settings
TCP_TIMEOUT = 3.0
TLS_TIMEOUT = 5.0
RESPONSE_TIMEOUT = 6.0

# 🇲🇲 မြန်မာနိုင်ငံနှင့် ပိုကိုက်ညီအောင် Test ပိုလုပ်မည်
PING_TESTS = 3  # တစ်ခုချင်းကို 3 ကြိမ် test ပြီး average ယူမည်


# ==============================================================================
# 🔍 DETAILED NODE ANALYSIS
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
        "fp": None,
        "pbk": None,
        "sid": None,
        "servername": None,
        "raw": line,
        "gfw_score": 0,
        "issues": [],
        "features": [],
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
            
            security = details["security"]
            transport = details["transport"]
            flow = details["flow"]
            
            if security == "reality":
                details["gfw_score"] += 10
                details["features"].append("🛡️ REALITY")
                if details["pbk"]:
                    details["features"].append("Reality Public Key ရှိ")
                if details["fp"]:
                    details["features"].append(f"uTLS Fingerprint: {details['fp']}")
            elif security == "tls":
                details["gfw_score"] += 4
                details["features"].append("TLS encryption")
                
            if flow and "xtls-rprx-vision" in flow:
                details["gfw_score"] += 8
                details["features"].append(f"🔥 XTLS Vision flow")
                
            if transport in GFW_BYPASS_FEATURES:
                score = GFW_BYPASS_FEATURES[transport]
                details["gfw_score"] += score
                details["features"].append(f"Transport: {transport} (+{score})")
                
            if details["fp"]:
                details["gfw_score"] += 2
                details["features"].append(f"uTLS fingerprint: {details['fp']}")
                
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
            
            details["gfw_score"] += 6
            details["features"].append("🐴 Trojan protocol")
            
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
            
            query_params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
            plugin = query_params.get("plugin", [None])[0]
            if plugin:
                details["features"].append(f"Plugin: {plugin}")
                if "v2ray-plugin" in plugin or "obfs" in plugin:
                    details["gfw_score"] += 4
                    details["features"].append("Obfuscation plugin")
            else:
                details["gfw_score"] += 2
                details["issues"].append("⚠️ Plain SS")
                
        elif line.startswith(("hysteria2://", "hy2://")):
            details["protocol"] = "hysteria2"
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            details["type"] = "url"
            details["host"] = parsed.hostname
            details["port"] = int(parsed.port or 443)
            details["sni"] = query_params.get("sni", [None])[0]
            
            details["gfw_score"] += 5
            details["features"].append("🚀 Hysteria2 (QUIC)")
            details["issues"].append("⚠️ QUIC/UDP")
            
        elif line.startswith("tuic://"):
            details["protocol"] = "tuic"
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            details["type"] = "url"
            details["host"] = parsed.hostname
            details["port"] = int(parsed.port or 443)
            details["sni"] = query_params.get("sni", [None])[0]
            
            details["gfw_score"] += 6
            details["features"].append("🚀 TUIC (QUIC+TLS)")
            details["issues"].append("⚠️ QUIC/UDP")

    except Exception as e:
        details["issues"].append(f"❌ Parse error: {str(e)}")

    return details


# ==============================================================================
# 🏓 ADVANCED CONNECTIVITY TEST - မြန်မာ့ Network အတွက် တင်းကြပ်စွာ စစ်ဆေး
# ==============================================================================

def tcp_connect_test(host, port, timeout=TCP_TIMEOUT):
    """TCP connection test with latency"""
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        latency = (time.time() - start) * 1000
        sock.close()
        return True, round(latency, 1)
    except socket.timeout:
        return False, -1
    except ConnectionRefusedError:
        return False, -2
    except Exception:
        return False, -3


def tls_handshake_test(host, port, sni=None, timeout=TLS_TIMEOUT):
    """TLS handshake test"""
    result = {
        "success": False,
        "protocol": None,
        "cipher": None,
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
            tls_sock.close()
            
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
                return True, len(response)
            return False, 0
            
    except Exception:
        return False, 0


# ==============================================================================
# 🧪 COMPREHENSIVE NODE TEST - Multiple Ping Tests for Myanmar
# ==============================================================================

def comprehensive_test(node_info):
    """Key တစ်ခုချင်းစီကို Multiple times စစ်ဆေးသည်"""
    host = node_info["host"]
    port = node_info["port"]
    sni = node_info.get("sni")
    path = node_info.get("path", "/")
    protocol = node_info.get("protocol", "unknown")
    
    result = {
        "node": node_info,
        "passed": False,
        "tcp_ok": False,
        "tls_ok": False,
        "http_ok": False,
        "avg_tcp_latency": -1,
        "avg_tls_latency": -1,
        "latencies": [],
        "tls_details": {},
        "final_score": 0,
        "verdict": "FAIL",
        "tests_passed": 0,
        "tests_total": 0,
    }
    
    # Step 0: Basic validation
    if not host or not port:
        return result
        
    # Step 1: Port check
    if port not in ALLOWED_PORTS:
        return result
    
    # Step 2: SNI block check
    if sni and any(b in sni.lower() for b in BLOCKED_SNIS):
        node_info["gfw_score"] -= 5
        node_info["issues"].append(f"⚠️ SNI '{sni}' သံသယရှိ")
    
    # Step 3: Multiple TCP + TLS tests
    tcp_latencies = []
    tls_latencies = []
    tls_success_count = 0
    tcp_success_count = 0
    
    tls_ports = {2096, 8443, 2053, 2083, 2087}
    is_tls_protocol = protocol in ("vless", "trojan", "vmess", "tuic", "hysteria2")
    need_tls = port in tls_ports or is_tls_protocol
    
    for test_num in range(PING_TESTS):
        # Small random delay between tests
        time.sleep(random.uniform(0.1, 0.3))
        
        # TCP test
        tcp_ok, tcp_lat = tcp_connect_test(host, port)
        if tcp_ok:
            tcp_success_count += 1
            tcp_latencies.append(tcp_lat)
        
        # TLS test
        if need_tls and tcp_ok:
            tls_result = tls_handshake_test(host, port, sni=sni)
            if tls_result["success"]:
                tls_success_count += 1
                tls_latencies.append(tls_result["latency_ms"])
                result["tls_details"] = tls_result
    
    result["tests_total"] = PING_TESTS
    
    # Strict: TCP must pass majority of tests
    if tcp_success_count < (PING_TESTS // 2 + 1):
        result["tcp_ok"] = False
        return result
    
    result["tcp_ok"] = True
    result["avg_tcp_latency"] = round(sum(tcp_latencies) / len(tcp_latencies), 1) if tcp_latencies else -1
    
    # TLS check
    if need_tls:
        if tls_success_count < (PING_TESTS // 2 + 1):
            result["tls_ok"] = False
            return result
        result["tls_ok"] = True
        result["avg_tls_latency"] = round(sum(tls_latencies) / len(tls_latencies), 1) if tls_latencies else -1
    else:
        result["tls_ok"] = True
    
    result["tests_passed"] = min(tcp_success_count, tls_success_count) if need_tls else tcp_success_count
    
    # HTTP probe for websocket/http transports
    transport = node_info.get("transport", "tcp")
    if transport in ("ws", "httpupgrade", "splithttp", "h2") and result["tls_ok"]:
        http_ok, resp_size = http_probe_test(host, port, path=path, sni=sni)
        result["http_ok"] = http_ok
        if not http_ok:
            # HTTP probe fail doesn't kill it, just penalize
            node_info["gfw_score"] -= 2
    
    # Calculate final score
    score = node_info.get("gfw_score", 0)
    
    # Port bonus
    if port in PRIORITY_PORTS:
        score += 5
        node_info["features"].append(f"✅ Priority Port {port}")
    
    # Latency scoring (မြန်မာအတွက် adjusted)
    latency = result["avg_tls_latency"] if result["avg_tls_latency"] > 0 else result["avg_tcp_latency"]
    if 0 < latency < 100:
        score += 6
    elif 0 < latency < 200:
        score += 4
    elif 0 < latency < 400:
        score += 2
    elif 0 < latency < 600:
        score += 0
    elif latency > 800:
        score -= 4
        node_info["issues"].append("⚠️ Latency >800ms")
    
    # Consistency bonus (stable connection = better)
    if result["tests_passed"] == PING_TESTS:
        score += 3
        node_info["features"].append(f"✅ All {PING_TESTS}/{PING_TESTS} tests passed")
    elif result["tests_passed"] >= PING_TESTS - 1:
        score += 1
        node_info["features"].append(f"⚠️ {result['tests_passed']}/{PING_TESTS} tests passed")
    
    result["final_score"] = score
    result["passed"] = True
    
    if score >= 15:
        result["verdict"] = "🟢 EXCELLENT"
    elif score >= 10:
        result["verdict"] = "🟡 GOOD"
    elif score >= 5:
        result["verdict"] = "🟠 FAIR"
    else:
        result["verdict"] = "🔴 WEAK"
    
    return result


# ==============================================================================
# 📋 DETAILED REPORTING
# ==============================================================================

def print_node_report(test_result, index, country_code, flag):
    """Key တစ်ခုချင်း၏ စစ်ဆေးရလဒ်ကို အသေးစိတ် print"""
    node = test_result["node"]
    latency = test_result["avg_tls_latency"] if test_result["avg_tls_latency"] > 0 else test_result["avg_tcp_latency"]
    
    print(f"\n  {'─'*66}")
    print(f"  🔑 {flag} {country_code} {index} | {node['protocol'].upper()} | {node['host']}:{node['port']}")
    print(f"  {'─'*66}")
    
    # Connection Results
    print(f"     🔌 TCP: ✅ {test_result['avg_tcp_latency']}ms (avg of {PING_TESTS})")
    if test_result["avg_tls_latency"] > 0:
        print(f"     🔒 TLS: ✅ {test_result['avg_tls_latency']}ms (avg of {PING_TESTS})")
    print(f"     📊 Tests: {test_result['tests_passed']}/{test_result['tests_total']} passed")
    
    # TLS Details
    tls = test_result.get("tls_details", {})
    if tls.get("success"):
        print(f"     📜 TLS: {tls.get('protocol', 'N/A')}")
    
    # Protocol Details
    print(f"     📦 {node['protocol'].upper()} | Transport: {node.get('transport', 'tcp')} | Security: {node.get('security', 'unknown')}")
    if node.get("flow") and node["flow"] != "none":
        print(f"     🌊 Flow: {node['flow']}")
    if node.get("sni"):
        print(f"     🏷️ SNI: {node['sni']}")
    
    # Score & Verdict
    print(f"     📊 Score: {test_result['final_score']} | {test_result['verdict']} | Latency: {latency}ms")
    
    if node.get("features"):
        for f in node["features"]:
            print(f"        ✨ {f}")
    
    if node.get("issues"):
        for i in node["issues"]:
            print(f"        ⚠️ {i}")
    
    return test_result["passed"]


# ==============================================================================
# 📥 FETCH & PROCESS
# ==============================================================================

def fetch_and_process_country(country_code, config, verbose=True):
    url = config["url"]
    flag = config["flag"]

    if verbose:
        print(f"\n{'='*70}")
        print(f"  🌍 Country: {country_code} {flag}")
        print(f"  📥 Source: {url}")
        print(f"{'='*70}")

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
            
            proto_counts = {}
            for n in all_nodes:
                p = n["protocol"]
                proto_counts[p] = proto_counts.get(p, 0) + 1
            for p, c in sorted(proto_counts.items(), key=lambda x: -x[1]):
                print(f"     {p.upper()}: {c}")

        # Test each node
        if verbose:
            print(f"\n  🧪 Testing {len(all_nodes)} keys ({PING_TESTS}x each)...\n")
        
        test_results = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(comprehensive_test, node): node for node in all_nodes}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    test_results.append(result)
                except Exception as e:
                    pass

        # Sort by score (descending), then by latency (ascending)
        test_results.sort(key=lambda x: (
            -x["final_score"],
            x["avg_tls_latency"] if x["avg_tls_latency"] > 0 else 9999
        ))
        
        # Filter only passed
        passed_results = [r for r in test_results if r["passed"]]
        failed_results = [r for r in test_results if not r["passed"]]
        
        if verbose:
            print(f"\n  📊 Results: ✅ {len(passed_results)} passed | ❌ {len(failed_results)} failed")
            print(f"\n  🏆 Top {MAX_PER_COUNTRY} Keys for {country_code}:")
        
        # Print detailed reports for top keys
        top_results = passed_results[:MAX_PER_COUNTRY]
        
        for idx, result in enumerate(top_results, 1):
            if verbose:
                print_node_report(result, idx, country_code, flag)

        # Format output for top nodes
        formatted = []
        count = 1
        for result in top_results:
            node = result["node"]
            raw = node["raw"]
            latency = result["avg_tls_latency"] if result["avg_tls_latency"] > 0 else result["avg_tcp_latency"]
            
            # Clean name format: 🇸🇬 SG 1, 🇯🇵 JP 1, etc
            clean_name = f"{flag} {country_code} {count}"

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

        return formatted, len(passed_results), len(failed_results)

    except Exception as e:
        print(f"  ❌ Error processing {country_code}: {e}")
        return [], 0, 0


# ==============================================================================
# 🚀 MAIN
# ==============================================================================

def main():
    print("=" * 70)
    print("  🔑 Myanmar GFW-Bypass Key Checker v3.0")
    print("  📅 Date:", datetime.now(pytz.timezone("Asia/Yangon")).strftime("%Y-%m-%d %H:%M:%S MMT"))
    print("  🎯 Port 443 + GFW Bypass + Multiple Ping Tests")
    print("  🇲🇲 Optimized for Myanmar Network")
    print("=" * 70)
    print(f"\n  ✅ Allowed Ports: {sorted(ALLOWED_PORTS)}")
    print(f"  ⭐ Priority Ports: {sorted(PRIORITY_PORTS)}")
    print(f"  🔄 Ping Tests: {PING_TESTS}x per key")
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
    current_time = datetime.now(tz).strftime("%I:%M %p")
    
    profile_title = f"#profile-title: {current_time} Updated"
    plain_content = profile_title + "\n" + "\n".join(all_nodes)
    
    encoded_content = base64.b64encode(plain_content.encode("utf-8")).decode("utf-8")
    
    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)
    
    with open("servers_plain.txt", "w", encoding="utf-8") as f:
        f.write(plain_content)
    
    print(f"\n  💾 Encoded output: servers")
    print(f"  📄 Plain text output: servers_plain.txt")
    print(f"\n  ✅ Done! Myanmar-optimized keys with strict testing.")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
