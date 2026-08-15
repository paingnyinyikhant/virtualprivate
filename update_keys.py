import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import socket
import ssl
import urllib.parse
import pytz
import requests

# 🎯 Main Source Link တစ်ခုတည်းမှ စစ်ထုတ်မည့် နိုင်ငံများနှင့် Flag များ
TARGET_COUNTRIES = {
    "SG": {"flag": "🇸🇬", "keywords": ["sg", "singapore"]},
    "JP": {"flag": "🇯🇵", "keywords": ["jp", "japan"]},
    "US": {"flag": "🇺🇸", "keywords": ["us", "united states", "america"]},
    "TH": {"flag": "🇹🇭", "keywords": ["th", "thailand"]},
}

SOURCE_URL = "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt"

MAX_PER_COUNTRY = 20

# 🎯 ဦးစားပေးစစ်ထုတ်မည့် Port များ (Port 443 ကို ပယ်ထားသည်)
PRIORITY_PORTS = {2096, 8388}
ALLOWED_PORTS = {2096, 8388, 8443, 2053, 2083, 2087}

BLOCKED_SNIS = ["cloudflare.com", "speedtest.net", "co.uk", "127.0.0.1"]
SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")

# 🚫 Facebook Ads Blocking Parameters
FB_ADS_BLOCK_PARAMS = (
    "block_domains=an.facebook.com,graph.facebook.com/adnw,"
    "pixel.facebook.com,connect.facebook.net/adnw"
)


def strict_myanmar_real_ping(host, port, path="/", sni=None):
    """ Fast Ping Test with Strict Timeout """
    try:
        port = int(port)
        if port not in ALLOWED_PORTS:
            return False

        if sni and any(b_sni in sni.lower() for b_sni in BLOCKED_SNIS):
            return False

        target_sni = sni if sni else host

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((host, port))

        if port in {2096, 8443, 2053, 2083, 2087} or sni:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with context.wrap_socket(sock, server_hostname=target_sni) as tls_sock:
                tls_sock.settimeout(1.0)
                clean_path = path if path.startswith("/") else "/" + path
                request = (
                    f"GET {clean_path} HTTP/1.1\r\n"
                    f"Host: {target_sni}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                tls_sock.sendall(request.encode("utf-8"))
                response = tls_sock.recv(128)
                tls_sock.close()
                return len(response) > 0
        else:
            sock.close()
            return True

    except Exception:
        return False


def parse_and_extract(line):
    try:
        if line.startswith("vmess://"):
            b64_str = line.replace("vmess://", "")
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            decoded = json.loads(base64.b64decode(b64_str).decode("utf-8"))
            ps = str(decoded.get("ps", "")).lower()
            return {
                "type": "vmess",
                "data": decoded,
                "host": decoded.get("add"),
                "port": int(decoded.get("port")),
                "sni": decoded.get("sni") or decoded.get("host"),
                "path": decoded.get("path", "/"),
                "ps": ps,
                "raw": line
            }
        elif any(line.startswith(p) for p in ["vless://", "trojan://", "hysteria2://", "hy2://", "tuic://"]):
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            ps = urllib.parse.unquote(parsed.fragment).lower()
            return {
                "type": "url",
                "host": parsed.hostname,
                "port": int(parsed.port or 443),
                "sni": query_params.get("sni", [None])[0] or query_params.get("host", [None])[0],
                "path": query_params.get("path", ["/"])[0],
                "ps": ps,
                "raw": line
            }
        elif line.startswith("ss://"):
            parts = line.split("#")
            ps = urllib.parse.unquote(parts[1]).lower() if len(parts) > 1 else ""
            base_url = parts[0]
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
                host, port = host_port.split(":", 1)
            return {
                "type": "ss",
                "host": host,
                "port": int(port),
                "sni": None,
                "path": "/",
                "ps": ps,
                "raw": line
            }
    except Exception:
        return None
    return None


def test_node(node_info):
    host = node_info["host"]
    port = node_info["port"]
    sni = node_info["sni"]
    path = node_info["path"]

    if host and port and strict_myanmar_real_ping(host, port, path=path, sni=sni):
        return node_info
    return None


def detect_country(node_info):
    """ Node ရဲ့ Host, SNI သို့မဟုတ် PS (Remark Name) မှ နိုင်ငံကို ခွဲခြားခြင်း """
    search_text = f"{node_info.get('host', '')} {node_info.get('sni', '')} {node_info.get('ps', '')}".lower()
    
    for code, info in TARGET_COUNTRIES.items():
        for kw in info["keywords"]:
            if kw in search_text:
                return code
    return None


def main():
    print(f"Fetching nodes from main list...")
    try:
        res = requests.get(SOURCE_URL, timeout=15)
        content = res.text.strip()
        try:
            decoded = base64.b64decode(content).decode("utf-8")
            lines = decoded.splitlines()
        except Exception:
            lines = content.splitlines()

        parsed_nodes = []
        for line in lines:
            line = line.strip()
            if line and any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                info = parse_and_extract(line)
                if info:
                    parsed_nodes.append(info)

        # နိုင်ငံအလိုက် Categorize ခွဲခြားခြင်း
        categorized = {"SG": [], "JP": [], "US": [], "TH": []}
        for node in parsed_nodes:
            country = detect_country(node)
            if country in categorized:
                categorized[country].append(node)

        all_nodes = []
        
        # နိုင်ငံအလိုက် Node များကို စစ်ထုတ်ပြီး Ping Test လုပ်ခြင်း
        for country_code, nodes in categorized.items():
            print(f"Testing {len(nodes)} nodes for {country_code}...")
            flag = TARGET_COUNTRIES[country_code]["flag"]
            
            valid_nodes = []
            with ThreadPoolExecutor(max_workers=30) as executor:
                results = executor.map(test_node, nodes)
                for r in results:
                    if r:
                        valid_nodes.append(r)

            # Priority Sorting (2096, 8388 ports များကို ရှေ့တင်မည်)
            priority_nodes = [n for n in valid_nodes if n["port"] in PRIORITY_PORTS]
            normal_nodes = [n for n in valid_nodes if n["port"] not in PRIORITY_PORTS]

            combined = (priority_nodes + normal_nodes)[:MAX_PER_COUNTRY]

            count = 1
            for item in combined:
                raw = item["raw"]
                clean_name = f"{flag} {country_code} {count}"

                if item["type"] == "vmess":
                    data = item["data"]
                    data["ps"] = clean_name
                    data["fb_block"] = FB_ADS_BLOCK_PARAMS
                    new_b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
                    all_nodes.append(f"vmess://{new_b64}")
                else:
                    base_url = raw.split("#")[0]
                    delimiter = "&" if "?" in base_url else "?"
                    base_url = f"{base_url}{delimiter}{FB_ADS_BLOCK_PARAMS}"
                    new_name = urllib.parse.quote(clean_name)
                    all_nodes.append(f"{base_url}#{new_name}")
                    
                count += 1

            print(f"Saved for {country_code}: {len(combined)} nodes")

        tz = pytz.timezone("Asia/Yangon")
        current_date = datetime.now(tz).strftime("%d-%b-%y")

        profile_title = f"#profile-title: {current_date} Updated\n"
        plain_content = profile_title + "\n".join(all_nodes)

        encoded_content = base64.b64encode(plain_content.encode("utf-8")).decode("utf-8")

        with open("servers", "w", encoding="utf-8") as f:
            f.write(encoded_content)

        print(f"Done! Successfully generated {len(all_nodes)} nodes from single URL.")

    except Exception as e:
        print(f"Error processing main URL: {e}")


if __name__ == "__main__":
    main()
