import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import socket
import ssl
import urllib.parse
import pytz
import requests

SOURCES = {
    "SG": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/all.txt",
        "flag": "🇸🇬",
    },
    "JP": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/jp/all.txt",
        "flag": "🇯🇵",
    },
}

# 🎯 တစ်နိုင်ငံလျှင် Server 20 ခု (Wifi 10 ခု + Sim 10 ခု)
WIFI_SLOTS = 10  # Port 443 (For Wifi)
SIM_SLOTS = 10   # ကျန် Port များ (For Sim Data and Wifi)

# 🎯 Sim Data + Wifi အဖွဲ့အတွင်း ဦးစားပေးစစ်ထုတ်မည့် Port များ
PRIORITY_PORTS = {2096, 8388}
# Port 443 (Wifi) အပါအဝင် စစ်ထုတ်ခွင့်ပြုထားသော Port အားလုံး
ALLOWED_PORTS = {443, 2096, 8388, 8443, 2053}

BLOCKED_SNIS = ["cloudflare.com", "speedtest.net", "co.uk", "127.0.0.1"]
SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")


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

        if port in {443, 2096, 8443, 2053} or sni:
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
            return {
                "type": "vmess",
                "data": decoded,
                "host": decoded.get("add"),
                "port": int(decoded.get("port")),
                "sni": decoded.get("sni") or decoded.get("host"),
                "path": decoded.get("path", "/"),
                "raw": line
            }
        elif any(line.startswith(p) for p in ["vless://", "trojan://", "hysteria2://", "hy2://", "tuic://"]):
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            return {
                "type": "url",
                "host": parsed.hostname,
                "port": int(parsed.port or 443),
                "sni": query_params.get("sni", [None])[0] or query_params.get("host", [None])[0],
                "path": query_params.get("path", ["/"])[0],
                "raw": line
            }
        elif line.startswith("ss://"):
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
                host, port = host_port.split(":", 1)
            return {
                "type": "ss",
                "host": host,
                "port": int(port),
                "sni": None,
                "path": "/",
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


def fetch_and_process_country(country_code, config):
    url = config["url"]
    flag = config["flag"]

    try:
        res = requests.get(url, timeout=10)
        content = res.text.strip()
        try:
            decoded = base64.b64decode(content).decode("utf-8")
            lines = decoded.splitlines()
        except Exception:
            lines = content.splitlines()

        nodes_to_test = []
        for line in lines:
            line = line.strip()
            if line and any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                info = parse_and_extract(line)
                if info:
                    nodes_to_test.append(info)

        valid_nodes = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(test_node, nodes_to_test)
            for r in results:
                if r:
                    valid_nodes.append(r)

        # Port 443 (For Wifi) နှင့် ကျန် Port (For Sim Data and Wifi) ခွဲခြားခြင်း
        wifi_nodes = [n for n in valid_nodes if n["port"] == 443]
        sim_priority_nodes = [
            n for n in valid_nodes
            if n["port"] in PRIORITY_PORTS and n["port"] != 443
        ]
        sim_normal_nodes = [
            n for n in valid_nodes
            if n["port"] not in PRIORITY_PORTS and n["port"] != 443
        ]

        # Wifi 10 ခု (SG 1-10) + Sim 10 ခု (SG 11-20) — မပြည့်လျှင် ရှိသလောက်
        combined = wifi_nodes[:WIFI_SLOTS] + (sim_priority_nodes + sim_normal_nodes)[:SIM_SLOTS]

        formatted = []
        count = 1
        for item in combined:
            raw = item["raw"]

            # Port 443 = For Wifi, ကျန် Port = For Sim Data and Wifi
            if item["port"] == 443:
                clean_name = f"{flag} {country_code} {count} (For Wifi)"
            else:
                clean_name = f"{flag} {country_code} {count} (For Sim Data and Wifi)"

            if item["type"] == "vmess":
                data = item["data"]
                data["ps"] = clean_name
                new_b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
                formatted.append(f"vmess://{new_b64}")
            else:
                base_url = raw.split("#")[0]

                new_name = urllib.parse.quote(clean_name)
                formatted.append(f"{base_url}#{new_name}")
                
            count += 1

        return formatted

    except Exception as e:
        print(f"Error: {e}")
        return []


def main():
    all_nodes = []
    for country_code, config in SOURCES.items():
        print(f"Testing nodes for {country_code}...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Saved for {country_code}: {len(nodes)} nodes")

    tz = pytz.timezone("Asia/Yangon")
    current_time = datetime.now(tz).strftime("%I:%M %p").lstrip("0")

    profile_title = f"#profile-title: {current_time} Updated\n"
    plain_content = profile_title + "\n".join(all_nodes)

    encoded_content = base64.b64encode(plain_content.encode("utf-8")).decode("utf-8")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(f"Done! Updated nodes with clean names.")


if __name__ == "__main__":
    main()
