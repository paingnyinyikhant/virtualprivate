import base64
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
    "TH": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/th/all.txt",
        "flag": "🇹🇭",
    },
}

MAX_PER_COUNTRY = 20

# 🎯 ဦးစားပေးစစ်ထုတ်မည့် Port များ (Port 2096 နှင့် 8388 ကို ထိပ်ဆုံးမှထားသည်)
PRIORITY_PORTS = {2096, 8388}
ALLOWED_PORTS = {2096, 8388, 443, 8443, 2053, 2083, 2087}

BLOCKED_SNIS = ["cloudflare.com", "speedtest.net", "co.uk", "127.0.0.1"]
SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")


def strict_myanmar_real_ping(host, port, path="/", sni=None, timeout=2.5):
    """ Happ App & ChatGPT/Gemini အတွက် Real Data Packet Test """
    try:
        port = int(port)
        if port not in ALLOWED_PORTS:
            return False

        if sni:
            sni_lower = sni.lower()
            if any(b_sni in sni_lower for b_sni in BLOCKED_SNIS):
                return False

        target_sni = sni if sni else host

        # TLS Probe Test for Port 2096, 443, etc.
        if port in {2096, 443, 8443, 2053, 2083, 2087} or sni:
            sock = socket.create_connection((host, port), timeout=timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with context.wrap_socket(sock, server_hostname=target_sni) as tls_sock:
                tls_sock.settimeout(timeout)
                clean_path = path if path.startswith("/") else "/" + path
                request = (
                    f"GET {clean_path} HTTP/1.1\r\n"
                    f"Host: {target_sni}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                tls_sock.sendall(request.encode("utf-8"))
                response = tls_sock.recv(256)

                if response and (b"101" in response or b"Sec-WebSocket-Accept" in response or b"HTTP/1.1 200" in response):
                    return True
        else:
            # TCP Direct Test for Port 8388 (Shadowsocks)
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True

    except Exception:
        return False

    return False


def parse_and_extract(line):
    """ Host, Port, Path, SNI တို့ကို Parse လုပ်ယူခြင်း """
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


def fetch_and_process_country(country_code, config):
    url = config["url"]
    flag = config["flag"]
    
    priority_nodes = []
    normal_nodes = []

    try:
        res = requests.get(url, timeout=12)
        content = res.text.strip()

        try:
            decoded = base64.b64decode(content).decode("utf-8")
            lines = decoded.splitlines()
        except Exception:
            lines = content.splitlines()

        for line in lines:
            line = line.strip()
            if not line or not any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                continue

            node_info = parse_and_extract(line)
            if not node_info:
                continue

            host = node_info["host"]
            port = node_info["port"]
            sni = node_info["sni"]
            path = node_info["path"]

            # Connection Ping Test
            if host and port and strict_myanmar_real_ping(host, port, path=path, sni=sni):
                # 🎯 Port 2096 နှင့် 8388 များကို Priority List သို့ ထည့်မည်
                if port in PRIORITY_PORTS:
                    priority_nodes.append(node_info)
                else:
                    normal_nodes.append(node_info)

        # Priority Port များကို ရှေ့ဆုံးမှ အရင်ယူမည်
        combined_nodes = priority_nodes + normal_nodes
        final_selected = combined_nodes[:MAX_PER_COUNTRY]

        # Rename Nodes
        formatted_nodes = []
        count = 1
        for item in final_selected:
            n_type = item["type"]
            raw = item["raw"]
            
            if n_type == "vmess":
                data = item["data"]
                data["ps"] = f"{flag} {country_code} {count} (P-{item['port']})"
                new_b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
                formatted_nodes.append(f"vmess://{new_b64}")
            else:
                base_url = raw.split("#")[0]
                new_name = urllib.parse.quote(f"{flag} {country_code} {count} (P-{item['port']})")
                formatted_nodes.append(f"{base_url}#{new_name}")
            
            count += 1

        return formatted_nodes

    except Exception as e:
        print(f"Error processing {country_code}: {e}")

    return []


def main():
    all_nodes = []

    for country_code, config in SOURCES.items():
        print(f"Extracting Ports 2096 & 8388 for {country_code}...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Saved for {country_code}: {len(nodes)} nodes")

    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")

    profile_title = f"#profile-title: {current_date} Updated (Port 2096/8388 Focused)\n"
    plain_content = profile_title + "\n".join(all_nodes)

    encoded_bytes = base64.b64encode(plain_content.encode("utf-8"))
    encoded_content = encoded_bytes.decode("utf-8")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(f"Done! Created 'servers' file with {len(all_nodes)} high-performance nodes.")


if __name__ == "__main__":
    main()
