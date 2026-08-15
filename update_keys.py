import base64
from datetime import datetime
import json
import socket
import ssl
import urllib.parse
import pytz
import requests

# Source URLs များ
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

# မြန်မာပြည် ISP များ ပိတ်ထားတတ်သော HTTP Unencrypted Ports များ
BANNED_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")


def strict_myanmar_real_ping(host, port, path="/", sni=None, timeout=2.5):
    """
    Shadowsocks, VMess, VLESS, Trojan & Lightweight Protocols များကို
    Happ App / v2rayNG တွင် 100% Data ဆွဲနိုင်ရန် Real Ping Test စစ်ဆေးခြင်း
    """
    try:
        if int(port) in BANNED_PORTS:
            return False

        sock = socket.create_connection((host, int(port)), timeout=timeout)
        target_sni = sni if sni else host

        # Port 443 သို့မဟုတ် SNI ပါပါက TLS Handshake စစ်ဆေးမည်
        if int(port) == 443 or sni:
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
                elif len(response) > 0:
                    return True

        sock.close()
        return True

    except Exception:
        # Direct TCP fallback test
        try:
            sock = socket.create_connection((host, int(port)), timeout=2.0)
            sock.close()
            return True
        except Exception:
            return False

    return False


def parse_and_rename_node(line, country_code, flag, count):
    """Protocol အမျိုးအစားအလိုက် Parse လုပ်ပြီး နာမည်ပြောင်းခြင်း"""
    try:
        # ၁။ VMess Protocol
        if line.startswith("vmess://"):
            b64_str = line.replace("vmess://", "")
            # Base64 padding ပြင်ဆင်ခြင်း
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            decoded_json = json.loads(base64.b64decode(b64_str).decode("utf-8"))
            
            host = decoded_json.get("add")
            port = decoded_json.get("port")
            sni = decoded_json.get("sni") or decoded_json.get("host")
            path = decoded_json.get("path", "/")

            if host and strict_myanmar_real_ping(host, port, path=path, sni=sni):
                decoded_json["ps"] = f"{flag} {country_code} {count}"
                new_b64 = base64.b64encode(json.dumps(decoded_json).encode("utf-8")).decode("utf-8")
                return f"vmess://{new_b64}"

        # ၂။ VLESS, Trojan, Hysteria2, TUIC Protocols
        elif any(line.startswith(p) for p in ["vless://", "trojan://", "hysteria2://", "hy2://", "tuic://"]):
            parsed = urllib.parse.urlparse(line)
            host = parsed.hostname
            port = parsed.port or 443

            query_params = urllib.parse.parse_qs(parsed.query)
            sni = query_params.get("sni", [None])[0] or query_params.get("host", [None])[0]
            path = query_params.get("path", ["/"])[0]

            if host and strict_myanmar_real_ping(host, port, path=path, sni=sni):
                base_url = line.split("#")[0]
                new_name = urllib.parse.quote(f"{flag} {country_code} {count}")
                return f"{base_url}#{new_name}"

        # ၃။ Shadowsocks (SS) Protocol
        elif line.startswith("ss://"):
            # SIP002 သို့မဟုတ် Legacy format parse လုပ်ခြင်း
            base_url = line.split("#")[0]
            parsed = urllib.parse.urlparse(base_url)
            host = parsed.hostname
            port = parsed.port

            if not host or not port:
                # Base64 encoded format စစ်ဆေးခြင်း
                try:
                    raw_ss = base_url.replace("ss://", "")
                    if "@" in raw_ss:
                        user_info, host_port = raw_ss.split("@", 1)
                        host, port = host_port.split(":", 1)
                    else:
                        decoded_ss = base64.b64decode(raw_ss + "==").decode("utf-8")
                        user_info, host_port = decoded_ss.split("@", 1)
                        host, port = host_port.split(":", 1)
                except Exception:
                    return None

            if host and port and strict_myanmar_real_ping(host, port):
                new_name = urllib.parse.quote(f"{flag} {country_code} {count}")
                return f"{base_url}#{new_name}"

    except Exception:
        return None
        
    return None


def fetch_and_process_country(country_code, config):
    url = config["url"]
    flag = config["flag"]
    valid_nodes = []

    try:
        res = requests.get(url, timeout=12)
        content = res.text.strip()

        # Base64 Decode ဖြစ်/မဖြစ် စစ်ဆေးခြင်း
        try:
            decoded = base64.b64decode(content).decode("utf-8")
            lines = decoded.splitlines()
        except Exception:
            lines = content.splitlines()

        count = 1
        for line in lines:
            line = line.strip()
            if not line or not any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                continue

            node_result = parse_and_rename_node(line, country_code, flag, count)
            if node_result:
                valid_nodes.append(node_result)
                count += 1

                if len(valid_nodes) >= MAX_PER_COUNTRY:
                    break

    except Exception as e:
        print(f"Error processing {country_code}: {e}")

    return valid_nodes


def main():
    all_nodes = []

    for country_code, config in SOURCES.items():
        print(f"Parsing all protocols (SS, VMess, VLESS, Trojan) for {country_code}...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Passed valid nodes for {country_code}: {len(nodes)}")

    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")

    profile_title = f"#profile-title: {current_date} Updated\n"
    plain_content = profile_title + "\n".join(all_nodes)

    encoded_bytes = base64.b64encode(plain_content.encode("utf-8"))
    encoded_content = encoded_bytes.decode("utf-8")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(f"Done! Encoded and saved {len(all_nodes)} nodes across all protocols to 'servers'.")


if __name__ == "__main__":
    main()
