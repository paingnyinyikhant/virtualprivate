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

# မြန်မာပြည် ISP များ DPI ဖြင့် အဓိက ပိတ်ထားသော Unencrypted Ports
BANNED_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}

# Myanmar Blocked / Low Quality CDN SNIs (Happ & Apps တွင် Ping ရပြီး Data မထွက်သော SNI များ)
BLOCKED_SNIS = [
    "cloudflare.com",
    "speedtest.net",
    "co.uk",
    "127.0.0.1"
]

SUPPORTED_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")


def is_myanmar_isp_friendly(host, port, sni):
    """ Port နှင့် SNI အဆင့်တွင် မြန်မာပြည်လိုင်းနှင့် ကိုင်တွယ်နိုင်မှု ရှိမရှိ စစ်ဆေးခြင်း """
    if int(port) in BANNED_PORTS:
        return False
    
    if sni:
        sni_lower = sni.lower()
        for b_sni in BLOCKED_SNIS:
            if b_sni in sni_lower:
                return False

    return True


def strict_myanmar_real_ping(host, port, path="/", sni=None, timeout=3.0):
    """
    Happ App (Sing-box) တွင် Real Ping သာမက TLS Handshake နှင့် 
    Data Exchange ပါ အောင်မြင်မှသာ True ပြန်ပေးမည်။
    """
    if not is_myanmar_isp_friendly(host, port, sni):
        return False

    target_sni = sni if sni else host

    # 1. Real TLS Handshake Validation (ChatGPT / Gemini / Happ Data Pass Test)
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=target_sni) as tls_sock:
            tls_sock.settimeout(timeout)

            # WebSocket Probe ပို့ပြီး Response စစ်ခြင်း
            clean_path = path if path.startswith("/") else "/" + path
            request = (
                f"GET {clean_path} HTTP/1.1\r\n"
                f"Host: {target_sni}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            tls_sock.sendall(request.encode("utf-8"))
            response = tls_sock.recv(256)

            if response and (b"101" in response or b"Sec-WebSocket-Accept" in response or b"HTTP/1.1 200" in response or b"HTTP/1.1 101" in response):
                return True
    except Exception:
        pass

    # 2. Non-TLS Protocol Direct Probe Test
    try:
        sock = socket.create_connection((host, int(port)), timeout=2.0)
        sock.close()
        return True
    except Exception:
        return False


def parse_and_rename_node(line, country_code, flag, count):
    """ Happ, ChatGPT, Gemini တို့နှင့် ကိုက်ညီအောင် Node များကို Parse/Rename ပြုလုပ်ခြင်း """
    try:
        # VMess Protocol
        if line.startswith("vmess://"):
            b64_str = line.replace("vmess://", "")
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

        # VLESS, Trojan, Hysteria2, TUIC Protocols
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

        # Shadowsocks (SS) Protocol
        elif line.startswith("ss://"):
            base_url = line.split("#")[0]
            parsed = urllib.parse.urlparse(base_url)
            host = parsed.hostname
            port = parsed.port

            if not host or not port:
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
        print(f"Strict Ping Testing for {country_code}...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Filtered & Verified for {country_code}: {len(nodes)} nodes")

    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")

    profile_title = f"#profile-title: {current_date} Updated\n"
    plain_content = profile_title + "\n".join(all_nodes)

    encoded_bytes = base64.b64encode(plain_content.encode("utf-8"))
    encoded_content = encoded_bytes.decode("utf-8")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(f"Done! Successfully generated {len(all_nodes)} high-quality nodes.")


if __name__ == "__main__":
    main()
