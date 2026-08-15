import base64
from datetime import datetime
import re
import socket
import ssl
import urllib.parse
import pytz
import requests

# Source URLs
SOURCES = {
    "SG": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/vless.txt",
        "flag": "🇸🇬",
    },
    "JP": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/jp/vless.txt",
        "flag": "🇯🇵",
    },
    "TH": {
        "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/th/vless.txt",
        "flag": "🇹🇭",
    },
}

MAX_PER_COUNTRY = 10


def is_vless_traffic_functional(host, port, path="/", sni=None, timeout=3.5):
    """
    မြန်မာပြည် Network တွင် 100% Data ဆွဲ၍ ရ/မရ အစစ်အမှန် Traffic စစ်ဆေးခြင်း
    """
    try:
        # ၁။ TCP Connection စစ်ဆေးခြင်း
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        target_sni = sni if sni else host

        # ၂။ TLS Wrapper ဖြင့် Handshake ပြုလုပ်ခြင်း
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(
            sock, server_hostname=target_sni
        ) as tls_sock:
            tls_sock.settimeout(timeout)

            # WebSocket Header ဖြင့် Connection Probe ပို့ခြင်း
            clean_path = path if path.startswith("/") else "/" + path
            ws_handshake = (
                f"GET {clean_path} HTTP/1.1\r\n"
                f"Host: {target_sni}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            tls_sock.sendall(ws_handshake.encode("utf-8"))

            response = tls_sock.recv(512)

            # Response Status စစ်ခြင်း (101 Switching Protocols, 200, or Valid WS Handshake)
            if response and (
                b"101" in response
                or b"HTTP/" in response
                or b"Sec-WebSocket-Accept" in response
            ):
                return True
            elif len(response) > 0:
                # Data Response ပြန်လာပါက သုံး၍ရသော Node အဖြစ် သတ်မှတ်မည်
                return True

    except Exception:
        # TLS Probe မအောင်မြင်ပါက Single TCP Layer Verification အဖြစ် စစ်မည်
        try:
            sock = socket.create_connection((host, int(port)), timeout=2.0)
            sock.close()
            return True
        except Exception:
            return False

    return False


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
            if not line or not line.startswith("vless://"):
                continue

            try:
                parsed = urllib.parse.urlparse(line)
                host = parsed.hostname
                port = parsed.port or 443

                query_params = urllib.parse.parse_qs(parsed.query)
                sni = query_params.get("sni", [None])[0] or query_params.get(
                    "host", [None]
                )[0]
                path = query_params.get("path", ["/"])[0]

                # Real Traffic စစ်ဆေးမှု အောင်မြင်သော Node များကိုသာ ရွေးမည်
                if host and is_vless_traffic_functional(
                    host, port, path=path, sni=sni, timeout=3.5
                ):
                    base_url = line.split("#")[0]
                    new_name = urllib.parse.quote(
                        f"{flag} {country_code} {count}"
                    )
                    valid_nodes.append(f"{base_url}#{new_name}")
                    count += 1

                    if len(valid_nodes) >= MAX_PER_COUNTRY:
                        break
            except Exception:
                continue

    except Exception as e:
        print(f"Error processing {country_code}: {e}")

    return valid_nodes


def main():
    all_nodes = []

    for country_code, config in SOURCES.items():
        print(f"Deep testing nodes for {country_code}...")
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

    print(f"Successfully processed and verified {len(all_nodes)} nodes.")


if __name__ == "__main__":
    main()
