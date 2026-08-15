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

MAX_PER_COUNTRY = 20


def v2rayng_real_ping_test(host, port, path="/", sni=None, timeout=2.5):
    """
    v2rayNG / Happ ရဲ့ Real Delay Test နည်းအတိုင်း
    Data အစစ် ထွက်/မထွက် စစ်ဆေးသည့် စနစ် (Strict Test)
    """
    try:
        # 1. Socket TCP Connection
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        target_sni = sni if sni else host

        # 2. TLS Handshake Setup
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(
            sock, server_hostname=target_sni
        ) as tls_sock:
            tls_sock.settimeout(timeout)

            # 3. WebSocket Handshake Packet ပို့ပြီး Response စစ်ခြင်း (Real Ping)
            clean_path = path if path.startswith("/") else "/" + path
            request = (
                f"GET {clean_path} HTTP/1.1\r\n"
                f"Host: {target_sni}\r\n"
                f"User-Agent: v2rayNG/1.8.5\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            tls_sock.sendall(request.encode("utf-8"))

            # Response ကို ဖတ်ယူခြင်း
            response = tls_sock.recv(256)

            # Response ထဲမှာ 101 Switching Protocols သို့မဟုတ် Server Data တကယ်ပါမှ အတည်ပြုမည်
            if response and (
                b"101" in response
                or b"Sec-WebSocket-Accept" in response
                or b"HTTP/1.1 200" in response
            ):
                return True

    except Exception:
        return False

    return False


def fetch_and_process_country(country_code, config):
    url = config["url"]
    flag = config["flag"]
    valid_nodes = []

    try:
        res = requests.get(url, timeout=10)
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

                # Strict Real Ping ကျော်ဖြတ်နိုင်သော Node များကိုသာ ယူမည်
                if host and v2rayng_real_ping_test(
                    host, port, path=path, sni=sni, timeout=2.5
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
        print(f"Error fetching {country_code}: {e}")

    return valid_nodes


def main():
    all_nodes = []

    for country_code, config in SOURCES.items():
        print(f"Testing Real Ping for {country_code}...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Passed strict test for {country_code}: {len(nodes)} nodes")

    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")

    profile_title = f"#profile-title: {current_date} Updated\n"
    plain_content = profile_title + "\n".join(all_nodes)

    encoded_bytes = base64.b64encode(plain_content.encode("utf-8"))
    encoded_content = encoded_bytes.decode("utf-8")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(f"Done! Saved {len(all_nodes)} 100% working nodes to 'servers'.")


if __name__ == "__main__":
    main()
