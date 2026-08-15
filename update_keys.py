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


def check_myanmar_network_ping(host, port, sni=None, timeout=2.5):
    """
    မြန်မာနိုင်ငံ Network နှင့် ကိုက်ညီသော TLS Handshake & TCP Combined Ping Check
    """
    try:
        # ၁။ ရှေ့ဦးစွာ TCP Connection စစ်ခြင်း
        sock = socket.create_connection((host, int(port)), timeout=timeout)

        # 端口 443 သို့မဟုတ် SNI ပါပါက TLS Handshake စစ်ပါမည် (မြန်မာပြည်တွင် SNI Block ခ่อยောမှ ဆွဲရန်)
        if int(port) == 443 or sni:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            server_hostname = sni if sni else host
            with context.wrap_socket(
                sock, server_hostname=server_hostname
            ) as tls_sock:
                tls_sock.settimeout(timeout)
                return True

        sock.close()
        return True
    except Exception:
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

                # Query string ထဲမှ SNI / Host parameter ကို ရှာခြင်း
                query_params = urllib.parse.parse_qs(parsed.query)
                sni = query_params.get("sni", [None])[0] or query_params.get(
                    "host", [None]
                )[0]

                # မြန်မာပြည် Network အတွက် သီးသန့် အဆင့်မြှင့်ထားသော Ping Test စစ်ခြင်း
                if host and check_myanmar_network_ping(
                    host, port, sni=sni, timeout=2.5
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
        print(f"Checking {country_code} for Myanmar Network Compatibility...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Passed for {country_code}: {len(nodes)} nodes")

    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")

    profile_title = f"#profile-title: {current_date} Updated\n"
    plain_content = profile_title + "\n".join(all_nodes)

    encoded_bytes = base64.b64encode(plain_content.encode("utf-8"))
    encoded_content = encoded_bytes.decode("utf-8")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(f"Done! Saved {len(all_nodes)} nodes.")


if __name__ == "__main__":
    main()
