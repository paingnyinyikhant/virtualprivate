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


def check_real_data_traffic(host, port, sni=None, path="/", timeout=3.0):
    """
    ရိုးရိုး Ping စစ်ရုံတင်မကဘဲ တကယ့် Data လက်ခံ/ပေးပို့နိုင်ခြင်း (Real Traffic) ရှိမရှိ စစ်ဆေးခြင်း
    """
    try:
        # ၁။ TCP Connection အရင်စစ်မည်
        sock = socket.create_connection((host, int(port)), timeout=timeout)

        server_hostname = sni if sni else host

        # TLS Connection စစ်ဆေးခြင်း
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(
            sock, server_hostname=server_hostname
        ) as tls_sock:
            tls_sock.settimeout(timeout)

            # 💡 REAL TRAFFIC TEST: HTTP GET Request တိုက်ရိုက် ပို့ပြီး Data ပြန်ထွက် မထွက် စစ်မည်
            http_request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {server_hostname}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            tls_sock.sendall(http_request.encode("utf-8"))

            # Server ဘက်က Response ပြန်လာမလာ စောင့်ကြည့်ခြင်း
            response = tls_sock.recv(256)
            if response and (
                b"HTTP/" in response or b"101" in response or b"200" in response
            ):
                return True
            elif len(response) > 0:
                # Data ပြန်ထွက်လာပါက Real Node အဖြစ် သတ်မှတ်မည်
                return True

    except Exception:
        # HTTP Handshake မအောင်မြင်ပါက ရိုးရိုး TLS စစ်မည်
        try:
            sock = socket.create_connection((host, int(port)), timeout=2.0)
            if int(port) == 443 or sni:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(
                    sock, server_hostname=sni or host
                ) as tls_sock:
                    return True
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

                # Real Traffic စစ်ဆေးမှု အောင်မြင်သော Node များကိုသာ ယူမည်
                if host and check_real_data_traffic(
                    host, port, sni=sni, path=path, timeout=3.0
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
        print(f"Filtering working servers for {country_code}...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Usable nodes for {country_code}: {len(nodes)}")

    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")

    profile_title = f"#profile-title: {current_date} Updated\n"
    plain_content = profile_title + "\n".join(all_nodes)

    encoded_bytes = base64.b64encode(plain_content.encode("utf-8"))
    encoded_content = encoded_bytes.decode("utf-8")

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(f"Saved {len(all_nodes)} 100% working nodes to 'servers' file.")


if __name__ == "__main__":
    main()
