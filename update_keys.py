import base64
from datetime import datetime
import socket
import urllib.parse
import pytz
import requests

# Source URLs များ
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

MAX_PER_COUNTRY = 20  # တစ်နိုင်ငံလျှင် အများဆုံး ၂၀ ခုပဲ ယူမည်


def check_ping(host, port, timeout=1.5):
    """TCP Ping စစ်ဆေးခြင်း"""
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
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

        # Base64 Decode လုပ်ရန် လို/မလို စစ်ဆေးခြင်း
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

                # Ping မိတာတွေကိုပဲ သီးသန့်ရွေးမည်
                if host and check_ping(host, port):
                    base_url = line.split("#")[0]
                    # ဥပမာ - 🇸🇬 SG 1, 🇸🇬 SG 2 စသဖြင့် နာမည်ပေးခြင်း
                    new_name = urllib.parse.quote(
                        f"{flag} {country_code} {count}"
                    )
                    valid_nodes.append(f"{base_url}#{new_name}")
                    count += 1

                    # အကောင့် ၂၀ ပြည့်ပါက ရပ်မည်
                    if len(valid_nodes) >= MAX_PER_COUNTRY:
                        break
            except Exception:
                continue

    except Exception as e:
        print(f"Error fetching {country_code}: {e}")

    return valid_nodes


def main():
    all_nodes = []

    # နိုင်ငံတစ်ခုချင်းစီအတွက် စစ်ဆေးပြီး Node များ စုစည်းခြင်း
    for country_code, config in SOURCES.items():
        print(f"Processing {country_code}...")
        nodes = fetch_and_process_country(country_code, config)
        all_nodes.extend(nodes)
        print(f"Found {len(nodes)} working nodes for {country_code}")

    # Myanmar/Asia Timezone နည်းဖြင့် လက်ရှိ Date ယူခြင်း (ဥပမာ - 15-Aug-26)
    tz = pytz.timezone("Asia/Yangon")
    current_date = datetime.now(tz).strftime("%d-%b-%y")

    # Dynamic Profile Title နှင့် Plain Text Data စုစည်းခြင်း
    profile_title = f"#profile-title: {current_date} Updated\n"
    plain_content = profile_title + "\n".join(all_nodes)

    # 💡 စာသားအကုန်လုံးကို Base64 အပြည့်အဝ Encode လုပ်ခြင်း
    encoded_bytes = base64.b64encode(plain_content.encode("utf-8"))
    encoded_content = encoded_bytes.decode("utf-8")

    # Base64 encode ထားပြီးသား text များကို 'servers' ဖိုင်အဖြစ် သိမ်းမည်
    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_content)

    print(
        f"Successfully encoded and written {len(all_nodes)} nodes to 'servers' file."
    )


if __name__ == "__main__":
    main()
