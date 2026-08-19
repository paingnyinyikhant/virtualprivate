import base64
import datetime
import json
import os
import subprocess
import time
import urllib.parse
import requests

SOURCE_URL = "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/vless.txt"
TEST_URL = "https://www.gstatic.com/generate_204"
LISTEN_PORT = 10808


def create_v2ray_config(vless_link):
    try:
        parsed = urllib.parse.urlparse(vless_link)
        netloc = parsed.netloc

        if "@" in netloc:
            uuid, host_port = netloc.split("@")
        else:
            return False

        if ":" in host_port:
            host, port = host_port.split(":")
        else:
            host, port = host_port, 443

        query = dict(urllib.parse.parse_qsl(parsed.query))

        network = query.get("type", "tcp")
        security = query.get("security", "none")
        sni = query.get("sni", query.get("host", host))
        path = query.get("path", "/")

        stream_settings = {"network": network, "security": security}

        if network == "ws":
            stream_settings["wsSettings"] = {
                "path": path,
                "headers": {"Host": query.get("host", sni)},
            }

        if security == "tls":
            stream_settings["tlsSettings"] = {
                "serverName": sni,
                "allowInsecure": True,
            }
        elif security == "reality":
            stream_settings["realitySettings"] = {
                "serverName": sni,
                "publicKey": query.get("pbk", ""),
                "shortId": query.get("sid", ""),
                "fingerprint": query.get("fp", "chrome"),
            }

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": LISTEN_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": int(port),
                        "users": [{
                            "id": uuid,
                            "encryption": query.get("encryption", "none"),
                        }],
                    }]
                },
                "streamSettings": stream_settings,
            }],
        }

        with open("temp_config.json", "w") as f:
            json.dump(config, f, indent=2)
        return True

    except Exception as e:
        print(f"Config parse error: {e}")
        return False


def check_real_delay(vless_link):
    if not create_v2ray_config(vless_link):
        return False

    # V2Ray တက်/မတက် စစ်ဆေးရန် Process ခေါ်ယူခြင်း
    process = subprocess.Popen(
        ["v2ray", "run", "-c", "temp_config.json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # V2Ray core အလုပ်လုပ်ရန် 2 စက္ကန့် စောင့်မည်
    time.sleep(2)

    # process သေသွားခဲ့ရင် Error ပြမည်
    if process.poll() is not None:
        _, err = process.communicate()
        print(f"\n[V2Ray Core Error]: {err.strip()}")
        return False

    proxies = {
        "http": f"socks5h://127.0.0.1:{LISTEN_PORT}",
        "https": f"socks5h://127.0.0.1:{LISTEN_PORT}",
    }

    is_alive = False
    try:
        # Timeout ကို 6 စက္ကန့်ထိ တိုးပေးထားသည်
        response = requests.get(TEST_URL, proxies=proxies, timeout=6)
        if response.status_code in [200, 204]:
            is_alive = True
    except Exception as e:
        # Error တက်ပါက အကြောင်းရင်း ထုတ်ပြရန်
        pass
    finally:
        process.terminate()
        process.wait()

    return is_alive


def process_configs():
    print("Fetching configs...")
    try:
        response = requests.get(SOURCE_URL, timeout=10)
        content = response.text.strip()
    except Exception as e:
        print(f"Error fetching source: {e}")
        return

    try:
        decoded_content = base64.b64decode(content).decode("utf-8")
    except Exception:
        decoded_content = content

    lines = decoded_content.splitlines()
    working_configs = []

    print("Testing configs via Real Delay...")
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("vless://"):
            continue

        print(f"Testing node...", end="", flush=True)
        if check_real_delay(line):
            print(" -> [✓] SUCCESS")
            working_configs.append(line)
        else:
            print(" -> [X] FAILED")

    print(f"\nTotal Working Nodes: {len(working_configs)}")

    formatted_lines = []
    today_date = datetime.datetime.now().strftime("%d-%b-%y")
    profile_header = f"#profile-title: {today_date} Updated"
    formatted_lines.append(profile_header)

    count = 1
    for config in working_configs:
        new_name = f"🇸🇬 SG {count}"
        if "#" in config:
            base_config = config.split("#")[0]
            new_config = f"{base_config}#{urllib.parse.quote(new_name)}"
        else:
            new_config = f"{config}#{urllib.parse.quote(new_name)}"

        formatted_lines.append(new_config)
        count += 1

    plain_text_output = "\n".join(formatted_lines)
    encoded_output = base64.b64encode(plain_text_output.encode("utf-8")).decode(
        "utf-8"
    )

    with open("servers", "w", encoding="utf-8") as f:
        f.write(encoded_output)

    if os.path.exists("temp_config.json"):
        os.remove("temp_config.json")

    print("Successfully generated and saved encoded 'servers' file.")


if __name__ == "__main__":
    process_configs()
