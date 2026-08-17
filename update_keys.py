import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import socket
import ssl
import urllib.parse
import pytz
import requests

# 🌐 အရန်နောက်ထပ် Source (Freedom-V2Ray Mixed List) — မူရင်း node မလုံလောက်လျှင် ဖြည့်ရန်
FREEDOM_MIX_URL = "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt"

SOURCES = {
    # [0] = အဓိက Source (အရင်ယူ) → [1] = အရန် Source (မပြည့်လျှင် ဖြည့်)
    "SG": [
        {
            "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/sg/all.txt",
            "flag": "🇸🇬",
        },
        {
            "url": FREEDOM_MIX_URL,
            "flag": "🇸🇬",
            "name_filter": "🇸🇬",
        },
    ],
    "JP": [
        {
            "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/jp/all.txt",
            "flag": "🇯🇵",
        },
        {
            "url": FREEDOM_MIX_URL,
            "flag": "🇯🇵",
            "name_filter": "🇯🇵",
        },
    ],
    "US": [
        {
            "url": "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/countries/us/all.txt",
            "flag": "🇺🇸",
        },
        {
            "url": FREEDOM_MIX_URL,
            "flag": "🇺🇸",
            "name_filter": "🇺🇸",
        },
    ],
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


# ============================================================================
# 🎯 စစ်မှန်သော Proxy Protocol စစ်ဆေးခြင်း (TCP/TLS ping သက်သက်မဟုတ်)
#    VLESS / Trojan / VMess / Shadowsocks — protocol handshake + တကယ့် data relay စစ်သည်
# ============================================================================

# 🎯 စစ်မှန်သော Proxy Protocol စစ်ဆေးခြင်း (TCP/TLS ping သက်သက်မဟုတ်)
#    VLESS / Trojan / VMess / Shadowsocks တို့၏ အစစ်အမှန် handshake ကို စစ်သည်
# ============================================================================
import hashlib
import hmac
import os
import struct
import time

# Proxy အတွင်းမှ စမ်းသပ် dial လုပ်မည့် Target (Server မှ ဆက်သွယ်ရသည်)
TEST_TARGET_HOST = "www.cloudflare.com"
TEST_TARGET_PORT = 80

TLS_PORTS = {443, 2096, 8443, 2053}
SS_AEAD_METHODS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}
SS_STREAM_METHODS = {"aes-128-cfb", "aes-192-cfb", "aes-256-cfb"}


# ------------------------- Pure-Python Crypto (stdlib only) -------------------------
_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _aes_expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [[key[4 * i + j] for j in range(4)] for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[x] for x in temp]
            temp[0] ^= rcon
            rcon = _gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[x] for x in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w, nr


def _aes_encrypt_block(key, block):
    w, nr = _aes_expand_key(key)
    state = [[block[4 * c + r] for r in range(4)] for c in range(4)]

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                state[c][r] ^= w[4 * rnd + c][r]

    def sub_bytes():
        for c in range(4):
            for r in range(4):
                state[c][r] = _SBOX[state[c][r]]

    def shift_rows():
        new = [[state[(c + r) % 4][r] for r in range(4)] for c in range(4)]
        for c in range(4):
            state[c] = new[c]

    def mix_columns():
        for c in range(4):
            a0, a1, a2, a3 = state[c]
            state[c][0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
            state[c][1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
            state[c][2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
            state[c][3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)

    add_round_key(0)
    for rnd in range(1, nr):
        sub_bytes()
        shift_rows()
        mix_columns()
        add_round_key(rnd)
    sub_bytes()
    shift_rows()
    add_round_key(nr)
    return bytes(state[c][r] for c in range(4) for r in range(4))


def _aes_cfb_encrypt(key, iv, data):
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        ks = _aes_encrypt_block(key, prev)
        enc = bytes(b ^ k for b, k in zip(block, ks))
        out += enc
        prev = enc
    return out


def _aes_cfb_decrypt(key, iv, data):
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        ks = _aes_encrypt_block(key, prev)
        out += bytes(b ^ k for b, k in zip(block, ks))
        prev = block
    return out


def _gf_mul(x, y):
    """GF(2^128) multiply in GCM's bit-reflected representation (x^128+x^7+x^2+x+1)."""
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ (0xE1 << 120)
        else:
            v >>= 1
    return z & ((1 << 128) - 1)


def _gcm_ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        y = _gf_mul(y ^ int.from_bytes(block.ljust(16, b"\x00"), "big"), h)
    return y


def _gcm_crypt(key, iv, data):
    h = int.from_bytes(_aes_encrypt_block(key, b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    out = b""
    counter = j0[:12] + ((int.from_bytes(j0[12:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        ks = _aes_encrypt_block(key, counter)
        out += bytes(b ^ k for b, k in zip(block, ks))
        counter = counter[:12] + ((int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")
    return out, h, j0


def _gcm_encrypt(key, iv, aad, pt):
    ct, h, j0 = _gcm_crypt(key, iv, pt)
    aad_pad = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    ct_pad = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    s = _gcm_ghash(h, aad_pad + ct_pad + (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big"))
    tag = int.to_bytes((int.from_bytes(_aes_encrypt_block(key, j0), "big") ^ s), 16, "big")
    return ct, tag


def _gcm_decrypt(key, iv, aad, ct, tag):
    pt, h, j0 = _gcm_crypt(key, iv, ct)
    aad_pad = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    ct_pad = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    s = _gcm_ghash(h, aad_pad + ct_pad + (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big"))
    calc = int.to_bytes((int.from_bytes(_aes_encrypt_block(key, j0), "big") ^ s), 16, "big")
    if not hmac.compare_digest(calc, tag):
        return None
    return pt


def _chacha20_block(key, counter, nonce):
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    for i in range(0, 32, 4):
        state.append(int.from_bytes(key[i:i + 4], "little"))
    state.append(counter & 0xFFFFFFFF)
    for i in range(0, 12, 4):
        state.append(int.from_bytes(nonce[i:i + 4], "little"))
    working = state[:]

    def qr(a, b, c, d):
        working[a] = (working[a] + working[b]) & 0xFFFFFFFF
        working[d] ^= working[a]
        working[d] = ((working[d] << 16) | (working[d] >> 16)) & 0xFFFFFFFF
        working[c] = (working[c] + working[d]) & 0xFFFFFFFF
        working[b] ^= working[c]
        working[b] = ((working[b] << 12) | (working[b] >> 20)) & 0xFFFFFFFF
        working[a] = (working[a] + working[b]) & 0xFFFFFFFF
        working[d] ^= working[a]
        working[d] = ((working[d] << 8) | (working[d] >> 24)) & 0xFFFFFFFF
        working[c] = (working[c] + working[d]) & 0xFFFFFFFF
        working[b] ^= working[c]
        working[b] = ((working[b] << 7) | (working[b] >> 25)) & 0xFFFFFFFF

    for _ in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)

    out = b""
    for i in range(16):
        out += ((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
    return out


def _chacha20_xor(key, nonce, data, counter=0):
    out = b""
    block_idx = counter
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, block_idx, nonce)
        block_idx += 1
        out += bytes(b ^ k for b, k in zip(data[i:i + 64], ks))
    return out


def _poly1305(key, data):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(data), 16):
        n = int.from_bytes(data[i:i + 16] + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _chacha20_poly1305_encrypt(key, nonce, aad, pt):
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    ct = _chacha20_xor(key, nonce, pt, counter=1)
    aad_pad = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    ct_pad = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    mac = _poly1305(poly_key, aad_pad + ct_pad + (len(aad)).to_bytes(8, "little") + (len(ct)).to_bytes(8, "little"))
    return ct, mac


def _chacha20_poly1305_decrypt(key, nonce, aad, ct, tag):
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    aad_pad = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    ct_pad = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
    calc = _poly1305(poly_key, aad_pad + ct_pad + (len(aad)).to_bytes(8, "little") + (len(ct)).to_bytes(8, "little"))
    if not hmac.compare_digest(calc, tag):
        return None
    return _chacha20_xor(key, nonce, ct, counter=1)


def _evp_bytes_to_key(password, key_len):
    d = b""
    prev = b""
    while len(d) < key_len:
        prev = hashlib.md5(prev + password).digest()
        d += prev
    return d[:key_len]


def _hkdf_sha1(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha1).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha1).digest()
        okm += t
        i += 1
    return okm[:length]


# Proxy မှ dial လုပ်မည့် Test Targets (Cloudflare မဟုတ်သော — VPS/DC IP မှလည်း ရနိုင်)
RELAY_TARGETS = [
    ("httpforever.com", 80, b"GET / HTTP/1.1\r\nHost: httpforever.com\r\n\r\n", b"httpforever"),
    ("detectportal.firefox.com", 80, b"GET /success.txt HTTP/1.1\r\nHost: detectportal.firefox.com\r\n\r\n", b"success"),
]
TEST_TARGET_HOST = RELAY_TARGETS[0][0]
TEST_TARGET_PORT = RELAY_TARGETS[0][1]

# 🚫 မြန်မာနိုင်ငံတွင် အဆင်မပြေသော Cloudflare CDN IP များ (offical list)
CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]


def _is_cloudflare_ip(host):
    """host IP သည် Cloudflare CDN ပိုင်ဆိုင်ပါက True"""
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return False
    for r in CLOUDFLARE_RANGES:
        if ip in ipaddress.ip_network(r):
            return True
    return False


def _is_domain_fronted(node_info):
    """host IP နှင့် SNI/host_header domain ၏ resolve IP မတူပါက True
    (CDN/domain-fronting setup — မြန်မာနိုင်ငံတွင် အဆင်မပြေတတ်)"""
    host = node_info.get("host")
    sni = node_info.get("sni") or node_info.get("host_header")
    if not host or not sni:
        return False
    if sni == host:
        return False
    try:
        host_ip = socket.gethostbyname(host)
        sni_ip = socket.gethostbyname(sni)
    except Exception:
        return False
    return host_ip != sni_ip

TLS_PORTS = {443, 2096, 8443, 2053}

SS_AEAD_METHODS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}
SS_STREAM_METHODS = {"aes-128-cfb", "aes-192-cfb", "aes-256-cfb"}


# ---------------------------------------------------------------- socket helpers
def _connect_tcp(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, int(port)))
    return s


def _tls_wrap(sock, host, sni, timeout=3.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(sock, server_hostname=sni or host)
    t.settimeout(timeout)
    return t


def _read_exact(sock, n, timeout=4.0):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf += chunk
    return buf


def _recv_until(sock, marker=b"\r\n\r\n", maxlen=8192, timeout=4.0):
    sock.settimeout(timeout)
    data = b""
    while marker not in data and len(data) < maxlen:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _recv_some(sock, maxlen, timeout=4.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(maxlen)
    except socket.timeout:
        return b""

def _verify_relay(data, target_idx=0):
    """proxy မှ တကယ့် data relay ဖြစ်မဖြစ် target signature ဖြင့် စစ်ဆေးခြင်း
    (fallback/echo server များသည် ဤ content ကို ပြန်၍မရနိုင်ပါ)"""
    if not data:
        return False
    return RELAY_TARGETS[target_idx][3] in data


# ---------------------------------------------------------------- websocket helpers
def _ws_handshake(sock, host, path, timeout=4.0):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("utf-8")
    sock.sendall(req)
    resp = _recv_until(sock, b"\r\n\r\n", timeout=timeout)
    return resp.startswith(b"HTTP/1.1 101")


def _ws_send_frame(sock, payload):
    mask = os.urandom(4)
    hdr = bytearray([0x82])  # FIN + binary
    n = len(payload)
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126)
        hdr += struct.pack(">H", n)
    else:
        hdr.append(0x80 | 127)
        hdr += struct.pack(">Q", n)
    hdr += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(hdr) + masked)


def _ws_read_frame(sock, timeout=5.0):
    h = _read_exact(sock, 2, timeout)
    masked = h[1] & 0x80
    n = h[1] & 0x7F
    if n == 126:
        n = struct.unpack(">H", _read_exact(sock, 2, timeout))[0]
    elif n == 127:
        n = struct.unpack(">Q", _read_exact(sock, 8, timeout))[0]
    if n > 65536:
        return None
    mask = _read_exact(sock, 4, timeout) if masked else None
    payload = _read_exact(sock, n, timeout) if n else b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return payload


# ---------------------------------------------------------------- vless / trojan / vmess
def _addr_only(host, domain_type):
    """atyp + address bytes (without port)."""
    try:
        return b"\x01" + socket.inet_aton(host)
    except OSError:
        hb = host.encode("utf-8")
        if len(hb) > 255:
            raise ValueError("host too long")
        return bytes([domain_type]) + bytes([len(hb)]) + hb


def _socks_addr(host, port):
    """Shadowsocks-style: 0x01 IPv4, 0x03 domain, 0x04 IPv6 (+port)."""
    return _addr_only(host, 0x03) + struct.pack(">H", port)


def _vless_header(uuid, host, port):
    """VLESS request: version(0) uuid addons(0) cmd(1) PORT(2B) + addr (0x02=domain)."""
    uid = uuid.replace("-", "")
    if len(uid) != 32:
        raise ValueError("bad uuid")
    return bytes([0]) + bytes.fromhex(uid) + bytes([0, 1]) + struct.pack(">H", port) + _addr_only(host, 0x02)


def _trojan_request(password, host, port):
    """Xray/trojan-go format: hex(SHA224(pwd)) CRLF cmd(1) addr CRLF (0x03=domain)."""
    pwd_hex = hashlib.sha224(password.encode("utf-8")).hexdigest().encode("ascii")
    return pwd_hex + b"\r\n" + bytes([1]) + _socks_addr(host, port) + b"\r\n"


def _check_vless(sock, info, framed, target_idx=0):
    uuid = info.get("uuid")
    if not uuid:
        return False
    th, tp, treq, _sig = RELAY_TARGETS[target_idx]
    try:
        # header + a real HTTP GET so the server relays a real target response
        # (xray only flushes its 0x00 response header once data flows)
        req = _vless_header(uuid, th, tp) + treq
    except Exception:
        return False
    try:
        if framed:
            _ws_send_frame(sock, req)
            deadline = time.time() + 7.0
            while time.time() < deadline:
                resp = _ws_read_frame(sock, timeout=min(7.0, deadline - time.time()))
                if resp is None:
                    return False
                if len(resp) > 0 and resp[0] == 0:
                    return True
            return False
        sock.sendall(req)
        resp = _recv_some(sock, 4096, timeout=7.0)
        return len(resp) > 0 and resp[0] == 0
    except Exception:
        return False


def _check_trojan(sock, info, framed, target_idx=0):
    password = info.get("password")
    if not password:
        return False
    th, tp, treq, _sig = RELAY_TARGETS[target_idx]
    # header + a real HTTP GET so the proxy relays a real target response
    req = _trojan_request(password, th, tp) + treq
    try:
        if framed:
            _ws_send_frame(sock, req)
            deadline = time.time() + 8.0
            data = b""
            while time.time() < deadline:
                resp = _ws_read_frame(sock, timeout=min(8.0, deadline - time.time()))
                if resp is None:
                    return False
                data += resp
                if _verify_relay(data, target_idx):
                    return True
                if len(data) > 16384:
                    break
            return False
        sock.sendall(req)
        data = _recv_until(sock, b"\r\n\r\n", maxlen=8192, timeout=8.0)
        if not (data.startswith(b"HTTP/1.1 2") or data.startswith(b"HTTP/1.1 3")):
            return False
        while _sig not in data and len(data) < 16384:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except Exception:
                break
        return _verify_relay(data, target_idx)
    except Exception:
        return False


def _check_vmess(sock, info, framed):
    if framed:
        # 101 upgrade already proves the ws proxy endpoint exists
        return True
    # tcp/raw: a real vmess server closes on garbage; a website replies HTTP
    try:
        sock.sendall(os.urandom(64))
        resp = _recv_some(sock, 512, timeout=2.5)
    except Exception:
        return False
    if not resp:
        return True
    return not resp.startswith(b"HTTP/")


# ---------------------------------------------------------------- shadowsocks
def _b64_maybe(pwd):
    """If the password looks like base64, return the decoded bytes too."""
    try:
        dec = base64.b64decode(pwd, validate=True)
        if dec and pwd.replace("=", "") and base64.b64encode(dec).decode().rstrip("=") == pwd.rstrip("="):
            return dec
    except Exception:
        pass
    return None


def _ss_keys(method, password):
    key_len = 16 if method == "aes-128-gcm" else 32
    keys = [_evp_bytes_to_key(password.encode("utf-8"), key_len)]
    dec = _b64_maybe(password)
    if dec is not None:
        alt = _evp_bytes_to_key(dec, key_len)
        if alt != keys[0]:
            keys.append(alt)
    return keys


def _ss_nonce(counter):
    return counter.to_bytes(4, "little") + b"\x00" * 8


def _ss_aead_encrypt(method, key, salt, aad, data, counter):
    subkey = _hkdf_sha1(key, salt, b"ss-subkey", len(key))
    nonce = _ss_nonce(counter)
    if method == "chacha20-ietf-poly1305":
        return _chacha20_poly1305_encrypt(subkey, nonce, aad, data)
    return _gcm_encrypt(subkey, nonce, aad, data)


def _ss_aead_decrypt(method, key, salt, aad, ct, tag, counter):
    subkey = _hkdf_sha1(key, salt, b"ss-subkey", len(key))
    nonce = _ss_nonce(counter)
    if method == "chacha20-ietf-poly1305":
        return _chacha20_poly1305_decrypt(subkey, nonce, aad, ct, tag)
    return _gcm_decrypt(subkey, nonce, aad, ct, tag)


def _ss_aead_try(method, key, host, port):
    key_len = len(key)
    salt_len = 16 if method == "aes-128-gcm" else 32
    sock = _connect_tcp(host, port)
    try:
        client_salt = os.urandom(salt_len)
        payload = _socks_addr(TEST_TARGET_HOST, TEST_TARGET_PORT) + (
            f"GET / HTTP/1.1\r\nHost: {TEST_TARGET_HOST}\r\n\r\n"
        ).encode("ascii")
        ct1, tag1 = _ss_aead_encrypt(method, key, client_salt, b"", struct.pack(">H", len(payload)), 0)
        ct2, tag2 = _ss_aead_encrypt(method, key, client_salt, b"", payload, 1)
        sock.sendall(client_salt + ct1 + tag1 + ct2 + tag2)

        server_salt = _read_exact(sock, salt_len, 8.0)
        ln_ct = _read_exact(sock, 18, 8.0)
        ln_pt = _ss_aead_decrypt(method, key, server_salt, b"", ln_ct[:2], ln_ct[2:], 0)
        if ln_pt is None:
            return False
        length = struct.unpack(">H", ln_pt)[0]
        if not (0 < length <= 0x3FFF):
            return False
        body = _read_exact(sock, length + 16, 8.0)
        pt = _ss_aead_decrypt(method, key, server_salt, b"", body[:length], body[length:], 1)
        if pt is None:
            return False
        return b"HTTP" in pt[:4096]
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _ss_stream_try(method, key, host, port):
    iv = os.urandom(16)
    payload = _socks_addr(TEST_TARGET_HOST, TEST_TARGET_PORT) + (
        f"GET / HTTP/1.1\r\nHost: {TEST_TARGET_HOST}\r\n\r\n"
    ).encode("ascii")
    sock = _connect_tcp(host, port)
    try:
        sock.sendall(iv + _aes_cfb_encrypt(key, iv, payload))
        server_iv = _read_exact(sock, 16, 8.0)
        data = b""
        sock.settimeout(8.0)
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in _aes_cfb_decrypt(key, server_iv, data[:2048]):
                break
        if len(data) < 32:
            return False
        pt = _aes_cfb_decrypt(key, server_iv, data[:2048])
        return b"HTTP" in pt
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def test_ss(node_info):
    method = (node_info.get("method") or "").lower()
    password = node_info.get("password")
    host = node_info["host"]
    port = int(node_info["port"])
    if not password or not host:
        return False

    if method in SS_AEAD_METHODS:
        for key in _ss_keys(method, password):
            if _ss_aead_try(method, key, host, port):
                return True
        return False
    if method in SS_STREAM_METHODS:
        key_len = {"aes-128-cfb": 16, "aes-192-cfb": 24, "aes-256-cfb": 32}[method]
        for key in [_evp_bytes_to_key(password.encode("utf-8"), key_len)]:
            dec = _b64_maybe(password)
            candidates = [key]
            if dec is not None:
                alt = _evp_bytes_to_key(dec, key_len)
                if alt != key:
                    candidates.append(alt)
            for k in candidates:
                if _ss_stream_try(method, k, host, port):
                    return True
        return False
    # 2022 / unknown methods: lenient TCP check (old behavior)
    try:
        _connect_tcp(host, port).close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- lenient fallbacks
def _test_reality(host, port, sni):
    """REALITY cannot be protocol-tested without x25519 auth; check TLS + real response."""
    try:
        sock = _connect_tcp(host, port)
        try:
            t = _tls_wrap(sock, host, sni or host)
            t.sendall(
                (f"GET / HTTP/1.1\r\nHost: {sni or host}\r\n"
                 "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").encode("utf-8")
            )
            resp = _recv_some(t, 128, timeout=4.0)
            return len(resp) > 0
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except Exception:
        return False


def _test_grpc(host, port, sni):
    """gRPC is HTTP/2: send the h2 preface and expect a SETTINGS frame."""
    try:
        sock = _connect_tcp(host, port)
        try:
            t = _tls_wrap(sock, host, sni or host)
            t.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            resp = _recv_some(t, 24, timeout=4.0)
            if len(resp) < 9:
                return False
            if resp[0] == 0x00 and resp[3] == 0x04:
                return True
            return not resp.startswith(b"HTTP/1.1")
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except Exception:
        return False


def _test_tcp_only(host, port):
    try:
        _connect_tcp(host, port).close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- main dispatcher
def strict_myanmar_real_ping(node_info, target_idx=0):
    """🎯 အစစ်အမှန် Proxy Protocol စစ်ဆေးခြင်း (TCP/TLS ping သက်သက်မဟုတ်)
    Target တစ်ခုနှင့် မရလျှင် နောက် target တစ်ခုဖြင့် ပြန်စမ်းသည်"""
    try:
        port = int(node_info["port"])
        if port not in ALLOWED_PORTS:
            return False
        sni = node_info.get("sni")
        if sni and any(b in sni.lower() for b in BLOCKED_SNIS):
            return False
        host = node_info.get("host")
        if not host:
            return False
        if _is_cloudflare_ip(host):
            return False
        if _is_domain_fronted(node_info):
            return False

        ntype = node_info.get("type")

        if ntype == "ss":
            return test_ss(node_info)

        if ntype in ("hysteria2", "hy2", "tuic"):
            return _test_tcp_only(host, port)

        network = (node_info.get("network") or "tcp").lower()
        security = (node_info.get("security") or "none").lower()

        if security == "reality":
            return _test_reality(host, port, sni)
        if network == "grpc":
            return _test_grpc(host, port, sni)

        sock = _connect_tcp(host, port)
        try:
            use_tls = port in TLS_PORTS or security == "tls"
            if use_tls:
                sock = _tls_wrap(sock, host, sni or host)

            if network in ("ws", "http"):
                hdr_host = node_info.get("host_header") or sni or host
                path = node_info.get("path") or "/"
                if not path.startswith("/"):
                    path = "/" + path
                if not _ws_handshake(sock, hdr_host, path):
                    return False
                if ntype == "vmess":
                    return True
                framed = network == "ws"
                if ntype == "vless":
                    return _check_vless(sock, node_info, framed, target_idx)
                if ntype == "trojan":
                    return _check_trojan(sock, node_info, framed, target_idx)
                return True

            if ntype == "vless":
                return _check_vless(sock, node_info, False, target_idx)
            if ntype == "trojan":
                return _check_trojan(sock, node_info, False, target_idx)
            if ntype == "vmess":
                return _check_vmess(sock, node_info, False)
            return True
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except Exception:
        if target_idx + 1 < len(RELAY_TARGETS):
            return strict_myanmar_real_ping(node_info, target_idx + 1)
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
                "sni": decoded.get("sni") or decoded.get("host") or None,
                "host_header": decoded.get("host") or None,
                "path": decoded.get("path", "/"),
                "network": decoded.get("net") or "tcp",
                "security": decoded.get("tls") or "none",
                "raw": line
            }
        elif line.startswith(("vless://", "trojan://")):
            parsed = urllib.parse.urlparse(line)
            query_params = urllib.parse.parse_qs(parsed.query)
            user = urllib.parse.unquote(parsed.username or "")
            network = (query_params.get("type", ["tcp"])[0] or "tcp").lower()
            if network == "tcp" and query_params.get("ws", ["0"])[0] in ("1", "true"):
                network = "ws"
            path = query_params.get("path", [None])[0] or query_params.get("wspath", [None])[0] or "/"
            host_header = query_params.get("host", [None])[0]
            sni = query_params.get("sni", [None])[0] or host_header
            return {
                "type": "vless" if line.startswith("vless://") else "trojan",
                "uuid": user,
                "password": user,
                "host": parsed.hostname,
                "port": parsed.port or 443,
                "sni": sni,
                "host_header": host_header,
                "path": path,
                "network": network,
                "security": query_params.get("security", ["none"])[0] or "none",
                "raw": line
            }
        elif line.startswith("ss://"):
            base_url = line.split("#")[0]
            parsed = urllib.parse.urlparse(base_url)
            raw_ss = base_url.replace("ss://", "")
            if "@" in raw_ss:
                user_info, host_port = raw_ss.split("@", 1)
            else:
                user_info, host_port = base64.b64decode(raw_ss + "===").decode("utf-8").split("@", 1)
            method, password = "unknown", ""
            try:
                dec = base64.b64decode(user_info + "===").decode("utf-8")
                method, password = dec.split(":", 1)
            except Exception:
                try:
                    method, password = urllib.parse.unquote(user_info).split(":", 1)
                except Exception:
                    pass
            host = parsed.hostname
            port = parsed.port
            if not host or not port:
                h, p = host_port.split(":", 1)
                host, port = h, int(p)
            return {
                "type": "ss",
                "method": method,
                "password": urllib.parse.unquote(password),
                "host": host,
                "port": int(port),
                "sni": None,
                "path": "/",
                "raw": line
            }
        elif line.startswith(("hysteria2://", "hy2://", "tuic://")):
            parsed = urllib.parse.urlparse(line)
            return {
                "type": "hysteria2" if line.startswith(("hysteria2://", "hy2://")) else "tuic",
                "host": parsed.hostname,
                "port": int(parsed.port or 443),
                "sni": None,
                "path": "/",
                "raw": line
            }
    except Exception:
        return None
    return None


def test_node(node_info):
    host = node_info.get("host")
    port = node_info.get("port")

    if host and port and strict_myanmar_real_ping(node_info):
        return node_info
    return None


def fetch_and_process_country(country_code, configs):
    """နိုင်ငံတစ်ခုအတွက် Source အများအပြား (အဓိက → အရန်) မှ Node များ စုစည်းခြင်း
    - [0] အဓိက Source မှ အရင်ယူ → မပြည့်လျှင် [1] အရန် Source မှ ဖြည့်
    - တူညီသော Server (host:port) ထပ်နေလျှင် ၁ ခုသာ ထည့်"""
    all_wifi = []
    all_sim = []
    seen = set()

    for config in configs:
        url = config["url"]
        flag = config["flag"]
        name_filter = config.get("name_filter")  # ဥပမာ "🇺🇸" — node name အလိုက် စစ်ထုတ်

        try:
            # 🌐 Freedom Mixed List ကဲ့သို့ URL တစ်ခုတည်းကို ထပ်ခါထပ်ခါ မဆွဲရန် Cache
            if url in _URL_CACHE:
                lines = _URL_CACHE[url]
            else:
                res = requests.get(url, timeout=10)
                content = res.text.strip()
                try:
                    lines = base64.b64decode(content).decode("utf-8").splitlines()
                except Exception:
                    lines = content.splitlines()
                _URL_CACHE[url] = lines

            nodes_to_test = []
            for line in lines:
                line = line.strip()
                if not line or not any(line.startswith(p) for p in SUPPORTED_PROTOCOLS):
                    continue
                if name_filter:
                    # Node အမည်ထဲမှ flag (ဥပမာ 🇺🇸) ပါမှသာ ထည့်မည်
                    raw_name = line.split("#", 1)[1] if "#" in line else ""
                    try:
                        raw_name = urllib.parse.unquote(raw_name)
                    except Exception:
                        pass
                    if name_filter not in raw_name:
                        continue
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

            # 🔁 တူညီသော Server (host:port) ထပ်နေလျှင် ဖယ်ထုတ်ခြင်း
            for n in wifi_nodes + sim_priority_nodes + sim_normal_nodes:
                key = (n.get("host"), n.get("port"))
                if key in seen:
                    continue
                seen.add(key)
                if n["port"] == 443:
                    all_wifi.append(n)
                else:
                    all_sim.append(n)

        except Exception as e:
            print(f"Error ({country_code} / {url}): {e}")

    # Wifi 10 ခု (SG 1-10) + Sim 10 ခု (SG 11-20) — မပြည့်လျှင် ရှိသလောက်
    combined = all_wifi[:WIFI_SLOTS] + all_sim[:SIM_SLOTS]

    # 🎯 20 ခု မပြည့်လျှင် (Sim port node ရှားပါးလျှင်) Wifi node များဖြင့် ဖြည့်ပါ
    if len(combined) < WIFI_SLOTS + SIM_SLOTS:
        remaining = WIFI_SLOTS + SIM_SLOTS - len(combined)
        combined += all_wifi[WIFI_SLOTS: WIFI_SLOTS + remaining]

    flag = configs[0]["flag"]
    formatted = []
    count = 1
    for item in combined:
        raw = item["raw"]

        # Node အမည် — နိုင်ငံအလိုက် ရိုးရိုးရှင်းရှင်း (ဥပမာ 🇸🇬 SG 1)
        clean_name = f"{flag} {country_code} {count}"

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


_URL_CACHE = {}


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
