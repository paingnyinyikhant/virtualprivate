import base64
from concurrent.futures import ThreadPoolExecutor
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
