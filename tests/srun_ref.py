# -*- coding: utf-8 -*-
"""srun3000 登录加密的 Python 参考实现（业界广泛使用的版本）。
用于交叉验证 BUAA-AutoLogin.ps1 中 PowerShell 实现的正确性。
输出与 `BUAA-AutoLogin.ps1 -SelfTest` 完全相同格式的四行结果。"""
import base64
import hashlib
import hmac
import json

TOKEN = '0123456789abcdef0123456789abcdef'
USERNAME = 'test_user'
PASSWORD = 'P@ss w0rd!'
IP = '10.20.30.40'
ACID = '78'


def s_(a, append_len):
    """等价于 srun js 的 s()：每 4 个字符打包为一个 uint32（小端），不足补 0。"""
    orig = len(a)
    pad = (4 - orig % 4) % 4
    a = a + '\x00' * pad
    v = [ord(a[i]) | (ord(a[i + 1]) << 8) | (ord(a[i + 2]) << 16) | (ord(a[i + 3]) << 24)
         for i in range(0, len(a), 4)]
    if append_len:
        v.append(orig)
    return v


def xencode_bytes(msg, key):
    """等价于 srun js 的 xencode()，直接返回原始字节。"""
    if msg == '':
        return b''
    v = s_(msg, True)
    k = s_(key, False)
    while len(k) < 4:
        k.append(0)
    n = len(v) - 1
    z = v[n]
    c = 0x86014019 | 0x183639A0
    q = 6 + 52 // (n + 1)
    d = 0
    while q > 0:
        q -= 1
        d = (d + c) & 0xFFFFFFFF
        e = (d >> 2) & 3
        p = 0
        while p < n:
            y = v[p + 1]
            m = (z >> 5) ^ ((y << 2) & 0xFFFFFFFF)
            m = (m + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)) ^ (d ^ y))) & 0xFFFFFFFF
            m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF
            v[p] = (v[p] + m) & 0xFFFFFFFF
            z = v[p]
            p += 1
        y = v[0]
        m = (z >> 5) ^ ((y << 2) & 0xFFFFFFFF)
        m = (m + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)) ^ (d ^ y))) & 0xFFFFFFFF
        m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF
        v[n] = (v[n] + m) & 0xFFFFFFFF
        z = v[n]
    out = b''
    for x in v:
        out += bytes([x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF])
    return out


ALPHA = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
TRANS = {STD[i]: ALPHA[i] for i in range(64)}


def srun_b64(b):
    """标准 base64 后按 srun 自定义字母表替换字符。"""
    return ''.join(TRANS.get(c, c) for c in base64.b64encode(b).decode())


info = {"username": USERNAME, "password": PASSWORD, "ip": IP,
        "acid": ACID, "enc_ver": "srun_bx1"}
info_json = json.dumps(info, separators=(',', ':'), ensure_ascii=True)

x = xencode_bytes(info_json, TOKEN)
info_param = '{SRBX1}' + srun_b64(x)  # 官方 Portal.js：chksum 用的是完整 info 字符串

hm = hmac.new(TOKEN.encode(), PASSWORD.encode(), hashlib.md5).hexdigest()
ck = (TOKEN + USERNAME + TOKEN + hm + TOKEN + ACID + TOKEN + IP
      + TOKEN + '200' + TOKEN + '1' + TOKEN + info_param)

print('hmac=' + hm)
print('chksum=' + hashlib.sha1(ck.encode('utf-8')).hexdigest())
print('info_b64=' + srun_b64(x))
print('info_json=' + info_json)
