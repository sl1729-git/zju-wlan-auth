
import base64
from email import base64mime
from email.mime import base
import json
import math
import hmac

key = "32e0821d9b0d1e7600a2117a38b674a2805eb5cedaf0573029fdee25101eaaf1"
password = "ZJU"
ac_id = 2
ip = "10.116.93.41"
n = 200
type = 1
username = ""
enc = ""
# username: username,
                    # password: data.password,
                    # ip: (data.ip || response.client_ip),
                    # acid: data.ac_id,
                    # enc_ver: enc
# {"username":"","password":"ZJU","ip":"10.116.93.41","acid":"2","enc_ver":"srun_bx1"}
d = "{" + f'"username":"{username}","password":"{password}","ip":"{ip}","acid":"{ac_id}","enc_ver":"srun_bx1"' + "}"
tmp = '{"username":"","password":"ZJU","ip":"10.116.93.41","acid":"2","enc_ver":"srun_bx1"}'
print(d == tmp)
def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)
 
 
def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0

def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd
 
 
def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)

def xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)

enc_res = hmac.new(key=key.encode("utf-8"), msg=password.encode("utf-8"))
print(enc_res.hexdigest())

ans = 'pgpUTMQEsH7G0TPH69rQBlCA1W+pGV4TbpXexVa/SZtASym8yJ8t7au3/r1hP0xrV3F+tvCYUolj9NPRzM2a+eML0qPrrj+tChIqWwt5D1PErcEHOHcATOIFafQ73w7u'
my_ans = base64.b64encode(force(xencode(tmp, key)))

mid_ans = force("ùfÏ»}MË6\u0011\u0014ÄÇ¾ê±¿e´%,\u001f!²X¹È\u0015¨?ä82´Ýei¡æQ\u0010Ü\u0006ÐÓ\u0001¤*õ0q\tÍÂ\u0016C\u00006q\u001e{T4\u0019\u001d§ný=á;y~ÔiEÿ­Zß·¦ýÕ")
print(f"mid ans is same ? {mid_ans == force(xencode(tmp, key))}")
print(ans == my_ans)
print(f"ans len:{len(ans)} my_ans len:{len(my_ans)}\n{ans}\n{my_ans}")
alpha1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
alpha2 = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
trans = {}
for a1,a2 in zip(alpha1, alpha2):
    trans[a1] = a2

trans_ans = "".join(list(map(lambda item:trans[item], my_ans.decode())))
print(trans_ans)