import base64
from hashlib import sha1
import hmac
import sys
sys.path.append(".")
from utils.xEncode import force, xencode


import json
from random import Random
import socket
import time
from typing import Dict
from urllib.parse import parse_qs, parse_qsl, urlparse
import requests
url0 = "http://10.115.9.1/"
url1 = "http://10.115.9.1/cgi-bin/rad_user_info"
url2 = "http://10.115.9.1/cgi-bin/get_challenge"
url3 = "http://10.115.9.1/cgi-bin/srun_portal"






url = "http://10.115.9.1/srun_portal_pc?ac_id=2&theme=basic"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"
# response = requests.get(url2, params=params, headers={"User-Agent":UA})
def get_acid(url:str, state:Dict):
    response = requests.get(url, headers={"User-Agent":UA})
    url_parsed = urlparse(response.url)
    acid = parse_qs(url_parsed.query).get("ac_id",[])
    acid.append(0)
    state["ac_id"] = acid[0]
    return acid[0]

def get_state(url:str, state:Dict):
    state['clock'] = int(time.time() * 1000)
    state["callback"] = "jQuery1124" + str(Random().random()).replace('.','') + "_" + str(state["clock"])
    state["clock"] = state["clock"] + 1
    params = {}
    params["callback"] = state["callback"]
    params["_"] = state["clock"]
    response = requests.get(url, params=params)
    content = json.loads(response.content[len(state["callback"]) + 1:-1])
    state["error"] = content["error"]
    state["res"] = content["res"]
    state["st"] = content["st"]
    state["client_ip"] = content["client_ip"]
    state["clock"] = state["clock"] + 1
    

def get_challenge(url:str, state:Dict):
    params = {"callback":state["callback"], "username":state["username"], "_":state['clock']}
    response = requests.get(url, params=params, headers={"User-Agent":UA})
    content = json.loads(response.content[len(state["callback"]) + 1:-1])
    state["challenge"] = content["challenge"]
    state["error"] = content["error"]
    state["client_ip"] = content["client_ip"]
    state["online_ip"] = content["online_ip"]
    # state["ac_id"] = content["ac_id"]
    state["clock"] = state["clock"] + 1

def get_info(state:Dict):
    username = state["username"]
    password = state["password"]
    ip = state["client_ip"]
    ac_id = state["ac_id"]
    token = state["challenge"]
    alpha1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    alpha2 = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA="
    trans = {}
    for a1,a2 in zip(alpha1, alpha2):
        trans[a1] = a2
    d = "{" + f'"username":"{username}","password":"{password}","ip":"{ip}","acid":"{ac_id}","enc_ver":"srun_bx1"' + "}"
    info = base64.b64encode(force(xencode(d, token))).decode()
    info = "".join(list(map(lambda item:trans[item], info)))
    info = "{SRBX1}" + info
    state["info"] = info
    return info

def get_password(state:Dict):
    password = state["password"]
    key = state["challenge"]
    hmd5 = hmac.new(key=key.encode("utf-8"), msg=password.encode("utf-8")).hexdigest()
    hmd5 = "{MD5}" + hmd5
    state["hmd5"] = hmd5
    return hmd5

def get_checksum(state:Dict):
    token = str(state["challenge"])
    username = str(state["username"])
    hmd5 = str(state["hmd5"])[5:]
    ac_id = str(state["ac_id"])
    ip = str(state["client_ip"])
    n = str(state["n"])
    type = str(state["type"])
    i = str(state["info"])
    checksum = token + username
    checksum = checksum + token + hmd5
    checksum = checksum + token + ac_id
    checksum = checksum + token + ip
    checksum = checksum + token + n
    checksum = checksum + token + type
    checksum = checksum + token + i
    checksum = sha1(checksum.encode("utf-8")).hexdigest()
    state["checksum"] = checksum
    return checksum


def try_login(url:str, state:Dict):
    get_password(state)
    get_info(state)
    get_checksum(state)
    params = {}
    params["callback"] = state["callback"]
    params["action"] = "login"
    params["username"] = state["username"]
    params["password"] = state["hmd5"]
    params["ac_id"] = state["ac_id"]
    params["ip"] = state["client_ip"]
    params["chksum"] = state["checksum"]
    params["info"] = state["info"]
    params["n"] = state["n"]
    params["type"] = state["type"]
    params["os"] = state["os"]
    params["name"] = state["name"]
    params["double_stack"] = state["double_stack"]
    params["_"] = state["clock"]
    response = requests.get(url, params=params)
    state["clock"] = state["clock"] + 1
    print(response.url)
    print(response.status_code)
    print(response.content)


def main():
    state = {
    "username":123,
    "password":"ZJU",
    "n":200,
    "type":1,
    "os":"Windows 95",
    "name":"Windows",
    "double_stack":0
    }
    get_acid(url0, state)
    get_state(url1, state)
    get_challenge(url2, state)
    try_login(url3, state)

if __name__ == "__main__":
    main()
