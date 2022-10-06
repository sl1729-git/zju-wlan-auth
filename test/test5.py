import json
from urllib import request
import urllib.parse as parse
url = "http://httpbin.org/post"
query = {"en":"english", "cn":"中文","empty":"","other":",.<>/?{}[]"}
headers = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
    "Accept-Language":"zh,zh-CN;q=0.9",
    "X-Requested-With":"XMLHttpRequest",
    "Content-Type":"application/json"
    }
data = json.dumps({"test1":"test1"}).encode("utf-8")
query = parse.urlencode(query)
req = request.Request(url= url + "?" +query, data=data, headers=headers, method="POST")
with request.urlopen(req) as f:
    print(f.read().decode("utf-8"))

