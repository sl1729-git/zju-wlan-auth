


import requests

headers = {"User-Agent":"testestee"}
data = {"test1":"test1"}
res = requests.get("http://httpbin.org/get", headers=headers, json=data)
print(res.content.decode("utf-8"))