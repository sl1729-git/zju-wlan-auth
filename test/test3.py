

from hashlib import sha1


print(sha1("123".encode("utf-8")).hexdigest())