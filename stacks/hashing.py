import hashlib


def sha512_256(data):
    sha512_256 = hashlib.new("sha512_256")
    sha512_256.update(data)
    return sha512_256
