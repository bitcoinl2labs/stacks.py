import hashlib
from ecdsa import SigningKey
from ecdsa.curves import NIST256p

def sha512_256(data):
    _sha512_256 = hashlib.new("sha512_256")
    _sha512_256.update(data)
    return _sha512_256

def sha256(data):
    _sha256 = hashlib.new("sha256")
    _sha256.update(data)
    return _sha256

def ripemd160(data):
    _ripemd160 = hashlib.new("ripemd160")
    _ripemd160.update(data)
    return _ripemd160