from ecdsa import SECP256k1, SigningKey, VerifyingKey
from hashlib import sha256 as hashlib_sha256
from .hashing import ripemd160, sha256
from ecdsa.util import sigencode_der, sigdecode_der


def generate_signing_and_verify_key():
    signing_key = SigningKey.generate(SECP256k1, hashfunc=hashlib_sha256)
    return (signing_key.to_string(), signing_key.verifying_key.to_string())


def get_verifying_key(private_key):
    signing_key = SigningKey.from_string(
        private_key, curve=SECP256k1, hashfunc=hashlib_sha256
    )
    return signing_key.verifying_key.to_string()


def sign(message, private_key):
    signing_key = SigningKey.from_string(
        private_key, curve=SECP256k1, hashfunc=hashlib_sha256
    )
    return signing_key.sign_digest_deterministic(message, hashfunc=hashlib_sha256)


def sign_der(message, private_key):
    signing_key = SigningKey.from_string(
        private_key, curve=SECP256k1, hashfunc=hashlib_sha256
    )
    der = signing_key.sign_digest_deterministic(
        message, hashfunc=hashlib_sha256, sigencode=sigencode_der
    )
    r, s = sigdecode_der(der, SECP256k1.order)
    if s > SECP256k1.order // 2:
        s = SECP256k1.order - s
    return sigencode_der(r, s, SECP256k1.order)


def verify(message, signature, public_key):
    verifying_key = VerifyingKey.from_string(
        public_key, curve=SECP256k1, hashfunc=hashlib_sha256
    )
    return verifying_key.verify(signature, message, hashlib_sha256)


def verify_der(message, signature, public_key):
    verifying_key = VerifyingKey.from_string(
        public_key, curve=SECP256k1, hashfunc=hashlib_sha256
    )
    return verifying_key.verify_digest(signature, message, sigdecode=sigdecode_der)


def compress_public_key(key):
    x = key[:32]
    y = key[32:]
    if y[-1] % 2 == 0:
        base = b"\02"
    else:
        base = b"\03"
    return base + x


def public_key_hash(public_key):
    return ripemd160(sha256(compress_public_key(public_key)).digest()).digest()
