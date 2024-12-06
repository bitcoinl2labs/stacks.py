from ecdsa import SECP256k1, SigningKey, VerifyingKey
from hashlib import sha256


def generate_signing_and_verify_key():
    signing_key = SigningKey.generate(SECP256k1, hashfunc=sha256)
    return (signing_key.to_string(), signing_key.verifying_key.to_string())


def get_verifying_key(private_key):
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1, hashfunc=sha256)
    return signing_key.verifying_key.to_string()


def sign(message, private_key):
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1, hashfunc=sha256)
    return signing_key.sign_deterministic(message, hashfunc=sha256)


def verify(message, signature, public_key):
    verifying_key = VerifyingKey.from_string(
        public_key, curve=SECP256k1, hashfunc=sha256
    )
    return verifying_key.verify(signature, message, sha256)
