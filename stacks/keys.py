from ecdsa import SECP256k1, SigningKey

def generate_signing_and_verify_key():
    signaing_key = SigningKey.generate(SECP256k1)
    return (signaing_key.to_string(), signaing_key.verifying_key.to_string())