import base64
import hashlib
from ecdsa import SigningKey, VerifyingKey
from hashlib import sha256
from ecdsa.util import sigencode_der, sigdecode_der

def test_verify(pubkey, message, signed_msg):
    vk = VerifyingKey.from_pem(pubkey, hashlib.sha256)
    signature = base64.b64decode(signed_msg)
    verified = vk.verify(signature, message.encode(), sha256, sigdecode=sigdecode_der)
    return verified

def test_sign(privkey, message):
    sk = SigningKey.from_pem(privkey, hashlib.sha256)
    signature = sk.sign_deterministic(
        message.encode(),
        hashfunc=sha256,
        sigencode=sigencode_der
    )
    encoded_sig = base64.b64encode(signature).decode("ascii")
    return encoded_sig


if __name__ == "__main__":
    pubkey = "-----BEGIN PUBLIC KEY-----\nME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE5puDej67SK0akoj0E3ocGplYObQcx/ii\nQQ5yMe6l3ogZWNm3bCbvEZ+kCUBJoeSi3SV7IFFiX4E=\n-----END PUBLIC KEY-----"
    privkey = "-----BEGIN PRIVATE KEY-----\nMGgCAQEEHFZohAYiPIo97TdVQTGKPyghByr+3bfhX2ryOmqgBwYFK4EEACGhPAM6\nAATmm4N6PrtIrRqSiPQTehwamVg5tBzH+KJBDnIx7qXeiBlY2bdsJu8Rn6QJQEmh\n5KLdJXsgUWJfgQ==\n-----END PRIVATE KEY-----"
    message = "Hello, world"
    s_m = test_sign(privkey, message)
    print("Signed base64: ", s_m)
    
    # Generated in Golang
    signed_message = "MD0CHQDMnLpDfApV5EFQMkIonwHZlUHdCUExY5VTM3UMAhwVChVNMO0Nin/fXYe/XazCzrgIzDg1OFjRiEb0"
    verified = test_verify(pubkey, message, signed_message)
    print("Verified: ", verified)
