import base64
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize the private key and store it in memory
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Serialize the public key and store it in memory
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def encode_jwt(payload: dict[str, Any]) -> str:
    return jwt.encode(payload, private_pem, algorithm="RS256")


def decode_jwt(token: str) -> dict[str, Any]:
    return jwt.decode(token, public_pem, algorithms=["RS256"])


def encrypt_pw(password: str):
    """ Encryption with public key such that only holder of private key can read this """
    password = password.encode('ascii')
    enc_pw = public_key.encrypt(
        password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(enc_pw).decode("ascii")


def decrypt_pw(b64_encoded_pw: str):
    """ Decrypt something that was encrypted with public key """
    enc_pw = base64.b64decode(b64_encoded_pw.encode("ascii"))
    decoded_pw = private_key.decrypt(
        enc_pw,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    password = decoded_pw.decode("ascii")
    return password
