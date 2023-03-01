import argparse
import base64
import pymongo
import jwt
import bcrypt

from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from flask import Flask, request

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

SALT = bcrypt.gensalt(12)

print("Salt:", SALT)

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

app = Flask(__name__)

parser = argparse.ArgumentParser()

parser.add_argument('-mpw', '--mongo_pw', type=str)
args = parser.parse_args()

mongo_pw = args.__getattribute__("mongo_pw")

print("Mongo pw:", mongo_pw)
mongo_url = f"mongodb+srv://KorbiQWeidinger:{mongo_pw}@korbifree.1nahf5e.mongodb.net/?retryWrites=true&w=majority"

client = pymongo.MongoClient(mongo_url)

db = client.get_database("auth-service")
users_collection = db.get_collection("users")
users_collection.create_index("username")


def store_user(username: str, password: str):
    result = users_collection.insert_one({"username": username, "password": password})
    print("Created user", result.inserted_id)


def encode_jwt(payload: dict[str, Any]) -> str:
    return jwt.encode(payload, private_pem, algorithm="RS256")


def decode_jwt(token: str) -> dict[str, Any]:
    return jwt.decode(token, public_pem, algorithms=["RS256"])


encrypted_password = public_key.encrypt(
    "password".encode('ascii'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Encrypted PW:", base64.b64encode(encrypted_password))


@app.route("/")
def homepage():
    return "HomePage"


@app.route("/api/pkey")
def pkey():
    return public_pem \
        .replace(b"-----BEGIN PUBLIC KEY-----\n", b"") \
        .replace(b"-----END PUBLIC KEY-----\n", b"")


@app.route("/api/jwt", methods=['POST'])
def login():
    username = request.get_json()["username"]
    encoded_pw = request.get_json()["password"]

    try:
        decoded_pw = private_key.decrypt(
            base64.b64decode(encoded_pw),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode("ascii")
    except ValueError:
        return {"error": "password decryption failed"}, 501

    token = encode_jwt({"username": username, "role": "ADMIN", "iat": datetime.now().timestamp()})
    return "foo"


def main():
    app.run(host="0.0.0.0", port=8080)
    try:
        pw1 = bcrypt.hashpw("admin".encode(), SALT)
        store_user("admin", pw1.decode())
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
