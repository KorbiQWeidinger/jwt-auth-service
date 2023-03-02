import logging
from datetime import datetime

import pymongo
from flask import Flask, request, make_response, jsonify

from config import config
from jwt_utils import public_pem, decrypt_pw, encode_jwt, encrypt_pw
from user_collection import UserCollection, User, UserRole

app = Flask(__name__)

client = pymongo.MongoClient(config['MONGODB_URI'])
db = client.get_database(config['MONGODB_NAME'])
user_collection = UserCollection(db)

logging.basicConfig(level=logging.NOTSET)


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
    error = {"error": "incorrect username or password"}, 406

    data = request.get_json()
    username = data.get("username")
    b64_encoded_pw = data.get("password")

    if not username or not b64_encoded_pw:
        return error

    try:
        password = decrypt_pw(b64_encoded_pw)
        user = user_collection.find(username)
    except ValueError:
        return error

    if not user.is_correct_password(password):
        return error

    # Generate JWT token
    payload = {
        "username": username,
        "role": user.role,
        "iat": datetime.now().timestamp()
    }
    token = encode_jwt(payload)

    # Create response
    response_data = {"message": "login success"}
    response = make_response(jsonify(response_data))
    response.set_cookie("jwt_cookie", token, httponly=True)
    response.status_code = 201

    return response


def main():
    try:
        logging.info(encrypt_pw("admin"))
        user_collection.add(User("admin", "admin", UserRole.ADMIN))
    except Exception as e:
        logging.exception(str(e))
    app.run(host="0.0.0.0", port=8080)


if __name__ == '__main__':
    main()
