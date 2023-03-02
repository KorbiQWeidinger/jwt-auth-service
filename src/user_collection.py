import logging
from dataclasses import dataclass
from enum import StrEnum

import bcrypt
from bson import ObjectId
from pymongo import database

SALT = b'$2b$12$oKQ6lY.JP9Zs/lJKau0ySu'


class UserRole(StrEnum):
    ADMIN = "ADMIN"
    HAIR_APARTMENT_ADMIN = "HAIR_APARTMENT_ADMIN"


@dataclass
class User:
    """
    A user object.
    Stores the encoded password!
    """
    _id: ObjectId | None
    username: str
    password: str
    role: str

    @classmethod
    def new(cls, username: str, password: str, role: UserRole):
        """ Expect the unencoded password and encodes it to create a user """
        enc_pw = bcrypt.hashpw(password.encode("ascii"), SALT).decode("ascii")
        return cls(username, enc_pw, role.__str__())

    def __init__(self, username: str, password: str, role: str, _id: ObjectId | None = None):
        self.username = username
        self.password = password
        self.role = role
        self._id = _id

    def is_correct_password(self, password):
        return self.password == bcrypt.hashpw(password.encode("ascii"), SALT).decode("ascii")


class UserCollection:
    COLLECTION_NAME = "users"

    def __init__(self, db: database.Database):
        if self.COLLECTION_NAME in db.list_collection_names():
            self.collection = db.get_collection(self.COLLECTION_NAME)
        else:
            self.collection = db.create_collection(self.COLLECTION_NAME)
            self.collection.create_index("username", unique=True)

    def add(self, user: User):
        user_dict = user.__dict__
        user_dict.pop("_id")
        result = self.collection.insert_one(user_dict)
        logging.info(f"Created user with id {result.inserted_id}")

    def list(self) -> list[User]:
        users = []
        result = self.collection.find({})
        for entry in result:
            users.append(User(**entry))
        return users

    def find(self, username: str) -> User:
        result = self.collection.find_one({"username": username})
        return User(**result)
