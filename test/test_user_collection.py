import unittest

import pymongo

from config import config
from user_collection import User, UserRole, UserCollection


class UserTest(unittest.TestCase):

    def test_password_encryption(self):
        user = User.new(username="user", password="password", role=UserRole.ADMIN)
        self.assertTrue(user.is_correct_password("password"))
        user = User.new(username="user", password="admin", role=UserRole.ADMIN)
        self.assertTrue(user.is_correct_password("admin"))


class UserCollectionTest(unittest.TestCase):

    def setUp(self):
        """ establish connection and create test db """
        client = pymongo.MongoClient(config['MONGODB_URI'])
        self.db = client.get_database("authentication-test-db")
        self.collection = UserCollection(self.db)

    def tearDown(self):
        """ drop test users collection """
        self.db.drop_collection(self.collection.COLLECTION_NAME)

    def test_add_user(self):
        new_user = User.new(username="user", password="password", role=UserRole.ADMIN)
        self.collection.add(new_user)
        self.assertTrue(new_user.username in [user.username for user in self.collection.list()])
