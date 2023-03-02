import unittest
from typing import Any

import jwt_utils as jwt


class JWTUtilsTest(unittest.TestCase):

    def test_password_encryption_decryption(self):
        def test_enc_dec(password: str):
            self.assertTrue(password == jwt.decrypt_pw(jwt.encrypt_pw(password)))

        test_enc_dec("password")
        test_enc_dec("Foo123!#")
        test_enc_dec("BlaBla-.123!#")

    def test_jwt_encryption_decryption(self):
        def test_enc_dec(payload: dict[str, Any]):
            self.assertTrue(payload == jwt.decode_jwt(jwt.encode_jwt(payload)))

        test_enc_dec({"some": "data"})
        test_enc_dec({"some": ["more", "data"]})
