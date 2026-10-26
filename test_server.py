import os
import time
import unittest
from server import app, init_db, DB_FILE


class TestJWKSServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Remove any existing DB file to ensure clean start state
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        init_db()
        cls.client = app.test_client()

    def test_jwks_endpoint(self):
        """Tests that JWKS endpoint responds successfully and returns keys format."""
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("keys", data)
        self.assertTrue(len(data["keys"]) >= 1)
        self.assertEqual(data["keys"][0]["kty"], "RSA")

    def test_auth_valid_token(self):
        """Tests standard auth request returning an unexpired token."""
        response = self.client.post("/auth")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("token", data)

    def test_auth_expired_token(self):
        """Tests auth request with expired flag returning an expired token."""
        response = self.client.post("/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("token", data)


if __name__ == "__main__":
    unittest.main()
