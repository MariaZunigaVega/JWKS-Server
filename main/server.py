import base64
import os
import sqlite3
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_FILE = "totally_not_my_privateKeys.db"


def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema and seeds initial key data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create table per Project 2 specification
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """
    )
    conn.commit()

    # Check if we need to seed keys so endpoints are immediately testable
    cursor.execute("SELECT COUNT(*) as count FROM keys")
    if cursor.fetchone()["count"] == 0:
        # 1. Generate an unexpired key (expires in 1 hour)
        private_key_valid = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        pem_valid = private_key_valid.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # <-- FIXED HERE
            encryption_algorithm=serialization.NoEncryption(),
        )
        exp_valid = int(time.time()) + 3600
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem_valid, exp_valid),
        )

        # 2. Generate an expired key (expired 1 hour ago)
        private_key_expired = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        pem_expired = private_key_expired.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # <-- FIXED HERE
            encryption_algorithm=serialization.NoEncryption(),
        )
        exp_expired = int(time.time()) - 3600
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem_expired, exp_expired),
        )

        conn.commit()
    conn.close()


def int_to_base64url(val: int) -> str:
    """Converts an integer to a Base64URL-encoded string needed for JWK."""
    bytestring = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return (
        base64.urlsafe_b64encode(bytestring)
        .decode("utf-8")
        .rstrip("=")
    )


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serves all active, unexpired public keys from the database."""
    current_time = int(time.time())
    conn = get_db_connection()
    cursor = conn.cursor()

    # SQL Injection 
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()
    conn.close()

    jwks_keys = []
    for row in rows:
        private_key = serialization.load_pem_private_key(
            row["key"], password=None
        )
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()

        jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": str(row["kid"]),
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
        }
        jwks_keys.append(jwk)

    return jsonify({"keys": jwks_keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    """Mocks user auth, reads keys from DB, and issues a signed JWT."""
    _ = request.authorization
    _ = request.get_json(silent=True)

    expired_param = request.args.get("expired")
    current_time = int(time.time())

    conn = get_db_connection()
    cursor = conn.cursor()

    # SQL Injection Proof: Fetch rows securely based on the presence of ?expired=true
    if expired_param is not None:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (current_time,),
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (current_time,),
        )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "No matching key found in database"}), 400

    # Deserialize PEM string back into usable RSA key object
    private_key = serialization.load_pem_private_key(row["key"], password=None)

    # Prepare JWT payload fields
    payload = {
        "sub": "userABC",
        "iat": current_time,
        "exp": row["exp"] if expired_param is not None else current_time + 3600,
    }

    # Include kid parameter directly into the JWT header context
    headers = {"kid": str(row["kid"])}

    # Encode token with RS256 algorithm
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return jsonify({"token": token}), 200


if __name__ == "__main__":
    init_db()
    app.run(port=8080)
