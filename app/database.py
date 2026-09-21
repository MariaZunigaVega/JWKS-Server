import sqlite3
import time
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_NAME = "keys.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id TEXT PRIMARY KEY,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        ''')
        conn.commit()

def generate_and_store_key(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL
    ).decode('utf-8')

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    key_id = str(uuid.uuid4())
    expiry = int(time.time()) + 3600 if not expired else int(time.time()) - 3600
    created_at = int(time.time()) 

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO keys (id, private_key, public_key, created_at)
            VALUES (?, ?, ?, ?)
        ''', (key_id, private_pem, public_key, created_at))
        conn.commit()

    return key_id

def get_keys(expired=False):
    current_time = int(time.time())
    query = 'SELECT id, private_key, public_key, created_at FROM keys'

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        return cursor.fetchall()
