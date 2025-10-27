import sqlite3
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_PATH = "totally_not_my_privateKeys.db"


def init_db():
    """
    Create (or open) the SQLite database file and ensure the keys table exists.
    Returns an open sqlite3.Connection.

    We set check_same_thread=False so the same connection can be safely used
    from different threads. This matters because:
      - main.py creates the connection at import time (main thread),
      - but the HTTP server handles requests in another thread (started by tests).
    Without check_same_thread=False, SQLite will raise:
      sqlite3.ProgrammingError: SQLite objects created in a thread can
      only be used in that same thread.
    """
    conn = sqlite3.connect(
        DB_PATH,
        check_same_thread=False  # <-- allow use from server thread
    )
    conn.row_factory = sqlite3.Row

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def generate_rsa_keypair_pem():
    """
    Generate a new RSA private key and return:
      - pem_bytes: PKCS1/TraditionalOpenSSL PEM-encoded private key (bytes)
      - private_key_obj: the private key object
    """
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes, private_key_obj


def insert_key(conn, pem_bytes: bytes, exp_epoch: int):
    """
    Insert a private key row. Returns the new kid (the primary key).
    """
    cur = conn.execute(
        "INSERT INTO keys(key, exp) VALUES(?, ?)",
        (pem_bytes, exp_epoch)
    )
    conn.commit()
    return cur.lastrowid


def count_keys(conn):
    """
    Return how many key rows currently exist in the database.
    """
    cur = conn.execute("SELECT COUNT(*) AS c FROM keys")
    row = cur.fetchone()
    return row["c"]


def get_unexpired_key(conn):
    """
    Return one unexpired key row (kid, key, exp).

    Strategy: pick the unexpired key with the LATEST expiration (highest exp),
    so we prefer the key that is most valid/future-facing.
    """
    now = int(time.time())
    cur = conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
        (now,)
    )
    return cur.fetchone()


def get_expired_key(conn):
    """
    Return one expired key row (kid, key, exp).

    Strategy: pick the MOST RECENTLY expired key (highest exp that is <= now),
    so we don't grab something from days/weeks ago if there's a fresher
    just-expired key.
    """
    now = int(time.time())
    cur = conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
        (now,)
    )
    return cur.fetchone()


def get_all_unexpired_keys(conn):
    """
    Return all unexpired keys (kid, key, exp), ordered by kid.

    These are the keys that should appear in /.well-known/jwks.json and /jwks.
    Only unexpired keys should be advertised publicly.
    """
    now = int(time.time())
    cur = conn.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC",
        (now,)
    )
    return cur.fetchall()

