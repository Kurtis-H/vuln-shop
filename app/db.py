"""SQLite storage and seed data."""

import hashlib
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    hidden INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    shipping_address TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
"""

# Demo accounts. Passwords are public on purpose: this is a local training app.
SEED_USERS = [("alice", "alice123"), ("bob", "bob123")]

SEED_PRODUCTS = [
    ("Mechanical Keyboard", 89.99, 0),
    ("USB-C Hub", 34.50, 0),
    ("Noise-Cancelling Headphones", 199.00, 0),
    ("Prototype Drone (INTERNAL - unreleased)", 999.00, 1),
]

# (username, product_id, address) - each user has one private order.
SEED_ORDERS = [
    ("alice", 1, "123 Alice Lane, Springfield"),
    ("bob", 3, "456 Bob Street, Shelbyville"),
]


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str, reset: bool = True) -> None:
    """Create tables and seed demo data. reset=True starts from a clean database."""
    if reset and db_path != ":memory:" and os.path.exists(db_path):
        os.remove(db_path)
    conn = connect(db_path)
    with conn:
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            user_ids = {}
            for username, password in SEED_USERS:
                salt = os.urandom(16).hex()
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, hash_password(password, salt), salt),
                )
                user_ids[username] = cur.lastrowid
            conn.executemany(
                "INSERT INTO products (name, price, hidden) VALUES (?, ?, ?)", SEED_PRODUCTS
            )
            conn.executemany(
                "INSERT INTO orders (user_id, product_id, shipping_address) VALUES (?, ?, ?)",
                [(user_ids[u], p, a) for u, p, a in SEED_ORDERS],
            )
    conn.close()
