"""Authentication for CerberusAI — the ACAS/Tenable.sc-style web login.

Install on a server, browse to it, and log in. Users and sessions live in their own
SQLite file so they persist across restarts (mounted on /data in Docker). Passwords
are salted + PBKDF2-hashed; sessions are opaque server-side tokens in an httpOnly
cookie. First run creates the admin during setup; admins can add analyst accounts.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from pathlib import Path

_DB = Path(os.environ.get("CERBERUS_USERS_DB", Path(__file__).resolve().parent / "cerberus_users.db"))
_ITERATIONS = 200_000
SESSION_TTL = 12 * 3600           # 12h, like a SOC shift
COOKIE_NAME = "cerberus_session"


class Auth:
    def __init__(self, db_path: str | Path | None = None):
        self._conn = sqlite3.connect(db_path or _DB, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, salt TEXT, pw_hash TEXT,
                role TEXT DEFAULT 'analyst', created REAL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, username TEXT, created REAL, expires REAL
            );
            """
        )
        self._conn.commit()

    # --- password hashing ----------------------------------------------------

    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS
        ).hex()

    # --- users ---------------------------------------------------------------

    def any_user_exists(self) -> bool:
        return self._conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    def create_user(self, username: str, password: str, role: str = "analyst") -> tuple[bool, str]:
        username = (username or "").strip()
        if not username or not password:
            return False, "Username and password are required."
        if len(password) < 8:
            return False, "Password must be at least 8 characters."
        if self._conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            return False, f"User '{username}' already exists."
        salt = secrets.token_hex(16)
        self._conn.execute(
            "INSERT INTO users (username, salt, pw_hash, role, created) VALUES (?,?,?,?,?)",
            (username, salt, self._hash(password, salt), role, time.time()),
        )
        self._conn.commit()
        return True, f"User '{username}' created."

    def verify(self, username: str, password: str) -> bool:
        row = self._conn.execute(
            "SELECT salt, pw_hash FROM users WHERE username=?", ((username or "").strip(),)
        ).fetchone()
        if not row:
            return False
        return hmac.compare_digest(self._hash(password, row["salt"]), row["pw_hash"])

    def role_of(self, username: str) -> str | None:
        row = self._conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        return row["role"] if row else None

    def list_users(self) -> list[dict]:
        return [
            {"username": r["username"], "role": r["role"]}
            for r in self._conn.execute("SELECT username, role FROM users ORDER BY created").fetchall()
        ]

    # --- sessions ------------------------------------------------------------

    def start_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        self._conn.execute(
            "INSERT INTO sessions (token, username, created, expires) VALUES (?,?,?,?)",
            (token, username, now, now + SESSION_TTL),
        )
        self._conn.commit()
        return token

    def session_user(self, token: str | None) -> dict | None:
        if not token:
            return None
        row = self._conn.execute(
            "SELECT username, expires FROM sessions WHERE token=?", (token,)
        ).fetchone()
        if not row or row["expires"] < time.time():
            if row:
                self.end_session(token)
            return None
        return {"username": row["username"], "role": self.role_of(row["username"])}

    def end_session(self, token: str | None) -> None:
        if token:
            self._conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            self._conn.commit()
