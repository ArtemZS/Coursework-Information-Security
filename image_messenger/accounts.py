import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


class Accounts:
    def __init__(self, database: Path):
        database.parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    username TEXT PRIMARY KEY,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL
                )
                """
            )

    def register(self, username: str, password: str) -> None:
        if not 1 <= len(username) <= 32 or not all(
            char.isalnum() or char in "-_" for char in username
        ):
            raise ValueError("Логин должен содержать от 1 до 32 букв, цифр, дефисов или подчёркиваний.")
        if not 8 <= len(password) <= 128:
            raise ValueError("Пароль должен содержать от 8 до 128 символов.")

        salt = secrets.token_bytes(16)
        digest = password_hash(password, salt)
        try:
            with closing(sqlite3.connect(self.database)) as connection, connection:
                connection.execute("INSERT INTO accounts VALUES (?, ?, ?)", (username, salt, digest))
        except sqlite3.IntegrityError as error:
            raise ValueError("Этот логин уже занят.") from error

    def authenticate(self, username: str, password: str) -> bool:
        if not 1 <= len(username) <= 32 or not 1 <= len(password) <= 128:
            return False
        with closing(sqlite3.connect(self.database)) as connection:
            result = connection.execute(
                "SELECT salt, password_hash FROM accounts WHERE username = ?", (username,)
            ).fetchone()
        return result is not None and hmac.compare_digest(password_hash(password, result[0]), result[1])
