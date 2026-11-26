"""Login and JWT handling."""

import time

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.db import hash_password

TOKEN_TTL_SECONDS = 3600
bearer = HTTPBearer(auto_error=False)


def create_token(user_id: int, username: str, secret: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def verify_login(conn, username: str, password: str):
    row = conn.execute(
        "SELECT id, username, password_hash, salt FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row and hash_password(password, row["salt"]) == row["password_hash"]:
        return row
    return None


def current_user(
    request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer)
) -> dict:
    """Return {'id': int, 'username': str} for a valid bearer token, else 401."""
    if creds is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    settings = request.app.state.settings
    try:
        payload = jwt.decode(creds.credentials, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token") from None
    return {"id": int(payload["sub"]), "username": payload.get("username", "")}
