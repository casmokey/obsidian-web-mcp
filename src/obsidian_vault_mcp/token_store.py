"""SQLite-backed OAuth token store with refresh token rotation.

Issues access + refresh token pairs, survives server restarts, and detects
refresh-token reuse by revoking the entire token family.

Token families: every authorization grant starts a new family. A refresh
rotates the pair but keeps the family. A reused (already-revoked) refresh
token triggers family-wide revocation -- the standard OAuth 2.1 mitigation
for leaked refresh tokens.
"""

import asyncio
import logging
import secrets
import sqlite3
import time
from pathlib import Path

from . import config

logger = logging.getLogger(__name__)

ACCESS_TOKEN_TTL = 3600              # 1 hour
REFRESH_TOKEN_TTL = 30 * 24 * 3600   # 30 days


_SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_tokens (
    token TEXT PRIMARY KEY,
    token_type TEXT NOT NULL CHECK(token_type IN ('access', 'refresh')),
    client_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_family ON oauth_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires ON oauth_tokens(expires_at);
"""


def _connect() -> sqlite3.Connection:
    db_path = Path(config.VAULT_OAUTH_DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    """Create schema. Call once at server startup."""
    conn = _connect()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _insert_pair(conn: sqlite3.Connection, client_id: str, family_id: str) -> tuple[str, str]:
    now = time.time()
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO oauth_tokens (token, token_type, client_id, family_id, expires_at, created_at) "
        "VALUES (?, 'access', ?, ?, ?, ?)",
        (access, client_id, family_id, now + ACCESS_TOKEN_TTL, now),
    )
    conn.execute(
        "INSERT INTO oauth_tokens (token, token_type, client_id, family_id, expires_at, created_at) "
        "VALUES (?, 'refresh', ?, ?, ?, ?)",
        (refresh, client_id, family_id, now + REFRESH_TOKEN_TTL, now),
    )
    return access, refresh


def _issue_pair_sync(client_id: str) -> tuple[str, str]:
    family_id = secrets.token_hex(16)
    conn = _connect()
    try:
        access, refresh = _insert_pair(conn, client_id, family_id)
        conn.commit()
        return access, refresh
    finally:
        conn.close()


async def issue_pair(client_id: str) -> tuple[str, str]:
    """Issue a fresh access+refresh token pair in a new family."""
    return await asyncio.to_thread(_issue_pair_sync, client_id)


def _validate_access_sync(token: str) -> bool:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT expires_at, revoked FROM oauth_tokens "
            "WHERE token = ? AND token_type = 'access'",
            (token,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or row["revoked"]:
        return False
    return row["expires_at"] >= time.time()


async def validate_access(token: str) -> bool:
    """Return True if the bearer token is a live OAuth-issued access token."""
    return await asyncio.to_thread(_validate_access_sync, token)


def _rotate_refresh_sync(refresh_token: str, client_id: str) -> tuple[str, str] | None:
    """Rotate a refresh token. Returns (new_access, new_refresh), or None if
    the refresh token is invalid, expired, or mismatched.

    On reuse of an already-revoked refresh token, revoke the entire family.
    """
    now = time.time()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT client_id, family_id, expires_at, revoked FROM oauth_tokens "
            "WHERE token = ? AND token_type = 'refresh'",
            (refresh_token,),
        ).fetchone()
        if row is None:
            return None
        if row["client_id"] != client_id:
            return None

        family_id = row["family_id"]

        if row["revoked"]:
            logger.warning(
                "Refresh token reuse detected for family %s; revoking family", family_id
            )
            conn.execute(
                "UPDATE oauth_tokens SET revoked = 1 WHERE family_id = ?",
                (family_id,),
            )
            conn.commit()
            return None

        if row["expires_at"] < now:
            return None

        # Rotate: revoke the used refresh token and any live access tokens in the family,
        # then issue a replacement pair under the same family.
        conn.execute(
            "UPDATE oauth_tokens SET revoked = 1 WHERE token = ?",
            (refresh_token,),
        )
        conn.execute(
            "UPDATE oauth_tokens SET revoked = 1 "
            "WHERE family_id = ? AND token_type = 'access' AND revoked = 0",
            (family_id,),
        )
        access, new_refresh = _insert_pair(conn, client_id, family_id)
        conn.commit()
        return access, new_refresh
    finally:
        conn.close()


async def rotate_refresh(refresh_token: str, client_id: str) -> tuple[str, str] | None:
    return await asyncio.to_thread(_rotate_refresh_sync, refresh_token, client_id)


def _purge_expired_sync() -> int:
    """Delete rows whose refresh window is fully past. Access tokens die with
    their refresh siblings via family_id."""
    cutoff = time.time() - 24 * 3600  # keep expired rows 1 day for observability
    conn = _connect()
    try:
        cur = conn.execute(
            "DELETE FROM oauth_tokens WHERE expires_at < ?",
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


async def purge_expired() -> int:
    return await asyncio.to_thread(_purge_expired_sync)
