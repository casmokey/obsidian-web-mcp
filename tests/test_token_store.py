"""SQLite token store: expiry, revocation, refresh rotation and reuse detection."""

import asyncio
import sqlite3
import time

import pytest

from obsidian_vault_mcp import config, token_store


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    path = tmp_path / "sub" / "oauth.db"  # parent dir does not exist yet
    monkeypatch.setattr(config, "VAULT_OAUTH_DB_PATH", str(path))
    token_store.init()
    return path


def run(coro):
    return asyncio.run(coro)


def _rows(db):
    c = sqlite3.connect(db)
    try:
        return c.execute("SELECT token, token_type, family_id, revoked FROM oauth_tokens").fetchall()
    finally:
        c.close()


def test_issue_and_validate(db):
    access, refresh = run(token_store.issue_pair("c1"))
    assert access != refresh and len(access) >= 32
    assert run(token_store.validate_access(access)) is True
    assert run(token_store.validate_access(refresh)) is False  # refresh tokens never authenticate
    assert run(token_store.validate_access("")) is False
    assert run(token_store.validate_access("nope")) is False


def test_tokens_are_random_and_unique():
    seen = set()
    for _ in range(20):
        seen.update(run(token_store.issue_pair("c1")))
    assert len(seen) == 40


def test_sql_metacharacters_in_token_are_inert(db):
    run(token_store.issue_pair("c1"))
    assert run(token_store.validate_access("' OR '1'='1")) is False
    assert run(token_store.validate_access("x' OR token_type='access")) is False
    assert len(_rows(db)) == 2


def test_access_token_expires(monkeypatch):
    access, _ = run(token_store.issue_pair("c1"))
    real = time.time
    monkeypatch.setattr(token_store.time, "time", lambda: real() + token_store.ACCESS_TOKEN_TTL - 5)
    assert run(token_store.validate_access(access)) is True
    monkeypatch.setattr(token_store.time, "time", lambda: real() + token_store.ACCESS_TOKEN_TTL + 5)
    assert run(token_store.validate_access(access)) is False


def test_refresh_rotates_pair_and_revokes_old_access(db):
    a1, r1 = run(token_store.issue_pair("c1"))
    a2, r2 = run(token_store.rotate_refresh(r1, "c1"))
    assert len({a1, r1, a2, r2}) == 4
    assert run(token_store.validate_access(a1)) is False
    assert run(token_store.validate_access(a2)) is True
    assert len({row[2] for row in _rows(db)}) == 1  # same family throughout


def test_refresh_with_wrong_client_fails_and_does_not_burn_token():
    _, r1 = run(token_store.issue_pair("c1"))
    assert run(token_store.rotate_refresh(r1, "someone-else")) is None
    assert run(token_store.rotate_refresh(r1, "c1")) is not None


def test_refresh_unknown_or_access_token_fails():
    a1, _ = run(token_store.issue_pair("c1"))
    assert run(token_store.rotate_refresh("nope", "c1")) is None
    assert run(token_store.rotate_refresh(a1, "c1")) is None  # an access token can't be used to refresh


def test_refresh_expired(monkeypatch):
    _, r1 = run(token_store.issue_pair("c1"))
    real = time.time
    monkeypatch.setattr(token_store.time, "time", lambda: real() + token_store.REFRESH_TOKEN_TTL + 5)
    assert run(token_store.rotate_refresh(r1, "c1")) is None


def test_refresh_reuse_revokes_whole_family(db):
    a1, r1 = run(token_store.issue_pair("c1"))
    a2, r2 = run(token_store.rotate_refresh(r1, "c1"))
    # attacker (or buggy client) replays the already-used refresh token
    assert run(token_store.rotate_refresh(r1, "c1")) is None
    assert run(token_store.validate_access(a2)) is False
    assert run(token_store.rotate_refresh(r2, "c1")) is None
    assert all(row[3] == 1 for row in _rows(db))


def test_reuse_in_one_family_leaves_other_families_alone():
    a_x, r_x = run(token_store.issue_pair("c1"))
    a_y, r_y = run(token_store.issue_pair("c1"))
    run(token_store.rotate_refresh(r_x, "c1"))
    run(token_store.rotate_refresh(r_x, "c1"))  # reuse -> family X dead
    assert run(token_store.validate_access(a_y)) is True
    assert run(token_store.rotate_refresh(r_y, "c1")) is not None


def test_purge_expired_keeps_recent_and_live_rows(db, monkeypatch):
    run(token_store.issue_pair("c1"))
    assert run(token_store.purge_expired()) == 0
    real = time.time
    # 2 days after the refresh window closed: everything is gone
    monkeypatch.setattr(token_store.time, "time", lambda: real() + token_store.REFRESH_TOKEN_TTL + 2 * 86400)
    assert run(token_store.purge_expired()) == 2
    assert _rows(db) == []


def test_purge_keeps_rows_expired_less_than_a_day(db, monkeypatch):
    run(token_store.issue_pair("c1"))
    real = time.time
    monkeypatch.setattr(token_store.time, "time", lambda: real() + token_store.ACCESS_TOKEN_TTL + 3600)
    assert run(token_store.purge_expired()) == 0


def test_init_is_idempotent_and_survives_restart(db):
    access, _ = run(token_store.issue_pair("c1"))
    token_store.init()
    token_store.init()
    assert run(token_store.validate_access(access)) is True


def test_token_type_check_constraint(db):
    c = sqlite3.connect(db)
    with pytest.raises(sqlite3.IntegrityError):
        c.execute("INSERT INTO oauth_tokens VALUES ('t','admin','c','f',1,1,0)")
    c.close()
