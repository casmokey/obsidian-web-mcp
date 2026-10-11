"""OAuth endpoints beyond the happy path: PKCE and redirect edge cases, refresh grant, password hashing."""

import asyncio
import base64
import hashlib
import secrets
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from obsidian_vault_mcp import config, oauth, token_store

PASSWORD = "correct horse battery"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_DB_PATH", str(tmp_path / "oauth.db"))
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD_HASH", oauth.hash_password(PASSWORD, n=2 ** 10))
    oauth._failures.clear()
    oauth._auth_codes.clear()
    token_store.init()
    return TestClient(Starlette(routes=oauth.oauth_routes), follow_redirects=False)


def _pkce():
    v = secrets.token_urlsafe(40)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def _query(challenge, **over):
    return {"response_type": "code", "client_id": "cid", "redirect_uri": REDIRECT, "state": "st",
            "code_challenge": challenge, "code_challenge_method": "S256"} | over


def _get_code(c, cid="cid", **over):
    v, ch = _pkce()
    r = c.post("/oauth/authorize", data=_query(ch, client_id=cid, **over) | {"password": PASSWORD})
    assert r.status_code == 302, r.text
    return parse_qs(urlsplit(r.headers["location"]).query)["code"][0], v


def _exchange(c, code, v, cid="cid", **over):
    return c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": cid,
                                        "redirect_uri": REDIRECT, "code_verifier": v} | over)


# ------------------------------------------------------------------ password hashing
def test_hash_password_roundtrip_and_format():
    h = oauth.hash_password("hunter2hunter2", n=2 ** 10)
    assert h.startswith("scrypt:") and "$" not in h
    assert oauth.check_password("hunter2hunter2", h)
    assert not oauth.check_password("hunter2hunter3", h)
    assert not oauth.check_password("", h)
    assert oauth.hash_password("hunter2hunter2", n=2 ** 10) != h  # salted


@pytest.mark.parametrize("stored", [
    "", "garbage", "scrypt:1:2:3", "md5:1:8:1:aa:bb", "scrypt:x:8:1:aa:bb", "scrypt:1024:8:1:zz:bb",
    "scrypt:1024:8:1:aa:bb:cc",
])
def test_check_password_malformed_hash_is_false_not_error(stored):
    assert oauth.check_password("whatever", stored) is False


def test_hash_cli_enforces_minimum_length(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    with pytest.raises(SystemExit):
        oauth.hash_password_cli()
    monkeypatch.setattr("sys.stdin", io.StringIO("a-long-enough-password\n"))
    oauth.hash_password_cli()
    assert oauth.check_password("a-long-enough-password", capsys.readouterr().out.strip())


# ------------------------------------------------------------------ authorize
def test_no_password_hash_configured_refuses_everything(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD_HASH", "")
    _, ch = _pkce()
    r = client.post("/oauth/authorize", data=_query(ch) | {"password": ""})
    assert r.status_code == 500 and "location" not in r.headers
    assert oauth._auth_codes == {}


@pytest.mark.parametrize("uri", [
    "http://evil.example/cb", "ftp://x/cb", "javascript:alert(1)", "https://", "", "claude.ai/cb",
    "https://claude.ai/cb#frag", "http://localhost.evil.example/cb", "//evil.example/cb",
])
def test_bad_redirect_uris_never_redirect(client, uri):
    _, ch = _pkce()
    r = client.post("/oauth/authorize", data=_query(ch, redirect_uri=uri) | {"password": PASSWORD})
    assert r.status_code == 400 and "location" not in r.headers
    r = client.get("/oauth/authorize", params=_query(ch, redirect_uri=uri))
    assert r.status_code == 400 and 'type="password"' not in r.text


@pytest.mark.parametrize("uri", ["http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:9/cb", "https://claude.ai/cb"])
def test_good_redirect_uris(client, uri):
    code, _ = _get_code(client, redirect_uri=uri)
    assert code


def test_plain_pkce_and_response_type_token_rejected(client):
    _, ch = _pkce()
    for over in ({"code_challenge_method": "plain"}, {"response_type": "token"}, {"client_id": ""}):
        r = client.post("/oauth/authorize", data=_query(ch, **over) | {"password": PASSWORD})
        assert r.status_code == 400, over


def test_redirect_carries_state_and_appends_to_existing_query(client):
    v, ch = _pkce()
    r = client.post("/oauth/authorize", data=_query(ch, redirect_uri=REDIRECT + "?x=1", state="a b&c") | {"password": PASSWORD})
    loc = urlsplit(r.headers["location"])
    q = parse_qs(loc.query)
    assert q["x"] == ["1"] and q["state"] == ["a b&c"] and "code" in q


def test_form_escapes_hostile_values(client):
    _, ch = _pkce()
    r = client.get("/oauth/authorize", params=_query(ch, state='"><script>alert(1)</script>'))
    assert "<script>alert(1)" not in r.text
    assert r.headers["x-frame-options"] == "DENY" and "no-store" in r.headers["cache-control"]
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_lockout_expires_after_window(client, monkeypatch):
    _, ch = _pkce()
    with mock.patch("time.sleep"):
        for _ in range(oauth.LOCKOUT[0]):
            client.post("/oauth/authorize", data=_query(ch) | {"password": "bad"})
        # locked even for the right password
        r = client.post("/oauth/authorize", data=_query(ch) | {"password": PASSWORD})
        assert r.status_code == 401
        later = time.time() + oauth.LOCKOUT[1] + 5
        monkeypatch.setattr(oauth.time, "time", lambda: later)
        r = client.post("/oauth/authorize", data=_query(ch) | {"password": PASSWORD})
    assert r.status_code == 302


def test_wrong_password_response_has_no_code_and_no_redirect(client):
    _, ch = _pkce()
    with mock.patch("time.sleep") as sl:
        r = client.post("/oauth/authorize", data=_query(ch) | {"password": "nope"})
    assert r.status_code == 401 and "Wrong password" in r.text and not oauth._auth_codes
    sl.assert_called()  # failed attempts are slowed down


# ------------------------------------------------------------------ token endpoint
def test_code_is_single_use(client):
    code, v = _get_code(client)
    assert _exchange(client, code, v).status_code == 200
    assert _exchange(client, code, v).status_code == 400


def test_failed_exchange_still_burns_the_code(client):
    code, v = _get_code(client)
    assert _exchange(client, code, "wrong-verifier").status_code == 400
    assert _exchange(client, code, v).status_code == 400


@pytest.mark.parametrize("over", [
    {"redirect_uri": "https://evil.example/cb"},
    {"cid": "other-client"},
    {"code": "not-a-code"},
    {"code": ""},
])
def test_exchange_binding_failures(client, over):
    code, v = _get_code(client)
    over = dict(over)
    cid = over.pop("cid", "cid")
    code = over.pop("code", code)
    assert _exchange(client, code, v, cid=cid, **over).status_code == 400


def test_empty_verifier_rejected(client):
    code, _ = _get_code(client)
    assert _exchange(client, code, "").status_code == 400


def test_non_ascii_verifier_does_not_crash(client):
    code, _ = _get_code(client)
    assert _exchange(client, code, "vérifier").status_code == 400


def test_expired_code_rejected(client, monkeypatch):
    code, v = _get_code(client)
    real = time.time
    monkeypatch.setattr(oauth.time, "time", lambda: real() + oauth.CODE_TTL + 1)
    assert _exchange(client, code, v).status_code == 400


def test_token_response_is_not_cacheable_and_shape(client):
    code, v = _get_code(client)
    r = _exchange(client, code, v)
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == token_store.ACCESS_TOKEN_TTL
    assert asyncio.run(token_store.validate_access(body["access_token"]))


def test_missing_or_unknown_grant_type(client):
    assert client.post("/oauth/token", data={}).json()["error"] == "unsupported_grant_type"
    assert client.post("/oauth/token", data={"grant_type": "password", "username": "a", "password": "b"}).status_code == 400
    assert client.post("/oauth/token", data={"grant_type": "implicit"}).status_code == 400


def test_refresh_grant_rotates_and_reuse_kills_family(client):
    code, v = _get_code(client)
    first = _exchange(client, code, v).json()
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": "cid"})
    assert r.status_code == 200
    second = r.json()
    assert second["access_token"] != first["access_token"]
    # replaying the first refresh token is refused ...
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": "cid"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    # ... and takes the newest pair down with it
    assert asyncio.run(token_store.validate_access(second["access_token"])) is False
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": second["refresh_token"], "client_id": "cid"})
    assert r.status_code == 400


@pytest.mark.parametrize("data", [
    {"refresh_token": "x"},                 # no client_id
    {"client_id": "cid"},                   # no refresh token
    {"refresh_token": "x", "client_id": "cid"},  # unknown token
])
def test_refresh_grant_validation(client, data):
    r = client.post("/oauth/token", data={"grant_type": "refresh_token"} | data)
    assert r.status_code == 400


def test_refresh_grant_wrong_client(client):
    code, v = _get_code(client)
    tok = _exchange(client, code, v).json()
    r = client.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": "evil"})
    assert r.status_code == 400


# ------------------------------------------------------------------ register + metadata
def test_register_tolerates_garbage_bodies_and_truncates_name(client):
    for body in ("not json", "[1,2]", "null", ""):
        r = client.post("/oauth/register", content=body, headers={"content-type": "application/json"})
        assert r.status_code == 201 and r.json()["client_id"].startswith("vault-mcp-")
    r = client.post("/oauth/register", json={"client_name": "x" * 500})
    assert len(r.json()["client_name"]) == 100


def test_registered_client_ids_are_unique(client):
    ids = {client.post("/oauth/register", json={}).json()["client_id"] for _ in range(10)}
    assert len(ids) == 10


def test_metadata_documents(client):
    m = client.get("/.well-known/oauth-authorization-server", headers={"host": "vault.example.com"}).json()
    assert m["issuer"] == "http://vault.example.com"
    assert m["code_challenge_methods_supported"] == ["S256"]
    assert m["token_endpoint_auth_methods_supported"] == ["none"]
    pr = client.get("/.well-known/oauth-protected-resource").json()
    assert pr["authorization_servers"] == [pr["resource"]]


def test_only_declared_methods_allowed(client):
    assert client.get("/oauth/token").status_code == 405
    assert client.get("/oauth/register").status_code == 405
    assert client.post("/.well-known/oauth-authorization-server").status_code == 405
