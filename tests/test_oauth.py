"""OAuth: no token without the connector password; PKCE and client binding enforced."""

import base64
import hashlib
import secrets
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
    verifier = secrets.token_urlsafe(40)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _authorize(c, password=PASSWORD, **over):
    verifier, challenge = _pkce()
    cid = c.post("/oauth/register", json={"redirect_uris": [REDIRECT]}).json()["client_id"]
    q = {"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT, "state": "s",
         "code_challenge": challenge, "code_challenge_method": "S256"} | over
    return cid, verifier, c.post("/oauth/authorize", data=q | {"password": password})


def test_register_hands_out_no_secret(client):
    r = client.post("/oauth/register", json={"redirect_uris": [REDIRECT]}).json()
    assert "client_secret" not in r and r["token_endpoint_auth_method"] == "none"


def test_get_shows_password_form_not_a_redirect(client):
    _, challenge = _pkce()
    r = client.get("/oauth/authorize", params={"response_type": "code", "client_id": "x", "redirect_uri": REDIRECT,
                                               "code_challenge": challenge, "code_challenge_method": "S256"})
    assert r.status_code == 200 and 'type="password"' in r.text and "location" not in r.headers


def test_wrong_password_no_code_and_lockout(client):
    with mock.patch("time.sleep"):
        _, _, r = _authorize(client, "nope")
        assert r.status_code == 401 and "location" not in r.headers
        for _ in range(oauth.LOCKOUT[0]):
            _authorize(client, "nope")
        _, _, r = _authorize(client)
    assert r.status_code == 401 and "Too many" in r.text


def test_full_flow(client):
    cid, verifier, r = _authorize(client)
    assert r.status_code == 302
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    t = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": cid,
                                          "redirect_uri": REDIRECT, "code_verifier": verifier})
    assert t.status_code == 200 and t.json()["refresh_token"]


def test_code_bound_to_client_and_verifier(client):
    cid, verifier, r = _authorize(client)
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    t = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": "other",
                                          "code_verifier": verifier})
    assert t.status_code == 400


def test_pkce_and_https_required(client):
    assert _authorize(client, code_challenge="")[2].status_code == 400
    assert _authorize(client, redirect_uri="http://evil.example/cb")[2].status_code == 400


def test_client_credentials_grant_is_gone(client):
    r = client.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": "a", "client_secret": "b"})
    assert r.json()["error"] == "unsupported_grant_type"
