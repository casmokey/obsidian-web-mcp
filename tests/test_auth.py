"""Bearer middleware and the assembled HTTP app: nothing is served without a valid token."""

import asyncio
import time

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth, config, oauth, token_store

ADMIN = "admin-token-abcdef"


async def _ok(request):
    return PlainTextResponse("secret data")


def _app():
    paths = ["/mcp", "/health", "/oauth/token", "/oauth/authorize", "/oauth/register",
             "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource",
             "/oauth/token/extra", "/mcp/health", "/HEALTH", "/health/"]
    app = Starlette(routes=[Route(p, _ok, methods=["GET", "POST"]) for p in paths])
    app.add_middleware(auth.BearerAuthMiddleware)
    return app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_DB_PATH", str(tmp_path / "oauth.db"))
    monkeypatch.setattr(auth, "VAULT_MCP_TOKEN", ADMIN)
    token_store.init()
    return TestClient(_app(), base_url="http://localhost")


def test_no_header_is_401_with_discovery_challenge(client):
    r = client.get("/mcp")
    assert r.status_code == 401 and "secret" not in r.text
    ch = r.headers["www-authenticate"]
    assert ch.startswith("Bearer ") and 'error="invalid_request"' in ch
    assert 'resource_metadata="http://localhost/.well-known/oauth-protected-resource"' in ch


@pytest.mark.parametrize("header", [
    "", "Bearer", "Bearer ", "Basic YWRtaW46cGFzcw==", f"Token {ADMIN}", ADMIN, f"bearer {ADMIN}",
])
def test_malformed_authorization_header_rejected(client, header):
    r = client.get("/mcp", headers={"Authorization": header})
    assert r.status_code == 401 and "secret" not in r.text


@pytest.mark.parametrize("token", [
    "wrong", ADMIN[:-1], ADMIN + "x", ADMIN.upper(), " " + ADMIN, ADMIN + " ", "x" * 5000,
])
def test_wrong_tokens_rejected(client, token):
    r = client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]


def test_non_ascii_token_is_401_not_a_crash(client):
    """hmac.compare_digest on str raises for non-ASCII input; that must not become a 500."""
    r = client.get("/mcp", headers={"Authorization": "Bearer café".encode("latin-1")})
    assert r.status_code == 401


def test_admin_token_accepted(client):
    r = client.get("/mcp", headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 200 and r.text == "secret data"


def test_oauth_issued_access_token_accepted_then_revoked_and_expired(client):
    access, refresh = asyncio.run(token_store.issue_pair("c1"))
    h = {"Authorization": f"Bearer {access}"}
    assert client.get("/mcp", headers=h).status_code == 200
    # a refresh token is not an access token
    assert client.get("/mcp", headers={"Authorization": f"Bearer {refresh}"}).status_code == 401
    # rotation revokes the old access token
    asyncio.run(token_store.rotate_refresh(refresh, "c1"))
    assert client.get("/mcp", headers=h).status_code == 401


def test_expired_access_token_rejected(client, monkeypatch):
    access, _ = asyncio.run(token_store.issue_pair("c1"))
    real = time.time
    monkeypatch.setattr(token_store.time, "time", lambda: real() + token_store.ACCESS_TOKEN_TTL + 5)
    r = client.get("/mcp", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401


def test_no_admin_token_configured_fails_closed_with_500(client, monkeypatch):
    monkeypatch.setattr(auth, "VAULT_MCP_TOKEN", "")
    # empty bearer must not match an empty admin token
    r = client.get("/mcp", headers={"Authorization": "Bearer "})
    assert r.status_code == 500 and "secret" not in r.text
    assert client.get("/mcp", headers={"Authorization": "Bearer anything"}).status_code == 500


@pytest.mark.parametrize("path", sorted(auth._AUTH_EXEMPT_PATHS))
def test_exempt_paths_need_no_token(client, path):
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", ["/oauth/token/extra", "/mcp/health", "/HEALTH", "/health/", "/mcp"])
def test_exemption_is_exact_not_prefix_or_case_insensitive(client, path):
    assert client.get(path).status_code == 401


def test_exempt_set_is_only_the_oauth_flow_and_health():
    assert auth._AUTH_EXEMPT_PATHS == {
        "/health", "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource",
        "/oauth/authorize", "/oauth/token", "/oauth/register",
    }


# ------------------------------------------------------------------ the real app
@pytest.fixture(scope="module")
def _mcp_app():
    """The real FastMCP streamable-http app with the real middleware and OAuth routes mounted the
    way server.main() does it. Module-scoped: a session manager can only be started once."""
    from obsidian_vault_mcp import server
    app = server.mcp.streamable_http_app()
    for route in oauth.oauth_routes:
        app.routes.insert(0, route)
    app.add_middleware(auth.BearerAuthMiddleware)
    with TestClient(app, base_url="http://localhost:8421") as c:
        yield c


@pytest.fixture
def mcp_client(_mcp_app, vault_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_DB_PATH", str(tmp_path / "oauth.db"))
    monkeypatch.setattr(auth, "VAULT_MCP_TOKEN", ADMIN)
    token_store.init()
    return _mcp_app


MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _rpc(method, params=None, id=1):
    return {"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}}


def test_real_app_requires_auth_for_mcp(mcp_client):
    r = mcp_client.post("/mcp", json=_rpc("tools/list"), headers=MCP_HEADERS)
    assert r.status_code == 401


def test_real_app_lists_tools_and_calls_one_with_admin_token(mcp_client):
    h = MCP_HEADERS | {"Authorization": f"Bearer {ADMIN}"}
    r = mcp_client.post("/mcp", json=_rpc("tools/list"), headers=h)
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert names == {"vault_read", "vault_batch_read", "vault_write", "vault_batch_frontmatter_update",
                     "vault_search", "vault_search_frontmatter", "vault_list", "vault_move", "vault_delete"}

    r = mcp_client.post("/mcp", json=_rpc("tools/call", {"name": "vault_read", "arguments": {"path": "../x"}}), headers=h)
    assert r.status_code == 200
    assert "error" in r.json()["result"]["content"][0]["text"]


def test_real_app_validates_tool_arguments(mcp_client, vault_dir):
    h = MCP_HEADERS | {"Authorization": f"Bearer {ADMIN}"}
    # delete without the required confirm flag, oversized path
    for name, args in [
        ("vault_delete", {"path": "test-note.md"}),
        ("vault_read", {"path": "a" * 501}),
        ("vault_batch_read", {"paths": []}),
        ("vault_search", {"query": "x", "max_results": 9999}),
    ]:
        r = mcp_client.post("/mcp", json=_rpc("tools/call", {"name": name, "arguments": args}), headers=h)
        body = r.json()
        text = body["result"]["content"][0]["text"] if "result" in body else ""
        failed = "error" in body or body["result"].get("isError") or '"error"' in text
        assert failed, (name, args, body)
    assert (vault_dir / "test-note.md").exists()


def test_real_app_rejects_foreign_host_header(mcp_client):
    """DNS-rebinding protection: an unexpected Host never reaches the tools."""
    h = MCP_HEADERS | {"Authorization": f"Bearer {ADMIN}", "Host": "evil.example.com"}
    r = mcp_client.post("/mcp", json=_rpc("tools/list"), headers=h)
    assert r.status_code in (400, 403, 421)


def test_real_app_oauth_endpoints_reachable_without_token(mcp_client):
    assert mcp_client.get("/.well-known/oauth-protected-resource").status_code == 200
    assert mcp_client.get("/.well-known/oauth-authorization-server").json()["code_challenge_methods_supported"] == ["S256"]
