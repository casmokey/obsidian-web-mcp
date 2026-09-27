"""OAuth 2.0 authorization code flow with PKCE for Claude app MCP integration.

Claude's MCP connector uses the full OAuth authorization code flow:
1. Discovers metadata at /.well-known/oauth-authorization-server
2. Dynamically registers at /oauth/register
3. Redirects user's browser to /oauth/authorize
4. The owner types the connector password; the server redirects back with an auth code
5. Claude exchanges the code (with its PKCE verifier) at /oauth/token for a bearer token
6. Claude uses the bearer token on all MCP requests

Registration is open (Claude needs it), so the password on the authorize page is the
security boundary: without it no code, and so no token, is ever issued. The password is
stored as a scrypt hash in VAULT_OAUTH_PASSWORD_HASH (make one with `vault-mcp-hash-password`).
Five wrong passwords in 15 minutes lock the page for 15 minutes.
"""

import base64
import hashlib
import hmac
import html
import logging
import secrets
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
from starlette.routing import Route

from . import config, token_store

logger = logging.getLogger(__name__)

CODE_TTL = 300
LOCKOUT = (5, 900)  # 5 wrong passwords within 15 minutes -> locked for 15 minutes
LOOPBACK = {"localhost", "127.0.0.1", "::1"}

# In-memory store for authorization codes (short-lived)
# Maps code -> {client_id, redirect_uri, code_challenge, expires_at}
_auth_codes: dict[str, dict] = {}
_failures: list[float] = []
_lock = threading.Lock()


def _cleanup_codes():
    now = time.time()
    expired = [k for k, v in _auth_codes.items() if v["expires_at"] < now]
    for k in expired:
        del _auth_codes[k]


# ------------------------------------------------------------------ password
def hash_password(pw: str, n: int = 2 ** 15, r: int = 8, p: int = 1) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024)
    return f"scrypt:{n}:{r}:{p}:{salt.hex()}:{h.hex()}"  # no "$": it lives in a systemd EnvironmentFile


def check_password(pw: str, stored: str) -> bool:
    try:
        kind, n, r, p, salt, want = stored.strip().split(":")
        if kind != "scrypt":
            return False
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024)
    except ValueError:
        return False
    return hmac.compare_digest(got.hex(), want)


def hash_password_cli() -> None:
    """Entry point: print a scrypt hash of a password read from the terminal or stdin."""
    import getpass
    pw = getpass.getpass("Connector password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
    if len(pw) < 12:
        sys.exit("use at least 12 characters")
    print(hash_password(pw))


# ------------------------------------------------------------------ metadata
async def oauth_metadata(request: Request) -> JSONResponse:
    """RFC 8414 OAuth authorization server metadata."""
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


async def protected_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 OAuth protected resource metadata.

    MCP clients (including Claude Code) fetch this first to learn which
    authorization server issues tokens for this resource. Without it, the
    client can't start the OAuth flow and reports "Failed to connect"
    instead of "Needs authentication".
    """
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse({
        "resource": base_url,
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
    })


# ------------------------------------------------------------------ authorize
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Vault</title>
<style>body{{font:16px system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem;color:#222}}
input,button{{font:inherit;padding:.5rem;width:100%;box-sizing:border-box;margin:.4rem 0}}
.err{{color:#a00}}</style></head><body><h1>Obsidian vault</h1>{body}</body></html>"""

_PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                               "form-action 'self' https: http://localhost:* http://127.0.0.1:*; "
                               "frame-ancestors 'none'",
}
_FIELDS = ("response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method",
           "scope", "resource")


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(body=body), status_code=status, headers=_PAGE_HEADERS)


def _form(q: dict, error: str = "") -> HTMLResponse:
    hidden = "".join(f'<input type="hidden" name="{k}" value="{html.escape(q[k])}">' for k in _FIELDS if q.get(k))
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    return _page(
        "<p>A client wants <b>read and write</b> access to the vault.</p>"
        f"{err}<form method=\"post\">{hidden}<label>Connector password"
        '<input type="password" name="password" autocomplete="current-password" autofocus required></label>'
        "<button>Allow</button></form>",
        401 if error else 200)


def _check_request(q: dict) -> str | None:
    """Return an error message for a bad authorize request, else None. Errors are shown on the
    page, never redirected, so a bad redirect_uri can't be used to bounce the browser."""
    if q.get("response_type") != "code":
        return "Only response_type=code is supported."
    uri = q.get("redirect_uri", "")
    p = urlsplit(uri)
    if not uri or p.fragment or not (p.scheme == "https" and p.hostname or
                                     p.scheme == "http" and p.hostname in LOOPBACK):
        return "redirect_uri must be https (or http on localhost)."
    if not q.get("client_id"):
        return "client_id is required."
    if not q.get("code_challenge") or q.get("code_challenge_method", "plain") != "S256":
        return "PKCE with S256 is required."
    return None


async def oauth_authorize(request: Request):
    """OAuth 2.0 authorization endpoint: GET shows the password page, POST checks it."""
    if request.method == "GET":
        q = {k: request.query_params.get(k, "") for k in _FIELDS}
        err = _check_request(q)
        return _page(f'<p class="err">{html.escape(err)}</p>', 400) if err else _form(q)

    form = await request.form()
    q = {k: str(form.get(k, "")) for k in _FIELDS}
    err = _check_request(q)
    if err:
        return _page(f'<p class="err">{html.escape(err)}</p>', 400)
    if not config.VAULT_OAUTH_PASSWORD_HASH:
        logger.error("VAULT_OAUTH_PASSWORD_HASH is not set: refusing every authorization")
        return _page('<p class="err">The server has no connector password set.</p>', 500)

    now = time.time()
    with _lock:
        _failures[:] = [t for t in _failures if t > now - LOCKOUT[1]]
        locked = len(_failures) >= LOCKOUT[0]
    if locked:
        return _form(q, "Too many wrong passwords. Try again in 15 minutes.")
    if not check_password(str(form.get("password", "")), config.VAULT_OAUTH_PASSWORD_HASH):
        with _lock:
            _failures.append(now)
        logger.warning("OAuth authorize: wrong password")
        time.sleep(1)
        return _form(q, "Wrong password.")

    code = secrets.token_urlsafe(32)
    with _lock:
        _cleanup_codes()
        _auth_codes[code] = {
            "client_id": q["client_id"],
            "redirect_uri": q["redirect_uri"],
            "code_challenge": q["code_challenge"],
            "expires_at": now + CODE_TTL,
        }
    logger.info("OAuth authorization code issued (client_id=%s)", q["client_id"])

    params = {"code": code}
    if q["state"]:
        params["state"] = q["state"]
    separator = "&" if urlsplit(q["redirect_uri"]).query else "?"
    return RedirectResponse(url=f"{q['redirect_uri']}{separator}{urlencode(params)}", status_code=302)


# ------------------------------------------------------------------ token
async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.0 token endpoint -- authorization code grant with PKCE, and refresh."""
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")

    if grant_type == "authorization_code":
        return await _handle_authorization_code(form, client_id)
    elif grant_type == "refresh_token":
        return await _handle_refresh_token(form, client_id)
    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def _handle_authorization_code(form, client_id: str) -> JSONResponse:
    """Exchange an authorization code for a bearer token."""
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")

    with _lock:
        _cleanup_codes()
        code_data = _auth_codes.pop(code, None)
    if code_data is None:
        return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired code"}, status_code=400)
    if client_id != code_data["client_id"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "client_id mismatch"}, status_code=400)
    if redirect_uri and redirect_uri != code_data["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # S256: BASE64URL(SHA256(code_verifier)) must match code_challenge
    digest = hashlib.sha256(code_verifier.encode("ascii", "replace")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if not code_verifier or not hmac.compare_digest(computed, code_data["code_challenge"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    access, refresh = await token_store.issue_pair(client_id)
    logger.info("OAuth token issued via authorization_code grant (client_id=%s)", client_id)
    return JSONResponse({
        "access_token": access,
        "token_type": "bearer",
        "expires_in": token_store.ACCESS_TOKEN_TTL,
        "refresh_token": refresh,
    }, headers={"Cache-Control": "no-store"})


async def _handle_refresh_token(form, client_id: str) -> JSONResponse:
    """Rotate a refresh token for a new access+refresh pair. The presented
    client_id must match the refresh token's client_id."""
    refresh_token_value = form.get("refresh_token", "")
    if not refresh_token_value or not client_id:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "refresh_token and client_id required"},
            status_code=400,
        )

    rotated = await token_store.rotate_refresh(refresh_token_value, client_id)
    if rotated is None:
        logger.info("OAuth refresh_token rejected (client_id=%s)", client_id)
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid, expired, or reused refresh token"},
            status_code=400,
        )

    new_access, new_refresh = rotated
    logger.info("OAuth token rotated via refresh_token grant (client_id=%s)", client_id)
    return JSONResponse({
        "access_token": new_access,
        "token_type": "bearer",
        "expires_in": token_store.ACCESS_TOKEN_TTL,
        "refresh_token": new_refresh,
    }, headers={"Cache-Control": "no-store"})


async def oauth_register(request: Request) -> JSONResponse:
    """Dynamic client registration endpoint (public clients: PKCE, no secret)."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    client_id = f"vault-mcp-{secrets.token_hex(8)}"
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "client_name": str(body.get("client_name", "Obsidian Vault MCP Client"))[:100],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": body.get("redirect_uris", []),
        "token_endpoint_auth_method": "none",
    }, status_code=201)


# Starlette routes to mount on the app
oauth_routes = [
    Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
    Route("/oauth/authorize", oauth_authorize, methods=["GET", "POST"]),
    Route("/oauth/token", oauth_token, methods=["POST"]),
    Route("/oauth/register", oauth_register, methods=["POST"]),
]
