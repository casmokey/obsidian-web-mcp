# obsidian-web-mcp

A secure, remote-accessible MCP server that gives LLMs read/write access to your Obsidian vault from anywhere -- your desktop, your phone, a hotel Wi-Fi network. Unlike local-only Obsidian MCP servers, this one runs over HTTPS with real authentication, so Claude (or any MCP client) can reach your vault whether you're at your desk or not.

It reads and writes markdown files on disk, parses YAML frontmatter, maintains an in-memory frontmatter index for fast queries, and handles full-text search -- all behind OAuth 2.0 authentication and a Cloudflare Tunnel that never exposes your machine directly to the internet.

## Why This Exists

There are many Obsidian MCP servers. Most are local stdio servers -- they work when Claude Code is running on the same machine as your vault. That's useful, but it means:

- **Claude.ai (web) can't reach your vault.** The browser-based Claude has no way to connect to a local stdio server.
- **Claude on your phone can't reach your vault.** Same problem.
- **If you use Obsidian Sync, local MCP servers can corrupt files.** Non-atomic writes create partial files that Sync propagates to every device.

This server solves all three. It runs as a persistent HTTP service on the machine where your vault lives, tunneled securely through Cloudflare, and authenticates via OAuth 2.0 -- the same protocol Claude uses for Gmail, Google Calendar, and other integrations. The result: your vault becomes a first-class MCP connector available everywhere Claude is.

## Architecture

```
+----------+     +------------+     +-----------------+     +------------------+
| Obsidian | <-> | Filesystem | <-> | obsidian-web-mcp| <-> | Cloudflare       |
| (app)    |     | (*.md)     |     | (MCP over HTTPS)|     | Tunnel           |
+----------+     +------------+     +-----------------+     +------------------+
                                                                   |
                                                            +------+-------+
                                                            | Claude       |
                                                            | (web/desktop/|
                                                            |  mobile)     |
                                                            +--------------+
```

Your vault files never leave your machine. Cloudflare Tunnel creates an outbound-only connection from your server to Cloudflare's edge -- no inbound ports opened, no public IP exposed, no port forwarding. Claude connects to the Cloudflare edge, which relays requests through the tunnel to your server.

Obsidian and the MCP server both operate on the same directory of markdown files. The server uses atomic writes (write-to-temp-then-rename) so Obsidian Sync and the server never conflict.

## Security Model

This is a server that provides network access to your personal notes. Security is not optional.

**Authentication is enforced on every request.** The server implements the OAuth 2.0 authorization code flow with PKCE for initial client authentication (what Claude uses when you connect the integration), plus bearer token validation on every subsequent MCP tool call. No request reaches a tool function without a valid token. Only the OAuth endpoints and `/health` are exempt from bearer auth.

**A connector password gates authorization.** Client registration is open (Claude needs that), so the password typed on the server's authorize page is the security boundary. It is stored only as a scrypt hash (`VAULT_OAUTH_PASSWORD_HASH`); if it is unset, no client can be authorized. Five wrong passwords within 15 minutes lock the page for 15 minutes. Access tokens last 1 hour; refresh tokens last 30 days and rotate on use, and reuse of a rotated refresh token revokes the whole token family.

**The server binds to loopback by default** (`127.0.0.1`), so only a local tunnel or local clients can reach it.

**Your vault is never exposed directly to the internet.** The recommended deployment uses a Cloudflare Tunnel -- an outbound-only encrypted connection. Your machine opens no inbound ports. You can layer Cloudflare Access on top for additional authentication (SSO, device posture checks, IP restrictions) if you want defense in depth.

**Path traversal is blocked at the filesystem layer.** Every file operation resolves paths against the vault root directory and rejects any attempt to escape it -- `..` traversal, symlink following, null byte injection, and dotfile access (`.obsidian`, `.git`, `.trash`) are all caught before they reach the filesystem. The server will never read or write outside your vault directory.

**Writes are atomic.** Every file write goes to a temporary file first, then atomically replaces the target via `os.replace()`. This guarantees that neither Obsidian nor Obsidian Sync ever sees a partially-written file -- the operation either completes fully or doesn't happen at all.

**Safety limits prevent abuse.** Writes are capped at 1MB per file, batch operations at 20 files per request, and search results at 50 matches. Deletions are soft -- files move to `.trash/` rather than being permanently removed, matching Obsidian's own behavior. The delete tool also requires an explicit `confirm=true` parameter as a safety gate.

## Tools

| Tool | Description |
|------|-------------|
| `vault_read` | Read a file, returning content, metadata, and parsed YAML frontmatter |
| `vault_batch_read` | Read multiple files in one call; handles missing files gracefully |
| `vault_write` | Write a file with optional frontmatter merging; creates parent dirs |
| `vault_batch_frontmatter_update` | Update YAML frontmatter fields on multiple files without touching body content |
| `vault_search` | Full-text search across vault files (uses ripgrep if available, falls back to Python) |
| `vault_search_frontmatter` | Query the in-memory frontmatter index by field value, substring, or field existence |
| `vault_list` | List directory contents with recursion depth, glob filtering, and file/dir toggles |
| `vault_move` | Move or rename a file or directory within the vault |
| `vault_delete` | Soft-delete a file by moving it to `.trash/` (requires explicit confirmation) |

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- An Obsidian vault (any directory of markdown files)
- [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) (only needed for remote access)
- A domain managed by Cloudflare (only needed for remote access)

## Quick Start

### Local development

```bash
# Clone and enter the project
git clone https://github.com/casmokey/obsidian-web-mcp.git
cd obsidian-web-mcp

# Admin bearer token for direct (non-OAuth) clients
export VAULT_MCP_TOKEN=$(python -c "import secrets; print(secrets.token_hex(32))")

# Connector password hash for the OAuth authorize page (prompts for a password of 12+ characters)
export VAULT_OAUTH_PASSWORD_HASH=$(uv run vault-mcp-hash-password)

# Point at your vault
export VAULT_PATH="$HOME/Obsidian/MyVault"

# Run the server
uv run vault-mcp
```

The server listens on `127.0.0.1:8420` by default and serves MCP over Streamable HTTP at `/mcp/`. It exits at startup if `VAULT_PATH` is not a directory.

## Configuration

All configuration is via environment variables (read in `src/obsidian_vault_mcp/config.py`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_PATH` | Yes | `~/Obsidian/MyVault` | Path to your Obsidian vault directory |
| `VAULT_MCP_TOKEN` | Yes | (none) | Admin bearer token for direct clients. If unset, every authenticated request is rejected |
| `VAULT_OAUTH_PASSWORD_HASH` | Yes, for OAuth clients | (none) | scrypt hash of the connector password, from `vault-mcp-hash-password`. If unset, no OAuth client can be authorized |
| `VAULT_MCP_HOST` | No | `127.0.0.1` | Interface the HTTP server binds to |
| `VAULT_MCP_PORT` | No | `8420` | Port the HTTP server listens on |
| `VAULT_MCP_PUBLIC_HOSTS` | For remote access | (empty) | Comma-separated public hostnames your tunnel forwards. Requests with any other `Host` header are refused (DNS rebinding protection) |
| `VAULT_MCP_NAME` | No | `Obsidian vault` | Name shown on the sign-in page |
| `VAULT_OAUTH_DB_PATH` | No | `~/.local/share/obsidian-vault-mcp/oauth.db` | SQLite file holding OAuth access and refresh tokens |

Generate a bearer token with: `python -c "import secrets; print(secrets.token_hex(32))"`

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| `8420` (`VAULT_MCP_PORT`) | HTTP, on `VAULT_MCP_HOST` (loopback by default) | MCP at `/mcp/`, OAuth endpoints (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/oauth/authorize`, `/oauth/token`, `/oauth/register`) |

No other ports are opened. Remote access goes through an outbound-only Cloudflare Tunnel that forwards to this port.

## Dependencies

- Runtime (from `pyproject.toml`): `mcp[cli]>=1.9.0`, `python-frontmatter>=1.1.0`, `pydantic>=2.0`, `watchdog>=4.0.0`
- Dev: `pytest>=8.0`, `pytest-asyncio>=0.23`
- Optional: `ripgrep` (faster full-text search), `cloudflared` (remote access)

## Connecting to Claude

The Claude desktop and mobile apps can connect to remote MCP servers via OAuth.

1. Start the server (locally or behind a tunnel) with `VAULT_OAUTH_PASSWORD_HASH` set
2. Open Claude and go to **Settings > Integrations > Add Integration**
3. Enter your server URL (e.g. `https://vault-mcp.yourdomain.com`)
4. Claude registers itself dynamically, discovers the OAuth endpoints, and opens a browser window
5. Type the connector password on the server's sign-in page; the server redirects back with an authorization code
6. Claude now has access to all nine vault tools -- on desktop and mobile

For local-only use (no tunnel), point Claude at `http://localhost:8420`. Clients that do not run OAuth can send `Authorization: Bearer <VAULT_MCP_TOKEN>` directly.

## Remote Access with Cloudflare Tunnel

To make the server accessible from anywhere:

```bash
# Install cloudflared
brew install cloudflare/cloudflare/cloudflared

# Set your desired hostname and run the interactive setup
export VAULT_MCP_HOSTNAME="vault-mcp.yourdomain.com"
./scripts/setup-tunnel.sh
```

The script authenticates with Cloudflare, creates a tunnel named `vault-mcp`, writes `~/.cloudflared/config-vault-mcp.yml` (ingress to `http://localhost:8420`), and sets up the DNS record. You will need a domain managed by Cloudflare. `VAULT_MCP_HOSTNAME` is read by this script only, not by the server.

Then tell the server which public hostname to accept:

```bash
export VAULT_MCP_PUBLIC_HOSTS="vault-mcp.yourdomain.com"
```

If you already run a `cloudflared` instance for other hostnames, add the ingress rule to that configuration instead of running a second connector.

## Production Deployment

The server is a single foreground process (`vault-mcp`), so any supervisor that sets the environment variables above and restarts it on failure will do (systemd, launchd, a container, and so on).

### macOS (launchd)

`scripts/launchd/` has plist templates that run the server and the tunnel at login and restart them on failure.

```bash
cp scripts/launchd/com.example.vault-mcp.plist ~/Library/LaunchAgents/
cp scripts/launchd/com.example.cloudflared-vault.plist ~/Library/LaunchAgents/
```

Replace the `REPLACE_WITH_*` placeholders in each plist (paths to `uv`, the project, the vault and `cloudflared`, your home directory, and the token values). Note that `com.example.vault-mcp.plist` still sets the old `VAULT_OAUTH_CLIENT_ID` and `VAULT_OAUTH_CLIENT_SECRET` variables, which the server no longer reads: replace them with `VAULT_OAUTH_PASSWORD_HASH` (and add `VAULT_MCP_PUBLIC_HOSTS` for remote access).

```bash
launchctl load ~/Library/LaunchAgents/com.example.vault-mcp.plist
launchctl load ~/Library/LaunchAgents/com.example.cloudflared-vault.plist
```

Verify with `launchctl list | grep vault`, `curl -s http://localhost:8420/.well-known/oauth-authorization-server`, and `tail -f ~/Library/Logs/vault-mcp-error.log`.

## Obsidian Sync Compatibility

The server coexists with Obsidian Sync (or any file-based sync mechanism) without conflict. All writes use atomic file replacement (`write-to-temp-then-rename`), which means:

- Obsidian never sees a half-written file
- If Sync and the MCP server write to the same file simultaneously, the last write wins (standard filesystem semantics) but neither write is corrupted
- The frontmatter index watches for filesystem changes via `watchdog` and updates automatically when Sync brings in new files

## Development

### Running tests

```bash
uv run pytest tests/ -v
```

Tests use temporary directories and never touch your real vault.

### Project structure

```
src/obsidian_vault_mcp/
    auth.py                 # Bearer token middleware (Starlette)
    config.py               # Environment variable configuration
    frontmatter_index.py    # In-memory YAML frontmatter index with filesystem watcher
    models.py               # Pydantic input validation models
    oauth.py                # OAuth 2.0 authorization code flow with PKCE, connector password page
    server.py               # FastMCP server setup, tool registration, entry point
    token_store.py          # SQLite-backed OAuth access/refresh tokens with rotation
    vault.py                # Core filesystem operations (path security, atomic writes)
    tools/
        manage.py           # list, move, delete tools
        read.py             # read, batch_read tools
        search.py           # full-text search, frontmatter search tools
        write.py            # write, batch_frontmatter_update tools
tests/
    conftest.py             # Shared fixtures (temp vault with sample files)
    test_frontmatter.py     # Frontmatter index and query tests
    test_oauth.py           # OAuth flow, password and token store tests
    test_tools.py           # Integration tests for tool functions
    test_vault.py           # Path resolution and file operation tests
scripts/
    setup-tunnel.sh         # Interactive Cloudflare Tunnel setup
    launchd/                # macOS launchd plist templates
```

## License

MIT -- see [LICENSE](LICENSE).
