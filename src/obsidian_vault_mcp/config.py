import os
from pathlib import Path

# Vault configuration
VAULT_PATH = Path(os.environ.get("VAULT_PATH", os.path.expanduser("~/Obsidian/MyVault")))
VAULT_MCP_TOKEN = os.environ.get("VAULT_MCP_TOKEN", "")
VAULT_MCP_PORT = int(os.environ.get("VAULT_MCP_PORT", "8420"))
# Loopback only by default: a Cloudflare tunnel (or Claude Code on this machine) reaches it there.
VAULT_MCP_HOST = os.environ.get("VAULT_MCP_HOST", "127.0.0.1")

# OAuth 2.0 (for Claude app integration): scrypt hash of the connector password typed on the
# authorize page. Unset = no client can be authorized.
VAULT_OAUTH_PASSWORD_HASH = os.environ.get("VAULT_OAUTH_PASSWORD_HASH", "")
VAULT_OAUTH_DB_PATH = os.environ.get(
    "VAULT_OAUTH_DB_PATH",
    os.path.expanduser("~/.local/share/obsidian-vault-mcp/oauth.db"),
)

# Safety limits
MAX_CONTENT_SIZE = 1_000_000  # 1MB max write size
MAX_BATCH_SIZE = 20           # Max files per batch operation
MAX_SEARCH_RESULTS = 50       # Max results per search
DEFAULT_SEARCH_RESULTS = 20
MAX_LIST_DEPTH = 5            # Max directory recursion depth
CONTEXT_LINES = 2             # Default lines of context in search results

# Directories to never expose or modify
EXCLUDED_DIRS = {".obsidian", ".trash", ".git", ".DS_Store"}

# Frontmatter index refresh interval (seconds)
FRONTMATTER_INDEX_DEBOUNCE = 5.0

# Rate limiting (requests per minute) -- track in-memory, enforce per-token
RATE_LIMIT_READ = 100
RATE_LIMIT_WRITE = 30
