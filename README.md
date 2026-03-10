# gogcli-safe

A fork of [steipete/gogcli](https://github.com/steipete/gogcli) that adds **Gmail access control** and a **credential-isolating proxy** for safe use by AI agents and automated workflows.

The upstream `gogcli` is a fast, script-friendly CLI for Gmail, Calendar, Drive, Docs, Sheets, and many more Google APIs. This fork keeps all of that and adds a security layer so you can hand Gmail access to an untrusted process (like an LLM agent) without giving it unrestricted access to your full inbox or credentials.

## What this fork adds

- **Per-account access policies** — allow/deny rules by email address and domain, keyed per Google account, that filter all Gmail operations (search, read, send, drafts)
- **Proxy server** — a Unix socket proxy that holds credentials in a separate process, so the agent process never sees your OAuth tokens
- **Nonce authentication** — the proxy validates each request with a one-time nonce to prevent unauthorized socket connections
- **Policy management CLI** — `gog config access-policy` commands to create, inspect, and test policies

Everything else (Calendar, Drive, Docs, Sheets, Contacts, Tasks, etc.) works exactly as upstream. See the [upstream README](https://github.com/steipete/gogcli) for the full command reference and general documentation.

## Installation

Build from source (requires Go 1.21+):

```bash
git clone https://github.com/jimmingcheng/gogcli-safe.git
cd gogcli-safe
make
```

The binary is at `./bin/gog`. For initial setup (OAuth credentials, account authorization, configuration), follow the [upstream Quick Start guide](https://github.com/steipete/gogcli#quick-start).

## Access Policies

An access policy restricts which email addresses a Gmail session can interact with. Policies are **per-account** — each Google account can have independent allow/deny rules. Accounts not listed in the policy file are unrestricted.

Policies operate in one of two modes:

- **allow** (whitelist) — only listed addresses/domains are permitted
- **deny** (blacklist) — listed addresses/domains are blocked; everything else is permitted

When a policy is active, it affects every Gmail operation:

| Operation | Effect |
|-----------|--------|
| `gmail search` / `gmail messages` | Query is augmented to include/exclude addresses; results are filtered |
| `gmail get` | Blocked if message involves restricted addresses |
| `gmail thread get` | Messages with restricted addresses are removed from the thread |
| `gmail send` | Blocked if any recipient (to/cc/bcc) is restricted |
| `gmail drafts` | Filtered the same as search and thread operations |

### Managing policies

All policy management commands require `--account` to specify which account to operate on:

```bash
# Create an allow-only policy for a personal account
gog config access-policy set --account you@gmail.com --mode allow \
  --addresses "alice@example.com,bob@work.com" \
  --domains "trusted-corp.com"

# Create a deny policy for a work account
gog config access-policy set --account work@company.com --mode deny \
  --domains "spam.com"

# Add an address to an existing account's policy
gog config access-policy add --account you@gmail.com --address "carol@example.com"

# Add a domain
gog config access-policy add --account you@gmail.com --domain "another-trusted.org"

# Remove an entry
gog config access-policy remove --account you@gmail.com --address "bob@work.com"

# View all accounts' policies
gog config access-policy show

# View a specific account's policy
gog config access-policy show --account you@gmail.com

# Test whether an address is allowed for an account
gog config access-policy test --account you@gmail.com alice@example.com
# → alice@example.com: allowed (allow mode)

gog config access-policy test --account you@gmail.com stranger@unknown.com
# → stranger@unknown.com: BLOCKED (allow mode)

# Test an unlisted account — always allowed (unrestricted)
gog config access-policy test --account unlisted@other.com anything@example.com
# → anything@example.com: allowed (no policy for account)
```

The policy file is stored at `~/.config/gogcli-safe/access-policy.json`:

```json
{
  "gmail": {
    "accounts": {
      "you@gmail.com": {
        "mode": "allow",
        "addresses": ["alice@example.com", "carol@example.com"],
        "domains": ["trusted-corp.com", "another-trusted.org"]
      },
      "work@company.com": {
        "mode": "deny",
        "domains": ["spam.com"]
      }
    }
  }
}
```

Accounts not listed in the file are unrestricted (no filtering).

### Loading a policy

Policies are loaded via the `--access-policy` flag or `GOG_ACCESS_POLICY` environment variable. The account is determined from `--account` or `GOG_ACCOUNT`:

```bash
# Via flags
gog --account you@gmail.com --access-policy ~/.config/gogcli-safe/access-policy.json gmail search inbox

# Via environment variables
export GOG_ACCOUNT=you@gmail.com
export GOG_ACCESS_POLICY=~/.config/gogcli-safe/access-policy.json
gog gmail search inbox
```

## Proxy Mode

The proxy separates credentials from the process that runs commands. A trusted **server** process holds your OAuth tokens and access policy; an untrusted **client** process sends commands over a Unix socket.

```
Agent / untrusted process          Proxy server (trusted)
┌─────────────────────┐           ┌─────────────────────────┐
│ GOG_PROXY_SOCKET=... │──────────│ Holds OAuth credentials  │
│ gog gmail search ... │  Unix    │ Enforces access policy   │
│                      │  socket  │ Blocks dangerous commands│
│ (no credentials)     │──────────│ Returns stdout/stderr    │
└─────────────────────┘           └─────────────────────────┘
```

### Starting the proxy server

```bash
gog proxy serve \
  --account you@gmail.com \
  --policy ~/.config/gogcli-safe/access-policy.json
```

This will:
1. Load credentials for the specified account
2. Load the access policy for that account into memory (immutable for the session)
3. Generate a random nonce and write it to `~/.config/gogcli-safe/proxy.nonce`
4. Listen on `~/.config/gogcli-safe/proxy.sock`

You can customize paths:

```bash
gog proxy serve \
  --account you@gmail.com \
  --policy /path/to/policy.json \
  --socket /tmp/gog-proxy.sock \
  --nonce-file /tmp/gog-proxy.nonce
```

### Running commands through the proxy

In the agent's environment, set the socket and nonce file paths:

```bash
export GOG_PROXY_SOCKET=~/.config/gogcli-safe/proxy.sock
export GOG_PROXY_NONCE_FILE=~/.config/gogcli-safe/proxy.nonce

# These commands are forwarded to the proxy server
gog gmail search "from:alice@example.com"
gog gmail thread get <threadId>
gog --json gmail messages search "newer_than:7d" --max 10
```

The client reads the nonce from disk, sends it with the command over the socket, and displays the server's response. The agent process never has access to OAuth tokens.

### Proxy security

The proxy blocks commands and flags that could compromise security:

**Blocked commands** — `auth`, `config`, `login`, `logout`, `status`, `proxy`, `version`

**Blocked flags** — `--access-token`, `--access-policy`, `--account` (the server injects its own account)

**Other protections:**
- Socket created with `0600` permissions (user-only)
- Nonce file created with `0600` permissions
- Nonce verified with constant-time comparison
- `GOG_PROXY_SOCKET` is cleared during in-process execution to prevent recursion

## End-to-end example

Set up an agent that can only interact with specific contacts:

```bash
# 1. Create the policy for your account
gog config access-policy set --account you@gmail.com --mode allow \
  --addresses "teammate@company.com,manager@company.com" \
  --domains "company.com"

# 2. Start the proxy (Terminal A)
gog proxy serve --account you@gmail.com \
  --policy ~/.config/gogcli-safe/access-policy.json

# 3. Give the agent these environment variables (Terminal B)
export GOG_PROXY_SOCKET=~/.config/gogcli-safe/proxy.sock
export GOG_PROXY_NONCE_FILE=~/.config/gogcli-safe/proxy.nonce

# Agent can search — query is automatically augmented with policy
gog gmail search inbox
# Only returns threads involving @company.com addresses

# Agent can read allowed threads
gog gmail thread get <threadId>

# Agent can send to allowed addresses
gog gmail send --to teammate@company.com --subject "Update" --body "Done."

# Agent CANNOT send to restricted addresses
gog gmail send --to stranger@outside.com --subject "Hi" --body "..."
# Error: access policy: sending to restricted address(es): stranger@outside.com

# Agent CANNOT access credentials
gog auth list
# Error: command 'auth' is blocked through the proxy
```

## Environment variables

In addition to all [upstream environment variables](https://github.com/steipete/gogcli#environment-variables), this fork adds:

| Variable | Description |
|----------|-------------|
| `GOG_ACCESS_POLICY` | Path to access policy JSON file |
| `GOG_PROXY_SOCKET` | Unix socket path for proxy mode (client side) |
| `GOG_PROXY_NONCE_FILE` | Path to nonce file for proxy authentication |

## Policy file format

```json
{
  "gmail": {
    "accounts": {
      "you@gmail.com": {
        "mode": "allow",
        "addresses": [
          "alice@example.com",
          "Bob <bob@work.com>"
        ],
        "domains": [
          "trusted-corp.com"
        ]
      },
      "work@company.com": {
        "mode": "deny",
        "domains": [
          "spam.com"
        ]
      }
    }
  }
}
```

- **accounts** — Map of Google account email → policy. Unlisted accounts are unrestricted.
- **mode** — `"allow"` (whitelist) or `"deny"` (blacklist)
- **addresses** — Email addresses; RFC 5322 format with display names is accepted and normalized
- **domains** — Domain names; all addresses at the domain are matched
- All matching is case-insensitive

## Development

```bash
make tools   # Install goimports, gofumpt, golangci-lint
make fmt     # Format
make lint    # Lint
make test    # Test
```

See the [upstream development docs](https://github.com/steipete/gogcli#development) for integration tests and live test scripts.

## License

MIT — see [LICENSE](LICENSE).

This fork retains the original copyright. See LICENSE for details.

## Links

- [This fork](https://github.com/jimmingcheng/gogcli-safe)
- [Upstream repository](https://github.com/steipete/gogcli)
- [Upstream README](https://github.com/steipete/gogcli#readme) — full command reference for Gmail, Calendar, Drive, Docs, Sheets, and all other Google APIs

## Credits

Original project by [Peter Steinberger](https://github.com/steipete), inspired by Mario Zechner's CLIs ([gmcli](https://github.com/badlogic/gmcli), [gccli](https://github.com/badlogic/gccli), [gdcli](https://github.com/badlogic/gdcli)).
