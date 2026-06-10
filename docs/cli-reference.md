# CLI Reference

This document covers every `servonaut` subcommand. For installation and
configuration see [Configuration Guide](configuration.md).

## Global flags

| Flag | Description |
|------|-------------|
| `--debug` | Enable verbose debug logging to stderr and `~/.servonaut/logs/servonaut.log` |
| `--ai-provider <name>` | Override the active AI provider for this invocation (`servonaut`, `openai`, `anthropic`, `ollama`, `gemini`). Does not mutate `config.json`. |
| `--no-tools` | Disable AI tool execution for this invocation — sets `allow_tools: false` in the request. Useful for read-only scripted use. |

`SERVONAUT_AI_PROVIDER` environment variable has the same effect as `--ai-provider`
and is honoured by all `servonaut ai *` subcommands.

---

## `servonaut ai`

The `ai` subcommand tree gives headless (non-TUI) access to the Servonaut AI
gateway. All subcommands require a valid login session — see
[`servonaut login`](#servonaut-login).

### Exit codes

All `servonaut ai *` commands use these exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Other / unknown error |
| `2` | Unauthenticated — run `servonaut login` |
| `3` | Insufficient entitlement — Solo or Teams plan required |
| `4` | Quota exhausted — run `servonaut ai topup` |
| `5` | Budget (cost-cap) exhausted — run `servonaut ai topup` |

---

### `servonaut ai chat`

Send a single prompt to the AI gateway and print the response.

```
servonaut ai chat <prompt> [--stream] [--no-tools] [--ai-provider <name>]
```

**Arguments:**

| Argument / flag | Type | Default | Description |
|-----------------|------|---------|-------------|
| `<prompt>` | string | required | The user message. Wrap in quotes for multi-word prompts. |
| `--stream` | flag | off | Stream tokens to stdout as they arrive (SSE mode). Without this flag the command waits for the full response and prints it at once (buffered mode). |
| `--no-tools` | flag | off | Disable tool execution; server will not emit `tool_call` events. Use when you want a read-only, non-interactive chat for scripting. |
| `--ai-provider <name>` | string | from config | Override the provider for this invocation only. |

**Examples:**

```bash
# Buffered (default) — waits for the complete answer
servonaut ai chat "why is nginx 502ing on web-prod-1?"

# Streamed — tokens appear as they are generated
servonaut ai chat --stream "summarise the last 50 errors in /var/log/app/error.log on api-server-2"

# Read-only: disable tool execution
servonaut ai chat --no-tools "what is the difference between a NACL and a security group?"
```

---

### `servonaut ai quota`

Print your current Servonaut AI token quota to stdout.

```
servonaut ai quota [--json]
```

**Arguments:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | off | Output raw JSON instead of the human-readable summary. Useful for scripts. |

**Examples:**

```bash
# Human-readable summary
servonaut ai quota
# Tokens used: 1,234,567 / 15,000,000 (≈ 2,753 queries remaining)
# Top-up balance: +500,000
# Resets: in 4 days (2026-05-01)

# Machine-readable
servonaut ai quota --json

# Use in a shell script
remaining=$(servonaut ai quota --json | jq .tokens_topup_remaining)
```

---

### `servonaut ai conversations list`

List your AI conversations, most-recent first.

```
servonaut ai conversations list [--limit <n>] [--before <iso>] [--status <status>] [--json]
```

**Arguments:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--limit <n>` | int | `25` | Number of conversations to return. Maximum 100. |
| `--before <iso>` | ISO 8601 string | — | Pagination cursor. Return only conversations updated before this timestamp. |
| `--status <status>` | string | `active` | Filter by status. One of `active`, `archived`, `deleted`. |
| `--json` | flag | off | Emit JSON array instead of tabular output. |

**Examples:**

```bash
# List the 10 most recent active conversations
servonaut ai conversations list --limit 10

# Paginate — fetch the next page using the last updated_at value
servonaut ai conversations list --before "2026-04-27T14:32:00Z"

# List archived conversations as JSON
servonaut ai conversations list --status archived --json
```

---

### `servonaut ai conversations show`

Print a full conversation thread (all messages) to stdout.

```
servonaut ai conversations show <uuid> [--json]
```

**Arguments:**

| Argument / flag | Type | Default | Description |
|-----------------|------|---------|-------------|
| `<uuid>` | UUID string | required | The conversation ID. Get it from `conversations list`. |
| `--json` | flag | off | Emit the raw JSON thread instead of formatted output. |

**Examples:**

```bash
# Formatted output
servonaut ai conversations show 550e8400-e29b-41d4-a716-446655440000

# Raw JSON
servonaut ai conversations show 550e8400-e29b-41d4-a716-446655440000 --json

# Pipe into jq to extract only assistant messages
servonaut ai conversations show 550e8400-e29b-41d4-a716-446655440000 --json \
  | jq '[.messages[] | select(.role=="assistant")]'
```

---

### `servonaut ai conversations export`

Export a conversation to a local file.

```
servonaut ai conversations export <uuid> <path> [--format md|json] [--force]
```

**Arguments:**

| Argument / flag | Type | Default | Description |
|-----------------|------|---------|-------------|
| `<uuid>` | UUID string | required | The conversation ID. |
| `<path>` | file path | required | Destination file path. Must resolve within the current working directory or `~/Downloads/`. Path traversal (`../`) is rejected. |
| `--format md\|json` | string | `md` | Export format: `md` for Markdown, `json` for raw JSON thread. |
| `--force` | flag | off | Overwrite `<path>` if it already exists. Without this flag the command exits with an error if the file exists. |

**Examples:**

```bash
# Export as Markdown to the current directory
servonaut ai conversations export 550e8400-e29b-41d4-a716-446655440000 ./nginx-debug.md

# Export as JSON, overwriting if the file already exists
servonaut ai conversations export 550e8400-e29b-41d4-a716-446655440000 \
  ~/Downloads/incident-2026-04-28.json --format json --force

# Export to Downloads folder
servonaut ai conversations export 550e8400-e29b-41d4-a716-446655440000 \
  ~/Downloads/chat.md
```

---

### `servonaut ai conversations archive`

Archive a conversation (moves it out of the `active` list without deleting it).

```
servonaut ai conversations archive <uuid>
```

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `<uuid>` | UUID string | The conversation ID to archive. |

**Examples:**

```bash
servonaut ai conversations archive 550e8400-e29b-41d4-a716-446655440000

# Archive everything from a date (requires jq)
servonaut ai conversations list --json \
  | jq -r '.[].id' \
  | xargs -I{} servonaut ai conversations archive {}
```

---

### `servonaut ai conversations delete`

Soft-delete a conversation. Deleted conversations can be listed with
`--status deleted` but are excluded from normal listings.

```
servonaut ai conversations delete <uuid>
```

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `<uuid>` | UUID string | The conversation ID to delete. |

**Examples:**

```bash
servonaut ai conversations delete 550e8400-e29b-41d4-a716-446655440000

# Delete a specific conversation and confirm it is gone
servonaut ai conversations delete 550e8400-e29b-41d4-a716-446655440000 \
  && echo "Deleted."
```

---

### `servonaut ai topup`

Open a Stripe Checkout session to purchase additional AI tokens.

```
servonaut ai topup [<pack>]
```

**Arguments:**

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `<pack>` | string | interactive | Top-up pack to purchase: `small`, `medium`, or `large`. If omitted, the TUI modal (or a CLI prompt) lets you choose. |

The command calls `POST /api/ai/topup/checkout`, receives a `checkout_url`, and
opens it in your default browser via `$BROWSER` / `webbrowser.open`. Stripe is
not embedded in the CLI. After the purchase completes the CLI schedules background
entitlement refreshes at +30 s and +60 s so your new `tokens_topup_remaining`
balance appears quickly.

**Examples:**

```bash
# Interactive pack selection
servonaut ai topup

# Buy the small pack directly
servonaut ai topup small

# Buy the medium pack and confirm the URL is opening
servonaut ai topup medium
# Opening https://checkout.stripe.com/... in your browser.
```

---

### `servonaut ai provider reset`

Clear the persistent provider preference and all dismissed-banner flags.
After this command, the provider picker decision tree runs again on the next
chat start.

```
servonaut ai provider reset
```

This command takes no arguments or flags.

**Examples:**

```bash
# Reset preference so the first-run picker shows again
servonaut ai provider reset

# Reset and immediately check which provider is active
servonaut ai provider reset && servonaut ai quota
```

---

## `servonaut connect`

Manage the Mercure SSE relay listener. Required for hosted AI agents and
team-mates to reach your instances.

```
servonaut connect [--bg] [--status] [--stop] [--reconnect] [--force-bg]
```

| Flag | Description |
|------|-------------|
| _(no flag)_ | Run relay in the foreground; Ctrl+C to stop |
| `--bg` | Detach; writes `~/.servonaut/relay.pid` |
| `--status` | Show local + backend connection status and any divergence |
| `--stop` | Send SIGTERM to the background listener |
| `--reconnect` | Stop then start the listener (heals a stale SSE socket) |
| `--force-bg` | Take over from the TUI's in-process listener |

**Examples:**

```bash
servonaut connect --bg          # start background relay
servonaut connect --status      # check status
servonaut connect --reconnect   # heal a stale connection
servonaut connect --stop        # stop
```

---

## `servonaut login`

Sign in to servonaut.dev via the OAuth2 device flow — works headless, no
TUI needed.

```bash
servonaut login                # prints a URL + code, waits for approval
servonaut login --no-browser   # never try to open a local browser
servonaut login --force        # re-authenticate over an existing session
```

The command prints a verification URL and a short code; open the URL in any
browser **on any device**, enter the code, and the CLI completes sign-in
automatically. Tokens are stored at `~/.servonaut/auth.json` (mode `0600`)
and are shared by every CLI subcommand, the MCP server, and the TUI — you
only sign in once per machine. After signing in, entitlements are fetched
and cached — the `premium_ai` and `allow_dangerous_ai_tools` flags become
available immediately.

Prefer the TUI? **Account → Login** in the sidebar runs the same flow.

---

## `servonaut logout`

Sign out: revoke the session at servonaut.dev (best-effort — local sign-out
proceeds even if the server is unreachable) and delete
`~/.servonaut/auth.json`.

```bash
servonaut logout
```

---

## Other top-level commands

| Command | Description |
|---------|-------------|
| `servonaut` | Launch the TUI |
| `servonaut --debug` | Launch the TUI with verbose logging |
| `servonaut --update` | Check for and apply updates from PyPI |
| `servonaut --install-desktop` | Create a desktop shortcut (Linux/macOS) |
| `servonaut --setup-ovh` | Guided OVHcloud credential setup |
| `servonaut --mcp` | Start as an MCP server (stdio transport) |
| `servonaut --mcp-install <agent>` | Auto-install MCP into `claude`, `opencode`, `cursor`, `windsurf`, `vscode`, or `all` |

See [MCP Tools reference](mcp-tools.md) for the full list of MCP tools.
