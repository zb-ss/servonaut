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

**Cancelling:** Ctrl+C cancels any running command with a one-line
`Cancelled.` and exit code `130` (the shell convention for SIGINT) — never a
traceback. `servonaut login` prints `Sign-in aborted.` (exit `130`).

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
| `4` | Invalid command usage, such as an unknown catalog key |

---

### `servonaut ai chat`

Send a single prompt to the AI gateway and print the response.

```
servonaut ai chat <prompt> [--stream] [--no-tools] [--tools] [--ai-provider <name>]
```

**Arguments:**

| Argument / flag | Type | Default | Description |
|-----------------|------|---------|-------------|
| `<prompt>` | string | required | The user message. Wrap in quotes for multi-word prompts. |
| `--stream` | flag | off | Stream tokens to stdout as they arrive (SSE mode). Without this flag the command waits for the full response and prints it at once (buffered mode). |
| `--no-tools` | flag | off | Disable tool execution; server will not emit `tool_call` events. Use when you want a read-only, non-interactive chat for scripting. |
| `--tools` | flag | off | Re-enable tool execution in buffered mode. Buffered chat defaults tools **off** — tool calls are executed by the TUI chat panel, so a headless buffered request with tools would block until the server's wall-clock cap and return no answer. `--no-tools` wins if both are given. |
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

Print your current hosted AI balance to stdout.

```
servonaut ai quota [--json]
```

**Arguments:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | off | Output the legacy quota projection plus the additive raw balance object when available. Useful for scripts. |

**Examples:**

```bash
# Human-readable summary uses the server's money display values
servonaut ai quota
# Balance remaining: £4.50
# Spent this period: £1.25
# Allowance remaining: £1.00

# Machine-readable: read money micros when a balance object is present
remaining=$(servonaut ai quota --json | jq .balance.remaining_micros)
```

Older servers may not return `balance`; in that case the command retains the
legacy token quota output and JSON fields for compatibility. New integrations
should prefer `balance.remaining_micros` and the server-provided display strings.

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

Open a Stripe Checkout session to purchase an available hosted AI balance pack.

```
servonaut ai topup [<pack>]
```

**Arguments:**

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `<pack>` | string | omitted | Current top-up catalog key. If omitted, Servonaut loads and lists the available catalog, then exits. |

The command loads the current catalog from `GET /api/ai/topup/packs`, then calls
`POST /api/ai/topup/checkout`, receives a `checkout_url`, and opens it in your
default browser via `$BROWSER` / `webbrowser.open`. Stripe is not embedded in the
CLI. The command exits after it opens checkout; after completing the purchase,
run `servonaut ai quota` to retrieve the latest hosted balance.

**Examples:**

```bash
# List the current catalog, then choose a key
servonaut ai topup

# Buy a key shown by the current catalog
servonaut ai topup <catalog-key>
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

**Authentication:** the listener uses your stored `servonaut login`
session (with automatic token refresh). Setting both
`SERVONAUT_RELAY_TOKEN` and `SERVONAUT_USER_ID` overrides the session
(legacy/CI mode). If the server rejects the session or token (expired or
revoked), the listener stops, reports it (on the terminal, and in
`~/.servonaut/logs/relay.log` for `--bg`) and exits with code `4`. Run
`servonaut login`, then start the relay again. A temporary failure to
refresh the session (network error, rate limit, server error, or a
firewall or CDN in front of the API blocking the request) does not stop
the listener; it keeps retrying. If the server keeps rejecting heartbeats
while the session is still valid, the listener keeps retrying and writes
one `heartbeat_rejected` line to `relay.log` (see
`relay.heartbeat_rejection_alert_after`).

**AI chat tool execution:** when started with a logged-in session, the
listener also executes tool calls dispatched by Servonaut AI chats
(headless `servonaut ai chat --tools`, web-originated conversations).
Approval is policy-driven because no human is present to confirm:
`relay.ai_tool_auto_approve` in `~/.servonaut/config.json` sets the
maximum guard tier executed without confirmation — `"readonly"`,
`"standard"` (default), or `"dangerous"` (additionally requires the
dangerous-AI-tools entitlement). Tools above the tier return a denial
the model can relay to the user. Every execution is written to
`~/.servonaut/mcp_audit.jsonl` with `source="ai_chat"`.

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
servonaut logout           # revoke the session, then delete auth.json
servonaut logout --local   # only delete auth.json; contact no server
```

If `SERVONAUT_API_URL` holds a refused URL (see
[Environment Variables](configuration.md#environment-variables)), `logout`
stops with an error instead of signing you out unrevoked. `--local` signs
you out on this device without contacting any server; the session stays
valid on the server until it expires. The TUI offers the same as **Sign out
on this device only** on the Account screen.

---

## `servonaut ssh`

Connect to a managed instance (AWS or custom server) by name or id. The SSH
key is resolved from your Bitwarden reference when one is registered, else
from `~/.ssh` — see [Bitwarden SSH keys](bitwarden-ssh.md).

```
servonaut ssh [--user USER] [--port PORT] <instance> [-- <command>...]
```

| Flag | Description |
|------|-------------|
| `--user`, `-u` | Override the SSH username (default: the matching connection rule's username, except for a custom server; then the server's own username, then `default_username`, then `ubuntu`) |
| `--port`, `-p` | Override the SSH port (default: the server's own port, else 22) |

Connection rules apply as in the TUI: a server that matches a rule with a
bastion is reached at its private address through that bastion, with the
rule's extra SSH options (see [Connection Rules](configuration.md#connection-rules)).

A name is checked against the servers of every account. An account that was
never listed on this machine (it has no cache yet) is listed once first, so
its servers count too, within `account_check_timeout_seconds` (see
[Configuration](configuration.md)). An account that cannot be listed gets a
`Note:` line on stderr saying why, and is left alone for a while:

| The note says | Tried again after |
|---------------|-------------------|
| `timed out after N s` or `no answer: …` (a timeout, or no connection) | `account_retry_seconds` |
| the provider's error (credentials, permissions, a credential helper, SSO, a missing profile) | its cache TTL |
| `was only partly listed (…)`: what was listed counts as checked, and the note repeats on every lookup | its cache TTL |

AWS lists the account's own default region first, then `us-east-1`, then the
rest. When an account is only partly listed in the time allowed, list only the
regions you use (`aws.regions`, or the account's `regions`) to make it
complete. The same applies to `servonaut servers verify` and
`servonaut memory`.

The AWS account without a profile is listed only when AWS is set up on this
machine: credentials in the environment, a `default` profile with
credentials in `~/.aws/credentials` or `~/.aws/config`, or an EC2 instance
(its instance role). Credentials are not resolved just to decide that. An
account that is set up is listed with the credentials it is configured
with, so a `credential_process` helper of the profile runs then, as it does
for any AWS listing: once, and if it fails, again only after the cache TTL.
A container on an EC2 instance sees the host's firmware details, so it counts
as an EC2 instance too, but it usually cannot reach the instance role (the
metadata service's hop limit): its first lookup per cache TTL waits for the
metadata timeouts and ends with a note that AWS could not be listed.

With no command, an interactive shell opens. With a command, it runs on the
instance and `servonaut ssh` exits with the command's exit status, like
`ssh host <command>`. Put the command after `--` whenever it has flags of its
own, so they are not read as `servonaut` options; everything after the first
`--` is passed through unchanged. Standard input is passed through too.
As with `ssh`, no terminal is allocated for a command, so programs that
need one (`top`, a `sudo` password prompt) belong in an interactive session.

**Examples:**

```bash
servonaut ssh web-1                              # interactive shell
servonaut ssh web-1 -- uname -a                  # run one command
servonaut ssh -u deploy web-1 -- systemctl status nginx --no-pager
servonaut ssh web-1 -- 'df -h / | tail -1'       # quote pipes for the remote shell
echo "hello" | servonaut ssh web-1 -- cat        # stdin reaches the remote command
```

**Exit codes** before a connection is attempted:

| Code | Meaning |
|------|---------|
| `1` | No instance matches the name or id |
| `2` | No SSH key found for the instance (also: invalid arguments) |
| `3` | Bitwarden key could not be read (CLI missing, vault locked, item not found) |
| `5` | More than one instance matches — use the id |

Once connected, the exit code is the remote command's (or the session's);
`255` means SSH itself could not connect.

---

## `servonaut vault`

Manage an encrypted personal or team vault. Vault keys and SSH private keys
remain on the device; the service stores encrypted records and signed metadata.
Sign in first with `servonaut login`. On a server that does not provide the
feature, existing local and Bitwarden SSH configuration continues to work.

```
servonaut vault status
servonaut vault setup
servonaut vault recover
servonaut vault identity confirm
servonaut vault devices list|approve|revoke
```

`setup` displays a recovery key once. Record it offline before continuing.
`recover` and escrow recovery read recovery material with a hidden terminal
prompt; do not place recovery keys in shell arguments or scripts.

A new identity must be confirmed before team owners and admins share vault
keys with it. Open the link Servonaut e-mails after `setup`, or sign in again
with two-factor (`servonaut login`) and run `servonaut vault identity confirm`.
Without a recent two-factor sign-in, `identity confirm` e-mails a new link
instead.

`servonaut vault status` ends with your next step, and the Vault screen shows
the same step:

- **On your own (a plan with a personal vault):** set up your identity,
  confirm it, then create your personal vault (`servonaut vault create`, or
  Create vault on the Vault screen) and import SSH keys into it.
- **Joining a team:** accept the invitation on the web, sign in, set up and
  confirm your identity. An owner's or admin's Servonaut then gives you access
  to the team vault while it is open or running `servonaut connect`:
  automatically, or after their approval if the vault requires it. Until then
  the Vault screen says you are waiting for access.
- **On another device:** run `servonaut vault devices add` there and approve it
  from a device you already use, or `servonaut vault recover` with your
  recovery key.

Use `servonaut vault devices approve <device-id>` only while comparing the
six-digit safety code on both devices. A mismatch rejects that registration;
start again with the new device rather than retrying it. `devices revoke` asks
for a reason because reporting a device as lost or compromised can require
vault-key rotation and expose affected SSH keys for review.

Vault and item commands are:

```
servonaut vault create [--team TEAM] [--name NAME] [--grant-policy auto|approval]
servonaut vault list
servonaut vault items --vault VAULT_ID [--include-deleted]
servonaut vault show ITEM_ID --vault VAULT_ID [--reveal --yes]
servonaut vault import ssh --vault VAULT_ID [--path PATH] [--break-glass --from-cidr CIDR [--from-cidr CIDR ...]]
servonaut vault import bitwarden --vault VAULT_ID --item BITWARDEN_ITEM_ID
servonaut vault bind SERVER ITEM_ID --vault VAULT_ID --team TEAM [--login USER] (--host-key 'OPENSSH_HOST_KEY' [--host-key ...] | --pin-host-key) --yes
servonaut vault bind-personal --vault VAULT_ID --item ITEM_ID --provider PROVIDER --instance-id INSTANCE_ID --hostname HOST --login USER --host-key 'OPENSSH_HOST_KEY' [--host-key 'OPENSSH_HOST_KEY' ...]
servonaut vault rotate --vault VAULT_ID --yes
servonaut vault exposures --vault VAULT_ID
servonaut vault exposures --vault VAULT_ID --rotate-ssh ITEM_ID --team TEAM --server SERVER_ID [--server SERVER_ID ...] --yes
servonaut vault grants process [--vault VAULT_ID] [--yes]
servonaut vault verify-member MEMBER
```

`items` and `show` print metadata by default. `show --reveal` requires an
explicit confirmation and only displays the value in the terminal; `--json`
never exports revealed values. `rotate` re-keys a vault after membership or
device changes. Review open exposures and rotate deployed SSH keys before
marking any exposure as accepted risk or not deployed.

`bind` pins the host keys you pass with `--host-key` (one OpenSSH public key
per flag, without a host name or comment, for example from `ssh-keyscan`
output). With `--pin-host-key` instead, it pins the keys this machine already
trusts for the server from an earlier `servonaut ssh` login. `bind-personal`
always requires explicit `--host-key` pins. Neither copies trust from an
unverified server record. For a cloud instance, `bind-personal` takes
`--provider aws|ovh|hetzner` and its instance id; for a custom server, use
`--provider custom` and the custom server's name. Renaming a custom server
needs a new binding.

The exposure rotation command installs and proves the replacement on every
selected host, then removes the old key. When every host completes, the
item's open exposures are resolved as rotated, with a note naming the hosts;
if you are not an owner or admin, ask one to resolve them. If any host does
not complete, it exits non-zero, names the servers where the old key may still
log in, and the exposure stays open. Replacing a key in the vault alone does
not close an exposure: `vault exposures` notes when the key was replaced but
may still be on servers.

After importing a Bitwarden SSH item in the Vault screen, you can choose a
team server that already uses that same Bitwarden reference. Servonaut checks
the match, creates the signed native binding, and proves a pinned SSH login.
Only after that proof does it offer a separate confirmation to remove the
server's old Bitwarden reference. It never deletes the Bitwarden item; cancel
or a failed proof leaves the existing server access in place.

For a sole-owner team, `servonaut vault escrow setup --vault VAULT_ID --label
LABEL` prints an offline recovery key once. `servonaut vault escrow recover`
uses a hidden prompt. A lost or compromised report can require a fresh MFA
login before escrow recovery.

---

## `servonaut ca`

Manage a team SSH certificate authority after the team has enabled the
feature and the account has completed MFA. These commands change access on
real hosts, so enrollment, refresh, unenrollment and enablement require an
interactive confirmation or `--yes`.

```
servonaut ca status --team TEAM
servonaut ca enable --team TEAM --yes
servonaut ca policy --team TEAM [--set '{"...": "..."}']
servonaut ca enroll SERVER --team TEAM [--break-glass-item ITEM_ID]
servonaut ca refresh SERVER --team TEAM --yes
servonaut ca unenroll SERVER --team TEAM --yes
servonaut ca krl --team TEAM [--server SERVER]
servonaut ca audit --team TEAM
servonaut ca break-glass-scan --team TEAM [--server SERVER ...] [--hours 24]
```

The enrollment path uses a versioned local script and structured enrollment
data. It refuses unrecognised script versions and does not execute server
supplied shell text. `ca krl` delivers the signed revocation list to selected
enrolled hosts. `ca audit` verifies the append-only certificate issuance log.

A break-glass key is an emergency root key for when certificate logins fail.
Import it into the team vault with `servonaut vault import ssh --break-glass
--from-cidr CIDR` (it may only be used from those networks), then pass its
item ID to `ca enroll --break-glass-item`: enrollment appends it to the host's
`/root/.ssh/authorized_keys` with a `from=` restriction. `ca break-glass-scan`
reads each enrolled host's SSH log over your existing access and reports any
login with a break-glass key to the team, once per event; the team owner is
notified.

---

## Other top-level commands

| Command | Description |
|---------|-------------|
| `servonaut` | Launch the TUI |
| `servonaut --debug` | Launch the TUI with verbose logging |
| `servonaut --update` | Check for and apply updates from PyPI |
| `servonaut --list-backups` | List local configuration backups, newest first |
| `servonaut --restore-backup [N]` | Restore configuration backup `N` from `--list-backups` (1 = newest); without `N`, choose from a list |
| `servonaut --install-desktop` | Add a launcher that opens the TUI in a terminal: **Servonaut (terminal)** on Linux, **Servonaut Terminal** in `~/Applications` on macOS. It replaces the shortcut earlier versions created under the desktop app's name |
| `servonaut --setup-ovh` | Guided OVHcloud credential setup |
| `servonaut --mcp` | Start as an MCP server (stdio transport) |
| `servonaut --mcp-install <agent>` | Auto-install MCP into `claude`, `opencode`, `cursor`, `windsurf`, `vscode`, `codex`, `agy`, `gemini`, or `all` |

On a stable release, `servonaut --update` and the in-app update check offer
stable releases only. New versions are published as release candidates (for
example `2.28.0rc1`) a few days before the stable release; pip and pipx
install them only when you ask for one. To try one without touching your
installation, run `pipx run --spec 'servonaut==2.28.0rc1' servonaut`. An
installation that is itself a release candidate is offered newer candidates
and the stable release that follows them. See
[Release candidates](release-candidates.md) for installing one, how updates
behave, and going back to the stable release.

See [MCP Tools reference](mcp-tools.md) for the full list of MCP tools.
