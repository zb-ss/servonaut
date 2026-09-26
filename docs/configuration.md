# Configuration Guide

All configuration is stored in `~/.servonaut/config.json`. The file is created automatically on first run with sensible defaults.

## Configuration Reference

```json
{
  "version": 2,
  "default_key": "/home/user/.ssh/my-default-key.pem",
  "instance_keys": {
    "i-0123456789abcdef0": "/home/user/.ssh/special-key.pem"
  },
  "default_username": "ec2-user",
  "cache_ttl_seconds": 3600,
  "terminal_emulator": "auto",
  "theme": "dark",
  "keyword_store_path": "~/.servonaut/keywords.json",
  "default_scan_paths": ["~/shared/", "/var/log/app.log"],
  "scan_rules": [],
  "connection_profiles": [],
  "connection_rules": []
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | int | `2` | Config schema version (auto-migrated from v1) |
| `default_key` | string | `""` | Default SSH key path for all instances |
| `instance_keys` | object | `{}` | Instance-specific key mappings `{instance_id: key_path}` |
| `default_username` | string | `"ec2-user"` | Default SSH username |
| `cache_ttl_seconds` | int | `3600` | Instance cache TTL in seconds (1 hour) |
| `terminal_emulator` | string | `"auto"` | Terminal preference (see [Supported Terminals](#supported-terminals)) |
| `theme` | string | `"dark"` | UI theme: `dark` or `light` |
| `keyword_store_path` | string | `"~/.servonaut/keywords.json"` | Path to keyword scan results file |
| `default_scan_paths` | array | `["~/"]` | Default paths to scan on all instances |
| `scan_rules` | array | `[]` | Conditional scan rules (see [Scan Rules](#scan-rules)) |
| `connection_profiles` | array | `[]` | SSH connection profiles (see [Connection Profiles](#connection-profiles)) |
| `connection_rules` | array | `[]` | Rules for applying profiles (see [Connection Rules](#connection-rules)) |

## Match Conditions

Match conditions are used by both scan rules and connection rules to target specific instances. All conditions in a rule are AND-ed together — every condition must match.

| Condition | Type | Description |
|-----------|------|-------------|
| `name_contains` | string | Case-insensitive substring match on instance name |
| `name_regex` | string | Regular expression match on instance name (case-insensitive) |
| `region` | string | Exact region match (e.g., `us-east-1`) |
| `id` | string | Exact instance ID match |
| `type_contains` | string | Substring match on instance type (e.g., `t3`) |
| `has_public_ip` | string | `"true"` or `"false"` — whether instance has a public IP |

## Scan Rules

Scan rules define what paths to search and commands to execute when scanning servers. Rules only apply to instances matching their conditions.

```json
{
  "scan_rules": [
    {
      "name": "Web server logs",
      "match_conditions": {
        "name_contains": "web",
        "region": "us-east-1"
      },
      "scan_paths": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log"
      ],
      "scan_commands": [
        "grep -r 'ERROR' /var/www/html/logs/"
      ]
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Descriptive name for the rule |
| `match_conditions` | object | Conditions to match instances (see [Match Conditions](#match-conditions)) |
| `scan_paths` | array | File paths to scan for keywords on matching instances |
| `scan_commands` | array | Shell commands to run on matching instances |

Scan results are stored persistently in the keyword store and searchable from the TUI.

## Connection Profiles

Connection profiles define how to connect to instances, including bastion/jump host configuration.

```json
{
  "connection_profiles": [
    {
      "name": "private-vpc-bastion",
      "bastion_host": "bastion.example.com",
      "bastion_user": "ubuntu",
      "bastion_key": "/home/user/.ssh/bastion-key.pem",
      "username": "ubuntu",
      "ssh_port": 22,
      "extra_ssh_options": []
    }
  ]
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Profile identifier (referenced by connection rules) |
| `bastion_host` | string | — | Bastion hostname or IP |
| `bastion_user` | string | `"ec2-user"` | Username for bastion connection |
| `bastion_key` | string | — | SSH key for bastion (optional — if omitted, uses same key as target) |
| `username` | string | — | SSH username for the **target** host (overrides `default_username`) |
| `proxy_command` | string | — | Custom ProxyCommand (optional — overrides bastion settings) |
| `ssh_port` | int | `22` | SSH port on bastion host |
| `extra_ssh_options` | array | `[]` | Extra `-o KEY=VALUE` entries for the target connection (see [Per-host SSH tuning](#per-host-ssh-tuning)) |

### How Proxy Works

The proxy method is chosen automatically based on what's configured:

| Configuration | SSH Method | Use Case |
|---------------|------------|----------|
| `bastion_key` is set | `-o ProxyCommand` with `-i` flag | Bastion needs a different key than the target |
| No `bastion_key` | `-o ProxyCommand` (`-J` when `ssh.host_key_checking` is `off`, and on Windows) | Bastion uses your SSH agent or default keys |
| `proxy_command` is set | `-o ProxyCommand` (raw) | Advanced/custom proxy setups |

When a bastion profile matches, the target host automatically switches to the instance's **private IP**.

The bastion hop runs as its own `ssh` process and verifies the bastion's
host key with the same settings as the target (see
[SSH host-key verification](#ssh-host-key-verification)). OpenSSH does not
apply command-line options to a `-J` jump host, which is why Servonaut spells
the hop out as a `ProxyCommand`. It forwards to the target the way `-J`
does, so IPv6 targets work through a bastion too. On Windows the hop still uses `-J`, so the
bastion is verified by your own OpenSSH configuration: add
`StrictHostKeyChecking accept-new` for it in `~/.ssh/config` so it is never
asked about interactively. A raw `proxy_command` is used exactly as written;
its host-key handling is up to that command.

### Per-host SSH tuning

`extra_ssh_options` lets you pass arbitrary `-o KEY=VALUE` flags to a specific subset of hosts without weakening your global SSH defaults. Each entry is the `KEY=VALUE` string — the leading `-o` is added automatically. The options are applied before proxy/identity flags, so they also flow through bastion connections.

The same field is also available on each `custom_servers` entry (see [Custom Servers](#custom-servers)), and both are merged together at connect time — profile options first, then custom-server options.

**Common uses:**

| Goal | Entry |
|------|-------|
| Talk to a legacy OpenSSH (< 7.2) server that only supports `ssh-rsa` (SHA-1) | `"HostKeyAlgorithms=+ssh-rsa,ssh-dss"` + `"PubkeyAcceptedAlgorithms=+ssh-rsa"` |
| Enable old ciphers on an ancient host | `"Ciphers=+aes128-cbc"` |
| Keep long SSH sessions alive through a NAT | `"ServerAliveInterval=30"`, `"ServerAliveCountMax=3"` |
| Bump the connect timeout for flaky networks | `"ConnectTimeout=20"` |
| Force IPv4 | `"AddressFamily=inet"` |

**Legacy host example** (a profile matched via a connection rule):

```json
{
  "connection_profiles": [
    {
      "name": "legacy-shared-hosting",
      "username": "appuser",
      "extra_ssh_options": [
        "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
        "PubkeyAcceptedAlgorithms=+ssh-rsa"
      ]
    }
  ]
}
```

> **Security note:** Re-enabling SHA-1 signatures (`ssh-rsa`) or DSA (`ssh-dss`) weakens the cryptographic guarantees of the connection. Scope these options to the specific hosts that need them via `extra_ssh_options` — **never** set them globally in your `~/.ssh/config`.

## SSH host-key verification

Servonaut connects through your system OpenSSH client and checks each
server's host key, so a changed key (a rebuilt server, or someone
intercepting the connection) stops the connection instead of going
unnoticed. The `ssh.host_key_checking` setting controls this:

```json
{
  "ssh": {
    "host_key_checking": "accept-new"
  }
}
```

| Value | Behaviour |
|-------|-----------|
| `accept-new` (default) | Trust on first use: the first connection to a host records its key, and a later connection presenting a different key is refused. |
| `yes` | Known hosts only: a host whose key is not already recorded is refused. |
| `off` | No verification. This was the behaviour before the setting existed; use it only when you knowingly need it. |

Any other value falls back to `accept-new`, with a warning in the log.

**Known hosts files.** New keys are recorded in Servonaut's own file,
`~/.servonaut/known_hosts`, which is created readable only by you. Your
`~/.ssh/known_hosts` is read too, so custom servers you already trust with
plain `ssh` connect without a new first-use step. Servonaut only uses its
own file while it is a regular file that you own, in a directory you own,
and neither can be written by anyone else; if `~/.servonaut` is writable by
your group (as a `umask` of `002` leaves it), that write access is removed.
When the file cannot be used, Servonaut logs a warning and checks against
`~/.ssh/known_hosts` alone, in `yes` mode, so that new keys are never
written to your own file: hosts you already know still connect, and new
hosts are refused, with a message saying why, until the file is fixed or
removed. A home directory whose path contains `${` cannot be passed to
OpenSSH literally; every host is then refused with an explanation.

**Cloud instances are pinned by instance, not by address.** AWS, OVH and
Hetzner instances are recorded under a stable name,
`provider:region:instance-id` (for example `aws:us-east-1:i-0abc…`), through
OpenSSH's `HostKeyAlias`. Private addresses repeat across networks and
regions, and public addresses are reused after an instance is released, so
pinning by address would raise false "key changed" alarms. Custom servers
keep their host name. With `yes`, a cloud instance is accepted only when its
key is recorded under that name.

**Where it applies.** The setting covers every connection Servonaut makes:
interactive sessions, commands, file transfers, the file browser, log
viewing, scans, server memory probes, **Verify SSH**, the MCP server, the
relay listener and bastion hops (see [How Proxy Works](#how-proxy-works)).
These options come first on the command line, so neither `extra_ssh_options`
nor your `~/.ssh/config` can override them. With `accept-new` and `yes`,
OpenSSH never asks about a host key, and it does not rewrite recorded keys
when a server offers new ones (`UpdateHostKeys=no`). Background work (the
MCP server, the relay listener, scans, memory probes, live monitoring and
the TUI's own commands) also runs without a terminal, and unattended work
in `BatchMode`, so it can never stop to wait for an answer.

**When a host key changes.** The connection is refused, and Servonaut names
the host and gives the command that removes the old entry, for example:

```text
SSH host key for [web-1.example.com]:2222 has changed, so the connection was
refused. ... remove the old one and reconnect:
ssh-keygen -R '[web-1.example.com]:2222' -f ~/.servonaut/known_hosts
```

Before running it, confirm the new key is genuine, for example by comparing
its fingerprint with the one shown in your provider's console. When the old
entry lives in `~/.ssh/known_hosts`, the command names that file instead.
Command output, MCP `run_command` / `get_logs`, file transfers, scans,
memory builds and **Verify SSH** all report the change this way. Messages
for the MCP server and the relay listener also say that a person must
verify the new fingerprint before anything is removed.

A remote command can print anything, including text that looks like
OpenSSH's warning, so Servonaut does not read ssh's messages from the
command's error output: for unattended connections ssh writes them to a
private temporary file instead (`ssh -E`, removed afterwards), and a bastion
hop does the same. A removal command is only suggested when ssh itself
failed and its message names this connection's server (or its bastion) and
a known_hosts file this connection used; anything else is reported as a
failed host-key verification without a command. `scp` cannot write such a
file, so for file transfers its own error output is checked, including the
exit code 1 that `scp` from OpenSSH before 9.0 (or with `-O`) uses.

**Upgrading from an earlier version.** Earlier versions did not check host
keys. After upgrading, the first connection to each server records its key;
nothing needs to be done beforehand. For a custom server whose key has
changed since you last connected to it with plain `ssh`, that first
connection reports the change; follow the message. A cloud instance is
always recorded afresh under its instance name on its first connection,
even when `~/.ssh/known_hosts` already holds its key under its address:
with `accept-new` this happens automatically. Bastions without a
`bastion_key` are now reached through a `ProxyCommand` rather than `-J`. To
keep the previous behaviour, set `"host_key_checking": "off"`. `servonaut
servers verify` has always checked host keys (trusting a new host,
refusing a changed one) and keeps doing so with `off`.

## Live SSH monitoring

Press **L** on a server's actions screen to start or stop the compact live
metrics section. It shows CPU, memory, load, root disk usage, and uptime
alongside the server's other details and actions.

Monitoring runs read-only Linux commands. It needs SSH access with a local
key or an available SSH agent; it cannot prompt for a password or unlock a
key. If authentication fails, check the SSH username and key, then press
**L** to retry. Polling stops when you leave the screen.

For OVH, monitoring uses `ovh.default_username` (or the provider's default
username) and chooses the key in this order: `instance_keys`,
`ovh.default_ssh_key`, `default_key`, then local key discovery. Bitwarden
SSH refs used by interactive SSH Connect are not resolved by live monitoring;
load the corresponding key into your SSH agent or configure a local key.

The `ssh` configuration object accepts these monitoring settings:

| Field | Default | Description |
|-------|---------|-------------|
| `live_stats_interval_seconds` | `3.0` | Delay after each successful sample; must be positive |
| `live_stats_timeout_seconds` | `20.0` | Total SSH command deadline, including connection setup; must be positive |

Existing configurations receive these defaults automatically. Choose a
monitoring timeout long enough for the configured SSH `connect_timeout`
and the remote command to complete.

## Custom Servers

Non-AWS servers (DigitalOcean, Hetzner, bare-metal, shared hosting, etc.) live under `custom_servers`. They show up in the instance list alongside AWS instances and use the same SSH/SCP/log-viewer UI.

```json
{
  "custom_servers": [
    {
      "name": "my-vps",
      "host": "203.0.113.10",
      "username": "root",
      "ssh_key": "~/.ssh/vps-key",
      "port": 22,
      "provider": "Hetzner",
      "group": "web",
      "tags": { "env": "prod" },
      "extra_ssh_options": []
    }
  ]
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Unique server identifier (shown in the instance list) |
| `host` | string | — | Hostname or IP address |
| `username` | string | `"root"` | SSH username |
| `ssh_key` | string | `""` | Path to SSH key file (supports `~` expansion) |
| `port` | int | `22` | SSH port — forwarded to both `ssh -p` and `scp -P` |
| `provider` | string | `""` | Free-form provider label (e.g., `"Hetzner"`) |
| `group` | string | `""` | Optional grouping label for match conditions |
| `tags` | object | `{}` | Arbitrary key/value metadata, targetable via `tag:<key>` match conditions |
| `extra_ssh_options` | array | `[]` | Extra `-o KEY=VALUE` entries (see [Per-host SSH tuning](#per-host-ssh-tuning)) |

Custom servers can also be added/edited/removed from the **Custom Servers** screen in the TUI, including the `extra_ssh_options` field as a multi-line input.

## Connection Rules

Connection rules link profiles to instances via match conditions.

```json
{
  "connection_rules": [
    {
      "name": "Private instances via bastion",
      "match_conditions": {
        "name_contains": "private",
        "region": "us-west-2"
      },
      "profile_name": "private-vpc-bastion"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Rule description |
| `match_conditions` | object | Conditions to match instances (see [Match Conditions](#match-conditions)) |
| `profile_name` | string | Name of connection profile to apply |

Rules are evaluated **in order** — the first matching rule wins. If the referenced profile doesn't exist, a warning is shown in the command overlay.

## AI Provider

Configure AI log analysis under the `ai_provider` key. Each provider has its own dedicated API-key field so keys don't leak across providers:

```json
{
  "ai_provider": {
    "provider": "openai",
    "openai_api_key": "$OPENAI_API_KEY",
    "anthropic_api_key": "$ANTHROPIC_API_KEY",
    "gemini_api_key": "$GEMINI_API_KEY",
    "ollama_api_key": "",
    "model": "",
    "base_url": "",
    "max_tokens": 2000,
    "temperature": 0.3
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | `"openai"` | Active provider: `openai`, `anthropic`, `gemini`, `ollama`, or `servonaut` |
| `openai_api_key` | string | `""` | OpenAI key (supports secret references — see below) |
| `anthropic_api_key` | string | `""` | Anthropic key (supports secret references) |
| `gemini_api_key` | string | `""` | Google Gemini key (supports secret references) |
| `ollama_api_key` | string | `""` | Optional [Ollama Cloud](https://docs.ollama.com/cloud) key — leave empty for local installs |
| `api_key` | string | `""` | **Legacy.** Pre-v4 single shared key. Still read on disk for one-release rollback safety; new configs should populate the per-provider fields above |
| `model` | string | `""` | Model name (empty = provider default) |
| `base_url` | string | `""` | Custom API base URL — set to `https://ollama.com` to point Ollama at the cloud instead of `http://localhost:11434` |
| `max_tokens` | int | `2000` | Maximum response tokens |
| `temperature` | float | `0.3` | Sampling temperature |
| `stream_silence_timeout_seconds` | float | `35.0` | Servonaut AI only: how long a streamed reply may go without any data (the service sends a keep-alive about every 15 s) before the connection counts as lost. Accepted range 20–600; values outside it are clamped. Time spent answering a tool prompt or running a tool does not count |
| `tool_confirm_timeout_seconds` | float | `50.0` | Servonaut AI only: how long a tool confirmation prompt stays open. When it passes, the prompt closes and the tool is not run. The service waits about 60 s for a tool result by default, so keep this below that |

Default models per provider: OpenAI → `gpt-4o-mini`, Anthropic → `claude-sonnet-4-20250514`, Gemini → `gemini-2.0-flash`, Ollama → `llama3`. When using Ollama Cloud, model names take **no `-cloud` suffix** (e.g. `gpt-oss:120b`); the suffix is only used by local Ollama proxying to a cloud model.

**`base_url` and API keys.** When a request carries an API key (OpenAI, Anthropic, Gemini, or Ollama with `ollama_api_key` set), `base_url` must follow the same rule as the [endpoint variables](#environment-variables): `https://`, or `http://` only for `127.0.0.1`, `::1` and `localhost`, with no credentials, query, fragment, spaces or backslashes. Otherwise the request is refused before anything is sent, with an error such as `The OpenAI API key was not sent: ai_provider.base_url must be an https:// URL (...)`. Gemini sends its key in the URL itself, so plain `http://` would expose it to anyone on the path. A keyless Ollama is not affected: `http://192.168.1.20:11434` (a model server elsewhere on your network) keeps working.

No extra install needed — `httpx` ships as a base dependency.

## Secrets

API keys and other sensitive values can be externalized so `config.json` is safe to commit to a dotfiles repo.

### Secret Reference Syntax

Any config value that accepts secrets supports three formats. Fields treated as secrets today: `ai_provider.openai_api_key`, `ai_provider.anthropic_api_key`, `ai_provider.gemini_api_key`, `ai_provider.ollama_api_key`, the legacy `ai_provider.api_key`, and `abuseipdb_api_key`.

| Format | Example | How it resolves |
|--------|---------|-----------------|
| `$ENV_VAR` | `$OPENAI_API_KEY` | Reads from environment variable |
| `file:path` | `file:~/.secrets/openai_key` | Reads file contents (whitespace-stripped) |
| Plain text | `sk-abc123...` | Used as-is |

### Auto-loading Secrets File

If `~/.secrets/servonaut.env` exists, it is loaded automatically on startup. This file uses simple `KEY=value` syntax:

```
# ~/.secrets/servonaut.env
OPENAI_API_KEY=sk-abc123...
ANTHROPIC_API_KEY=ant-abc123...
```

Rules:
- Existing environment variables are **not** overwritten (env takes precedence)
- `#` comments and blank lines are supported
- Values may be optionally quoted with single or double quotes
- The file is silently skipped if it doesn't exist

### Example Setup

**`~/.servonaut/config.json`** (safe to commit):
```json
{
  "ai_provider": {
    "provider": "openai",
    "openai_api_key": "$OPENAI_API_KEY",
    "anthropic_api_key": "$ANTHROPIC_API_KEY"
  }
}
```

**`~/.secrets/servonaut.env`** (gitignored, stays local):
```
OPENAI_API_KEY=sk-LwhfdskfjdhskfwueihfFJ...
ANTHROPIC_API_KEY=sk-ant-...
```

Or using a file reference instead:
```json
{
  "ai_provider": {
    "openai_api_key": "file:~/.secrets/openai_key"
  }
}
```

## Environment Variables

These environment variables override hardcoded API endpoints. Useful for pointing the CLI at a staging server.

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVONAUT_API_URL` | `https://api.servonaut.dev` | Base URL for the Servonaut API (auth, config sync, teams, entitlements) |
| `SERVONAUT_MCP_URL` | `https://mcp.servonaut.dev` | Base URL for the hosted MCP server (premium tools) |
| `SERVONAUT_RELAY_TOKEN` | — | Legacy/CI override: auth token for `servonaut connect` (the stored `servonaut login` session is used when unset) |
| `SERVONAUT_USER_ID` | — | Legacy/CI override: user ID for `servonaut connect` |
| `SERVONAUT_PYPI_URL` | `https://pypi.org/pypi/servonaut/json` | PyPI JSON document read by the update check (pip and pipx installs) |
| `SERVONAUT_HETZNER_API_URL` | `https://api.hetzner.cloud/v1` | Hetzner Cloud API base URL, version path included |
| `SERVONAUT_IP_API_URL` | `http://ip-api.com` | Base URL for IP geolocation lookups (CloudWatch IP info, `enrich_ips`) |
| `SERVONAUT_ABUSEIPDB_URL` | `https://api.abuseipdb.com/api/v2` | Base URL for AbuseIPDB reputation lookups |

Every URL variable above accepts only `https://` URLs; plain `http://` is allowed for `127.0.0.1`, `::1` and `localhost` only, so an override can point at a local test server but never sends requests unencrypted to another machine. URLs with embedded credentials, spaces or backslashes are refused too, and so is a query (`?`) or fragment (`#`): paths are appended to these base URLs, which a query or fragment would swallow. An invalid value is refused rather than silently replaced by the default. The ip-api.com default itself is `http://` because its free tier does not offer HTTPS; an `http://` override of it is still accepted only for those loopback hosts.

### HTTPS required for `SERVONAUT_API_URL` and `SERVONAUT_MCP_URL`

Earlier versions accepted any value for these two variables. Every request to them carries your login token (sign-in, token refresh, and every account, AI and hosted-MCP call), so an `http://` URL to another machine sent that token over the network unencrypted. Such a value is now refused:

- CLI commands that need the variable stop with `Error: SERVONAUT_API_URL must be an https:// URL (http:// is accepted only for 127.0.0.1, ::1 or localhost).` and exit code 1. The message names the variable, never the URL.
- The TUI shows the same error at startup; account features that need the variable report it when used.
- MCP tools that call the API (`api_request`, `mcp_tool_call`) return an `invalid_endpoint` error, and `whoami` reports it as `base_url_error`.
- Nothing is sent to the refused URL, and Servonaut never falls back to the production API in its place.

If you pointed either variable at a development or staging server over plain `http://`, serve that server over HTTPS, or reach it through a loopback address (for example an SSH tunnel to `http://127.0.0.1:8000`).

`servonaut logout` needs the API to revoke your session, so it is refused too while `SERVONAUT_API_URL` is. Don't unset the variable to get a logout through: that would send a token issued by your development server to the production API. Instead run `servonaut logout --local`, or choose **Sign out on this device only** on the TUI's Account screen. Both delete `~/.servonaut/auth.json` (with its cached plan details) without contacting any server; the session itself stays valid on the server that issued it until it expires.

The hosted MCP server tells the CLI where to send tool calls. That address is used only when it has the same scheme, host and port as `SERVONAUT_MCP_URL`; otherwise the CLI ignores it and uses `/mcp/message` on that base, so the login token never goes to another host.

The relay listener's local timeouts can be lengthened on slow or heavily loaded machines. Values are in seconds; a missing, non-numeric, zero, negative or infinite value falls back to the default, so a typo can never make shutdown unbounded.

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVONAUT_RELAY_CONTROL_TIMEOUT_SECONDS` | `2` | Bound on each local control request, such as the TUI asking a background listener to hand over |
| `SERVONAUT_RELAY_CLEANUP_TIMEOUT_SECONDS` | `10` | Deadline for the listener's shutdown cleanup; never shorter than the control timeout |

These can be set inline, exported, or added to `~/.secrets/servonaut.env`:

```
# Point CLI at staging
SERVONAUT_API_URL=https://staging.example.com
SERVONAUT_MCP_URL=https://staging.example.com
```

## Relay Listener (`relay`)

Settings for the Mercure SSE relay used by `servonaut connect` and the
TUI's in-process listener:

```json
{
  "relay": {
    "base_url": "https://api.servonaut.dev",
    "mercure_url": "https://servonaut.dev/.well-known/mercure",
    "heartbeat_interval": 30,
    "heartbeat_rejection_alert_after": 3,
    "ai_tool_auto_approve": "standard"
  }
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `base_url` | _(derived from API base)_ | REST API for heartbeats, Mercure JWTs, and results |
| `mercure_url` | _(derived from API base)_ | The Mercure hub URL |
| `heartbeat_interval` | `30` | Seconds between heartbeats |
| `heartbeat_rejection_alert_after` | `3` | Rejected heartbeats (while your session is still valid) before the listener reports that commands are not being delivered: one `heartbeat_rejected` line in `~/.servonaut/logs/relay.log` and the TUI indicator changes from "connected" to "connecting…". The listener keeps retrying and returns to "connected" once a heartbeat is accepted; until then it renews the session on every Nth rejected heartbeat only. Minimum `1`; lower or non-numeric values are treated as `1` and the default respectively. |
| `ai_tool_auto_approve` | `"standard"` | Max guard tier a headless listener auto-approves for AI chat tool calls: `"readonly"`, `"standard"`, or `"dangerous"`. `"dangerous"` additionally requires the dangerous-AI-tools entitlement. Tools above the tier are denied with an explanatory message. |

`base_url` receives your login token and `mercure_url` the relay subscription token, so both follow the same rule as the endpoint variables above: `https://`, or `http://` only for `127.0.0.1`, `::1` and `localhost`, with no embedded credentials, query, fragment, spaces or backslashes. With any other value `servonaut connect` (and `connect --bg`, before it starts anything) exits with an error naming the key (for example `Error: relay.base_url must be an https:// URL ...`), the TUI reports that the relay failed to start and shows the reason on the relay status screen, and Settings refuses to save it. Previously the TUI listener accepted any URL, and `servonaut connect` refused `http://` even for a loopback test server. If you saved an `http://` address on your network here, change it to `https://`, or clear both fields to use the defaults derived from the API base.

## Supported Terminals

Set `terminal_emulator` to one of the following, or `"auto"` for automatic detection:

- `gnome-terminal`
- `konsole`
- `alacritty`
- `kitty`
- `xterm`
- `xfce4-terminal`
- `mate-terminal`
- `tilix`
- `Terminal.app` (macOS)
- `iTerm.app` (macOS)
- `wt.exe` (Windows Terminal)

## Servonaut AI

Servonaut AI is a hosted AI gateway included with Solo and Teams plans on
[servonaut.dev](https://servonaut.dev). It requires no local API key — authentication
is handled by your existing Servonaut Cloud session (TUI → Account → Login). Once subscribed, the provider is
active automatically: open the AI chat panel in the TUI, or run `servonaut ai chat` from
the command line, and your prompts are routed through the gateway. The hosted model can
tail logs, run commands, and triage incidents on your servers through the existing Mercure
relay — your AWS credentials never leave the CLI.

### Enabling Servonaut AI

Sign in from the TUI: launch `servonaut`, open **Account → Login** in the
sidebar, and approve the device-flow prompt at servonaut.dev.

After login the CLI fetches your entitlements. If your plan includes `premium_ai`, the
Servonaut AI provider becomes available in the provider picker (TUI Settings panel or
`--ai-provider servonaut`). No further configuration is needed.

### Provider settings

Servonaut AI adds three fields to the `ai_provider` config block:

```json
{
  "ai_provider": {
    "provider": "openai",
    "provider_preference": "servonaut",
    "local_fallback_provider": null,
    "dismissed_banners": []
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | `"openai"` | Active provider for the **current** config (mutated by Settings) |
| `provider_preference` | string\|null | `null` | Persistent preference set by the first-run picker or `servonaut ai provider reset`. When set, overrides the decision tree at every chat-start. |
| `local_fallback_provider` | string\|null | `null` | Opt-in local fallback on repeated `upstream_unavailable` errors. Accepts `"ollama"`, `"openai"`, or `"anthropic"`. Default `null` means no automatic fallback — you will be offered a one-shot per-session prompt instead. Ollama is the recommended value for privacy (prompts stay on-machine). |
| `dismissed_banners` | array | `[]` | IDs of banners the user has dismissed forever. Managed automatically; cleared by `servonaut ai provider reset`. |

**How the provider picker decides:**

| Plan | Other providers configured | Explicit preference | CLI does |
|------|---------------------------|---------------------|----------|
| Solo/Teams | Yes | Yes | Honour preference |
| Solo/Teams | Yes | No | Show first-run modal; persist choice |
| Solo/Teams | No | n/a | Use Servonaut AI (only option) |
| Free | Yes | Yes | Honour preference |
| Free | Yes | No | Use first-configured provider |
| Free | No | n/a | Empty-state onboarding |

Run `servonaut ai provider reset` to clear `provider_preference` and `dismissed_banners`
and trigger the picker again on next chat start.

### `allow_dangerous_ai_tools`

This entitlement is set by a Teams plan administrator and is **opt-in** — it is `false`
by default for all accounts. When `false`, the tools `deploy`, `provision`, and
`security_scan` are hidden from the chat panel and any server-side call for those tools
will be rejected (the server enforces this independently). When `true`, those tools
appear in the panel and require a typed confirmation ("type RUN to confirm") before
execution. The setting is cached locally from `/api/entitlements` and refreshed on each
login and chat response; mid-session changes take effect on the next
`refresh_entitlements()` cycle, not mid-stream.

### Top-up flow

When your monthly token quota is exhausted you will see a modal with a **Top up** button.
Clicking it (or running `servonaut ai topup [pack]`) calls
`POST /api/ai/topup/checkout` and opens the resulting Stripe Checkout URL in your default
browser. The CLI does not embed Stripe. After completing the purchase, your
`tokens_topup_remaining` balance typically refreshes within 60 seconds (the CLI
schedules two background entitlement fetches at +30 s and +60 s to absorb webhook
latency).

Top-up packs: `small`, `medium`, `large` (canonical names; pricing at
`servonaut.dev/account/billing/topup`).

### Error codes

| Code | What it means | CLI response |
|------|--------------|--------------|
| `rate_limited` | You are sending requests too fast | Auto-retries up to 3× with `retry_after` + jitter; toast if all retries fail |
| `quota_exhausted` | Monthly token allowance is used up | Top-up modal with link to billing; no auto-retry |
| `budget_exhausted` | Your per-period cost cap has been reached | Same modal; shows `$X.XX of $Y.YY used` |
| `free_not_entitled` | This path requires Solo or Teams | Upgrade modal linking to `/pricing` |
| `entitlement_required` | `premium_ai` is false for your account | Same upgrade modal; triggers `refresh_entitlements()` first in case of stale cache |
| `service_unavailable` | Servonaut AI feature flag is off | Banner: "AI temporarily off"; offers fallback to your local provider if configured |
| `upstream_unavailable` | All vendor backends exhausted | Same banner; if `fallback_used` was already true, adds "all vendors flaky" note |
| `context_too_large` | Message history exceeds ~200 k tokens | CLI auto-chunks via `chunk_text` and retries once |
| `content_blocked` | Safety filter rejected the response | Toast "Response blocked by safety filter"; raw payload is logged but never displayed |
| `validation_failed` | Malformed request body | Toast "Internal error — please report"; details written to debug log only |

### Exit codes for `servonaut ai *` commands

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Other / unknown error |
| `2` | Unauthenticated — run `servonaut login` |
| `3` | Insufficient entitlement — requires Solo or Teams plan |
| `4` | Quota exhausted — run `servonaut ai topup` |
| `5` | Budget exhausted — cost cap reached; run `servonaut ai topup` |

## Config Migration

If you're upgrading from v1 (flat configuration structure), the app automatically migrates to v2 on first load. The v1 bastion settings are converted to a connection profile and rule. No manual action required.

## Runtime Files

All runtime files are stored under `~/.servonaut/`:

| File | Purpose |
|------|---------|
| `~/.servonaut/config.json` | Main configuration |
| `~/.servonaut/cache.json` | Cached instance list with timestamp |
| `~/.servonaut/keywords.json` | Keyword scan results |
| `~/.servonaut/command_history.json` | Saved commands and command history |
| `~/.servonaut/known_hosts` | SSH host keys recorded on first connect (see [SSH host-key verification](#ssh-host-key-verification)) |
| `~/.servonaut/logs/servonaut.log` | Application log |
| `~/.servonaut/logs/servonaut_*.sh` | Temporary SSH wrapper scripts |
