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
| No `bastion_key` | `-J` (ProxyJump) | Bastion uses same key or SSH agent |
| `proxy_command` is set | `-o ProxyCommand` (raw) | Advanced/custom proxy setups |

When a bastion profile matches, the target host automatically switches to the instance's **private IP**.

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

Default models per provider: OpenAI → `gpt-4o-mini`, Anthropic → `claude-sonnet-4-20250514`, Gemini → `gemini-2.0-flash`, Ollama → `llama3`. When using Ollama Cloud, model names take **no `-cloud` suffix** (e.g. `gpt-oss:120b`); the suffix is only used by local Ollama proxying to a cloud model.

Requires `httpx`: `pip install 'servonaut[ai]'`

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
| `SERVONAUT_RELAY_TOKEN` | — | Auth token for the CLI relay listener (`servonaut --connect`) |
| `SERVONAUT_USER_ID` | — | User ID for the CLI relay listener |

These can be set inline, exported, or added to `~/.secrets/servonaut.env`:

```
# Point CLI at staging
SERVONAUT_API_URL=https://staging.servonaut.dev
SERVONAUT_MCP_URL=https://staging.servonaut.dev
```

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
is handled by your existing `servonaut login` session. Once subscribed, the provider is
active automatically: open the AI chat panel in the TUI, or run `servonaut ai chat` from
the command line, and your prompts are routed through the gateway. The hosted model can
tail logs, run commands, and triage incidents on your servers through the existing Mercure
relay — your AWS credentials never leave the CLI.

### Enabling Servonaut AI

```bash
servonaut login   # authenticates against servonaut.dev via device flow
```

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
| `~/.servonaut/logs/servonaut.log` | Application log |
| `~/.servonaut/logs/servonaut_*.sh` | Temporary SSH wrapper scripts |
