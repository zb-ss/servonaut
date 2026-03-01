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
      "ssh_port": 22
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
| `proxy_command` | string | — | Custom ProxyCommand (optional — overrides bastion settings) |
| `ssh_port` | int | `22` | SSH port on bastion host |

### How Proxy Works

The proxy method is chosen automatically based on what's configured:

| Configuration | SSH Method | Use Case |
|---------------|------------|----------|
| `bastion_key` is set | `-o ProxyCommand` with `-i` flag | Bastion needs a different key than the target |
| No `bastion_key` | `-J` (ProxyJump) | Bastion uses same key or SSH agent |
| `proxy_command` is set | `-o ProxyCommand` (raw) | Advanced/custom proxy setups |

When a bastion profile matches, the target host automatically switches to the instance's **private IP**.

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

Configure AI log analysis under the `ai_provider` key:

```json
{
  "ai_provider": {
    "provider": "openai",
    "api_key": "$OPENAI_API_KEY",
    "model": "",
    "base_url": "",
    "max_tokens": 2000,
    "temperature": 0.3
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | `"openai"` | Provider name: `openai`, `anthropic`, or `ollama` |
| `api_key` | string | `""` | API key (supports secret references — see below) |
| `model` | string | `""` | Model name (empty = provider default) |
| `base_url` | string | `""` | Custom API base URL (empty = provider default) |
| `max_tokens` | int | `2000` | Maximum response tokens |
| `temperature` | float | `0.3` | Sampling temperature |

Default models per provider: OpenAI → `gpt-4o-mini`, Anthropic → `claude-sonnet-4-20250514`, Ollama → `llama3`.

Requires `httpx`: `pip install 'servonaut[ai]'`

## Secrets

API keys and other sensitive values can be externalized so `config.json` is safe to commit to a dotfiles repo.

### Secret Reference Syntax

Any config value that accepts secrets (currently `ai_provider.api_key`) supports three formats:

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
    "api_key": "$OPENAI_API_KEY"
  }
}
```

**`~/.secrets/servonaut.env`** (gitignored, stays local):
```
OPENAI_API_KEY=sk-LwhfdskfjdhskfwueihfFJ...
```

Or using a file reference instead:
```json
{
  "ai_provider": {
    "api_key": "file:~/.secrets/openai_key"
  }
}
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
