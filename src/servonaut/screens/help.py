"""Help screen for Servonaut v2.0."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer

from servonaut.widgets.sidebar import Sidebar
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Markdown


HELP_TEXT = """
# Servonaut — Help

## Main Menu

| Option | Shortcut | Description |
|--------|----------|-------------|
| **List Instances** | `1` or `L` | View all EC2 + custom servers |
| **Manage SSH Keys** | `2` or `K` | Configure SSH keys and SSH agent |
| **Scan Servers** | `3` or `C` | Run scans on all running instances |
| **Custom Servers** | `4` | Add/edit/remove non-AWS servers |
| **CloudTrail Logs** | `5` | Browse AWS CloudTrail events |
| **IP Ban Manager** | `6` | Ban IPs via WAF, Security Groups, or NACLs |
| **Settings** | `7` or `T` | Edit configuration (including AI provider) |
| **Quit** | `8` or `Q` | Exit |

## Instance List Shortcuts

| Action | Shortcut | Description |
|--------|----------|-------------|
| Navigate | `Up` / `Down` | Move between instances |
| Select | `Enter` | Open server actions |
| SSH Connect | `S` | Quick SSH to selected instance |
| Browse Files | `B` | Open remote file browser |
| Run Command | `C` | Open command overlay |
| SCP Transfer | `T` | Open file transfer |
| Search | `/` | Search instances and keyword scan results |
| Refresh | `R` | Force-refresh from AWS |
| Back | `Escape` | Return to main menu |

## Server Actions

| Action | What it does |
|--------|-------------|
| **Browse Files** | Interactive remote filesystem tree via SSH |
| **Run Command** | Execute commands on the server (overlay panel, `Up`/`Down` for history, `Ctrl+R` picker, `Ctrl+S` save) |
| **SSH Connect** | Opens a **new terminal window** with SSH session |
| **SCP Transfer** | Upload/download files via SCP |
| **View Scan Results** | Show keyword scan data for this server |
| **View Logs** | Real-time log streaming via `tail -f` |
| **AI Analysis** | Send logs to AI for analysis (requires `httpx`) |
| **Ban IP** | Ban the instance's IP via configured method |

## Custom Servers

Add non-AWS servers from any provider (DigitalOcean, Hetzner, on-prem, etc.).
Custom servers appear alongside EC2 instances with a **Provider** column.
All features work transparently: SSH, SCP, file browsing, commands, log viewing, AI analysis.

Each custom server has: name, host, port, username, SSH key, provider label, group, and tags.

## Log Viewer (tail -f)

Stream remote server logs in real-time via SSH.

| Key | Action |
|-----|--------|
| `P` | Pause / resume streaming |
| `C` | Clear output |
| `F` | Find / search in output |
| `L` | Switch to a different log file |
| `Escape` | Stop streaming and go back |

The viewer auto-detects readable log files on the server (syslog, auth.log,
nginx, apache, mysql, postgresql). Configure custom paths per instance in settings.

## CloudTrail Event Browser

Browse AWS CloudTrail events with filters:

- **Region** — specific region or all regions
- **Time Range** — ISO format or relative (e.g., "24h")
- **Event Name** — filter by API action (e.g., "RunInstances")
- **Username** — filter by IAM user
- **Resource Type** — filter by resource type

Select an event row to view the full raw JSON detail.

## IP Ban Manager

Ban IPs using three AWS methods:

| Method | How it works |
|--------|-------------|
| **WAF** | Adds IP to a WAF IP set (requires `wafv2` permissions) |
| **Security Group** | Adds deny ingress rule tagged "servonaut-ban" |
| **NACL** | Creates DENY rule in Network ACL |

Configure ban methods in `config.json` under `ip_ban_configs`.
All ban/unban operations are logged to `~/.servonaut/ip_ban_audit.json`.

## AI Log Analysis

Send log text to an AI provider for analysis. Requires `httpx` (`pip install 'servonaut[ai]'`).

| Provider | Config |
|----------|--------|
| **OpenAI** | Set `api_key`, default model: `gpt-4o-mini` |
| **Anthropic** | Set `api_key`, default model: `claude-sonnet-4-20250514` |
| **Ollama** | Set `base_url` (default: `http://localhost:11434`), default model: `llama3` |

Configure in Settings or in `config.json` under `ai_provider`.
Large logs are automatically chunked. Token count and estimated cost are displayed.

### API Key Formats

The `api_key` field supports three formats so you don't have to store secrets in `config.json`:

| Format | Example | How it resolves |
|--------|---------|-----------------|
| `$ENV_VAR` | `$OPENAI_API_KEY` | Reads from environment variable |
| `file:path` | `file:~/.secrets/openai_key` | Reads from file (whitespace-stripped) |
| Plain text | `sk-abc123...` | Used as-is |

You can also create `~/.secrets/servonaut.env` with `KEY=value` pairs — these are
auto-loaded into the environment on startup (existing env vars take precedence).

## MCP Server (for AI Agents)

Expose Servonaut tools to AI agents like Claude Code.

```
servonaut --mcp           # Start MCP server (stdio)
servonaut --mcp-install   # Auto-install into Claude Code
```

**Tools:** `list_instances`, `run_command`, `get_logs`, `check_status`, `get_server_info`, `transfer_file`

**Guard levels** (set in `config.json` under `mcp.guard_level`):

| Level | Allowed |
|-------|---------|
| `readonly` | list, status, info only |
| `standard` | read + safe commands (ls, cat, grep, ps, df, etc.) |
| `dangerous` | all operations (blocklist still enforced) |

Dangerous commands (`rm -rf`, `shutdown`, `reboot`, etc.) are **always blocked**.
All operations logged to `~/.servonaut/mcp_audit.jsonl`.

## Instance Caching

Instances are cached to `~/.servonaut/cache.json` for fast startup.

| Scenario | Behavior |
|----------|----------|
| First launch (no cache) | Fetches from AWS with progress bar |
| Restart within TTL | **Instant load** from cache, no AWS call |
| Restart after TTL | Shows stale data immediately, refreshes in background |
| Press `R` | Force-refresh from AWS |

Default TTL is **1 hour** (`cache_ttl_seconds: 3600` in config).

## Connection Profiles (Bastion Support)

For instances behind a bastion host, add to `~/.servonaut/config.json`:

```json
{
  "connection_profiles": [
    {
      "name": "my-bastion",
      "bastion_host": "bastion.example.com",
      "bastion_user": "ec2-user",
      "bastion_key": "~/.ssh/bastion-key.pem",
      "ssh_port": 22
    }
  ],
  "connection_rules": [
    {
      "name": "private-instances",
      "match_conditions": {"name_contains": "myapp"},
      "profile_name": "my-bastion"
    }
  ]
}
```

**Match conditions:** `name_contains`, `name_regex`, `region`, `id`, `type_contains`, `has_public_ip`, `provider`, `group`, `tag:<key>`

## SSH Key Management

Keys are auto-discovered in `~/.ssh/` by AWS key pair name
(e.g., `mykey`, `mykey.pem`, `id_rsa_mykey`).

You can also set keys per-instance or set a default key in Settings.

## Configuration Reference

Config file: `~/.servonaut/config.json`

| Field | Default | Description |
|-------|---------|-------------|
| `default_username` | `ec2-user` | SSH username |
| `default_key` | (empty) | Default SSH key for all instances |
| `cache_ttl_seconds` | `3600` | Cache duration (1 hour) |
| `terminal_emulator` | `auto` | Terminal: `auto`, `gnome-terminal`, `konsole`, `alacritty`, etc. |
| `default_scan_paths` | `["~/"]` | Paths to scan on all servers |
| `theme` | `dark` | UI theme |
| `custom_servers` | `[]` | Non-AWS custom server list |
| `log_viewer_tail_lines` | `100` | Initial tail lines for log viewer |
| `log_viewer_max_lines` | `10000` | Max lines before clearing log viewer |
| `cloudtrail_default_lookback_hours` | `24` | Default CloudTrail time range |
| `cloudtrail_max_events` | `100` | Max CloudTrail events per query |
| `ip_ban_configs` | `[]` | IP ban method configurations |
| `ai_provider` | OpenAI defaults | AI provider settings (provider, api_key, model, etc.) |
| `mcp.guard_level` | `standard` | MCP server guard level |

## Command Overlay Shortcuts

| Key | Action |
|-----|--------|
| `Up` / `Down` | Navigate command history |
| `Ctrl+R` | Open command picker (saved + recent) |
| `Ctrl+S` | Save current command to favorites |
| `Ctrl+C` | Stop running command |
| `Escape` | Close overlay |

## Logging & Debugging

Logs: `~/.servonaut/logs/servonaut.log`
Debug mode: `servonaut --debug`

SSH failures keep the terminal window **open** so you can read the error message.

## Global Shortcuts

| Key | Action |
|-----|--------|
| `Q` | Quit |
| `?` or `H` | This help screen |
| `Escape` | Go back / close |
| `Tab` / `Shift+Tab` | Next / previous widget |
"""


class HelpScreen(Screen):
    """Help screen displaying the user manual."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("q", "back", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Markdown(HELP_TEXT, id="help_content"),
                id="help_container"
            )
        yield Footer()

    def action_back(self) -> None:
        """Navigate back."""
        self.app.pop_screen()
