"""Help screen for Servonaut v2.0.

The key tables are built from the screens' own ``BINDINGS``, so the help
always lists the keys that are really bound, in the case they are bound in.
A binding's ``tooltip`` (also shown when hovering its footer entry) is its
description here; without one, its footer label is.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, ScrollableContainer
from textual.keys import format_key

from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from textual.screen import Screen
from textual.widgets import Footer, Static, Markdown

# How the help writes named keys; any other key is shown as Textual shows it.
_KEY_NAMES = {
    "escape": "Esc",
    "enter": "Enter",
    "tab": "Tab",
    "up": "Up",
    "down": "Down",
    "left": "Left",
    "right": "Right",
    "space": "Space",
    "slash": "/",
    "question_mark": "?",
}
_MODIFIER_NAMES = {"ctrl": "Ctrl", "shift": "Shift", "alt": "Alt", "meta": "Meta"}

Row = Tuple[str, str]


def key_label(key: str) -> str:
    """One bound key as the help writes it, e.g. ``s``, ``D``, ``Ctrl+R``, ``F2``."""
    *modifiers, base = key.split("+")
    if len(base) == 1:
        # Alone, a letter's case matters (``d`` and ``D`` are different
        # keys); with Ctrl it does not, and a capital reads better.
        name = base.upper() if modifiers else base
    elif base in _KEY_NAMES:
        name = _KEY_NAMES[base]
    elif base[:1] == "f" and base[1:].isdigit():
        name = base.upper()
    else:
        name = format_key(base)
    return "+".join([*(_MODIFIER_NAMES.get(m, m.title()) for m in modifiers), name])


def binding_rows(bindings: Iterable[BindingType]) -> List[Row]:
    """(keys, description) rows for *bindings*, one per action, in binding order."""
    rows: dict = {}
    for binding in bindings:
        if not isinstance(binding, Binding):
            binding = Binding(*binding)
        for key in binding.key.split(","):
            label = f"`{key_label(key.strip())}`"
            keys, text = rows.get(binding.action, ([], binding.tooltip or binding.description))
            if label not in keys:
                keys.append(label)
            rows[binding.action] = (keys, text)
    return [(" / ".join(keys), text) for keys, text in rows.values()]


def _escape_cell(text: str) -> str:
    return text.replace("|", r"\|")


def key_table(rows: Sequence[Row], header: Row = ("Key", "Action")) -> str:
    """A Markdown table of *rows*."""
    lines = [f"| {header[0]} | {header[1]} |", "|-----|--------|"]
    # A "|" in a description would end its cell.
    lines += [f"| {keys} | {_escape_cell(text)} |" for keys, text in rows]
    return "\n".join(lines)


def build_help_text() -> str:
    """The help, with each key table taken from the bindings it describes."""
    from servonaut.app import ServonautApp
    from servonaut.screens.command_overlay import CommandOverlay
    from servonaut.screens.instance_list import InstanceListScreen
    from servonaut.screens.log_viewer import LogViewerScreen
    from servonaut.screens.server_actions import ServerActionsScreen

    tables = {
        "<<fleet-keys>>": key_table(
            [("`Up` / `Down`", "Move between instances")]
            + binding_rows(InstanceListScreen.BINDINGS)
        ),
        "<<server-action-keys>>": key_table(binding_rows(ServerActionsScreen.BINDINGS)),
        "<<log-viewer-keys>>": key_table(binding_rows(LogViewerScreen.BINDINGS)),
        "<<command-overlay-keys>>": key_table(binding_rows(CommandOverlay.BINDINGS)),
        "<<global-keys>>": key_table(
            binding_rows(ServonautApp.BINDINGS)
            + [
                ("`Ctrl+P`", "Command palette: every screen and command by name"),
                ("`Esc`", "Go back / navigate to instances"),
                ("`Tab` / `Shift+Tab`", "Next / previous widget"),
            ]
        ),
    }
    text = _HELP_TEMPLATE
    for marker, table in tables.items():
        text = text.replace(marker, table)
    return text


_HELP_TEMPLATE = """
# Servonaut — Help

## Navigation

Use the **sidebar** on the left to switch between views. The sidebar is
available on every screen. Hover over buttons for descriptions.

## Instance List

Keys are case-sensitive: `D` is Shift+d.

<<fleet-keys>>

The footer lists as many of these as fit the terminal's width. When the table
is wider than the window, `Left` / `Right` scroll it sideways.

The **detail panel** at the bottom shows the selected instance's metadata.
You can highlight text in the detail panel with the mouse to copy it.

## Server Actions

<<server-action-keys>>

| Action | What it does |
|--------|-------------|
| **Browse Files** | Interactive remote filesystem tree via SSH |
| **Run Command** | Execute commands on the server (overlay panel, `Up`/`Down` for history, `Ctrl+R` picker, `Ctrl+S` save) |
| **SSH Connect** | Opens a **new terminal window** with SSH session |
| **Memory** | View / refresh / pin / annotate the server's fact cache (see below) |
| **SCP Transfer** | Upload/download files via SCP |
| **View Scan Results** | Show keyword scan data for this server |
| **View Logs** | Real-time log streaming via `tail -f` |
| **AI Analysis** | Send logs to AI for analysis (requires `httpx`) |
| **Ban IP** | Ban the instance's IP via configured method |

## Server Memory (AI-queryable fact cache)

Memory builds a structured, redactable snapshot of each server — OS,
runtimes, services, web stack, recent log paths, annotations — and stores
it locally under `~/.servonaut/memory/`. The **chat panel** and **MCP
agents** read this cache so common questions ("what's running on X?",
"which PHP version is installed?") answer instantly without an SSH
round-trip.

| Surface | How to use it |
|---------|---------------|
| **Sidebar → Fleet Memory** | Fleet-wide status table. `s` scans every server, `f` refreshes stale modules, `enter` opens the per-server view. |
| **Instance list → Mem column** | At-a-glance icon per row: `●` green fresh, `●` yellow stale, `○` not probed, `⛔` opted-out. |
| **Instance list → `m`** | Opens the per-server Memory screen for the selected row. |
| **Server Actions → `m`** | Same per-server view from the action stack. |
| **MCP `get_server_memory`** | Agents call this first. If it returns `missing`, they should call `build_server_memory` to populate. |
| **MCP `build_server_memory` / `refresh_server_memory`** | Trigger probing from an AI agent. Returns per-module successes + failures so the agent can explain what broke. |

Memory is **opt-out per server** via `memory.per_server_overrides` in
config.json. Sensitive probe output is scrubbed by the redaction library
when `memory.redaction_enabled` is true (the default).

## Custom Servers

Add non-AWS servers from any provider (DigitalOcean, Hetzner, on-prem, etc.).
Custom servers appear alongside EC2 instances with a **Provider** column.
All features work transparently: SSH, SCP, file browsing, commands, log viewing, AI analysis.

Each custom server has: name, host, port, username, SSH key, provider label, group, and tags.

## Log Viewer (tail -f)

Stream remote server logs in real-time via SSH.

<<log-viewer-keys>>

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
| **OpenAI** | Set `openai_api_key`, default model: `gpt-4o-mini` |
| **Anthropic** | Set `anthropic_api_key`, default model: `claude-sonnet-4-20250514` |
| **Ollama** | Set `base_url` (default: `http://localhost:11434`), default model: `llama3` |

Configure in Settings or in `config.json` under `ai_provider`.
Large logs are automatically chunked. Token count and estimated cost are displayed.

### API Key Formats

The per-provider key fields (`openai_api_key`, `anthropic_api_key`, `gemini_api_key`,
`ollama_api_key`) support three formats so you don't have to store secrets in `config.json`:

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
servonaut --mcp-install [TARGET]  # Auto-install (claude, opencode, cursor,
                                  #   windsurf, vscode, codex, agy, all)
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
| Press `r` | Refresh from every provider |

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
| `cloudtrail_max_events` | `500` | Max CloudTrail events per fetch (the browser pages 100 at a time) |
| `ip_ban_configs` | `[]` | IP ban method configurations |
| `ai_provider` | OpenAI defaults | AI provider settings (provider, api_key, model, etc.) |
| `mcp.guard_level` | `standard` | MCP server guard level |

## Command Overlay Shortcuts

<<command-overlay-keys>>

## Logging & Debugging

Logs: `~/.servonaut/logs/servonaut.log` (auto-rotated: 2 MB per file, 5
backups → `servonaut.log.1` … `servonaut.log.5`, max ~10 MB on disk).
Debug mode: `servonaut --debug`

SSH failures keep the terminal window **open** so you can read the error message.

## Copying Text

| Method | Where it works |
|--------|---------------|
| **Mouse highlight** | Static text, detail panels, TextArea widgets |
| **`y` key** | Instance list (full row), log viewer (buffer), command output |
| **`v` key (Copy Mode)** | Log viewer, command output — opens selectable TextArea |

Mouse text selection auto-copies to clipboard on Static widgets and TextArea fields.
For scrollable views (log output, tables), use `v` to enter Copy Mode.

## Global Shortcuts

<<global-keys>>
"""


class HelpScreen(Screen):
    """Help screen displaying the user manual."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("q", "back", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Markdown(build_help_text(), id="help_content"),
                id="help_container"
            )
        yield Footer()

    def action_back(self) -> None:
        """Navigate back."""
        self.app.pop_screen()
