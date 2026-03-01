"""Help screen for Servonaut v2.0."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import ScrollableContainer
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Markdown


HELP_TEXT = """
# Servonaut v2.0 — Help

## Main Menu

| Option | Shortcut | Description |
|--------|----------|-------------|
| **List Instances** | `1` or `L` | View all EC2 instances across AWS regions |
| **Manage SSH Keys** | `2` or `K` | Configure SSH keys and SSH agent |
| **Scan Servers** | `3` or `C` | Run scans on all running instances |
| **Settings** | `4` or `T` | Edit configuration |
| **Quit** | `5` or `Q` | Exit |

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

## Instance Caching

Instances are cached to `~/.servonaut/cache.json` for fast startup.

| Scenario | Behavior |
|----------|----------|
| First launch (no cache) | Fetches from AWS with progress bar |
| Restart within TTL | **Instant load** from cache, no AWS call |
| Restart after TTL | Shows stale data immediately, refreshes in background |
| Press `R` | Force-refresh from AWS |

Default TTL is **1 hour** (`cache_ttl_seconds: 3600` in config).
Background refresh shows a notification when complete (e.g., "2 more instances found").

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

When a rule matches, the connection automatically routes through the bastion
and targets the instance's **private IP**.

**Match conditions:** `name_contains`, `region`, `state`

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
| `default_scan_paths` | `["~/shared/"]` | Paths to scan on all servers |
| `theme` | `dark` | UI theme |

## Logging & Debugging

Logs: `~/.servonaut/logs/servonaut.log`
Debug mode: `servonaut --debug`

SSH failures keep the terminal window **open** so you can read the error message.

## Command Overlay Shortcuts

| Key | Action |
|-----|--------|
| `Up` / `Down` | Navigate command history |
| `Ctrl+R` | Open command picker (saved + recent) |
| `Ctrl+S` | Save current command to favorites |
| `Ctrl+C` | Stop running command |
| `Escape` | Close overlay |

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
        yield ScrollableContainer(
            Markdown(HELP_TEXT, id="help_content"),
            id="help_container"
        )
        yield Footer()

    def action_back(self) -> None:
        """Navigate back."""
        self.app.pop_screen()
