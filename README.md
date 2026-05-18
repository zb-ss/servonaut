# Servonaut

**Your servers. Your terminal. Your AI agent. One TUI.**

Manage AWS, Hetzner, OVH, and custom servers from one terminal — with a built-in AI assistant and MCP server.

## Quick Install

**Linux / macOS:**

```bash
curl -sSL https://raw.githubusercontent.com/zb-ss/servonaut/master/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/zb-ss/servonaut/master/install.ps1 | iex
```

**Or install directly via pipx / pip:**

```bash
pipx install servonaut
```

**Manual install from source:**

```bash
git clone https://github.com/zb-ss/servonaut.git
cd servonaut
pipx install .
```

## Screenshots

![Instance List](docs/screenshots/instances.png)
*Instance list with sidebar navigation, detail panel, and server metadata*

![AI Chat Assistant](docs/screenshots/instances-chat.png)
*Built-in AI assistant with MCP server integration for DevOps tasks*

![CloudWatch Logs Browser](docs/screenshots/cloudwatch.png)
*CloudWatch log browsing with Top IPs analysis, geolocation, and abuse scoring*

![IP Ban Manager](docs/screenshots/ip-ban-manager.png)
*Ban/unban IPs via WAF, Security Groups, or NACLs with audit trail*

## Features

- **Interactive TUI** with mouse and keyboard support powered by [Textual](https://textual.textualize.io/)
- **Multi-provider** — AWS EC2, OVHcloud (dedicated servers, VPS, Public Cloud), Hetzner Cloud (full lifecycle — list / create / destroy), plus custom servers from any provider (DigitalOcean, on-prem, etc.) with full SSH/SCP support
- **List and search** instances across all AWS regions with OVH and Hetzner instances merged into the same view
- **SSH into instances** — launches in new terminal window with auto-detected emulator
- **Run remote commands** via overlay panel with real-time streaming output, persistent history, and saved command favorites
- **Browse remote file systems** — interactive file tree navigation
- **SCP file transfer** — upload/download files and directories
- **Real-time log viewer** — stream remote logs via `tail -f` with pause, search, and log switching
- **Keyword-based server scanning** — search file contents across instances
- **CloudTrail event browser** — browse AWS CloudTrail events with filters for region, time range, event name, and user
- **CloudWatch Logs browser** — browse AWS CloudWatch log groups with Top IPs analysis, IP geolocation lookup, and AbuseIPDB integration
- **IP ban manager** — ban IPs via AWS WAF, Security Groups, or NACLs with audit trail
- **OVHcloud management** — `OVH → ⚙ Manage` per-provider screen with create / start / stop / reboot / delete (Cloud / VPS / dedicated routed automatically), region-first create wizard with API-backed flavor pricing, plus DNS zones, IP blocks and failover IPs, snapshots, block storage, billing and invoices, project-level SSH keys
- **Hetzner Cloud management** — `Hetzner → ⚙ Manage` per-provider screen with full lifecycle (create / power on / shutdown / power off / reboot / delete), state-aware action toolbar, project SSH-key registry, plus equivalent CLI (`servonaut hetzner list / create / destroy / ssh-keys / server-types`). Auto-registers new servers into the fleet. [Full docs](docs/hetzner.md)
- **AI log analysis** — analyze logs with OpenAI, Anthropic, Gemini, or Ollama (local install or [Ollama Cloud](https://docs.ollama.com/cloud)) with cost estimation
- **Built-in AI chat** — LLM assistant with tool-calling against your instances (powered by the same MCP tool surface below)
- **Servonaut AI** — hosted AI gateway included with Solo and Teams plans. Subscribe at [servonaut.dev](https://servonaut.dev) and chat with your fleet without configuring any local API key. The model can tail logs, run commands (with confirmation), and triage incidents through the existing Mercure relay — your AWS credentials and SSH keys never leave the CLI. Quota and top-up balance are shown inline in the chat panel and via `servonaut ai quota`.
- **Bring your own key** — prefer to use your own model? Configure each cloud provider's key independently in Settings → AI Provider (`ai_provider.openai_api_key`, `ai_provider.anthropic_api_key`, `ai_provider.gemini_api_key`, `ai_provider.ollama_api_key` for Ollama Cloud). Local Ollama needs no key — just point `ai_provider.base_url` at your install. All options coexist with Servonaut AI; a one-time picker lets you choose the default and you can switch per-session from the chat-panel header.
- **Server memory** — persistent per-server cache of OS/runtime/service/web-stack/log/database/container/network/git/disk facts. Agents call `get_server_memory(id)` before SSH round-trips; CLI has `servonaut memory build|refresh|show|export|annotate|pin|clear`. [Full docs](docs/memory.md)
- **Memory Sync** — Solo+ feature that backs up your fleet memory to servonaut.dev with end-to-end encryption (X25519 keypair + AES-256-GCM envelopes wrapped to a passphrase you control). Drift detection across re-probes, cross-device history, and AI-queryable fact cache. The TUI's `☁ Memory Sync` sidebar entry is the unified setup / unlock / status hub.
- **MCP server for AI agents** — Claude Code, Cursor, Windsurf, etc. ~40 tools covering instance ops, full Hetzner + OVH lifecycle (create / start / stop / reboot / delete), SSH-key registry CRUD, server-memory queries, session introspection, and authenticated REST proxy. Three-tier guard system (`readonly` / `standard` / `dangerous`), confirmation-protocol prompt baked into every mutating tool's description, and a JSONL audit trail.
- **Servonaut Cloud account** — optional `servonaut login` unlocks config sync across machines and the MCP relay
- **MCP relay** — `servonaut connect` (or the TUI autostart) keeps a Mercure SSE connection open so AI agents and team-mates can dispatch MCP tool calls to this machine over the internet. Tokens never leave the CLI; heartbeats every 30 s with automatic Mercure JWT refresh.
- **Config sync** — client-side-encrypted snapshots of your config.json pushed/pulled from servonaut.dev, paired with a passphrase you control
- **Bastion host / jump server support** via ProxyJump or ProxyCommand
- **Per-host SSH tuning** — `extra_ssh_options` per connection profile / custom server for legacy boxes (`HostKeyAlgorithms=+ssh-rsa`, custom keepalives, etc.)
- **SSH key management** with auto-discovery and per-instance configuration
- **Instance caching** with stale-while-revalidate for fast startup
- **Auto-update check** — notifies of new versions on startup, one-click update from the menu or `servonaut --update`
- **Desktop shortcut** — `servonaut --install-desktop` adds an app launcher entry (Linux/macOS)
- **Fully configurable** — all settings in `~/.servonaut/config.json`

## Prerequisites

- Python 3.10+
- AWS CLI configured (`~/.aws/credentials` and `~/.aws/config`)
- SSH client (standard on Linux/macOS, OpenSSH on Windows)
- `pipx` for isolated installation (recommended)

Your AWS credentials need `ec2:DescribeInstances` and `ec2:DescribeRegions` permissions. Additional permissions needed for optional features:

| Feature | Required Permissions |
|---------|---------------------|
| CloudTrail browser | `cloudtrail:LookupEvents` |
| IP ban (WAF) | `wafv2:GetIPSet`, `wafv2:UpdateIPSet` |
| IP ban (Security Groups) | `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`, `ec2:DescribeSecurityGroups` |
| IP ban (NACLs) | `ec2:CreateNetworkAclEntry`, `ec2:DeleteNetworkAclEntry`, `ec2:DescribeNetworkAcls` |
| CloudWatch Logs | `logs:DescribeLogGroups`, `logs:FilterLogEvents` |
| OVHcloud (optional) | OVH API credentials — 3-key (application key / secret / consumer key) or OAuth2. Set up via `servonaut --setup-ovh` or in Settings. |

## Usage

```bash
# Core
servonaut                         # Launch the TUI
servonaut --debug                 # Launch with debug logging to stderr
servonaut --update                # Check for updates and upgrade
servonaut --install-desktop       # Create desktop shortcut (Linux/macOS)
servonaut --setup-ovh             # Guided OVHcloud credential setup

# MCP server for AI agents
servonaut --mcp                   # Start as MCP server (stdio transport)
servonaut --mcp-install <agent>   # Auto-install into claude, opencode,
                                  # cursor, windsurf, vscode, or all

# Relay — keep this machine reachable for hosted AI agents + team-mates
servonaut connect                 # Foreground relay (Ctrl+C to stop)
servonaut connect --bg            # Detach; writes ~/.servonaut/relay.pid
servonaut connect --status        # Local + backend view with divergence warning
servonaut connect --stop          # SIGTERM the background listener
servonaut connect --reconnect     # Heal a stale SSE socket (stop+start)
servonaut connect --force-bg      # Take over from a TUI's in-process listener
```

The TUI also starts an in-process relay listener automatically once you
log in — no need to run `servonaut connect` separately unless you want
the connection to survive closing the TUI. See [Servonaut Cloud
account](#servonaut-cloud-account) below.

### Keyboard Shortcuts

| Context | Key | Action |
|---------|-----|--------|
| Main Menu | `U` | Update Servonaut (when update available) |
| Global | `Q` | Quit |
| Global | `?` | Help screen |
| Global | `Escape` | Go back / close |
| Instance List | `/` | Focus search |
| Instance List | `R` | Force-refresh from AWS |
| Instance List | `S` | SSH to selected instance |
| Instance List | `B` | Browse remote files |
| Instance List | `C` | Run command overlay |
| Instance List | `T` | SCP transfer |
| Instance List | `Y` | Copy IP to clipboard |
| Global | `F2` | Toggle AI chat panel |
| Anywhere | Mouse drag | Select text (auto-copies to clipboard) |
| Anywhere | `Ctrl+C` | Copy selected text |
| Command Overlay | `Ctrl+C` | Stop running command |
| Command Overlay | `Ctrl+R` | Command picker (saved + recent) |
| Command Overlay | `Ctrl+S` | Save command to favorites |
| Command Overlay | `Up/Down` | Command history |
| Log Viewer | `P` | Pause/resume streaming |
| Log Viewer | `C` | Clear output |
| Log Viewer | `F` | Find/search in output |
| Log Viewer | `L` | Switch log file |

### What You Can Do

The TUI opens to a unified instance list (AWS + OVH + Hetzner + custom servers in one searchable table). The collapsible left sidebar groups everything else by purpose:

**Core**
- **📋 Instances** — search and SSH the unified fleet
- **💻 Custom Servers** — add / edit / remove non-AWS servers (DigitalOcean, on-prem, etc.)
- **🔑 SSH Keys** — configure default and per-instance keys

**Logs & Security**
- **📊 CloudWatch** — browse AWS log groups with Top IPs analysis, action filter (All/Allowed/Blocked), IP geolocation, AbuseIPDB lookup
- **🔒 IP Ban Manager** — ban IPs via WAF, Security Groups, or NACLs
- **🔍 CloudTrail** — audit AWS API activity with filters

**Tools**
- **🧠 Fleet Memory** — scan / refresh / inspect the AI-queryable fact cache
- **☁ Memory Sync** — encrypted backup of fleet memory across devices (Solo+)
- **🔄 Sync Config** — encrypted config snapshots (Solo+)
- **🔧 Settings** — configuration, scan rules, AI provider, AbuseIPDB key

**OVH** (visible when configured)
- **⚙ Manage** — table of OVH instances with state-aware lifecycle toolbar (Create / Start / Stop / Reboot / Delete)
- **🔑 SSH Keys** — project-level SSH key registry (the one the create wizard injects from)
- DNS Zones · IP Management · Block Storage · Billing

**Hetzner** (visible when configured)
- **⚙ Manage** — table of Hetzner servers with full lifecycle toolbar (Create / Power on / Shutdown / Reboot / Delete)
- **🔑 SSH Keys** — Hetzner Cloud project SSH key registry

**Account**
- Login · Teams · Bug Reports

**Server Actions** (clicking any instance row): Browse Files, Run Command, SSH Connect, SCP Transfer, View Scan Results, View Logs (tail -f), AI Analysis, Ban IP

Command history persists across sessions — use `Ctrl+R` to search history and saved commands, `Ctrl+S` to save favorites.

### Instance Caching

| Scenario | Behavior |
|----------|----------|
| First launch (no cache) | Fetches from AWS with progress indicator |
| Restart within TTL (default 1h) | Instant load from cache |
| Restart after TTL | Shows stale data immediately, refreshes in background |
| Press `R` | Force-refresh from AWS |

### Configuration

All configuration lives in `~/.servonaut/config.json`, created automatically on first run.

See [Configuration Guide](docs/configuration.md) for the full reference including connection profiles, custom servers, scan rules, and match conditions.

**Legacy / special-case SSH hosts:** connection profiles and custom servers both accept an `extra_ssh_options` array that appends arbitrary `-o KEY=VALUE` flags per host — use it to talk to ancient OpenSSH boxes (`HostKeyAlgorithms=+ssh-rsa`), tune keepalives, or set connect timeouts without weakening your global SSH defaults. See [Per-host SSH tuning](docs/configuration.md#per-host-ssh-tuning).

**Secrets:** API keys in `config.json` support `$ENV_VAR` and `file:~/.secrets/key` syntax so the config file stays secret-free. You can also create `~/.secrets/servonaut.env` with `KEY=value` pairs — loaded automatically on startup.

### Optional Dependencies

```bash
# AI log analysis (OpenAI, Anthropic, Gemini, Ollama)
pipx inject servonaut httpx
# or: pip install 'servonaut[ai]'

# MCP server for AI agents
pipx inject servonaut mcp
# or: pip install 'servonaut[mcp]'

# Install everything
pip install 'servonaut[all]'
```

### MCP Server for AI Agents

Servonaut includes an integrated MCP server that exposes tools to AI agents like Claude Code:

```bash
# Auto-install into a coding agent
servonaut --mcp-install claude     # Claude Code
servonaut --mcp-install cursor     # Cursor
servonaut --mcp-install windsurf   # Windsurf
servonaut --mcp-install opencode   # OpenCode
servonaut --mcp-install vscode     # VS Code Copilot
servonaut --mcp-install all        # All of the above

# Run MCP server manually (stdio transport)
servonaut --mcp
```

**Available tools:**

| Category | Tools |
|----------|-------|
| Instance ops | `list_instances`, `check_status`, `get_server_info`, `run_command`, `get_logs`, `transfer_file` |
| Server memory | `get_server_memory`, `list_server_memories`, `build_server_memory`, `refresh_server_memory` |
| Session / backend | `whoami`, `api_request` |
| Relay | `relay_status`, `relay_reconnect`, `mcp_tool_call` |
| Hetzner Cloud | `hetzner_list_servers`, `hetzner_list_server_types`, `hetzner_list_ssh_keys`, `hetzner_create_ssh_key`, `hetzner_delete_ssh_key`, `hetzner_create_server`, `hetzner_delete_server`, `hetzner_power_on`, `hetzner_power_off`, `hetzner_shutdown`, `hetzner_reboot` |
| OVHcloud | `ovh_monitoring`, `ovh_list_ips`, `ovh_firewall_rules`, `ovh_ssh_keys`, `ovh_snapshots`, `ovh_dns_records`, `ovh_billing`, `ovh_invoices`, `ovh_create_instance`, `ovh_delete_instance`, `ovh_start_instance`, `ovh_stop_instance`, `ovh_reboot_instance` |

- `whoami` returns session metadata — the OAuth bearer is never exposed.
- `api_request` lets an agent make authenticated REST calls against servonaut.dev with automatic 401 refresh and a CLI-side rate limit (30/min). The bearer stays on the CLI.
- `mcp_tool_call` wraps a JSON-RPC 2.0 `tools/call` envelope against the hosted MCP at `mcp.servonaut.dev` — used for premium tools when your plan includes them.
- `get_server_memory(id)` returns the cached fact snapshot — agents call this BEFORE any SSH round-trip so they answer most OS / runtime / service questions without `run_command`. Pass `format='context_block'` to get back a `<CONTEXT>` envelope for direct prompt injection.

**Guard levels:** `readonly` (list/status/introspection only), `standard` (read + safe commands + authenticated REST + power management — start / stop / reboot / shutdown), `dangerous` (everything, including `create_server` / `delete_server` / `transfer_file`). Dangerous shell commands (`rm -rf`, `shutdown`, `reboot`, etc.) are always blocked regardless of guard level. Mutating tools carry an explicit "confirm with the user before calling" cue in their descriptions; the top-level MCP instructions document the three-step protocol (summarise → state args → wait for affirmative reply). All operations are logged to `~/.servonaut/mcp_audit.jsonl`.

### Set Up with an AI Agent

Paste this prompt into Claude Code, Cursor, or any AI coding assistant to get Servonaut installed and configured automatically:

<details>
<summary>Copy-paste setup prompt</summary>

```
Install and configure Servonaut, a TUI for managing servers.

1. Install: `pipx install servonaut` (or `pip install servonaut`)
2. Install optional deps: `pipx inject servonaut httpx mcp` (for AI analysis + MCP server)
3. Run `servonaut` once to generate ~/.servonaut/config.json
4. Read ~/.servonaut/config.json and help me configure:
   - AWS regions to scan (default scans all, set `regions` array to limit)
   - Default SSH username (`default_username`, default "ec2-user")
   - Cache TTL (`cache_ttl_seconds`, default 3600)
   - Terminal emulator if not auto-detected (`terminal_emulator`)
5. If I use bastion/jump hosts, help me set up `connection_profiles` and `connection_rules`
6. If I have non-AWS servers, help me add them to `custom_servers`
7. If I want AI log analysis, help me configure `ai_provider` (openai/anthropic/gemini/ollama)
   - Each cloud provider has its own dedicated key field (`openai_api_key`, `anthropic_api_key`, `gemini_api_key`, `ollama_api_key`)
   - All key fields support `$ENV_VAR` and `file:~/.secrets/key` syntax so they don't go in the config file
8. Install MCP server into your coding agent: `servonaut --mcp-install claude` (or `cursor`, `windsurf`, `opencode`, `vscode`, `all`)

After setup, launch with `servonaut` and walk me through the key features.
```

</details>

## Servonaut Cloud account

Optional — Servonaut works fully offline against your own AWS / OVH
credentials. Signing in at [servonaut.dev](https://servonaut.dev) unlocks:

- **Config sync** — push/pull an encrypted snapshot of your
  `config.json` between machines. The passphrase never leaves your
  client; the server only sees ciphertext. Sidebar entry `🔄 Sync
  Config` opens the snapshot manager directly (Pull Latest / Push New
  / Restore / Rename / Delete).
- **MCP relay** — a Mercure SSE channel that lets AI agents and
  team-mates dispatch MCP tool calls to this machine. While the relay
  is connected, `https://servonaut.dev/account` reports your CLI as
  online, and hosted agents can reach it.
- **Memory Sync (Solo+)** — encrypted fleet memory backup with drift
  detection. Open the `☁ Memory Sync` sidebar entry, click *Unlock
  Memory Sync*, and enter a passphrase. The same screen handles
  first-time enrolment AND post-restart unlock — your private key is
  wrapped with the passphrase locally, so the server never sees it.
  After unlock, click *Sync now* to push every cached server's memory
  modules as encrypted envelopes. Per-feature settings (digest
  cadence, Mercure push, AI consent) live at the bottom of the
  Settings panel and are stored on your servonaut.dev account.

Sign in from the TUI's Account / Login screen. After a successful
device-flow authentication, the TUI auto-starts an in-process relay
listener and the sidebar indicator flips to `● connected`.

The listener is tied to the TUI window — closing the TUI drops the
connection after ~60 s. For always-on reachability (CI runners,
headless boxes), use `servonaut connect --bg` instead; the CLI and
TUI cooperate over `~/.servonaut/relay.lock` so they can't run at the
same time. The TUI shows `external listener (PID N)` when a `--bg`
listener is holding the connection.

Tokens are stored at `~/.servonaut/auth.json` with mode `0600`, written
atomically via tmp + `os.replace()`. If an older build left the file
world-readable, the next run auto-fixes it.

## Development

```bash
# Run directly (primary dev workflow)
PYTHONPATH=src python3 -m servonaut.main

# Run with debug logging
PYTHONPATH=src python3 -m servonaut.main --debug

# Install editable
pip install -e .

# Update pipx installation after changes
pipx install . --force
```

```bash
# Run tests
pip install -e ".[test]"
pytest
```

See [Architecture](docs/architecture.md) for codebase structure and design patterns.

## Troubleshooting

See [Troubleshooting Guide](docs/troubleshooting.md) for help with SSH connections, bastion hosts, key management, and AWS credentials.

## Runtime Files

All runtime files are under `~/.servonaut/`:

| File | Purpose |
|------|---------|
| `config.json` | Main configuration |
| `cache.json` | Cached instance list (AWS + merged OVH) |
| `auth.json` | OAuth tokens for servonaut.dev, mode `0600`, atomic writes |
| `keywords.json` | Scan results store |
| `command_history.json` | Saved commands and command history |
| `ip_ban_audit.json` | IP ban audit trail |
| `mcp_audit.jsonl` | MCP server audit trail |
| `relay.pid` | Background `servonaut connect --bg` PID (when running) |
| `relay.lock` | Advisory flock shared between the TUI's in-process listener and `--bg`, carries `{pid, mode, acquired_at}` |
| `memory/` | Server-memory store: `<provider>/<instance_id>/<module>.json` per probed server, plus `index.json` |
| `memory/sync_queue.jsonl` | Pre-encryption envelopes waiting to be pushed to servonaut.dev. Replayed on next bootstrap; deleted after a successful drain. Only present while Memory Sync has unsent work. |
| `logs/servonaut.log` | Application log |
| `logs/relay.log` | Relay lifecycle events (one JSON line per event, secrets redacted) |

## Logging

Logs are always written to `~/.servonaut/logs/servonaut.log`. Use `--debug` for verbose stderr output.

When SSH fails, the terminal window stays open showing the error and exit code.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
