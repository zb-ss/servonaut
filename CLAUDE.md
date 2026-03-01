# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Servonaut is a Terminal User Interface (TUI) for managing servers. Built with Python and Textual, it provides SSH connections, SCP file transfer, remote file browsing, command execution, keyword-based server scanning, real-time log viewing, CloudTrail event browsing, IP banning (WAF/SG/NACL), AI log analysis, and an MCP server for AI agents. Supports both AWS EC2 instances and non-AWS custom servers from any provider.

## Development Commands

```bash
# Run directly without installing (primary dev workflow)
PYTHONPATH=src python3 -m servonaut.main

# Or run the script directly
python src/servonaut/main.py

# Run with debug logging (prints to stderr + log file)
PYTHONPATH=src python3 -m servonaut.main --debug

# Install via pipx (production)
pipx install .

# Update existing pipx installation after changes
pipx install . --force

# Install editable for development
pip install -e .
```

Tests use pytest. Run with `pip install -e ".[test]" && pytest`. CI runs on push/PR to master via GitHub Actions.

```bash
# Start MCP server (for AI agents)
PYTHONPATH=src python3 -m servonaut.main --mcp

# Auto-install MCP server into Claude Code
PYTHONPATH=src python3 -m servonaut.main --mcp-install
```

## Architecture

Modular TUI built on Textual, organized into six packages under `src/servonaut/`:

- **`config/`** — Configuration management: `AppConfig` dataclass hierarchy (`schema.py`), JSON load/save/validate (`manager.py`), v1→v2 migration (`migration.py`). Nested dataclasses: `ScanRule`, `ConnectionProfile`, `ConnectionRule`, `CustomServer`, `IPBanConfig`, `AIProviderConfig`, `MCPConfig`
- **`services/`** — Business logic with abstract interfaces (`interfaces.py`). Each service implements its interface. Key services: `AWSService` (boto3 EC2 API), `CacheService` (stale-while-revalidate), `SSHService` (key management, command building), `ConnectionService` (bastion/ProxyJump resolution), `ScanService` + `KeywordStore` (keyword scanning), `TerminalService` (terminal detection/launch), `SCPService` (file transfer), `CustomServerService` (non-AWS server CRUD), `LogViewerService` (log path probing, tail commands), `CloudTrailService` (boto3 CloudTrail event lookup), `IPBanService` (WAF/SG/NACL strategies with audit trail), `AIAnalysisService` (OpenAI/Anthropic/Ollama adapters)
- **`screens/`** — Textual `Screen` subclasses for each view (main menu, instance list, server actions, file browser, command overlay, SCP transfer, scan results, settings, key management, help, custom servers, log viewer, CloudTrail browser, IP ban, AI analysis)
- **`widgets/`** — Reusable Textual widgets: `InstanceTable` (DataTable with Provider column), `RemoteTree` (Tree for remote fs), `StatusBar`, `ProgressIndicator`, `CommandOutput` (RichLog)
- **`utils/`** — Helpers: `formatting.py`, `platform_utils.py`, `ssh_utils.py`, `match_utils.py` (instance matching with conditions: `name_contains`, `name_regex`, `region`, `id`, `type_contains`, `has_public_ip`, `provider`, `group`, `tag:<key>`)
- **`mcp/`** — MCP server for AI agents: `server.py` (stdio transport), `tools.py` (6 tool implementations), `guards.py` (readonly/standard/dangerous guard levels), `audit.py` (JSONL audit trail), `installer.py` (auto-install into Claude Code)

### Service Initialization and Access

All services are created in `ServonautApp._init_services()` (in `app.py`) during `on_mount`. Services are stored as attributes on the app instance. Screens access them via `self.app.<service>` (e.g., `self.app.ssh_service`, `self.app.connection_service`).

Service dependency chain:
```
ConfigManager → config
  ├── CacheService(ttl_seconds=config.cache_ttl_seconds)
  │     └── AWSService(cache_service)
  ├── SSHService(config_manager)
  ├── ConnectionService(config_manager)
  ├── ScanService(config_manager)
  ├── KeywordStore(config.keyword_store_path)
  ├── TerminalService(preferred=config.terminal_emulator)
  ├── SCPService()
  ├── CommandHistoryService(config.command_history_path)
  ├── CustomServerService(config_manager)
  ├── LogViewerService(config_manager)
  ├── CloudTrailService(config_manager)
  ├── IPBanService(config_manager)
  └── AIAnalysisService(config_manager)
```

### Screen Navigation

Screens use `self.app.push_screen()` / `self.app.pop_screen()`. Shared instance data lives in `self.app.instances` (list of dicts with keys: `id`, `name`, `type`, `state`, `public_ip`, `private_ip`, `region`, `key_name`). Custom servers add extra keys: `provider`, `group`, `tags`, `port`, `username`, `is_custom`.

### Async Pattern

Long-running operations (AWS API, SSH) are async and run via `self.run_worker()` to avoid blocking the TUI. Workers notify the UI via `self.notify()`.

### Styling

All CSS is in a single `app.css` file using Textual's CSS-like syntax with design tokens (`$surface`, `$primary`, `$accent`, etc.). Screen-specific styles are organized into labeled sections within this file.

## Key Design Decisions

**SSH Connection Strategy:**
- ProxyJump (`-J`) when no separate bastion key; ProxyCommand when `bastion_key` is set (allows different key for bastion vs target)
- `IdentitiesOnly=yes` only added when `-i` flag is present
- Key auto-discovery searches `~/.ssh/` with multiple patterns (exact match, `.pem`, fuzzy)
- External SSH sessions launch in new terminal window via wrapper script that keeps terminal open on failure

**Instance Caching (stale-while-revalidate):**
- Cache at `~/.servonaut/cache.json` with configurable TTL (default 3600s)
- Startup: show stale data immediately, refresh in background if expired
- `CacheService.load()` respects TTL; `load_any()` ignores TTL; `is_fresh()` checks TTL
- Force refresh via `R` key in instance list

**Configuration:**
- JSON at `~/.servonaut/config.json`, dataclass-based schema (`AppConfig` + nested dataclasses)
- Schema versioning (`CONFIG_VERSION = 2`) with automatic v1→v2 migration
- New fields with defaults need no migration — `AppConfig(**config_dict)` silently uses defaults for missing keys
- Connection rules evaluated in order — first match wins

**Instance Matching (`match_utils.py`):**
- Used by scan rules, connection rules, and custom server filtering
- Supports: `name_contains`, `name_regex`, `region`, `id`, `type_contains`, `has_public_ip`, `provider`, `group`, `tag:<key>`
- All conditions are AND-ed together

**Custom Servers:**
- Non-AWS servers stored in `config.custom_servers` as `CustomServer` dataclass instances
- Converted to instance dict format via `CustomServerService.to_instance_dict()` with `is_custom: True` flag
- Merged into `self.app.instances` alongside AWS instances, re-merged after AWS refresh
- SSH commands use custom server's `username`, `port`, and `ssh_key` transparently

**IP Ban Strategy Pattern:**
- Three strategies: `WAFStrategy` (IP sets), `SecurityGroupStrategy` (ingress rules with "servonaut-ban" tag), `NACLStrategy` (deny rules)
- `IPBanService` selects strategy based on `IPBanConfig.method`
- All operations logged to audit trail at `ip_ban_audit_path`

**AI Analysis Provider Adapters:**
- Three providers via `httpx`: OpenAI (`/v1/chat/completions`), Anthropic (`/v1/messages`), Ollama (`/api/chat`)
- API keys support `$ENV_VAR` syntax for environment variable resolution
- Large logs chunked with overlap; cost estimated at ~4 chars/token
- Graceful degradation if `httpx` not installed

**MCP Server:**
- Launched via `servonaut --mcp` with stdio transport
- Initializes all services headless (no TUI)
- Guard system: `readonly` (list/status only), `standard` (read + allowlisted commands), `dangerous` (all except blocklist)
- Command blocklist (rm -rf, shutdown, etc.) ALWAYS enforced, even in dangerous mode
- All operations logged to JSONL audit trail

## Runtime Files

All runtime files are under `~/.servonaut/`:

- `~/.servonaut/config.json` — Main configuration
- `~/.servonaut/cache.json` — Cached instance list
- `~/.servonaut/keywords.json` — Scan results store
- `~/.servonaut/command_history.json` — Saved commands and command history
- `~/.servonaut/ip_ban_audit.json` — IP ban audit trail
- `~/.servonaut/mcp_audit.jsonl` — MCP server audit trail (JSON lines)
- `~/.servonaut/logs/servonaut.log` — Application log
- `~/.servonaut/logs/servonaut_*.sh` — Temporary SSH wrapper scripts

## Dependencies

**Required:**
- `boto3` — AWS EC2 + CloudTrail API
- `tabulate` — Table formatting (legacy)
- `textual>=0.40.0` — TUI framework
- Python 3.8+ required

**Optional:**
- `httpx>=0.25.0` — AI log analysis (`pip install 'servonaut[ai]'`)
- `mcp>=1.0.0` — MCP server for AI agents (`pip install 'servonaut[mcp]'`)
- Install all: `pip install 'servonaut[all]'`
