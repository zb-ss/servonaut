# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Servonaut is a Terminal User Interface (TUI) for managing servers. Built with Python and Textual, it provides SSH connections, SCP file transfer, remote file browsing, command execution, and keyword-based server scanning across all AWS regions.

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

## Architecture

Modular TUI built on Textual, organized into five packages under `src/servonaut/`:

- **`config/`** — Configuration management: `AppConfig` dataclass hierarchy (`schema.py`), JSON load/save/validate (`manager.py`), v1→v2 migration (`migration.py`)
- **`services/`** — Business logic with abstract interfaces (`interfaces.py`). Each service implements its interface. Key services: `AWSService` (boto3 EC2 API), `CacheService` (stale-while-revalidate), `SSHService` (key management, command building), `ConnectionService` (bastion/ProxyJump resolution), `ScanService` + `KeywordStore` (keyword scanning), `TerminalService` (terminal detection/launch), `SCPService` (file transfer)
- **`screens/`** — Textual `Screen` subclasses for each view (main menu, instance list, server actions, file browser, command overlay, SCP transfer, scan results, settings, key management, search, help)
- **`widgets/`** — Reusable Textual widgets: `InstanceTable` (DataTable), `RemoteTree` (Tree for remote fs), `StatusBar`, `ProgressIndicator`, `CommandOutput` (RichLog)
- **`utils/`** — Helpers: `formatting.py`, `platform_utils.py`, `ssh_utils.py`, `match_utils.py` (instance matching with conditions like `name_contains`, `region`, `name_regex`)

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
  └── CommandHistoryService(config.command_history_path)
```

### Screen Navigation

Screens use `self.app.push_screen()` / `self.app.pop_screen()`. Shared instance data lives in `self.app.instances` (list of dicts with keys: `id`, `name`, `type`, `state`, `public_ip`, `private_ip`, `region`, `key_name`).

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
- JSON at `~/.servonaut/config.json`, dataclass-based schema (`AppConfig`, `ScanRule`, `ConnectionProfile`, `ConnectionRule`)
- Schema versioning (`CONFIG_VERSION = 2`) with automatic v1→v2 migration
- Connection rules evaluated in order — first match wins

**Instance Matching (`match_utils.py`):**
- Used by both scan rules and connection rules
- Supports: `name_contains`, `name_regex`, `region`, `id`, `type_contains`, `has_public_ip`
- All conditions are AND-ed together

## Runtime Files

All runtime files are under `~/.servonaut/`:

- `~/.servonaut/config.json` — Main configuration
- `~/.servonaut/cache.json` — Cached instance list
- `~/.servonaut/keywords.json` — Scan results store
- `~/.servonaut/command_history.json` — Saved commands and command history
- `~/.servonaut/logs/servonaut.log` — Application log
- `~/.servonaut/logs/servonaut_*.sh` — Temporary SSH wrapper scripts

## Dependencies

- `boto3` — AWS EC2 API
- `tabulate` — Table formatting (legacy)
- `textual>=0.40.0` — TUI framework
- Python 3.8+ required
