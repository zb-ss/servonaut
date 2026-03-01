# Architecture

Servonaut is a modular TUI application built on the [Textual](https://textual.textualize.io/) framework. The v2.0 rewrite replaced the original CLI script with a structured package-based architecture.

## Package Structure

```
src/servonaut/
├── config/       # Configuration management
├── services/     # Business logic layer
├── screens/      # Textual screens (views)
├── widgets/      # Reusable UI components
├── utils/        # Utility functions
├── app.py        # ServonautApp (main Textual App class)
├── app.css       # All TUI styling (Textual CSS)
└── main.py       # Entry point with arg parsing and logging setup
```

### config/

- **`schema.py`** — Dataclass definitions: `AppConfig`, `ScanRule`, `ConnectionProfile`, `ConnectionRule`. Schema version constant (`CONFIG_VERSION = 2`).
- **`manager.py`** — `ConfigManager` handles JSON load/save/validate at `~/.servonaut/config.json`.
- **`migration.py`** — Automatic v1 → v2 migration (flat bastion settings → nested profiles/rules).

### services/

All services implement abstract interfaces from `interfaces.py`. Services are stateless where possible, taking config or other services as constructor arguments.

| Service | Interface | Responsibility |
|---------|-----------|---------------|
| `AWSService` | `InstanceServiceInterface` | EC2 API calls via boto3, multi-region instance fetching |
| `CacheService` | — | Stale-while-revalidate caching with configurable TTL |
| `SSHService` | `SSHServiceInterface` | Key management, key discovery, SSH command building |
| `ConnectionService` | `ConnectionServiceInterface` | Profile resolution, ProxyJump/ProxyCommand argument building |
| `ScanService` | `ScanServiceInterface` | Keyword scanning via SSH across matching instances |
| `KeywordStore` | `KeywordStoreInterface` | Persistent JSON storage for scan results |
| `SCPService` | `SCPServiceInterface` | SCP upload/download command building and execution |
| `TerminalService` | `TerminalServiceInterface` | Terminal emulator detection and SSH session launching |

### screens/

Each screen is a `textual.screen.Screen` (or `ModalScreen`) subclass:

| Screen | Type | Description |
|--------|------|-------------|
| `MainMenuScreen` | Screen | Main menu with 6 options |
| `InstanceListScreen` | Screen | Instance DataTable with search, status bar, progress indicator |
| `ServerActionsScreen` | Screen | Actions menu for selected instance |
| `CommandOverlay` | ModalScreen | Remote command execution with streaming output |
| `FileBrowserScreen` | Screen | Remote filesystem tree via SSH |
| `SCPTransferScreen` | Screen | File upload/download with direction selector |
| `ScanResultsScreen` | Screen | Keyword scan results viewer |
| `SearchScreen` | Screen | Search across instances and scan results |
| `SettingsScreen` | Screen | Configuration editor |
| `KeyManagementScreen` | Screen | SSH key configuration and agent status |
| `HelpScreen` | Screen | Keybinding reference and user manual |

### widgets/

- **`InstanceTable`** — Textual `DataTable` subclass for the instance list
- **`RemoteTree`** — Textual `Tree` subclass for remote filesystem browsing
- **`StatusBar`** — Bottom bar showing instance count, cache status
- **`ProgressIndicator`** — Togglable progress display for async operations
- **`CommandOutput`** — `RichLog` wrapper for command overlay output

### utils/

- **`match_utils.py`** — `matches_conditions()` function used by both scan rules and connection rules. Supports: `name_contains`, `name_regex`, `region`, `id`, `type_contains`, `has_public_ip`.
- **`formatting.py`** — String formatting helpers
- **`platform_utils.py`** — OS/platform detection
- **`ssh_utils.py`** — SSH-specific utilities

## Service Initialization

All services are created in `ServonautApp._init_services()` during `on_mount`:

```
ConfigManager
├── CacheService(ttl_seconds=config.cache_ttl_seconds)
│     └── AWSService(cache_service)
├── SSHService(config_manager)
├── ConnectionService(config_manager)
├── ScanService(config_manager)
├── KeywordStore(config.keyword_store_path)
├── TerminalService(preferred=config.terminal_emulator)
└── SCPService()
```

Services are stored as attributes on the app instance (`self.config_manager`, `self.aws_service`, etc.). Screens access them via `self.app.<service>`.

## Navigation

Screens use `self.app.push_screen()` and `self.app.pop_screen()` for stack-based navigation. Shared instance data lives in `self.app.instances` — a list of dicts with keys: `id`, `name`, `type`, `state`, `public_ip`, `private_ip`, `region`, `key_name`.

## Async & Threading

- AWS API calls and cache operations are `async def` methods
- Long-running tasks use `self.run_worker()` to avoid blocking the event loop
- Workers notify the UI via `self.notify()` or `self.app.call_from_thread()`
- The command overlay uses `subprocess.Popen` in a threaded worker with line-by-line streaming, plus a daemon thread for stderr

## Styling

All CSS lives in a single `app.css` file using Textual's CSS-like syntax with design tokens (`$surface`, `$primary`, `$accent`, `$boost`, etc.). Styles are organized into labeled sections per screen/widget. No per-screen CSS files.

## SSH Connection Flow

1. `ConnectionService.resolve_profile(instance)` — finds matching profile via connection rules
2. `ConnectionService.get_target_host(instance, profile)` — returns public IP (direct) or private IP (bastion)
3. `ConnectionService.get_proxy_args(profile)` — builds `-J` or `-o ProxyCommand` args
4. `SSHService.build_ssh_command(host, username, key_path, proxy_args)` — assembles the full SSH command
5. For terminal sessions: `TerminalService.launch_ssh_in_terminal(ssh_cmd)` — wraps in a shell script and launches in detected terminal
6. For command overlay: `subprocess.Popen` in a threaded worker with streaming I/O

## Command Overlay Details

- Commands are wrapped in `bash -ic` so `.bashrc` is sourced (nvm, rbenv, pyenv work)
- Interactive commands (`vim`, `htop`, `tmux`, etc.) are detected and blocked with guidance to use SSH terminal
- Missing connection profiles are detected and warned about on mount
- Ctrl+C terminates the running subprocess without closing the overlay
- Command history navigable with Up/Down arrows

## Config Migration

v1 configs (flat `bastion_host`/`bastion_user` at root level) are automatically converted to v2 (nested `connection_profiles` + `connection_rules`). Migration runs on first load when `version` is missing or < 2.
