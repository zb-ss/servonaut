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
# Check for updates and upgrade
PYTHONPATH=src python3 -m servonaut.main --update

# Create desktop shortcut (Linux/macOS)
PYTHONPATH=src python3 -m servonaut.main --install-desktop

# Start MCP server (for AI agents)
PYTHONPATH=src python3 -m servonaut.main --mcp

# Auto-install MCP server into a coding agent (claude, opencode, cursor, windsurf, vscode, all)
PYTHONPATH=src python3 -m servonaut.main --mcp-install claude
```

## Architecture

Modular TUI built on Textual, organized into six packages under `src/servonaut/`:

- **`config/`** — Configuration management: `AppConfig` dataclass hierarchy (`schema.py`), JSON load/save/validate (`manager.py`), chained v1→v2→v3→v4 migrations (`migration.py`; `manager.load()` calls `migrate_to_latest`). Nested dataclasses: `ScanRule`, `ConnectionProfile`, `ConnectionRule`, `CustomServer`, `IPBanConfig`, `AIProviderConfig`, `MCPConfig`
- **`services/`** — Business logic with abstract interfaces (`interfaces.py`). Each service implements its interface. Key services: `AWSService` (boto3 EC2 API), `CacheService` (stale-while-revalidate), `SSHService` (key management, command building), `ConnectionService` (bastion/ProxyJump resolution), `ScanService` + `KeywordStore` (keyword scanning), `TerminalService` (terminal detection/launch), `SCPService` (file transfer), `CustomServerService` (non-AWS server CRUD), `LogViewerService` (log path probing, tail commands), `CloudTrailService` (boto3 CloudTrail event lookup), `CloudWatchService` (boto3 CloudWatch Logs browsing with Top IPs analysis, WAF action tracking, IP geolocation via ip-api.com, AbuseIPDB integration), `IPBanService` (WAF/SG/NACL strategies with audit trail), `AIAnalysisService` (OpenAI/Anthropic/Ollama adapters), `UpdateService` (PyPI version check, upgrade execution). The `services/memory/` package holds the local memory cache + cloud sync layer: `MemoryService` (orchestration), `MemoryStore` (filesystem persistence), `MemorySyncService` (X25519 keypair, AES-256-GCM envelope encryption, JSONL queue, batched POST to `/api/v1/memory/sync`), `MemorySettingsService` (digest/mercure/ai-consent settings stored server-side), `TeamMemoryService` (team grants), `AISummaryService`, `ExportService` (signed compliance tarball), and the per-module probers under `services/memory/modules/`.
- **`screens/`** — Textual `Screen` subclasses for each view (instance list, server actions, file browser, command overlay, SCP transfer, scan results, settings, key management, help, custom servers, log viewer, CloudTrail browser, CloudWatch browser, IP ban, AI analysis, copy mode, fleet memory, per-instance memory, snapshot manager, login). Memory Sync–specific: `MemorySyncSetupScreen` (state-aware unlock/setup hub, sidebar entry `☁ Memory Sync`), `MemoryDriftScreen`, `MemoryExportScreen`, `ShareInstanceScreen` (was `ShareInstanceModal` — converted to Screen so the sidebar is visible during multi-step share). Relay status: `RelayStatusScreen` (was `RelayStatusModal`, same conversion). Every full-screen panel includes a `Sidebar` widget for navigation.
- **`widgets/`** — Reusable Textual widgets: `Sidebar` (persistent navigation), `InstanceTable` (DataTable with Provider column), `RemoteTree` (Tree for remote fs), `StatusBar`, `ProgressIndicator`, `CommandOutput` (RichLog), `ChatPanel` (AI chat dock)
- **`utils/`** — Helpers: `formatting.py`, `platform_utils.py`, `ssh_utils.py`, `match_utils.py` (instance matching with conditions: `name_contains`, `name_regex`, `region`, `id`, `type_contains`, `has_public_ip`, `provider`, `group`, `tag:<key>`)
- **`mcp/`** — MCP server for AI agents: `server.py` (stdio transport), `tools.py` (6 tool implementations), `guards.py` (readonly/standard/dangerous guard levels), `audit.py` (JSONL audit trail), `installer.py` (auto-install into Claude Code)

### Service Initialization and Access

All services are created in `ServonautApp._init_services()` (in `app.py`) during `on_mount`. Services are stored as attributes on the app instance. Screens access them via `self.app.<service>` (e.g., `self.app.ssh_service`, `self.app.connection_service`).

Service dependency chain:
```
UpdateService() (no dependencies, created first)
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
  ├── CloudWatchService()
  ├── IPBanService(config_manager)
  └── AIAnalysisService(config_manager)
```

### Screen Navigation

The app opens directly to `InstanceListScreen`. A persistent `Sidebar` widget appears on every screen for top-level navigation. Sidebar buttons use `self.app.switch_screen()` to replace the current view (no stacking). Sub-screens (e.g., `ServerActionsScreen` from clicking an instance) use `self.app.push_screen()` to stack on top. `pop_screen()` is overridden on the app to navigate to `InstanceListScreen` when at the root instead of crashing.

Shared instance data lives in `self.app.instances` (list of dicts with keys: `id`, `name`, `type`, `state`, `public_ip`, `private_ip`, `region`, `key_name`). Custom servers add extra keys: `provider`, `group`, `tags`, `port`, `username`, `is_custom`.

### Async Pattern

Long-running operations (AWS API, SSH) are async and run via `self.run_worker()` to avoid blocking the TUI. Workers notify the UI via `self.notify()`.

### Styling

All CSS is in a single `app.css` file using Textual's CSS-like syntax with design tokens (`$surface`, `$primary`, `$accent`, etc.). Screen-specific styles are organized into labeled sections within this file. The `Sidebar` widget defines its own `DEFAULT_CSS` for base layout. Borders use `round` style (not `solid`, which has rendering gaps in some terminals). Avoid emoji with VS16 variant selectors (`U+FE0F`) in button labels — they cause row-wide rendering corruption.

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
- API endpoints overridable via env vars: `SERVONAUT_API_URL` (api_client + auth_service), `SERVONAUT_MCP_URL` (remote MCP client). Defaults to production subdomains. For staging: set both to `https://staging.servonaut.dev`
- Relay listener URLs (`base_url`, `mercure_url`) are configured in `config.json` under `relay` key, not env vars

**Instance Matching (`match_utils.py`):**
- Used by scan rules, connection rules, and custom server filtering
- Supports: `name_contains`, `name_regex`, `region`, `id`, `type_contains`, `has_public_ip`, `provider`, `group`, `tag:<key>`
- All conditions are AND-ed together

**Custom Servers:**
- Non-AWS servers stored in `config.custom_servers` as `CustomServer` dataclass instances
- Converted to instance dict format via `CustomServerService.to_instance_dict()` with `is_custom: True` flag
- Merged into `self.app.instances` alongside AWS instances, re-merged after AWS refresh
- SSH commands use custom server's `username`, `port`, and `ssh_key` transparently

**CloudWatch Top IPs:**
- `extract_top_ips()` parses JSON structured logs (WAF/ALB) to extract `clientIp` from `httpRequest` field, avoiding false matches on version numbers in user-agent strings (e.g. `Chrome/145.0.0.0`)
- Falls back to IP regex for non-JSON log lines
- Tracks WAF `action` per IP: returns `allowed`/`blocked` counts alongside total
- Action filter parameter: `None` (all), `"ALLOW"`, `"BLOCK"` — cycled via `f` key or clickable toggle
- IP info lookup (`i` key): geolocation via `ip-api.com` (free, no key), abuse reports via AbuseIPDB (optional, key in Settings, supports `$ENV_VAR`)

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
- `textual>=8.0.0` — TUI framework
- Python 3.10+ required

**Optional:**
- `httpx>=0.25.0` — AI log analysis (`pip install 'servonaut[ai]'`)
- `mcp>=1.0.0` — MCP server for AI agents (`pip install 'servonaut[mcp]'`)
- Install all: `pip install 'servonaut[all]'`

## Workflow Learnings

### Patterns Discovered
- MCP `ServonautTools` receives `custom_server_service` as constructor argument and uses `list_as_instances()` to merge custom servers alongside AWS instances in both `_find_instance` and `list_instances`.
- `_find_instance` performs case-insensitive match on both `id` and `name` fields across the merged AWS + custom list. AWS instances are searched first, so they take precedence on name collisions.
- `SCPService._build_base_args` accepts `port: Optional[int]` and emits `-P <port>` (uppercase P, SCP convention) when port is non-None and not 22.
- Custom server connection is branched in `_resolve_connection` via `instance.get('is_custom')`: custom servers read `username`, `ssh_key`, and `port` directly from the instance dict; AWS instances use `SSHService.get_key_path` and profile-based username resolution.

### Issues Resolved
- MCP tools previously ignored `CustomServerService` entirely — `_find_instance` only queried AWS, and `list_instances` never included custom servers. Fixed by injecting `custom_server_service` into `ServonautTools` and merging both lists.
- Port was not forwarded from custom server instance dict to SSH/SCP commands. Fixed by passing `conn.get('port')` through `build_ssh_command` and `build_upload_command`/`build_download_command`.
- `SCPServiceInterface` signatures lacked the `port` parameter, causing a mismatch with the implementation. Fixed by adding `port: Optional[int] = None` to both abstract methods.

### Key Decisions
- Chose Option B (inline resolver in `_find_instance`) rather than a separate `InstanceResolver` class — sufficient for current provider count (AWS + custom) and keeps the surface area small. Can be extracted if a third provider is added.
- Tool descriptions in `server.py` updated from EC2-specific language to "any managed instance" to reflect multi-provider reality.

### Memory conventions (T1-T13)
- **Never reach into `MemoryService._store` from outside `services/memory/`.** Use the public API helpers: `stale_modules`, `get_all_modules`, `get_annotations_path`, `update_index`, `is_memory_disabled`. Screens, CLI, MCP tools, and chat all go through these.
- **Opt-out is checked by BOTH id and name on every surface.** Call `memory_service.is_memory_disabled(id, name)` or `config.memory.is_instance_disabled(id, name)` — never `is_module_disabled_for(id)`. An id-only check misses name-keyed overrides and vice versa.
- **Probers never raise.** Every `ModuleProber._run_command` captures timeouts (`<timeout>`) and ssh-runner exceptions (`<error: ...>`) into `raw_output` and returns a `ModuleResult` with `partial=True`. New probers that override `probe()` (like `GitProber`) must preserve this contract.
- **Prober commands are allowlisted at construction time.** The base class runs every command through `_assert_no_writes` and rejects any token that could write (`>`, `>>`, `tee`, `mv`, `cp`, `dd`, numeric-FD redirects except `2>`, `sed -i`).
- **Memory and LogViewerService have a mutual dependency.** Construct `LogViewerService` first with `memory_service=None`, create `MemoryService` with the log viewer injected, then wire back via `log_viewer_service.set_memory_service(memory_service)`. All three construction sites (`app.py::_init_services`, `mcp/server.py::create_mcp_server`, `cli/memory.py::_init_headless_services`) follow this pattern.
- **Redaction is wired via `config.memory.redaction_enabled`.** Default true. The selector (`default_redactor` vs `noop_redactor`) is mirrored at each construction site. The 11-category regex library lives in `services/memory/redaction.py`; every match is tagged `<redacted:{category}>` so operators can see what was scrubbed.
- **Annotations save path** must NOT silently scrub secrets. Use `redaction.scan_for_secrets(text)` to detect and warn the user; let them save anyway (they may have pasted a placeholder intentionally).
- **Rich markup escape** on every user-influenced string interpolated into markup (server names from cloud metadata, annotations, etc.).
- **Textual workers for memory operations declare `group=...`** distinct from other background work (`memory_refresh`, `memory_mutation`, `memory_io`, `memory_first_connect`). `exclusive=True` cancels every worker in the default group.
- **Path-traversal validation** runs at the top of every `MemoryStore` method that touches the filesystem (`_validate_instance_id`, `_validate_module_name`).
- **MCP audit log on every early return.** Success path + every error path must call `self._audit.log(name, args, payload, success=False, reason=<distinct-code>)`.

### Memory Sync conventions (T14-T19)

- **`MemorySyncService.is_configured` requires THREE attributes**: `_self_pubkey`, `_self_privkey`, AND `_self_user_id`. The user_id half is critical — every envelope's DEK self-wrap is keyed by `recipient_user_id == caller`; without it the server rejects every envelope with `missing_self_wrap`. A pubkey-only check would let `is_configured=True` while `drain_now` silently early-returns. The setup card (`MemorySyncSetupScreen`) checks this single property to decide between "Locked" and "Active" states.
- **`bootstrap()` MUST raise on missing user_id.** `fetch_user_id()` returning None means we'd silently half-bootstrap and accumulate envelopes that can never be self-wrapped. Raise `MemoryBackendError("Could not resolve your user_id…")` instead of continuing.
- **`fetch_user_id` has a fallback chain**: `/api/v1/me` → Mercure-JWT decode of `/api/cli/mercure-token`'s `subscribe` claim (`/cli/{user_id}/commands`). The fallback is a workaround — once the backend exposes user_id in `/api/oauth/token` or `/api/entitlements`, delete `_user_id_from_mercure_jwt`. See the brief at `~/.dotfiles/org/org/servonaut/plans/backend/expose-user-id-to-cli.org`.
- **`enqueue_module` is a no-op when `is_configured=False`.** This is intentional: we don't accumulate plaintext envelopes on disk for users who never opt in. The flip side: probes done BEFORE keypair enrolment never reach the queue, so `MemorySyncService.backfill_from_local_store()` exists to bridge that gap. `_do_sync_now` calls backfill then drains in a loop until empty. Backfill is idempotent within a session (skips `(instance_id, module)` pairs already pending) and skips `ai_summary` (server-generated only).
- **`drain_now` re-queues on APIError/RateLimit/MissingUserId and returns an empty `SyncBatchResult`.** Loop callers MUST also read `sync.status.last_error` / `halted_reason` after the loop — otherwise an "all batches returned 0/0" outcome looks indistinguishable from a successful drain of an empty queue. See `MemorySyncSetupScreen._do_sync_now` for the surface pattern.
- **`APIClient.post/patch/put` enforce `json=` keyword-only.** Positional payload calls (`api.post("/foo", payload)`) raise `TypeError` at runtime. Tests mocking the client MUST use `MagicMock(spec=APIClient)` so positional misuse fails at test time instead of silently passing.

### ModalScreen vs Screen rule of thumb

Use `ModalScreen` for **brief blocking interactions**: yes/no confirms, single-field inputs, passphrase prompts, tier-gate notices, transient overlays. They render above the active screen with a dim background — the visual cue is "dismiss to return".

Use a regular `Screen` (with `Sidebar` in compose) for **anything content-heavy or multi-step**: status panels with multiple actions, share/setup workflows, settings pages. The persistent sidebar keeps navigation context; pop returns to the previous screen.

When in doubt: if the panel has more than one button row, more than one form field, or any user-readable status that takes >1 row to render, it's a Screen. Recent migrations: `RelayStatusModal` → `RelayStatusScreen`, `ShareInstanceModal` → `ShareInstanceScreen` (back-compat alias kept).

### Premium AI conventions

When working on the hosted-AI provider (`services/ai_providers/servonaut_provider.py`)
or the chat-panel streaming integration:

- ServonautProvider is registered LATE via `AIAnalysisService.register_servonaut_provider(api_client, auth_service)` because it needs DI; the original PROVIDERS dict is for nullary providers only.
- ServonautProvider.chat / stream_chat / analyze are decorated with @require_premium_ai / @require_premium_ai_stream — the gate raises ForbiddenEntitlementError BEFORE any network IO.
- ServonautProvider.chat is the public surface; it accepts keyword extras `task`, `allow_tools`, `conversation_id`, `context`. The CLI and tests must NOT call `_chat_internal` (private) — call `provider.chat(...)` instead.
- SSE consumption runs in a Textual worker with `group="ai_chat"` (the canonical group for chat-panel streaming, top-up, and history-load workers). `ai_stream` was the original plan name; `ai_chat` is the implementation.
- Tool guard map in services/ai_tool_bridge.py mirrors the server-side enforcement; this is defense-in-depth, NOT the source of truth. `_escalate_guard(server, client)` enforces the client mirror as a FLOOR — a server-supplied `guard_level` lower than the client mirror is escalated, not honoured.
- The dangerous-tool gate (deploy/provision/security_scan) is hidden in the UI when `auth.has_dangerous_ai_tools` is False. Server enforces independently — both layers required.
- mcp_audit.jsonl rows for AI-originated tool calls carry `_source="ai_chat"` + `_conversation_id` + `_tool_call_id` so the audit trail can distinguish MCP-driven vs AI-driven tool runs.
- Provider preference resolution: ProviderPreferenceResolver.resolve() is PURE (no IO). The resolver returns a ProviderDecision with events; UI consumers are responsible for pushing modals / banners. The chat panel owns `SHOW_FIRST_RUN_MODAL`, `SHOW_EMPTY_STATE`, and `PINNED_ERROR_NO_PROVIDER` reactions.
- Banner dismissal is durable: AIProviderConfig.dismissed_banners is a list of banner IDs persisted to ~/.servonaut/config.json.
- **Per-provider API keys (v4 schema)**: `AIProviderConfig` has separate `openai_api_key`, `anthropic_api_key`, `gemini_api_key`, `ollama_api_key` fields plus a legacy `api_key` field kept on disk for one-release backward compat. ALWAYS read keys via `config.key_for(provider_name)` — it returns the per-provider field, falling back to the legacy field only when `config.provider == provider_name` (Ollama is excluded from the legacy fallback because the legacy field was never populated for it). Never read `config.api_key` directly: a leftover key from one provider would silently authenticate calls to a different one. The resolver's `is_provider_configured()` and the per-provider adapters in `services/ai_analysis_service.py` go through `key_for()` for exactly this reason.
- **Ollama Cloud vs local**: `OllamaProvider` attaches `Authorization: Bearer <key>` only when `config.key_for("ollama")` is non-empty, so local installs (no key) keep working without auth and Cloud users (`base_url=https://ollama.com`) get authenticated. Detection rule (`_CONFIG_RULES["ollama"]`) returns True if either `base_url` or the key is set — empty/empty defaults are not assumed-running. When pointing `base_url` at `https://ollama.com`, model names use NO `-cloud` suffix (e.g. `gpt-oss:120b`); the `-cloud` suffix is only for local Ollama proxying to a cloud model.
- Local fallback is OPT-IN. Default ai.local_fallback_provider is null. Privacy is the differentiator — never silently route prompts away from Servonaut AI.
- AIQuota.from_dict(None) is the free-user case. Every chat-panel quota render must `if quota is None`-guard.
- **Top-up post-checkout has TWO variants**: `schedule_post_topup_refresh()` for the long-running TUI (creates +30s/+60s asyncio tasks); `await_post_topup_refresh()` for the one-shot CLI (blocks inline ~45s then refreshes once). The CLI MUST call the await variant — the schedule variant's tasks die when `asyncio.run` exits.
- Conversations export validates dest_path against (cwd OR ~/Downloads); other locations are rejected. `force=True` allows overwrite ONLY after the path-traversal validator runs — never delete a file outside the allowed roots even with `--force`.
- **Rich markup hygiene**: every `app.notify(...)` call that interpolates a server-controlled string (APIError.message, SSE error payloads, info events) MUST pass `markup=False`. Streamed assistant content, user-role rows imported from server-stored conversations, and the thinking-status accumulator MUST escape via `rich.markup.escape` before interpolating into Rich-markup contexts.
- **Stripe checkout URL validation**: top-up handlers (`widgets/chat_panel.py::_do_topup_checkout`, `cli/ai.py::_handle_topup`) call `is_valid_stripe_checkout_url(url)` from `services/ai_providers/servonaut_provider.py` BEFORE auto-launching the browser. Non-Stripe URLs render with "Open this URL manually" and skip `webbrowser.open`.

### Wire-format additive contracts — store raw payload dicts at the boundary

When the CLI consumes a JSON wire format from servonaut.dev (entitlements, secrets-config, future endpoints), the boundary code does **two things**:

1. **Cache the raw payload dict**, not a typed parse. `AuthToken.entitlements: Dict`, `AuthToken.secrets_config: Dict`, `AuthToken.teams_cached: List` are stored verbatim; consumers extract typed fields at read time via `.get(...)` helpers.
2. **Defensive `from_wire` parse** for the in-process typed shape (`SecretsConfig.from_wire`) — drops unknown keys, coerces bad shapes, never crashes on a partial response. The PARSE is for the in-process consumer; the CACHE is the wire dict.

Concrete proof in the secrets-management feature: three additive contract fields landed without ever cutting a CLI release.

- `entitlements.allow_dangerous_ai_tools` — added server-side (F4); existing CLI cached the raw entitlements dict, `_extract_bool_feature` started returning the new flag on next fetch.
- `secrets_config.config.token_env_var` — added during scope; cached path picked it up.
- `secrets_config.team_slug` — added on 2026-05-17; `active_team_slug()` reads `secrets_config.get("team_slug")` and lit up the cached path on next fetch.

Each cycle: server change → users see new behavior on next cache refresh. NOT: server change → CLI parse → CLI release → CI green → ship → users update.

**The rule**: when designing a new wire-cached field, store the dict verbatim AND parse-by-name at read time. The temptation to "extract everything typed at apply time" feels cleaner but forfeits this pattern. Confirmed working consistently — extend the pattern, don't break it. (Coordinated with `servonaut-dev` on agent-bus thread `secrets-management-kickoff`; web-side has the symmetric note.)
