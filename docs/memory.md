# Server Memory

Server Memory is a persistent per-server fact cache that Servonaut probes, stores, redacts, and serves back to humans and AI agents.  Instead of asking an SSH subprocess "what OS does this box run?" on every chat turn, the memory subsystem caches the answer for 30 days and returns it instantly — with declared overrides, staleness flags, and a Markdown summary small enough to paste into an AI system prompt.

This document covers the full user-facing contract.  For implementation details, see `src/servonaut/services/memory/`.

## Table of contents

- [Why memory exists](#why-memory-exists)
- [Architecture](#architecture)
- [Module catalogue](#module-catalogue)
- [CLI reference](#cli-reference)
- [TUI reference](#tui-reference)
- [MCP tools for AI agents](#mcp-tools-for-ai-agents)
- [Chat integration](#chat-integration)
- [Configuration](#configuration)
- [Secret redaction](#secret-redaction)
- [Storage layout](#storage-layout)
- [Opt-out and privacy](#opt-out-and-privacy)
- [Paid-tier hooks](#paid-tier-hooks)
- [FAQ](#faq)

---

## Why memory exists

When an AI agent is asked "restart nginx on web-prod-1", the naive flow is:

1. SSH to probe which OS is running, what web server is installed, whether systemd or upstart controls it, what the service unit name is — three or four round-trips each adding 2-5 seconds.
2. Finally issue the action.

Server memory skips step 1 entirely.  On the first probe — usually a one-liner `servonaut memory build web-prod-1` — Servonaut runs a bounded set of allowlisted read-only commands, stores the result, and returns it as a Markdown summary ≤1500 tokens.  Future agent runs call `get_server_memory(web-prod-1)` instead of guessing, producing faster, cheaper, more accurate answers.

Memory also supports:

- **Pinned declarations** — `servonaut memory pin web-prod-1 os.version_id "22.04-hardened"` records that this box is on a custom kernel; agents see both observed and declared values.
- **Free-form annotations** — `servonaut memory annotate web-prod-1` opens `$EDITOR` on a Markdown file that the summary appends.  Use it for tribal knowledge the probes can't discover.
- **Staleness tracking** — each module has a TTL (ranging from 30 minutes for containers to 30 days for the OS kernel); stale data is flagged so agents don't trust it blindly.

---

## Architecture

```
┌───────────────┐      ┌─────────────────┐     ┌────────────────┐
│  CLI / TUI /  │──▶   │  MemoryService  │──▶  │  MemoryStore   │
│  MCP / Chat   │      │  (orchestrates) │     │  (JSON files)  │
└───────────────┘      └────────┬────────┘     └────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  ModuleProber[]  │
                       │  (SSH allowlist) │
                       └────────┬─────────┘
                                ▼
                         SSH to server
```

- **MemoryService** is the public facade.  Every CLI/MCP/chat caller goes through it — never poke `_store` directly.
- **ModuleProbers** each own one module (e.g. `OSProber`).  They emit a bounded list of allowlisted read-only commands; any write-capable token (`>`, `tee`, `mv`, ...) is rejected at construction time by the base class.
- **MemoryStore** persists modules as per-file JSON under `~/.servonaut/memory/<provider>/<instance_id>/<module>.json` with mode `0o600` and atomic writes.
- **Summariser** is pure data→string; same modules always produce byte-identical summaries.
- **Redactor** scrubs secrets from raw probe output *before* it reaches disk.

---

## Module catalogue

| Module       | TTL       | What it probes                                        |
|--------------|-----------|-------------------------------------------------------|
| `os`         | 30 days   | `/etc/os-release` + `uname -rma` → distro, version, kernel, arch |
| `runtimes`   | 7 days    | Node, Python, PHP, Ruby, Go versions                  |
| `services`   | 6 hours   | Enabled systemd units (fallback to `service --status-all`) |
| `web_stack`  | 1 day     | Nginx/Apache version + enabled sites                  |
| `logs`       | 1 day     | Readable log paths from the log-viewer configuration  |
| `databases`  | 1 day     | MySQL / MariaDB / PostgreSQL / Redis / MongoDB versions + listening DB ports |
| `containers` | 30 min    | Docker / Podman / kubectl versions + running containers |
| `network`    | 1 day     | Listening sockets, iptables rules, UFW status         |
| `git`        | 1 day     | Git checkouts under `/opt`, `/var/www`, `/home`, `/srv` |
| `disk`       | 1 hour    | Filesystem usage from `df -h`                         |

Each module emits an `observed` dict (facts the probe found), a `declared` dict (operator pins), plus metadata: `sudo_used`, `truncated`, `partial`, `probed_at`, `ttl_seconds`.

---

## CLI reference

All commands share the same instance resolution rules as the rest of Servonaut — pass either the cloud ID (`i-abc123`), the configured name (`web-prod-1`), or a custom-server name.  Match is case-insensitive; AWS wins on collision.

### `servonaut memory build <instance>`

Probe every enabled module for the given instance and persist the results.

```bash
# Full probe
servonaut memory build web-prod-1

# Only the cheap modules
servonaut memory build web-prod-1 --modules os runtimes

# All instances, max 5 concurrent SSH sessions
servonaut memory build --all

# Machine-readable output
servonaut memory build web-prod-1 --json
```

Exit codes: `0` success, `1` instance not found, `2` memory disabled/opted-out, `3` partial failure during `--all`, `4` usage error.

### `servonaut memory refresh <instance>`

Identical to `build` but skips TTL freshness checks so every requested module is re-probed.

```bash
servonaut memory refresh web-prod-1 --modules os services
```

### `servonaut memory show <instance>`

Print stored memory.  Three formats:

```bash
# Summary (default, token-bounded Markdown — ~1500 tokens)
servonaut memory show web-prod-1

# Full Markdown, no token cap
servonaut memory show web-prod-1 --format markdown

# Raw JSON for every stored module
servonaut memory show web-prod-1 --format json

# Inspect a single module's JSON
servonaut memory show web-prod-1 --module runtimes

# Only the modules past their TTL (useful for diff-style checks)
servonaut memory show web-prod-1 --stale --format json
```

### `servonaut memory pin <instance> <module>.<field> <value>`

Pin an operator-declared value.  The summary shows *both* observed and declared when they differ.

```bash
servonaut memory pin web-prod-1 os.version_id "22.04-hardened"
servonaut memory pin web-prod-1 runtimes.node "v20.11.0"
```

### `servonaut memory annotate <instance>`

Open `annotations.md` for the instance in `$VISUAL` / `$EDITOR` / `vi`.  Contents appear verbatim under `## Annotations` in the summary.

### `servonaut memory export <instance>`

Write the full Markdown summary to a file.

```bash
# Default: ~/.servonaut/memory/<provider>/<id>/summary.md
servonaut memory export web-prod-1

# Custom destination
servonaut memory export web-prod-1 --out /tmp/web.md
```

### `servonaut memory clear <instance>`

Delete stored memory.

```bash
# Clear all modules
servonaut memory clear web-prod-1 --all

# Clear specific modules
servonaut memory clear web-prod-1 --modules containers network
```

### `servonaut memory reset-prompts`

Reset the TUI's first-connect prompt counter to zero.  Run this if you dismissed the "Build memory for …? [y]" banner too many times and want it re-enabled.

---

## TUI reference

### Memory screen (`m` from instance list)

Press `m` while hovering over an instance in the main list to open the memory screen.

| Key | Action                               |
|-----|--------------------------------------|
| `r` | Refresh all modules                  |
| `m` | Refresh the module at the cursor     |
| `p` | Pin a declared value for the row     |
| `c` | Clear a module (confirm prompt)      |
| `a` | Open annotations in `$EDITOR`        |
| `e` | Export summary to Markdown           |

If the DataTable is empty and the server is not opted out, a CTA banner appears prompting you to press `r` or click **Probe server now** — this resolves the UAT gap where new users couldn't find the build trigger.

### First-connect prompt

After your first successful SSH connect to a server in a given session, a small banner appears on the instance list:

> **Build memory for prod-web-01?** Press [y] to probe, [n] to dismiss.

Pressing `y` kicks off a background `MemoryService.build`.  Three successive dismissals persist a counter in your config, and the banner stops appearing until you run `servonaut memory reset-prompts`.

---

## MCP tools for AI agents

Three MCP tools are exposed over stdio when you run `servonaut --mcp`, and over the relay when you're signed in to Servonaut Cloud (TUI → Account → Login).  They're also available to the built-in TUI chat (those flagged `chat_exposed: True`).

### `get_server_memory(instance_id, format="summary")`

Return cached memory for an instance.  **Call this FIRST** before any SSH round-trips — the cached summary frequently answers OS/runtime/service/web-stack questions without touching the network.

- `format="summary"` (default) — Markdown digest ≤1500 tokens
- `format="markdown"` — untruncated Markdown (full section set)
- `format="full"` — raw JSON for every module including `observed`, `declared`, `probed_at`, `ttl_seconds`, `sudo_used`, `truncated`, `partial`, `raw_output` (scrubbed via the redaction library when `config.memory.redaction_enabled=true`, which is the default)

*chat_exposed: yes*

### `refresh_server_memory(instance_id, modules=[...])`

Re-probe one or more modules, bypassing the TTL.  Use after significant server changes.

```json
{"instance_id": "web-prod-1", "modules": ["os", "runtimes"]}
```

*chat_exposed: no (requires SSH; not safe as an agent freehand)*

### `list_server_memories(stale_only=false)`

List every instance that has cached memory.  Pass `stale_only=true` to show only instances with at least one module past its TTL — useful for a "what should I re-probe?" dashboard.

*chat_exposed: yes*

### Audit trail

Every memory MCP tool call is recorded in `~/.servonaut/mcp_audit.jsonl` with timestamp, arguments, success/failure, and a short reason code on early returns.  Guard levels (`readonly` / `standard` / `dangerous`) apply here exactly as they do to the other MCP tools.

---

## Chat integration

When the built-in Servonaut chat resolves an active instance — either via an `@mention` in the prompt, the selected row in the instance table, or the currently-open server actions screen — it injects a small block into the system prompt:

```xml
<server_memory id="web-prod-1" provider="AWS" stale="false">
# Memory — web-prod-1 (i-abc123) @ AWS

## Identity
pretty_name: Ubuntu 22.04.4 LTS
kernel: 5.15.0-107-generic
arch: x86_64

## Runtimes
| Runtime | Version |
| --- | --- |
| node | v20.11.0 |
| php | PHP 8.3.4 |
...
</server_memory>
```

The tag is visible to the LLM but not to the user; agents are free to reference it.  If any module is stale a small yellow banner is shown in the chat panel (debounced 2 s to avoid flicker).

---

## Configuration

Memory is configured under the `memory` key in `~/.servonaut/config.json`:

```json
{
  "memory": {
    "enabled": true,
    "redaction_enabled": true,
    "default_ttl_overrides": {
      "services": 1800,
      "containers": 300
    },
    "disabled_modules": ["network"],
    "per_server_overrides": {
      "i-critical-prod":   { "memory_disabled": true },
      "bastion-sensitive": { "memory_disabled": true }
    }
  },
  "memory_first_connect_dismissed_count": 0
}
```

- `enabled` — master switch.  When `false`, no probes run and no memory is read or written.
- `redaction_enabled` — passes every `raw_output` field through the T9 redaction library before it lands on disk.  Default `true`; flip to `false` only if you control the boxes and want raw output for debugging.
- `default_ttl_overrides` — per-module TTL in seconds.  Overrides the prober's built-in default.
- `disabled_modules` — module names that are globally skipped.
- `per_server_overrides` — map keyed by **either** cloud ID or name; `{"memory_disabled": true}` opts that server out entirely.

---

## Secret redaction

The redaction library (T9, `src/servonaut/services/memory/redaction.py`) scrubs raw probe output before it reaches disk.  Eleven categories are detected:

| Category          | Example pattern                                 | Placeholder                          |
|-------------------|-------------------------------------------------|--------------------------------------|
| `aws-access-key`  | `AKIA[0-9A-Z]{16}`                              | `<redacted:aws-access-key>`          |
| `aws-secret-key`  | `aws_secret_access_key = <40 chars>`            | `<redacted:aws-secret-key>`          |
| `github-token`    | `ghp_...`, `gho_...`, `github_pat_...`          | `<redacted:github-token>`            |
| `jwt`             | `eyJ...\...\...`                                | `<redacted:jwt>`                     |
| `ssh-private-key` | `-----BEGIN OPENSSH PRIVATE KEY-----...`        | `<redacted:ssh-private-key>`         |
| `pem-block`       | `-----BEGIN CERTIFICATE-----...`                | `<redacted:pem-block>`               |
| `bearer-token`    | `Bearer <≥20 chars>`                            | `Bearer <redacted:bearer-token>`     |
| `password`        | `password=<value>` / `password: "<value>"`      | `password=<redacted:password>`       |
| `slack-token`     | `xoxb-...` / `xoxp-...` / etc.                  | `<redacted:slack-token>`             |
| `stripe-key`      | `sk_test_...` / `sk_live_...`                   | `<redacted:stripe-key>`              |
| `conn-string`     | `mysql://user:pass@host/db`                     | `mysql://<redacted:conn-user>:<redacted:conn-pass>@host/db` |

Structural scaffolding (the `Bearer ` prefix, the `=`/`:` operator, the connection-string scheme) is preserved so downstream parsers don't break.

**Annotation files** (the free-form notes you write with `memory annotate`) are NOT silently scrubbed — the user may have intentionally included a placeholder.  Instead, the UI flags a `scan_for_secrets` warning so you can review before saving.

Performance: 100 KB of log output is scrubbed in well under 100 ms on a dev machine; regexes are compiled once at import time.

---

## Storage layout

```
~/.servonaut/memory/
├── index.json                      # {version: 1, instances: {...}}
├── aws/
│   └── i-abc123/
│       ├── os.json
│       ├── runtimes.json
│       ├── services.json
│       ├── web_stack.json
│       ├── logs.json
│       ├── databases.json
│       ├── containers.json
│       ├── network.json
│       ├── git.json
│       ├── disk.json
│       ├── annotations.md          # user-authored
│       └── summary.md              # generated by `memory export`
├── custom/
│   └── <custom-server-name>/...
└── ovh/
    └── <ovh-instance-id>/...
```

Every file is written atomically (sibling `.tmp` + `os.replace`) with mode `0o600`.  The index lives alongside the provider directories and tracks `first_scan`, `last_scan`, and `modules` per instance.

---

## Opt-out and privacy

- To opt a single server out: add `"<id-or-name>": {"memory_disabled": true}` to `per_server_overrides`.  The CLI, MCP, chat, and screen layers all check this via `is_instance_disabled(id, name)` — both keys are checked, so an override keyed by name works even when the caller passes the ID (and vice-versa).
- To disable memory globally: set `"memory": {"enabled": false}` in your config.
- To disable only one module globally: add it to `memory.disabled_modules`.
- Data never leaves your machine unless you explicitly run `servonaut memory export` or enable one of the paid-tier cloud hooks.

---

## Paid-tier hooks

Memory integrates with Servonaut Cloud (sign in via TUI → Account → Login) for operators who want cross-machine and cross-team sharing.  The following operations are plan-gated on the backend — on the Free plan they no-op silently:

- **Cross-machine sync** — push your memory to servonaut.dev and pull it on another machine.
- **Team-shared memories** — list memories your teammates have shared within a team.
- **AI summaries** — when `ai_provider` is configured and the plan permits, the summariser can produce a richer `ai_summary.md` alongside the deterministic `summary.md`.

See the pricing page at [servonaut.dev](https://servonaut.dev) for current plan details.  The CLI + MCP layer always respects the backend's entitlement check — unauthorized calls return a structured "not available on your plan" response rather than an error.

---

## FAQ

**Do probes require sudo?**
No.  All commands are non-privileged.  The `services` module has a `service --status-all` fallback when systemctl is unavailable, and `containers` degrades gracefully when the docker socket requires root.

**What if a command takes too long?**
Every probe command has a 5 s wall-clock timeout and a 16 KB stdout cap.  Timeouts are recorded in `raw_output` as `<timeout>`; truncated output sets `truncated=true` in the module metadata.

**What if the server rejects SSH?**
Probers never raise.  Any SSH-runner exception is captured into `raw_output` as `<error: ...>`, the module is marked `partial=true`, and the service continues with whatever data is available.

**Can I run memory on an offline box?**
No — memory is a remote-SSH subsystem.  If you need offline inventory, run `memory build` before cutting the server off and the cached data survives indefinitely (subject to TTL staleness flags).

**How do I see the raw JSON for a module?**
`servonaut memory show <instance> --module <module>` dumps the on-disk JSON verbatim, including the redacted `raw_output`.

**Is the summary deterministic?**
Yes.  Given the same module JSON on disk, `summarise()` produces byte-identical Markdown.  This makes memory safe to diff across builds and eliminates UI flicker in the chat panel.
