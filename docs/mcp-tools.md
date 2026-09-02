# MCP Tools Reference

Servonaut ships an MCP (Model Context Protocol) server over stdio.  Start it with:

```bash
servonaut --mcp
```

Or auto-install into a coding agent:

```bash
servonaut --mcp-install claude       # or: cursor, windsurf, vscode, opencode, codex, agy, gemini, all
```

The installer forwards a fixed set of environment variables to the server by reference (`SSH_AUTH_SOCK`, `BW_SESSION`, `BWS_ACCESS_TOKEN`, the `AWS_*` credential and profile variables, `SERVONAUT_API_URL`, `SERVONAUT_MCP_URL`, plus any `$VARIABLE` referenced from your config). A variable that is not set when the agent starts arrives as an empty string; the server ignores those and falls back to each SDK's defaults (for AWS: the shared credentials file and the `default` profile), and lists the ignored names in `~/.servonaut/logs/servonaut.log` at startup.

This document lists every exposed tool.  The full canonical list (with JSON Schemas) lives in `src/servonaut/mcp/tool_schemas.py`.  When adding a tool, put the schema there — both the MCP server and the built-in chat adapter pick it up automatically.

## Guard levels

Every tool call passes through a `CommandGuard` configured in `config.mcp.guard_level`:

- `readonly` — only listing and status tools.
- `standard` (default) — read + a curated command allowlist.
- `dangerous` — everything except a hard-coded blocklist (`rm -rf`, `shutdown`, `dd`, ...).

Every call is logged to `~/.servonaut/mcp_audit.jsonl` with a timestamp, arguments, success flag, and short reason code on early returns.

## Tool categories

- [Instance inventory and ops](#instance-inventory-and-ops)
- [Server memory](#server-memory)
- [OVHcloud](#ovhcloud)
- [Session and backend](#session-and-backend)

---

## Instance inventory and ops

### `list_instances(region?, state?)`

List every managed instance (AWS EC2, OVH, custom servers).  Optional filters on `region` or `state`.

### `check_status(instance_id)`

Quick status check — state, IPs, region, instance type.

### `get_server_info(instance_id)`

Detailed host info via SSH: hostname, uptime, disk, memory.

### `run_command(instance_id, command)`

Run a command over SSH.  Guard-gated — blocked commands return a structured refusal.  Output is truncated at `config.mcp.max_output_lines`.

### `get_logs(instance_id, log_path?, lines?)`

Fetch trailing log content from the remote host.

### `transfer_file(instance_id, local_path, remote_path, direction)`

SCP upload/download.  Not chat-exposed — the guard treats it as dangerous.

---

## Server memory

These tools surface the [Server Memory](memory.md) subsystem.  Agents should call `get_server_memory` FIRST before any SSH round-trip; the cached summary answers OS / runtime / service / web-stack / log questions instantly.

### `get_server_memory(instance_id, format="summary")`

Return cached memory for an instance.

**Arguments**

| Name          | Type    | Default     | Description                                          |
|---------------|---------|-------------|------------------------------------------------------|
| `instance_id` | string  | *required*  | Instance ID, name, or custom-server name.            |
| `format`      | string  | `"summary"` | `summary` \| `markdown` \| `full`                   |

**Return**

- `summary`: token-efficient Markdown digest (target ≤1500 tokens).
- `markdown`: untruncated Markdown with every section.
- `full`: raw JSON per module — `observed`, `declared`, `probed_at`, `ttl_seconds`, `sudo_used`, `truncated`, `partial`, `raw_output`.  `raw_output` is scrubbed by the redaction library when `config.memory.redaction_enabled=true` (default).

*chat_exposed: yes*

### `refresh_server_memory(instance_id, modules?)`

Re-probe one or more modules, bypassing TTL freshness.  Omit `modules` to refresh all.

```json
{"instance_id": "web-prod-1", "modules": ["os", "runtimes"]}
```

*chat_exposed: no (requires SSH; not safe as agent freehand)*

### `list_server_memories(stale_only?)`

Return every instance that has cached memory.

| Name         | Type    | Default | Description                                       |
|--------------|---------|---------|---------------------------------------------------|
| `stale_only` | boolean | `false` | When `true`, return only instances with ≥1 stale module. |

*chat_exposed: yes*

---

## OVHcloud

All OVH tools require the OVH service to be configured (`servonaut --setup-ovh` or the Settings screen).  Tools are dropped from `tools/list` entirely when OVH is not wired up.

- `ovh_monitoring(instance_id, period?)` — CPU/RAM/network metrics.
- `ovh_list_ips()` — account-wide IP inventory with routing info.
- `ovh_firewall_rules(ip)` — firewall rules for an IP.
- `ovh_ssh_keys()` — registered SSH keys.
- `ovh_snapshots(instance_id)` — snapshot list for VPS or Public Cloud.
- `ovh_dns_records(zone, record_type?)` — DNS records.
- `ovh_billing()` — current billing summary.
- `ovh_invoices(limit?)` — recent invoices.

None of these are chat-exposed by default — they're read-only but noisy for the LLM.

---

## Session and backend

### `whoami()`

Describe the currently logged-in servonaut.dev session (email, plan, API base URL, token expiry).  The bearer itself never leaves the CLI.

### `api_request(method, path, query?, body?, headers?)`

Authenticated request against servonaut.dev REST API.  Headers are strictly filtered — only `Accept`, `Content-Type`, `Accept-Language`, `If-None-Match` are honoured.  Response body capped at 1 MiB, sliding-window rate-limited at 30/60s.

*chat_exposed: no — the LLM doesn't need to hit arbitrary endpoints; covered over MCP for external agents with their own guard policy.*

### `relay_status()` / `relay_reconnect(force?)`

Operational: report / heal the Mercure relay connection.  Not chat-exposed.

### `mcp_tool_call(name, arguments?)`

Invoke a tool on the hosted MCP server at `mcp.servonaut.dev`.  Wraps name + arguments in a JSON-RPC 2.0 `tools/call` envelope.

---

## Adding a new tool

1. Add the schema entry to `TOOL_SCHEMAS` in `src/servonaut/mcp/tool_schemas.py`.  Include `description`, `schema`, `chat_exposed`, and optionally `required_service`.
2. Implement the handler method with the same name on `ServonautTools` (`src/servonaut/mcp/tools.py`).
3. Both MCP and the chat adapter pick it up automatically — no further registration needed.

See the commit history of `tool_schemas.py` for examples.
