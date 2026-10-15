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
- `standard` (default) — read + a curated command allowlist. `run_command` accepts one allowlisted command, optionally piped into other allowlisted commands (`ps aux | grep nginx`), with an optional leading `sudo`. Command lists (`;`, `&&`, `||`), redirects, background jobs, subshells and command substitution are refused, as are the options of allowlisted commands that write files or change the system (for example `find -exec`/`-delete`, `sort -o`, `ip ... add/del/set`, `ifconfig ... down`, `date -s`). Use `dangerous` for those.
- `dangerous` — everything except a hard-coded blocklist (`rm -rf`, `shutdown`, `dd`, ...).

Every call is logged to `~/.servonaut/mcp_audit.jsonl` with a timestamp, arguments, success flag, and short reason code on early returns.

### Team shared servers

On a server one of your teams shares with you, the team decides what your agents may do. This covers the MCP server, the tools of the AI chat and everything relayed to this machine (see below). Your own settings can make it stricter, never looser:

- Your agents run at the stricter of your `guard_level` and the level your role in the team gets: owners, admins and members get `standard`, viewers get `readonly`. If Servonaut cannot tell your role, it uses `readonly`.
- At `standard`, only the built-in command allowlist applies, with the same option rules as on your own servers (no `find -delete`, no `ip ... add`, and so on). Commands you added to your own allowlist do not work on a team's servers, and commands you removed from it stay refused.
- The built-in blocklist always applies, and so do the patterns you added to your own blocklist.
- `transfer_file` and the other `dangerous` tools are not available on a team's servers.

A refusal names the team, the level and what was refused, for example: *Blocked: on team Ops's shared servers your agents run at the standard level (set by the team), and 'systemctl restart nginx' is not an allowed command there.* When the command is on the allowlist but one of its options is not allowed, the refusal says which rule it broke. The audit log records every refusal with the reason `team_rule`.

Relayed requests follow the same rule: commands you type in the web console, remediation fixes you approve and on-box IP bans. A remediation fix runs several commands in one go, which the `standard` level does not allow, so fixes are refused on a team's servers and the refusal names the fix.

Your own servers keep your own settings. A server that is both in your own inventory and shared by a team keeps your own settings when your agent names it by your own name or id; named through the team (`ops/<name>`, or the team's id for it), the team's rule applies. Commands you type yourself in the TUI or with `servonaut ssh` do not fall under team rules.

## Several accounts per provider

When a provider has more than one account configured (see
[Multiple accounts per provider](multiple-accounts.md)):

- `list_instances` names those servers `label/name` and takes an `account`
  filter (an account label, or `custom`).
- Every `instance_id` / `identifier` also accepts `label/name`,
  `label/<id>` and `custom/<name>`. An instance id always wins, so OVH
  Public Cloud ids (`<project_id>/<id>`) keep working. A name several
  servers share is refused with the references that pick each one.
- Tools that act on a whole account (AWS listings, CloudTrail, CloudWatch,
  IP bans, S3, Hetzner and OVH registries, billing, create) take an optional
  `account`; without it they use the provider's primary account. If the
  primary account cannot connect, name the account to use.
- Start, stop, reboot and delete find the account the server belongs to
  themselves; `account` narrows the search. A server that no account lists
  is refused rather than tried in the primary account.

## Tool categories

- [Instance inventory and ops](#instance-inventory-and-ops)
- [Basic monitoring](#basic-monitoring)
- [Server memory](#server-memory)
- [OVHcloud](#ovhcloud)
- [Session and backend](#session-and-backend)

---

## Instance inventory and ops

### `list_instances(region?, state?, account?)`

List every managed instance (AWS EC2, OVH, Hetzner, custom servers) of every account.  Optional filters on `region`, `state` or `account`.

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

## Basic monitoring

These read-only tools collect current information over SSH from managed Linux
servers across AWS, OVH, Hetzner, and custom providers. They need working SSH
access and return a snapshot; they do not store historical metrics.

| Tool | Use |
|------|-----|
| `fleet_health_snapshot(region?, running_only?, timeout?)` | One fleet-wide table of load averages, CPU count, memory usage percentage, PHP-FPM workers/capacity, and detected web services. Unreachable hosts are reported separately. |
| `get_server_info(instance_id)` | One server's hostname, uptime/load, filesystem usage, and memory totals. |
| `disk_usage(instance_id, top_n?)` | A more detailed disk-usage inspection. |
| `docker_stats(instance_id)` | Current CPU, memory, network, and block-I/O counters per container. |

Use `fleet_health_snapshot` for fleet triage and `get_server_info` for a quick
single-server check. CPU count and load are not CPU utilization percentages;
`docker_stats` reports CPU percentages for containers only. OVH SSH reads use
the same configured username and key selection as dashboard metrics.

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
