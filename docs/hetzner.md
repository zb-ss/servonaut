# Hetzner Cloud Provider

Servonaut speaks **Hetzner Cloud** as a first-class provider, with full
server lifecycle (list / create / destroy / SSH keys). Designed for
disposable demo / staging fleets and dev-mindshare workflows where
hourly billing and clean teardown beat long-lived AWS-style fleets.

## Quick start

### 1. Get an API token

In the Hetzner Cloud Console, open the project you want Servonaut to
manage and create a *new API token* under *Security → API Tokens* with
**Read & Write** scope. Copy it once — Hetzner only shows it on
creation.

### 2. Make the token available to Servonaut

Servonaut resolves the token from the first matching source:

| # | Source                                | Notes                                                              |
|---|---------------------------------------|--------------------------------------------------------------------|
| 1 | `config.hetzner.api_token`            | Supports `$ENV_VAR` and `file:/path/to/token`                      |
| 2 | `$HCLOUD_TOKEN` env variable          | Same env var the official `hcloud` CLI / Terraform provider use    |
| 3 | `~/.config/hcloud/token`              | Default location of the `hcloud` CLI's token file — zero-config    |

Recommended: drop the token at `~/.config/hcloud/token` so the same
file works for the `hcloud` CLI, Servonaut, and Terraform without
duplication.

```bash
mkdir -p ~/.config/hcloud
echo "abc...your-token..." > ~/.config/hcloud/token
chmod 600 ~/.config/hcloud/token
```

### 3. Enable the provider

Edit `~/.servonaut/config.json` and set `hetzner.enabled = true`:

```jsonc
{
  "hetzner": {
    "enabled": true,
    "api_token": "",                          // empty → fall through to env / file
    "default_username": "root",
    "default_image": "ubuntu-22.04",
    "default_server_type": "cx23",            // current cheapest x86 in fsn1
    "default_location": "fsn1",
    // Hetzner-side identifier — a name (or numeric ID) of an SSH key
    // already registered with Hetzner Cloud. NOT a local file path.
    "default_hetzner_ssh_key": "my-laptop",
    // Local file path used by ``ssh -i`` when connecting INTO created
    // servers. Falls back to AppConfig.default_key when empty.
    "default_local_ssh_key": "~/.ssh/id_ed25519",
    "cache_ttl_seconds": 300,
    "cache_path": "~/.servonaut/hetzner_cache.json",
    "audit_path": "~/.servonaut/hetzner_audit.jsonl",
    "cost_alert_threshold": 0.0,
    // When true (default), refuse to create a server with no SSH keys.
    // Hetzner would otherwise spawn one with a random root password we
    // cannot recover, leaving a billed unreachable box. Set to false
    // (or pass --allow-no-keys) only if you know what you're doing.
    "require_ssh_keys_on_create": true
  }
}
```

The CLI is more lenient — `servonaut hetzner ...` works even with
`enabled=false`, as long as the token chain resolves. The TUI and AI
chat both honour the `enabled` flag.

### 4. Validate

```bash
servonaut hetzner test-connection
# → Connected. 0 server(s) in project.
```

## CLI reference

```text
servonaut hetzner list                      [--json] [--state STATE]
servonaut hetzner create NAME               [--type cx23]
                                            [--image ubuntu-22.04]
                                            [--location fsn1]
                                            [--ssh-key NAME|ID] (repeatable)
                                            [--no-wait] [--json]
servonaut hetzner destroy NAME_OR_ID        [--yes] [--json]
servonaut hetzner ssh-keys list             [--json]
servonaut hetzner ssh-keys add NAME --public-key-file PATH [--json]
servonaut hetzner server-types              [--json]
servonaut hetzner test-connection           [--json]
```

### Examples

```bash
# Spin up a single Ubuntu 22.04 box in Falkenstein with the SSH key
# named "laptop" (already registered with Hetzner) injected.
servonaut hetzner create my-demo --ssh-key laptop

# List, filtering on state
servonaut hetzner list --state running

# Destroy without typed confirmation (CI / scripts).
servonaut hetzner destroy my-demo --yes

# Register a new SSH key from a file.
servonaut hetzner ssh-keys add laptop --public-key-file ~/.ssh/id_ed25519.pub

# Browse types + prices.
servonaut hetzner server-types
```

### Exit codes

| Code | Meaning                                                           |
|------|-------------------------------------------------------------------|
| 0    | success                                                           |
| 1    | generic error (API failure, network)                              |
| 2    | not configured (no token resolvable)                              |
| 3    | typed-confirmation declined for `destroy`                         |
| 4    | input validation error                                            |

## TUI integration

When `hetzner.enabled = true` and a token resolves, the instance list
shows Hetzner servers alongside AWS / OVH / custom. The Provider column
displays `hetzner`. SSH connect, command overlay, file browser, log
viewer — all of these work transparently against Hetzner servers using
the configured `default_local_ssh_key` and `default_username` (root by
default — Hetzner's stock images don't ship a non-root user).

A background refresh worker keeps the list up to date; press `R` to
force a refresh.

## MCP-tool catalogue

Six tools, registered automatically when the Hetzner service is wired
up. They appear in `tools/list` for any agent (Claude Code, Cursor,
Windsurf, ...) that connects to the Servonaut MCP server:

| Tool                            | Guard      | Description                                            |
|---------------------------------|------------|--------------------------------------------------------|
| `hetzner_list_servers`          | readonly   | List servers in project                                |
| `hetzner_list_server_types`     | readonly   | Catalogue + EUR prices                                 |
| `hetzner_list_ssh_keys`         | readonly   | Registered SSH keys                                    |
| `hetzner_create_ssh_key`        | standard   | Register a new SSH public key                          |
| `hetzner_create_server`         | dangerous  | Create a server (auto-registers in fleet)              |
| `hetzner_delete_server`         | dangerous  | Permanently delete a server                            |

The dangerous-tier tools are gated behind `mcp.guard_level = dangerous`
in `~/.servonaut/config.json` and are also hidden from the chat UI
when `auth.has_dangerous_ai_tools` is false. Both server-side and
client-side enforcement apply (defense-in-depth).

## Auto-registration into the fleet

`hetzner_create_server` automatically busts the local Hetzner cache
on success, so the next call to `list_instances` (or any TUI refresh)
sees the new server. The instance dict carries:

- `provider: "hetzner"`
- `is_hetzner: true`
- `username: <config.hetzner.default_username>`
- `ssh_key: <config.hetzner.default_local_ssh_key, literal — not dereferenced>`
- `owned_by_servonaut: true`
- `disposable: true`

Downstream tools (`run_command`, `check_status`, `get_logs`,
`transfer_file`) work on the new server within seconds, with no manual
"add server" flow.

## Demo-fleet recording

`scripts/demo-fleet.sh` spins up four servers, lists them, and tears
them down — under one second wall clock against a warm API. Used as
the canonical recording target for marketing videos.

```bash
./scripts/demo-fleet.sh                 # 4 servers, full create+destroy
./scripts/demo-fleet.sh --keep          # leave fleet up (manual cleanup)
./scripts/demo-fleet.sh --reset         # nuke residual servonaut-demo-* first
./scripts/demo-fleet.sh --count 6       # different fleet size
```

The script is wrapped in safety rails: a hard 5-minute wall-clock cap,
a typed-name confirmation step (skipped with `--yes`), Ctrl-C hooked
into a best-effort cleanup, and a final "verify zero residuals" pass
that calls a sweep delete on any `servonaut-demo-*` server still
present.

## Troubleshooting

### `unsupported location for server type`

Hetzner deprecates server types per location every ~18 months
(see [Hetzner changelog 2025-09-24](https://docs.hetzner.cloud/changelog#2025-09-24-per-location-server-types)).
If your `default_server_type` is no longer available in
`default_location`, `servonaut hetzner create` will fail with this
error.

Fix: run `servonaut hetzner server-types` to see what's currently
available, then either pass `--type` per call or update
`hetzner.default_server_type` in `~/.servonaut/config.json` to a
non-deprecated type for your default location.

### `No Hetzner Cloud API token configured`

Resolve the token chain manually:

```bash
servonaut hetzner test-connection
# → Hetzner not configured: No Hetzner Cloud API token configured. Set …
```

Place the token at one of:

- `config.hetzner.api_token` (with optional `$ENV_VAR` / `file:` prefix)
- `$HCLOUD_TOKEN`
- `~/.config/hcloud/token`

### SSH host-key prompt on first connect

Hetzner does not return the new server's host fingerprint in the
create response. Servonaut's SSH wrapper uses
`StrictHostKeyChecking=accept-new`, so the first connect adds the host
to your `known_hosts` automatically. No special Hetzner handling.

### `shutdown` sent but the server stays running

`servonaut hetzner shutdown` (and the `hetzner_shutdown` MCP tool)
sends an ACPI signal to the guest. On a freshly-booted Hetzner
cloud-init image, **acpid isn't started yet during the first ~3
minutes**, so the signal is dropped and the server stays in `running`
state. The CLI/MCP call returns success because the API accepted the
signal — guest cooperation is what didn't happen.

Two options:

- Wait until the server has fully booted (cloud-init finished,
  `systemctl is-system-running` returns `running`) before issuing
  `shutdown`.
- Use `servonaut hetzner power off` / `hetzner_power_off` instead —
  that's a hard power-off via the Hetzner API which doesn't depend on
  the guest. Risks in-flight write loss, so prefer `shutdown` on
  settled servers and `power off` on fresh ones or when the guest is
  unresponsive.

## Security notes

- The API token is stored in `~/.servonaut/config.json`, which is
  encrypted at rest if you opt in to a passphrase via the existing
  config-encryption flow (`services/config_crypto.py`,
  AES-256-GCM with PBKDF2-HMAC-SHA256, 600 000 iterations). The token
  is stripped from any config-sync upload to servonaut.dev — see
  `SENSITIVE_FIELDS` in `services/config_sync_service.py`. So even
  if you opt in to config sync, the token stays on this machine.
- The dataclass `__repr__` for `HetznerConfig` is overridden to
  redact `api_token` to `'<set>'` so log lines that interpolate the
  config object never spill the live token to disk.
- The local cache (`~/.servonaut/hetzner_cache.json`) and audit log
  (`~/.servonaut/hetzner_audit.jsonl`) are written with `0o600`
  permissions and `O_NOFOLLOW` to defeat symlink-redirect attacks.
  The cache is written atomically via ``temp + rename`` so a
  concurrent reader never sees a partial JSON.
- Mutating MCP tools require `mcp.guard_level = dangerous`. The
  blocklist on `run_command` still applies even after a server is
  spun up.
- `hetzner_create_ssh_key` does NOT log the public key text in either
  the local audit or the MCP audit. Only the key name is recorded.
  Upstream API errors that may include public-key fragments are
  truncated to 160 chars in the audit reason.
- `hetzner_create_server` refuses by default to create a server with
  no SSH keys configured (`require_ssh_keys_on_create=true`). The
  reason: Hetzner would otherwise spawn one with a random root
  password the CLI discards, leaving a billed unreachable box.

## Limitations (out of scope)

These are deliberately out of scope:

- Hetzner Robot (dedicated servers) — different API surface, smaller
  user base. Planned for the future.
- Storage Boxes, DNS, Load Balancers, Volumes, Networks, Firewalls,
  Floating IPs, Placement Groups — manage these in the Hetzner
  Console for now.
- Snapshot / image management.
- AWS create/destroy parity — planned separately.
