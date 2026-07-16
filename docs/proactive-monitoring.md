# Proactive Monitoring — Findings

*Solo and Teams plans (Free shows an upgrade card).*

Servonaut can watch your fleet for problems and surface each one as a
triageable **finding card** — severity, description, evidence, and
remediation options — with low-risk fixes applied by an explicit,
human-confirmed click. Detection runs in the Servonaut cloud; the client
only runs read-only probes over your relay connection and renders the
results.

- [How it works](#how-it-works)
- [What it detects](#what-it-detects)
- [The Findings inbox](#the-findings-inbox)
- [Scanning](#scanning)
- [Triage](#triage)
- [Gated one-click remediation](#gated-one-click-remediation)
- [Safety & privacy model](#safety--privacy-model)

---

## How it works

The work is split deliberately between the cloud and your machine:

| Stage | Where it runs | What happens |
|-------|---------------|--------------|
| **Detection** | Servonaut cloud | Detectors decide *what to look for* and *what counts as a problem*. |
| **Probing** | Your machine, over the relay | The client runs **read-only** probes on your servers and returns the raw output. |
| **Rendering** | The TUI | Findings are shown as cards; nothing is analysed or decided locally. |
| **Remediation** | Your machine, over the relay | Only on an explicit click, from a server-signed preview, through a verb-allowlisted executor. |

Because detection is server-side, the open-source client never contains
the detection logic — it is a thin renderer that probes and displays.

## What it detects

Detectors are matched to each box's profile (a database detector won't run
where no database is configured, and so on). Current coverage includes:

- **Disk pressure** — filesystems approaching full.
- **Failed / dead services** — units that failed to start or are down.
- **Slow database queries** — long-running or saturating queries.
- **Suspicious traffic** — SSH credential-scanning and invalid-user
  sweeps, **cross-referenced against fail2ban** so already-mitigated IPs
  aren't flagged and genuinely unmitigated attackers are surfaced.
- **Container problems** — OOM kills, crash loops, unhealthy containers.
- **Expired TLS certificates** — certs past (or near) expiry.
- **Pending package updates** — outstanding OS updates.

## The Findings inbox

- **Fleet inbox** — `🛡 Findings` in the sidebar lists findings across
  every instance, with status and severity filters (`f` / `v`) and paging.
- **Per-instance** — press `F` on any server's action screen to see just
  that instance's findings.

## Scanning

Press **`s`** (**Scan now**) to trigger a scan; live per-detector progress
streams into the panel.

- Scans dispatch **read-only** probes to your CLI over the relay, so
  `servonaut connect` (or the TUI's relay autostart) must be running.
- Detectors that can't apply to a box are reported **with the reason**
  (e.g. no database credentials saved, no Docker present) rather than
  failing silently.

## Triage

Open a finding (`enter`) and:

| Key | Action |
|-----|--------|
| `a` | Acknowledge |
| `r` | Resolve |
| `x` | Suppress |

Status changes sync server-side, so your whole team sees the same state.

## Gated one-click remediation

Findings that carry an automatable fix show a **Run** action. The flow is
designed so nothing runs that you didn't explicitly approve:

1. **Signed preview** — the server returns the *exact* command it would
   run, plus a confirmation token signed over it. The CLI never builds or
   free-forms a command.
2. **Confirm** — you review the command; anything that changes state
   requires a **typed confirmation**. A **dry-run** preview is available
   first.
3. **Execute** — the fix runs over your relay through a
   **verb-allowlisted executor**, and every execution is audited.

**Fixes available today:**

| Fix | What it does |
|-----|--------------|
| **Block IP** | Bans a source IP via **AWS** (WAF / Security Group / NACL) or the **box's own firewall** — nftables / ufw / firewalld, auto-detected on non-AWS hosts. The ban is reversible (the IP is its own unban handle). |
| **Renew certificate** | Renews an expiring/expired TLS certificate via the box's ACME client and reloads the web server. |

Remediations are **always a human click** — nothing runs autonomously.

## Safety & privacy model

- **Read-only probes** — probing is limited to a read-only allowlist (the
  same three-tier guard system as the [MCP server](../README.md#mcp-server-for-ai-agents)).
- **Human-in-the-loop** — every remediation requires an explicit click and
  a signed preview; state-changing actions require typed confirmation.
- **Server-signed commands** — the client executes only the exact command
  the server signed; it never invents one.
- **Audited** — every probe and every remediation execution is written to
  the local audit trail.
- **Gated server-side** — availability is enforced in the Servonaut cloud,
  not by the open-source client.

---

Included with Solo and Teams plans (with a monitored-instance allowance);
Free shows an upgrade card. See also [servonaut.dev/docs](https://servonaut.dev/docs).
