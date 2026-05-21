# Demo Mode

Demo mode makes every screen safe to record, screenshot, or share publicly.
All identifying data — IP addresses, AWS account IDs, ARNs, home paths, API
keys, log group names, S3 bucket names, and URLs — is replaced with
deterministic fake equivalents. The substitutions are consistent within a
session so the UI looks realistic and coherent, not randomly scrambled.

## Activating demo mode

### At launch (recommended)

```bash
servonaut --demo
```

Redaction applies from the first frame. Instances are redacted in memory
before any screen renders.

### At runtime (toggle)

Press `ctrl+shift+d` from any screen.

A notification confirms the mode change. The status bar shows a
`[DEMO]` badge while active. Toggle again to restore real data.

> **Recording tip:** toggle, wait one second for any in-flight flushes to
> complete, then start recording. Mid-stream flushes from the log viewer or
> CloudWatch events table may land a partial frame of real data during the
> ~100 ms flush tick immediately after the toggle.

### Kill switch (emergency bypass)

```bash
SERVONAUT_DEMO_DISABLE_STREAM=1 servonaut --demo
```

When this environment variable is set to `1`, `scrub_stream` returns its
input unchanged. Useful when a downstream integration test needs to inject
raw data through a demo-mode-enabled app without triggering redaction.

---

## What is redacted

| Category | Example input | Redacted output |
|---|---|---|
| IPv4 addresses | `1.2.3.4` | `192.0.2.17` (RFC 5737 doc-range) |
| IPv6 addresses (≥3 colon groups) | `fe80::1234:5678:abcd:ef01` | `2001:db8::1` (RFC 3849 doc-range) |
| ECR hostnames | `123456789012.dkr.ecr.us-east-1.amazonaws.com` | `000000000000.dkr.ecr.us-east-1.amazonaws.com` |
| AWS access keys | `AKIAIOSFODNN7EXAMPLE` | `<redacted:aws-access-key>` |
| AWS secret keys | `aws_secret_access_key = abc123…` | `aws_secret_access_key = <redacted:aws-secret-key>` |
| GitHub tokens | `ghp_…`, `github_pat_…` | `<redacted:github-token>` |
| Bearer tokens | `Bearer eyJ…` | `Bearer <redacted:bearer-token>` |
| Passwords | `password=hunter2` | `password=<redacted:password>` |
| JWTs | `eyJhbGci…` | `<redacted:jwt>` |
| SSH/PEM private keys | `-----BEGIN RSA PRIVATE KEY-----` | `<redacted:ssh-private-key>` |
| Slack tokens | `xoxb-…` | `<redacted:slack-token>` |
| Stripe keys | `sk_live_…` | `<redacted:stripe-key>` |
| DB connection strings | `postgres://user:pwd@host/db` | `postgres://<redacted:conn-user>:<redacted:conn-pass>@host/db` |
| ARN account IDs | `arn:aws:iam::123456789012:user/alice` | `arn:aws:iam::000000000000:user/alice` |
| Bare 12-digit account IDs | `account 123456789012` | `account 000000000000` |
| Home paths | `/home/alice/.ssh/id_rsa` | `/home/user/.ssh/id_rsa` |
| macOS user paths | `/Users/bob/Documents/` | `/Users/user/Documents/` |
| URLs | `https://api.company.com/v1?token=xyz` | `https://example.com/v1` |
| Email addresses | `john.doe@company.com` | `<fake-name>@example.com` (deterministic) |
| CloudWatch log groups | `/aws/lambda/my-function` | `/aws/lambda/<fake-name>` |
| S3 URIs | `s3://company-prod-data/logs` | `s3://<fake-name>/logs` |
| Instance names | `web-prod-7` | `api-staging-3` (deterministic) |
| Instance IPs | `54.234.1.99` | `198.51.100.42` (RFC 5737 doc-range) |
| Instance IDs | `i-0abc123def456789a` | `i-<sha256-derived>` |
| Hostnames | `web-prod-7.eu-central-1.compute.internal` | `monitor-12.example.com` |
| SSH key names | `my-prod-key` | `deploy-key` |
| Usernames | `alice` | `ubuntu` (from fake pool) |

**Redaction is deterministic:** the same input always maps to the same fake
output within a session. Repeated IP addresses show the same fake IP.

---

## What is NOT redacted

| Item | Reason |
|---|---|
| Event names (`RunInstances`, `CreateBucket`) | AWS public taxonomy |
| Region codes (`us-east-1`, `eu-west-2`) | AWS public taxonomy |
| Error codes (`AccessDenied`, `NoSuchBucket`) | AWS public taxonomy |
| CloudTrail resource *types* | AWS public taxonomy |
| Memory module names and keys | Taxonomy — scrub would hide which modules ran |
| Commands the user types in the terminal overlay | User-authored; not a server secret |
| SCP source/destination paths the user types | User-authored; not a server secret |
| On-disk chat session content | Session files stay raw; redaction is display-only |
| 15-digit numbers (GCP project IDs) | Negative-lookaround prevents false positives |

---

## Affected screens and widgets

| Surface | Redaction applied |
|---|---|
| Instance list | Instance fields (in-place at startup / on refresh) |
| Log viewer | Every SSH `tail -f` line via `scrub_stream` |
| Terminal overlay (command output) | `append_output` and `append_error` |
| CloudWatch events table | `message` and `log_stream` columns |
| CloudWatch event detail | Full message text |
| CloudWatch top-IPs table | IP column (`display_ip`, raw used for network calls) |
| CloudWatch IP info panel | Header shows `display_ip`; httpx call uses raw IP |
| CloudTrail events table | `username`, `source_ip`, `resource_name` columns |
| CloudTrail event detail | All PII fields + raw event JSON blob |
| IP ban audit log | `ip_address` and `message` fields |
| IP ban banned-IPs table | Display IP column (`display_ip`) |
| Memory screen (observed / declared) | `obs_str` and `decl_str` values only |
| AI chat panel (streaming) | Full scrub on every token (always-scrub; heuristic removed); tool-result rows scrubbed; tool messages scrubbed on reload |
| AI analysis screen | Log text, `_raw_text` buffer, AI output, and error messages scrubbed |
| CloudTrail copy buffer | `action_copy_output` payload scrubbed (IPs, ARNs, email usernames, raw event JSON) |
| CloudWatch copy buffer | `action_copy_output` payload scrubbed (messages, selected IP) |
| Command overlay copy buffer | `_output_lines` scrubbed before append so copy is safe |
| CloudWatch IP geo panel | Entire geolocation block hidden in demo mode (`[redacted in demo mode]`) |
| CloudWatch AbuseIPDB panel | Entire AbuseIPDB block hidden in demo mode (`[redacted in demo mode]`) |
| Fleet scan summary modal | Failure `reason` and module `message` fields scrubbed |
| AI analysis SSH stderr | SSH stderr scrubbed before showing in status |
| AI analysis probe exceptions | Exception messages scrubbed before showing in status |
| Fleet memory (remote rows) | Remote merged rows scrubbed with `redact_name` / `redact_instance_id` / `redact_provider` |
| All `App.notify()` call sites | Centrally scrubbed via `ServonautApp.notify()` override (50+ call sites) |
| Status bar | Adds `[DEMO]` badge |

---

## Known limitations

The following patterns are intentionally **not** redacted. Each entry explains
why or documents the accepted trade-off.

| Pattern | Reason / workaround |
|---|---|
| Quoted S3 bucket names (e.g. `"my-bucket"`) | The DNS-shaped quoted-name regex is too broad — it matches everyday prose like `"hello-world"`. Use the `s3://` URI form to guarantee redaction. |
| S3 ARNs without an account (e.g. `arn:aws:s3:::bucket`) | No 12-digit account component to match. Resource name is scrubbed only via `s3://` URI path. |
| Free-form unquoted bucket names in prose | No syntactic anchor — indistinguishable from ordinary words. |
| `/root/` paths | Not matched by the home-path pattern (only `/home/<user>/` and `/Users/<user>/`). |
| `~`-prefixed paths (e.g. `~/.ssh/config`) | Tilde expansion is shell-side; the raw string has no `/home/` prefix to anchor. |
| Windows paths (e.g. `C:\Users\alice\`) | Not matched — Servonaut is Linux/macOS only. |
| Compressed IPv6 loopback `::1` | Requires only one colon group — the `{2,7}` repetition requires ≥3 colons. Full-form and most abbreviated IPv6 addresses are redacted; loopback is not. |
| Compressed IPv6 forms with double-colon | Addresses like `2001:db8::1` that use `::` elision may produce malformed display output like `2001:db8::1::1` after substitution. The real address bits are removed, but the rendering can look strange. This is a cosmetic issue only — no real address leaks. |
| MAC addresses (e.g. `aa:bb:cc:dd:ee:ff`) | The IPv6 regex may match 6-group hex-colon sequences. MAC addresses are not a privacy concern so false-positive replacement is harmless but noted here. |
| Uppercase `ARN:` prefix | The ARN regex matches only lowercase `arn:`. AWS tooling always emits lowercase, so this is low-priority. |
| 15-digit numbers (GCP project IDs) | Intentionally excluded by the `(?<![\d.])(\d{12})(?![\d.])` lookaround. |
| Timestamps containing 12-digit sub-sequences (e.g. `10:23:45.123456789012`) | Excluded by the dot-boundary lookaround (`(?<![\d.])` / `(?![\d.])`). |
| Process tree / system monitor output | P2 — Not fixable by the demo-mode pipeline. **Do not show a process list or system monitor while recording.** Process names and arguments can reveal real service names, users, and paths that are not captured by any redactor. |
| Toggle race condition | P3 — If a log-viewer or CloudWatch stream flush lands during the ~100 ms window after `ctrl+shift+d` is pressed, one partial frame of real data may appear. Wait one second after toggling before starting a recording. |

**Fake-name collision probability:** the name pool contains ~62,000 entries (48 prefixes × 43 suffixes × 30 numbers). Collision probability is < 1% for fleets ≤100 servers and < 50% for fleets ≤265 servers (birthday paradox). Fleets larger than ~265 unique server names may see repeated fake names.

---

## Architecture notes

- `scrub_stream` lives on `RedactionService` (no `app` reference).
- Every call site uses the caller-side guard:
  ```python
  if self.app.demo_mode and self.app.redaction_service:
      line = self.app.redaction_service.scrub_stream(line)
  ```
- Composition order: secrets first → IPv4 → ARN → bare account ID →
  log group → URL → email → path → resource name. This order is critical — see
  `RedactionService.scrub_stream` docstring for rationale. URL runs before email
  so URL-embedded credentials (`user:pass@host`) are consumed first.
- `scrub_stream` is idempotent: calling it twice on the same string
  returns the same result as calling it once.
- `redact_ip` is idempotent: doc-range IPs (192.0.2.x, 198.51.100.x,
  203.0.113.x) are short-circuited and returned unchanged.
