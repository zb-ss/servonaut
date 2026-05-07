# Annotated AI Chat Session — Diagnosing an Nginx 502

This example shows a full `servonaut ai chat` session in **streamed** mode
(`--stream`). The user asks why Nginx is returning 502 errors on `web-prod-1`.
The model uses two read-only tools — no confirmation prompts are shown for
`tail_log` or `ssh_exec_readonly` because their guard level is `readonly`.

---

## Invocation

```
$ servonaut ai chat --stream "why is nginx 502ing on web-prod-1?"
```

---

## Session transcript

```
Servonaut AI  [gemini-2-flash-002]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You › why is nginx 502ing on web-prod-1?
```

### Tool call 1 — tail_log (readonly, no prompt)

The model immediately reaches for the Nginx error log. Because `tail_log` has
guard level `readonly`, no confirmation prompt is displayed.

```
  [tool] tail_log
         instance: web-prod-1
         path:     /var/log/nginx/error.log
         lines:    100
         → executing… (no confirmation required)
```

The relay dispatches the tool call to your CLI, streams the output back, and
posts the result to `POST /api/ai/chat/tool-result`. The server continues
generating tokens once the result arrives.

**Sample log output sent to the model (truncated):**

```
2026-04-28 09:14:02 [error] 1234#1234: *89 connect() failed (111: Connection
refused) while connecting to upstream, client: 203.0.113.45,
server: example.com, request: "GET /api/health HTTP/1.1",
upstream: "http://127.0.0.1:8000/api/health", host: "example.com"

2026-04-28 09:14:03 [error] 1234#1234: *90 connect() failed (111: Connection
refused) while connecting to upstream, client: 203.0.113.46, …
```

### Tool call 2 — ssh_exec_readonly (readonly, no prompt)

The model now checks whether the upstream app process is running.

```
  [tool] ssh_exec_readonly
         instance: web-prod-1
         command:  systemctl status gunicorn
         → executing… (no confirmation required)
```

**Command output sent to the model:**

```
● gunicorn.service - Gunicorn WSGI server
     Loaded: loaded (/etc/systemd/system/gunicorn.service; enabled)
     Active: failed (Result: exit-code) since 2026-04-28 09:13:58 UTC
    Process: 5678 ExecStart=/usr/bin/gunicorn … (code=exited, status=1/FAILURE)

Apr 28 09:13:57 web-prod-1 gunicorn[5678]: ModuleNotFoundError: No module
named 'psycopg2'
Apr 28 09:13:57 web-prod-1 gunicorn[5678]: [ERROR] Worker failed to boot.
```

---

### Streamed response

Tokens stream to stdout as they are generated. `…` marks the streaming point.

```
Assistant ›

The 502 errors are caused by Nginx failing to reach its upstream — Gunicorn
has crashed and is not listening on 127.0.0.1:8000.

**Root cause:** Gunicorn exited at 09:13:58 UTC with a Python import error:

  ModuleNotFoundError: No module named 'psycopg2'

This typically means a recent deployment updated `requirements.txt` but the
virtual-environment on `web-prod-1` was not refreshed, leaving `psycopg2`
(the PostgreSQL adapter) absent.

**To fix:**

1. SSH into web-prod-1 and activate the virtual environment:
   ```
   ssh web-prod-1
   cd /var/www/myapp
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Restart Gunicorn:
   ```
   sudo systemctl restart gunicorn
   ```
3. Verify Nginx is healthy:
   ```
   sudo nginx -t && sudo systemctl reload nginx
   curl -I http://localhost/api/health
   ```

If the missing package problem recurs after the next deployment, add a
post-deploy hook that runs `pip install -r requirements.txt` inside the
virtualenv before Gunicorn is restarted. …
```

---

## Confirmation prompts (for reference)

This session used only `readonly` tools, so no prompts appeared. For
comparison, if the model had requested `run_command` (guard level `standard`),
you would have seen:

```
  [tool] run_command
         instance: web-prod-1
         command:  sudo systemctl restart gunicorn

  Allow this command? [y/N] _
```

Typing `y` posts `status: "ok"` to the server and the conversation continues.
Typing `n` (or pressing Enter) posts `status: "denied"` and the model
acknowledges the refusal before ending its turn.

For `dangerous`-tier tools (e.g., `deploy`, `provision`) a typed confirmation
is required: the prompt reads **"Type RUN to confirm"** and any other input is
treated as a denial.

---

## Quota footer (end of turn)

After the `usage` SSE event closes the stream, the chat panel (TUI) or the
terminal (CLI) renders a quota summary line:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tokens: 13,588,432 / 15,000,000 used  (≈ 282 queries remaining)  Resets in 3 days
Model: gemini-2-flash-002  ·  2 tool calls  ·  input 4,112 / output 487 tokens
```

If `tokens_topup_remaining` is non-zero, it appears next to the monthly
bucket:

```
Tokens: 13,588,432 / 15,000,000 used  [+500,000 topup]  (≈ 382 queries remaining)
```

When the quota is soft-capped (approaching the monthly limit), the model line
shows a downgrade badge:

```
Model: gemini-2-flash-001 (downgraded to Flash — approaching limit)
```

---

## Running the same query headlessly

```bash
# Buffered (waits for the full answer)
servonaut ai chat "why is nginx 502ing on web-prod-1?"

# Streamed to stdout (one token per write, no ANSI)
servonaut ai chat --stream "why is nginx 502ing on web-prod-1?"

# Read-only — disables tool execution entirely
servonaut ai chat --no-tools "why is nginx 502ing on web-prod-1?"
```

Exit code `0` on success. See [CLI Reference](../docs/cli-reference.md) for
full flag documentation and exit codes.
