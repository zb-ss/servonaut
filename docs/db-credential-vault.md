# Database credential vault

*Solo and Teams plans — requires a configured [secret store](../README.md#secrets-management-solo).*

Give the database introspection tools (`db_processlist`, `db_top_queries`) the
credentials your apps already use, without ever putting a password in your
config or in an AI agent's context. Servonaut scans a server for the DB
credentials its applications already have on disk, stages them **server-side**,
and — on one confirmation — stores the password in your secret vault under a
per-site label. From then on the tools resolve the credential **by name**, with
no re-SSH and no plaintext in the model context.

## How it works

1. **Scan** a server (read-only). Servonaut looks for the credentials an app
   already ships with and parses them locally:
   - `.env` / `.env.local` / `.env.production` — `DATABASE_URL` (and
     environment-suffixed variants like `DATABASE_URL_PROD` /
     `DATABASE_URL_STAGING`), plus `DB_*`, `POSTGRES_*`, `MYSQL_*` fields
   - `wp-config.php` (WordPress), `configuration.php` (Joomla), `env.php`
     (Magento)
   - `docker-compose*.yml` / `compose*.yaml` — DB credentials in `environment:`
     blocks, resolving `${VAR}` references against a co-located `.env`
   - Root-owned config files are read with a non-interactive `sudo -n` fallback
     (read-only) so **containerized stacks whose `.env` isn't world-readable**
     are still discovered.
2. **Review** the redacted candidates. Only masked previews (`pw=****xyz`) and
   the connection shape (`engine user@host:port/db`) are shown — the plaintext
   password stays in server-side staging and is never rendered.
3. **Label** the credential. Each site gets a label derived from its config path
   (e.g. `shop.example.com`). You can accept it, edit it, or clear it for a
   single/default DB. Give each site on a multi-DB box its own label — including
   separate labels for a prod vs. staging DB on the same site.
4. **Store.** The password goes to your secret vault (name `db/<instance>/<label>`);
   the non-secret connection metadata (`user`, `host`, `port`, `engine`,
   `database`) goes to `~/.servonaut/config.json`. The two are recombined at
   connect time.

## Using stored credentials

Once stored, the introspection tools resolve the credential by name — no
password argument, no re-scan:

```
db_processlist(instance_id)                    # single DB on the instance
db_processlist(instance_id, app="shop")        # pick a site when several exist
db_top_queries(instance_id, app="shop.example.com")
```

`app=` matches loosely (exact → unique prefix → unique substring). When an
instance has several DBs and you omit `app`, the tool lists the stored sites so
you can name one.

## Coverage & management (TUI)

- **Scan a server:** click an instance → **Scan DB creds** (or `servonaut db
  setup <instance>` on the CLI). Already-vaulted sites are flagged on re-scan.
- **Coverage view:** **Secrets → DB coverage** lists one row per stored site
  (Server · Site · Secret · status) so you can see which instances are covered
  and which are gaps across the fleet.
- **Remove:** press `d` on a coverage row to remove a stored credential, with an
  optional "also delete the secret from the vault" toggle.

## Security model

- **The scan is read-only.** The on-box command only lists and reads config
  files (`find` + `sed`, plus a read-only `sudo -n` fallback). It never writes.
- **The password never enters an AI agent's context.** Candidates are held in
  server-side staging; agents and the audit trail only ever see the masked
  preview and the opaque staging token.
- **Only the password is encrypted in the vault.** The username, host, port, and
  database name are non-secret connection metadata kept in local config; if you
  open the vault entry on its own you'll see a password with no username by
  design.
