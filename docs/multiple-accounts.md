# Multiple accounts per provider

Servonaut can work with several accounts of the same cloud provider at once:

- **AWS** — several AWS accounts, each reached through a named profile from
  your AWS config (`~/.aws/config`, `~/.aws/credentials`).
- **Hetzner Cloud** — several projects, one API token each.
- **OVHcloud** — several OVH accounts, each with its own API credentials.

Servers from every account appear in the one fleet table and work exactly as
before: SSH, file transfer, logs, scans, server memory. Anything done to a
server — start, stop, reboot, delete, snapshots, firewall — runs in the account
the server belongs to. Views that work on a whole account (CloudTrail,
CloudWatch, IP bans, object storage, SSH key registries, billing, DNS, create
wizards) show an **Account** picker as soon as the provider has more than one
account.

Nothing changes for a provider that has a single account: no picker, no new
column, the same names.

## Accounts and labels

Each provider's existing settings are its **first (primary) account**. Extra
accounts are added next to it. Every account has a short **label**:

- the primary account is labelled after its provider (`aws`, `hetzner`,
  `ovh`) unless you rename it;
- labels are unique across all providers, compared without regard to case
  (if a hand-edited config gives two providers' primary accounts the same
  label, the later provider in the order AWS, Hetzner, OVH uses its provider
  name instead, and Settings shows the problem);
- they start with a letter or digit and use letters, digits, `.`, `_` and `-`
  (at most 32 characters);
- `custom` is reserved.

Add, edit and remove accounts in **Settings** under the provider. The setup
wizards (`servonaut --setup-ovh`, the Hetzner setup screen) can also add a
further account once the first one is configured.

## Configuration

Accounts live in `~/.servonaut/config.json`, in an `accounts` list inside each
provider block. Secrets accept `$ENV_VAR` and `file:/path` references, which
keep them out of the file.

### AWS

```json
{
  "aws": {
    "profile": "",
    "regions": [],
    "accounts": [
      {"label": "prod", "profile": "prod-admin", "regions": ["eu-west-1", "us-east-1"]},
      {"label": "sandbox", "profile": "sandbox"}
    ]
  }
}
```

- An extra account **must** name a profile. The primary account uses your
  default credentials (environment, default profile, instance role) unless
  `aws.profile` names one.
- `regions` limits the regions listed for that account. Empty means every
  region the account has enabled; listing only the regions you use makes
  refreshes faster.
- Profiles can use anything the AWS SDK supports — access keys, SSO,
  `role_arn` + `source_profile`, `credential_process`.
- **SSO profiles**: sign in with `aws sso login --profile <name>` before
  refreshing. When the desktop app is started from a launcher it does not see
  your shell's `PATH`, so a `credential_process` helper must be given with its
  full path.

### Hetzner Cloud

```json
{
  "hetzner": {
    "enabled": true,
    "api_token": "$HCLOUD_TOKEN",
    "accounts": [
      {
        "label": "staging",
        "api_token": "$HCLOUD_TOKEN_STAGING",
        "default_hetzner_ssh_key": "laptop",
        "default_local_ssh_key": "~/.ssh/staging_ed25519"
      }
    ]
  }
}
```

- Each extra project needs its own `api_token`. Only the primary project falls
  back to `$HCLOUD_TOKEN` and the `hcloud` CLI token file.
- `default_hetzner_ssh_key` names a key registered **in that project**.
- `default_local_ssh_key` and `default_username` default to the provider-wide
  values.
- Object storage keys for the project go in its own `object_storage` block.

### OVHcloud

```json
{
  "ovh": {
    "enabled": true,
    "application_key": "...",
    "application_secret": "$OVH_APP_SECRET",
    "consumer_key": "$OVH_CONSUMER_KEY",
    "accounts": [
      {
        "label": "ca",
        "endpoint": "ovh-ca",
        "client_id": "...",
        "client_secret": "$OVH_CA_CLIENT_SECRET",
        "cloud_project_ids": ["0123456789abcdef0123456789abcdef"]
      }
    ]
  }
}
```

- An extra account needs a complete credential set: application key, secret
  and consumer key, or an OAuth2 client ID and secret.
- `cloud_project_ids`, the `include_*` switches, `default_ssh_key` and
  `default_username` are per account.

## Server names and references

When a provider has more than one account, its servers are shown as
`label/name` — for example `prod/web-1` and `staging/web-1`. The search box
also matches the label, so typing `prod/` lists that account's servers.

Wherever you name a server — the CLI, MCP tools, the AI chat — you can use:

| Reference | Picks |
|-----------|-------|
| `i-0abc…`, `4200001`, … | the server with that ID |
| `prod/web-1` | `web-1` in account `prod` |
| `prod/i-0abc…` | that ID in account `prod` |
| `custom/edge` | the custom server `edge` |
| `web-1` | `web-1`, if exactly one server has that name |

A name shared by several servers is **refused**, with the references that pick
each one (the instance id when two servers of one account share the name):

```
'web-1' matches 2 servers: prod/web-1 (i-0aaa…, AWS), staging/web-1 (i-0bbb…, AWS).
Use one of these references or an instance ID.
```

Nothing is ever picked by guessing — which matters most for stop and delete.

## Rules per account

Connection rules and scan rules accept an `account` condition, so one account's
servers can use their own bastion:

```json
{
  "connection_rules": [
    {"name": "prod via bastion", "match_conditions": {"account": "prod"}, "profile_name": "prod-bastion"}
  ]
}
```

## CLI and MCP

- `servonaut hetzner … --account <label>` runs a Hetzner command in one
  project; `servonaut hetzner list` shows every project's servers.
- `servonaut ssh`, `servonaut servers verify` and `servonaut memory` see the
  servers of every account and accept `label/name`. An account not yet listed
  on this machine is listed once before a name counts as unique; see the
  [CLI reference](cli-reference.md#servonaut-ssh).
- MCP tools that work on a whole account (AWS listings, CloudTrail,
  CloudWatch, IP bans, S3, Hetzner and OVH registries, billing, create) take
  an optional `account` argument; without it they use the provider's primary
  account. Tools that act on a server find its account themselves. See the
  [MCP tools reference](mcp-tools.md#several-accounts-per-provider).
- `list_instances` shows the `label/name` form and accepts an `account` filter.

## The primary account

The provider block's own settings are always the **default** account: every
command or tool call that names no account uses it. If it cannot connect (for
example its token comes from a `$VARIABLE` that is not set in this shell),
there is no default: Servonaut says why and asks you to name one of the other
accounts, rather than acting in an account you did not choose. Its servers
stay listed from cache, and every refresh names the account that is
unavailable.

## Config sync

Synced configs carry the accounts but **never their secrets**: tokens, keys and
client secrets are removed before a snapshot is uploaded. After pulling a
config on another device, enter the secrets of any account that is new to that
device, or use `$ENV_VAR` references so every device reads its own
environment. Pulling a snapshot made before accounts existed keeps the
accounts configured on the device.

## Demo mode

Demo mode replaces account labels that could name a client or team, AWS
profile names and account IDs with stand-ins. Provider-default labels and
environment words such as `prod` or `staging` are left as they are.

## Troubleshooting

- **"… account 'x' is skipped: …"** — the account's label or credentials are
  incomplete; Settings shows the reason next to the account.
- **An account shows no servers and a warning names two accounts** — both point
  at the same underlying account (for example two AWS profiles for one
  account). Its servers are listed once, under the first.
- **"No … account named 'x'"** — the label in a command or tool call does not
  match a configured account; the message lists the ones that exist.
- **"… account 'x' is not available: …"** / **"No … account is available (…)"**
  — the account is configured but cannot connect (for example its token is a
  `$VARIABLE` that is not set in this shell); the message gives the reason
  for each account.
- **Refresh warnings name an account** (`staging: …`) — that account failed to
  refresh; its last known servers stay listed and every other account is fresh.
