# Troubleshooting

## AWS Credentials

Ensure your AWS credentials are correctly configured:

```bash
aws configure
aws sts get-caller-identity
```

Verify permissions for `ec2:DescribeInstances` and `ec2:DescribeRegions`.

## OVH Actions Report Missing Permissions

A successful connection test confirms that the credential can read your account;
individual operations can require additional permissions. Existing consumer keys
keep the permissions granted when they were created, even after upgrading
Servonaut.

If an operation reports a permission error, open `servonaut --setup-ovh`, request
a new consumer key, and review and approve its permissions on OVH's validation
page before saving it. Keep the previous key until the replacement is working.

OVH Object Storage uses a separate S3 access key and secret, configured in
Settings. Replacing the OVH API consumer key does not replace those S3 credentials.

## SSH Connection Fails

When SSH fails, the terminal window **stays open** showing the error and exit code. Common causes:

1. **Wrong key** — Check `instance_keys` in config, or set `default_key`
2. **Wrong username** — Default is `ec2-user`; Ubuntu AMIs use `ubuntu`, Amazon Linux uses `ec2-user`
3. **No key configured** — Without a key or SSH agent key, SSH falls back to password auth (which EC2 doesn't support)
4. **Security group** — Ensure port 22 is open from your IP

Check the log for the exact SSH command:

```bash
grep "SSH command" ~/.servonaut/logs/servonaut.log
```

## SSH Host Key Has Changed

Servonaut records each server's SSH host key the first time it connects
(trust on first use) and refuses a later connection that presents a
different key. The message names the host and the command that removes the
old key, for example:

```text
SSH host key for web-1.example.com has changed, so the connection was refused.
The server may have been rebuilt or re-keyed, or the connection may be
intercepted. Once you have confirmed the new key is genuine, remove the old one
and reconnect: ssh-keygen -R web-1.example.com -f ~/.servonaut/known_hosts
```

1. **Confirm the new key first** — compare the server's key fingerprint
   with the one shown in your provider's console, or ask whoever rebuilt the
   server. An unexpected change can mean the connection is being
   intercepted.
2. **Run the command from the message** — copy it exactly: cloud instances
   are recorded under a name such as `aws:us-east-1:i-0abc…` rather than
   their address, and the command names the right known_hosts file (yours or
   Servonaut's).
3. **Reconnect** — the new key is recorded on the next connection.

See [SSH host-key verification](configuration.md#ssh-host-key-verification)
for the `ssh.host_key_checking` setting and where keys are stored.

## Bastion Connection Hangs

If the terminal opens but SSH hangs:

1. **No connection profile** — Check that `connection_profiles` and `connection_rules` are set in `~/.servonaut/config.json`
2. **Wrong bastion host** — Verify reachability: `ssh -i key.pem user@bastion-host`
3. **Wrong bastion key** — If the bastion uses a different key, set `bastion_key` in the profile
4. **Private IP unreachable** — The bastion must be able to reach the target's private IP

The command overlay also warns if a connection rule matches but the referenced profile doesn't exist.

## SSH Agent Not Running

If you see "Could not open a connection to your authentication agent":

```bash
eval $(ssh-agent -s)
ssh-add ~/.ssh/your-key.pem
```

## Key Permissions

SSH keys require strict permissions (600 or 400). The tool will warn and offer to fix permissions automatically.

```bash
chmod 600 ~/.ssh/your-key.pem
```

## Too Many Authentication Failures

Servonaut automatically uses `IdentitiesOnly=yes` when specifying a key with `-i`, which prevents the SSH client from trying every key in the agent. If you still hit this:

```bash
ssh-add -D  # Remove all keys from agent
```

## SSH Key Auto-Discovery

Auto-discovery searches `~/.ssh/` using multiple patterns:

- Exact match on AWS key pair name (e.g., `mykey`)
- Key name with `.pem` extension (e.g., `mykey.pem`)
- Common prefixes (e.g., `id_rsa_mykey`, `aws_mykey`)
- Fuzzy matching on filename stems

If keys are stored elsewhere, provide the full path manually via Settings or the key management screen.

## Command Overlay Issues

The command overlay runs commands via SSH with `bash -ic` for shell initialization (so tools installed via nvm, rbenv, pyenv are available).

**Interactive commands blocked** — Commands like `vim`, `htop`, `tmux`, `nano`, `pm2 monit` require a real terminal and cannot run in the overlay. Use SSH Connect (press `S`) instead.

**Ctrl+C behavior** — Pressing Ctrl+C stops the currently running command without closing the overlay. Press Escape to close the overlay.

## Remote File Browser

The file browser connects via SSH to list directory contents. If it fails:

1. **Connection issues** — Same as SSH troubleshooting above
2. **Permissions** — The SSH user must have read access to the directories
3. **Key auto-discovery** — If no key is configured, the browser attempts auto-discovery from the instance's `key_name`

## Installed a Release Candidate by Mistake

A version such as `2.28.0rc1` is a release candidate, a preview of the next
release. To go back to the newest stable release, keeping your
configuration:

```bash
pipx install --force servonaut           # pipx, including the install scripts
pip install --force-reinstall servonaut  # pip
```

If you installed with extras, name them again, for example
`pipx install --force 'servonaut[all]'`.

A candidate installed with `pipx install --pip-args=--pre` makes pipx
remember `--pre`, so `pipx upgrade-all` and `pipx reinstall` keep choosing
pre-releases; the `--force` install above clears that. On Windows, if the
installer keeps installing candidates, `SERVONAUT_PRE` is still set in that
PowerShell window: run `Remove-Item Env:SERVONAUT_PRE` or open a new window.

See [Release candidates](release-candidates.md) for how candidates and their
updates work.

## Logging

Logs are always written to `~/.servonaut/logs/servonaut.log` and include:

- SSH commands executed
- Terminal emulator detection
- Connection profile resolution
- Cache hit/miss/refresh status
- Error details with stack traces

For verbose stderr output during development:

```bash
servonaut --debug
```
