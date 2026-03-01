# Troubleshooting

## AWS Credentials

Ensure your AWS credentials are correctly configured:

```bash
aws configure
aws sts get-caller-identity
```

Verify permissions for `ec2:DescribeInstances` and `ec2:DescribeRegions`.

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
