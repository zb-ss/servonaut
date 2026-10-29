# Team vault keys on your servers

*Teams plan.* A team vault holds the SSH keys a team's members connect with.
Its owners and admins bind a key from it to each server the team shares, and
every member then connects to that server with that key, without having the
key on their own computer. This page explains how a team key and your own
key work together on a server you own, where the login of a binding comes
from, and how to bind many servers at once.

## Your key and the team's key on the same server

A server you share with a team is listed twice in Servonaut: as your own
server (an AWS, OVH or Hetzner instance, or a custom server) and as the
team's shared server. Each can have its own vault key:

- **The team's key** belongs to the team's shared server. Every member of the
  team connects with it, as the login the binding names.
- **Your own key** belongs to your own server. Only you connect with it. It
  can come from your personal vault or from a team vault you administer.

When you connect to your own server, your own key wins. Setting the team's
key on a server you own therefore does not change how *you* connect to it.
After **Use Vault Key → Everyone in team** on a server of your own, Servonaut
checks your own binding: when it uses another key or another login than the
team key you just set, it offers **Also update your own key for this
server**. **Update mine** moves your own binding to the team's key and login,
with the same pinned host keys; **Keep mine** (the default) leaves it as it
is, and the message says which login you keep connecting as.

A server of your own with no key of yours on this computer connects with the
team's key, and says so.

## Where the login comes from

Every binding stores the login SSH uses with its key. Auto-bind and Use Vault
Key take it from, in this order:

1. for a team's shared server, the login the shared server names (set it on
   the **Teams** screen when you share the server);
2. the server's own record, such as a custom server's username;
3. the username of a matching [connection rule](configuration.md#connection-rules);
4. the SSH defaults of the server's OVH account;
5. otherwise only `default_username` from Settings.

Auto-bind shows where each login comes from, in the review and in the CLI
output (`login from connection rule`, `login from default username`, and so
on). A login that is only the default username gets a note: it is right only
when it matches the server's operating system (for example `ubuntu` on
Ubuntu, `ec2-user` on Amazon Linux, `admin` on Debian). Set the right login in
a connection rule, or on the team's shared server, before you bind.

## Which key Auto-bind picks

For each server, Auto-bind picks the vault key:

1. that is the key file set for the server (**SSH Keys → Add Mapping**, the
   key your own SSH connection to it uses), compared by its public-key
   fingerprint, from its `.pub` file or the key itself when it has no
   passphrase, else by the file's name;
2. named like the server's key pair (an AWS instance's key pair name, or a
   custom server's key file);
3. named like the server.

Names compare without case and without a `.pem` or `.key` extension. The
review says which rule matched. When the key file set for a server is not in
the vault, the server falls back to the other rules and the review notes it:
check that the key it shows really logs in, or import the right key first.

## Binding many servers at once

In the app, open **Vault → Auto-bind keys** and choose the team's vault in
the picker. Only the vaults of teams you own or administer are offered, and
only while the team's shared servers are in your server list (they load with
it; opening the team on the **Teams** screen lists them again). When no team
vault is offered, the status line says why for each one.

On the command line:

```bash
servonaut vault auto-bind --team TEAM --fetch-host-keys --dry-run   # review only
servonaut vault auto-bind --team TEAM --fetch-host-keys             # review, then confirm
```

A binding pins the host keys your computer already trusts for the server.
For a server it has never connected to, **Fetch host keys** (`f` in the app,
`--fetch-host-keys` on the command line) connects to it once. It logs in
with your own access to that server, the way `servonaut ssh` does with your
own server's key file or key pair, records the host key in temporary storage
(never in your known_hosts files) and shows its fingerprint. For an AWS
instance whose console output still holds the first-boot host keys, the key
is checked against them; any other fetched key is marked *not verified*:
compare its fingerprint with the server's console or your provider before
you confirm.

A server that already has a team key keeps it: Auto-bind never replaces one.
Change it with **Use Vault Key** on the server instead.

## Letting members use the team vault

A member can use the team's keys once the vault is shared with their vault
identity (a grant). Owners and admins grant access with **Grants** (`g`) on
the Vault screen, or `servonaut vault grants process`. A member who needs
your approval first, for example because their vault identity changed since
your computer last saw it, is shown with their name, role and safety number.
Approve only after they confirm the same safety number over a channel you
trust. Without a terminal, or with `--yes`, nobody is approved: such members
stay pending until you run it again interactively.
