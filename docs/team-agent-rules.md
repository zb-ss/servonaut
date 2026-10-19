# Team agent rules

*Teams plan.* A team's owners and admins decide what the members' AI agents
may do on the servers the team shares: the level each role runs at, a
different level on a particular server, the commands agents may run, and the
patterns they may never run. Every member's Servonaut applies these rules to
every AI agent that works through it, whichever AI provider is behind the
agent, and whichever cloud the server is on.

A member's own settings can only make the rules stricter. The rules cover
agents, not people: see [What the rules do not cover](#what-the-rules-do-not-cover).

## What owners and admins set

Owners and admins edit the rules on servonaut.dev, on the team's
**Policies** tab (`https://servonaut.dev/account/teams/<team>/policies`).

### Levels

Each role (owner, admin, member, viewer) gets one of the guard levels the
[MCP server](mcp-tools.md#guard-levels) uses:

- `readonly` — listing and status tools only; no commands.
- `standard` — read tools, plus the commands on the allowed list.
- `dangerous` — every tool; any command except the blocked ones.

Until the team changes them, owners, admins and members run at `standard`
and viewers at `readonly`.

A team can give a role a different level on one of its servers, for example
`readonly` for members on a production database server. The roles that a
server's level leaves out keep the team-wide level there.

Admins can change every role's level except the owner's. Only the owner can
change the owner's own level or set any level to `dangerous`, and
`dangerous` also needs the team to allow dangerous AI tools. Turning
dangerous AI tools off lowers every `dangerous` level to `standard`.

### Allowed commands

At the `standard` level, agents may run only commands on the allowed list.
Leave it unset to use Servonaut's built-in list (`ls`, `cat`, `grep`, `ps`,
`df`, `uptime`, `tail`, and similar read-only commands), or give the team's
own list of command names.

Each entry is a command name, such as `uptime` or `systemctl`, not a prefix
or a pattern. A command may be piped into others (`ps aux | grep nginx`) and
may start with `sudo`; each part must start with an allowed name, matched
exactly and case-sensitively. An entry that is not a plain command name
(`ls -la`, `apt*`) is ignored. An empty list allows no commands at all.

A member's own `command_allowlist` still applies: on a team's server a
command must be on both lists. If the team allows a command that Servonaut's
built-in list does not have, members add it to their own list too (MCP
settings, or `mcp.command_allowlist` in `~/.servonaut/config.json`). Until
then, a refusal of that command says the team allows it and the member's own
list does not.

### Blocked patterns

Blocked patterns are regular expressions in Python's
[`regex`](https://pypi.org/project/regex/) syntax, which also reads common
PCRE forms such as `\h` and `\p{L}`. Each is searched for anywhere in the
command, for example `\.env\b` to keep agents away from applications' `.env`
files. They are added to Servonaut's built-in blocklist (`rm -rf`,
`shutdown`, `dd`, ...), which always applies, and to the member's own blocked
patterns. They apply at every level, `dangerous` included. At the `standard`
level a command is also checked as it will run, with its quotes removed, so
`cat .e'nv'` is refused like `cat .env`.

If Servonaut cannot use one of the team's patterns, it runs no command at all
on the team's servers until an owner or admin changes the pattern. Other tools
keep their level. The Teams screen and `servonaut team rules` name the
pattern.

Checking a command against all of the team's patterns may take at most
`mcp.team_pattern_timeout_ms` (100 milliseconds unless the member changes it).
A command that a pattern takes longer to check is refused, and the refusal
names the pattern, so a slow pattern cannot hang a member's agents. Keep
patterns simple: a pattern that can backtrack a lot (such as `(a|aa)+$`)
refuses ordinary commands.

## What members see

- **Teams screen.** Open the team: the **What agents may do here** card shows
  each role's level and yours, the servers with levels of their own, the
  command lists, the rules' version, when they were last fetched and until
  when they are valid. When the rules cannot be used, it says so first, and
  why.
- **Command line.** [`servonaut team rules TEAM`](cli-reference.md#servonaut-team-rules)
  prints the same, or JSON with `--json`.
- **MCP.** [`list_instances`](mcp-tools.md#list_instancesregion-state-account)
  ends with the level agents run at on each team server and who set it.
- **Refusals.** A refused tool call names the team, the level, who set it, and
  what was refused, for example:

  > Blocked: on team Ops's shared servers your agents run at the standard
  > level (set by the team), and 'cat /srv/app/.env' is refused there: it
  > matches the blocked pattern \.env\b.

  The MCP audit log (`~/.servonaut/mcp_audit.jsonl`) records every refusal
  with the reason `team_rule`.

## Which agents the rules cover

The rules are applied in Servonaut's tools, not in the AI model, so they hold
for:

- the **AI chat** in the TUI, with Servonaut AI or with your own OpenAI,
  Anthropic, Gemini or Ollama key;
- **Servonaut AI's tool calls relayed to your machine** by `servonaut connect`
  or the TUI's relay, from the web app or another session;
- **any agent using Servonaut's MCP server** (`servonaut --mcp`): Claude Code,
  Codex, Cursor, Windsurf, VS Code, OpenCode and others.

A command an AI proposes stays the AI's command when you confirm it in the
chat, so the team's rules still apply to it. The cloud a server runs on makes
no difference: AWS, Hetzner, OVHcloud or a custom server, a server the team
shares is under the team's rules.

## Your own settings

Your own settings can only make the team's rules stricter: your agents run at
the stricter of your own level and the team's, a command must be on both
allowed lists, and your own blocked patterns apply as well.

## How the rules reach your machine

servonaut.dev signs each team's rules. Your Servonaut checks the signature
with keys built into each release, and checks that the rules are the team's
own and not older than rules it already has, before it uses them.

Each signed copy is valid for a limited time. Servonaut fetches the rules
whenever it lists the team's servers (at start, and on `R` in the server
list), when you open the team on the Teams screen, and again halfway through
each copy's validity while the TUI, `servonaut --mcp` or `servonaut connect`
runs. A change an owner or admin makes therefore reaches running agents
without a restart.

The last good copy of each team's rules is kept in
`~/.servonaut/team_policy.json` (readable by you only). It applies at once
when Servonaut starts, until it expires. It is checked again every time it is
read, so editing the file can only make the team's servers read-only.

## When the rules fall back to read-only

When Servonaut has no rules it can use for a team, every role runs at
`readonly` on that team's servers, owners included, and every refusal says
why:

| The refusal says | What to do |
|------------------|------------|
| the team's agent rules have not been loaded yet | Wait a moment: Servonaut fetches them when it lists the team's servers. |
| the team's agent rules could not be fetched; check that you are online and signed in | Check your connection and run `servonaut login` if your session ended. |
| the team's agent rules expired and could not be refreshed; check that you are online and signed in | As above: the last copy ran out while servonaut.dev could not be reached. |
| this Servonaut cannot verify the team's agent rules; update Servonaut | Update Servonaut (`servonaut --update`): the rules were signed with a key this release does not have. |
| the team's agent rules need a newer Servonaut; update Servonaut | Update Servonaut. |
| the team's agent rules use a setting this Servonaut does not know; update Servonaut | Update Servonaut: the team uses a setting newer than this release, which may limit agents in a way this release cannot apply. |
| this Servonaut trusts no key for agent rules from the API address it is set to use | Servonaut is set to use another API address (`SERVONAUT_API_URL`). Releases trust only the Servonaut service's signing keys, so updating does not help: unset it to use the team's rules. |
| the team service sent no signed agent rules | Try again later. |
| the team's agent rules could not be read | Update Servonaut. If that does not help, ask a team owner or admin to save the rules again. |
| the team's agent rules could not be verified | The rules were changed on their way to your machine, for example by a proxy. Check your network. |
| the team service sent another team's agent rules | The answer was not the one asked for, for example because of a proxy. Check your network. |
| the team service sent older agent rules than this device already has | An older copy came back after a newer one. Check your network. |
| the team service sent different agent rules under a version this device already has | Ask a team owner or admin to save the rules again: the new version replaces the copy on your machine. |

## What the rules do not cover

- **What people do themselves.** Commands typed in the TUI's command box, the
  file browser, `servonaut ssh`, the web console, and remediation fixes a
  person approves are not under these rules. People are limited by their SSH
  access: with team [SSH certificates](cli-reference.md#servonaut-ca), owners
  set which server logins each role gets.
- **Agents that bypass Servonaut.** A coding agent that runs `ssh` in its own
  shell with a member's own key is not stopped by these rules; only SSH access
  limits it. For full control, members hold no personal keys to the team's
  servers, and reach them with team vault keys or SSH certificates.
- **The same machine listed as your own.** A server you also have as your own
  (in your own cloud account, or as a custom server) and reach with your own
  key keeps your own rules when an agent names it as your server. Named
  through the team (`ops/web-1`), the team's rules apply. If your own entry
  connects with a key from the team's vault, the team's rules apply to it as
  well, and its refusals say so ("on this server, which connects with a key
  from team Ops's vault, ..."). If that team is not one of yours, agents run
  at `readonly` there until the server uses another key.
- **A modified Servonaut.** The rules are applied by the Servonaut on the
  member's machine. For Servonaut AI, servonaut.dev also checks each role's
  level before it sends a tool call to a member's machine, which holds even
  against a modified client; the command lists are applied on the member's
  machine.
