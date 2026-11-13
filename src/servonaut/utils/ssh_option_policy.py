"""Which SSH options a team may set on a member's computer.

A team configuration (and a team's record of a shared server) can carry
``ProxyCommand=...``, ``LocalCommand=...`` and other SSH options. Several of
them make ssh run a program or load a library on the member's computer. This
module decides, for each option, whether it is accepted from a team, and
builds the refusal that connection builders raise.

The table is a closed list. An option name is in exactly one of three
groups, and a name that is in neither is refused from a team as unknown. A
list of the dangerous names would be bypassed by an alias (OpenSSH accepts
``SmartcardDevice`` as another spelling of ``PKCS11Provider``) or by an
option a later release adds.

Only entries that came from a team are judged. An entry is a team's when its
canonical text is recorded in ``ssh.team_options`` (written when a team
configuration is applied), or when it comes from a team's shared-server
record. Everything Servonaut builds itself is never judged here.

This module imports no UI library: the MCP server loads it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from servonaut.utils.ssh_names import SSHNameError, SSHRefusal, check_ssh_host, shown

__all__ = [
    "ACCEPTED_OPTIONS",
    "RefusedOption",
    "REFUSED_OPTION_VALUE",
    "REFUSED_OPTIONS",
    "SSHOptionRefused",
    "Verdict",
    "baseline_existing_options",
    "canonical",
    "classify",
    "collect_team_options",
    "judge_entries",
    "non_accepted_texts",
    "option_entries",
    "proxy_command_entry",
    "judge_proxy_command",
    "merge_recorded",
    "origin_label",
    "team_option_rows",
    "parse_option",
    "membership",
    "raise_if_refused",
    "set_allowed",
]

# What ssh is told when a builder is handed a refused option without
# checking it first: ssh rejects the name, so the connection still fails.
REFUSED_OPTION_VALUE = "ServonautRefusedOption=yes"

_ALLOW_HINT = 'To allow it, run "servonaut team options" or open Settings > Connections.'

_RUNS_PROGRAM = "runs a program on this computer"
_LOADS_LIBRARY = "loads a library on this computer"
_CARRIES = "changes the program that carries the connection"

# Group A: refused from a team unless the member allows it. name -> phrase.
REFUSED_OPTIONS: Dict[str, str] = {
    "proxycommand": _RUNS_PROGRAM,
    "localcommand": _RUNS_PROGRAM,
    "permitlocalcommand": "lets a connection run a program on this computer",
    "knownhostscommand": _RUNS_PROGRAM,
    "pkcs11provider": _LOADS_LIBRARY,
    "smartcarddevice": _LOADS_LIBRARY,
    "securitykeyprovider": _LOADS_LIBRARY,
    "xauthlocation": "names a program to run on this computer",
    "forwardx11": "lets the server use this computer's display",
    "forwardx11trusted": "lets the server use this computer's display",
    "proxyjump": _CARRIES,
    "proxyusefdpass": _CARRIES,
    "remotecommand": "sets the command that runs on the server",
    "userknownhostsfile": "writes to a file on this computer",
    "userknownhostsfile2": "writes to a file on this computer",
    "include": "reads more SSH settings",
    "match": "reads more SSH settings",
    "host": "reads more SSH settings",
    "forwardagent": "lets the server use this computer's SSH keys",
    "sendenv": "sends this computer's environment variables to the server",
    "remoteforward": "lets the server reach this computer's network",
    "streamlocalbindunlink": "can replace a file on this computer",
    "gssapidelegatecredentials": "lets the server use this computer's Kerberos credentials",
    "ignoreunknown": "makes SSH skip settings it does not know",
}

# These only switch a feature off, so the value "no" or "false" is accepted.
_SWITCHES = frozenset(
    {
        "permitlocalcommand", "forwardx11", "forwardx11trusted", "proxyusefdpass", "forwardagent",
        "streamlocalbindunlink", "gssapidelegatecredentials",
    }
)
_OFF_VALUES = frozenset({"no", "false"})

# Group B: accepted from a team (every other option of OpenSSH 10.2's
# ssh_config, plus three old names still in common use).
ACCEPTED_OPTIONS = frozenset(
    """
    addkeystoagent addressfamily batchmode bindaddress bindinterface canonicaldomains
    canonicalizefallbacklocal canonicalizehostname canonicalizemaxdots canonicalizepermittedcnames
    casignaturealgorithms certificatefile challengeresponseauthentication channeltimeout checkhostip
    ciphers clearallforwardings compression connectionattempts connecttimeout controlmaster controlpath
    controlpersist dynamicforward enableescapecommandline enablesshkeysign escapechar
    exitonforwardfailure fingerprinthash forkafterauthentication forwardx11timeout
    gatewayports globalknownhostsfile gssapiauthentication gssapiclientidentity
    gssapikexalgorithms gssapikeyexchange gssapirenewalforcesrekey
    gssapiserveridentity gssapitrustdns hashknownhosts hostbasedacceptedalgorithms
    hostbasedauthentication hostbasedkeytypes hostkeyalgorithms hostkeyalias hostname identitiesonly
    identityagent identityfile ipqos kbdinteractiveauthentication kbdinteractivedevices
    kexalgorithms localforward loglevel logverbose macs nohostauthenticationforlocalhost
    numberofpasswordprompts obscurekeystroketiming passwordauthentication permitremoteopen port
    preferredauthentications pubkeyacceptedalgorithms pubkeyacceptedkeytypes pubkeyauthentication
    refuseconnection rekeylimit requesttty requiredrsasize revokedhostkeys
    serveralivecountmax serveraliveinterval sessiontype setenv stdinnull streamlocalbindmask
    stricthostkeychecking syslogfacility tag tcpkeepalive tunnel tunneldevice
    updatehostkeys user verifyhostkeydns versionaddendum visualhostkey warnweakcrypto
    """.split()
)

# name, optional whitespace/"="/whitespace, value. The name may be wrapped in
# one pair of double quotes. A tab counts as whitespace; every other control
# character makes the entry malformed.
_ENTRY = re.compile(
    r'^[ \t]*(?:"(?P<quoted>[A-Za-z][A-Za-z0-9]*)"|(?P<bare>[A-Za-z][A-Za-z0-9]*))'
    r"(?:[ \t]*=[ \t]*|[ \t]+)(?P<value>.*)$",
    re.DOTALL,
)
_USER_SHELL = re.compile("[\\x00-\\x1f\\x7f-\\x9f'\"`;&<>|(){}$]")
_BAD_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


class SSHOptionRefused(SSHRefusal):
    """A team-supplied SSH option that has not been allowed."""


class RefusedOption(str):
    """What a getter returns in place of an option that was refused.

    Its text is an option ssh rejects, so a builder that forgets to check
    still fails closed; ``message`` is what the refusal says.
    """

    message: str

    def __new__(cls, message: str) -> "RefusedOption":
        obj = super().__new__(cls, REFUSED_OPTION_VALUE)
        obj.message = message
        return obj


@dataclass(frozen=True)
class Verdict:
    """How one option entry is judged when it comes from a team.

    ``kind`` is ``accepted``, ``refused`` (group A), ``unknown`` (group C) or
    ``malformed``. ``name`` is the option name as written (``""`` when the
    entry does not parse) and ``phrase`` says what a refused option does.
    """

    kind: str
    name: str
    phrase: str
    canonical: str


@dataclass(frozen=True)
class _Parsed:
    name: str
    value: str


def parse_option(entry: object) -> Optional[_Parsed]:
    """Split an ``-o`` entry into name and value, or None when it is malformed."""
    if not isinstance(entry, str) or not entry.strip() or _BAD_CHARS.search(entry):
        return None
    match = _ENTRY.match(entry)
    if match is None:
        return None
    return _Parsed(match.group("quoted") or match.group("bare"), match.group("value").strip(" \t"))


def canonical(entry: object) -> str:
    """The text a recorded option is compared by: ``name`` lower-cased, ``=``, value stripped."""
    parsed = parse_option(entry)
    if parsed is not None:
        return f"{parsed.name.lower()}={parsed.value}"
    if not isinstance(entry, str):
        return str(entry)
    # Not an option ssh reads: keep the text, with the name part lower-cased
    # so the same entry always has the same text, however it was built.
    text = entry.strip(" \t")
    name, sep, rest = text.partition("=")
    return f"{name.lower()}{sep}{rest}"


def proxy_command_entry(command: object) -> Optional[str]:
    """The ``ProxyCommand=...`` entry a profile's ``proxy_command`` field stands for.

    The one place that reads the field, for recording, the pull preview and
    connecting alike, so all of them judge and run the same text. A command is
    stripped of surrounding whitespace (line breaks included); a value that is
    not text is kept as it is written, so it is recorded and refused like any
    other odd entry. None when the field is empty.
    """
    if command is None or command == "" or command == []:
        return None
    if isinstance(command, str):
        command = command.strip()
        return f"ProxyCommand={command}" if command else None
    return f"ProxyCommand={command}"


def option_entries(extras: object) -> List[Any]:
    """The entries of an ``extra_ssh_options`` field, whatever shape it came in.

    A list or tuple is its items. Any other value (a text, a mapping, a
    number) is one entry, which then fails to parse and is refused from a team.
    """
    if not extras:
        return []
    return list(extras) if isinstance(extras, (list, tuple)) else [extras]


def non_accepted_texts(entry: object) -> List[str]:
    """The canonical texts to record for *entry*, as written and as an editor would save it.

    The editors split an entry that holds line breaks into several options
    and save ``str.strip()`` of each (which removes more than space and tab).
    Every piece is recorded both ways, so a team's entry cannot become the
    member's own by being saved from a form.
    """
    if not isinstance(entry, str):
        return [] if classify(entry).kind == "accepted" else [canonical(entry)]
    texts: List[str] = []
    for piece in (entry, *entry.splitlines()):
        for text in (piece, piece.strip()):
            if text and classify(text).kind != "accepted":
                texts.append(canonical(text))
    return list(dict.fromkeys(texts))


def _unsafe_value(key: str, value: str) -> str:
    """What is wrong with the value of an accepted option Servonaut later puts in a command.

    ``HostName`` becomes the ``%h`` and ``Port`` the ``%p`` of a hop's command;
    neither may hold anything a shell reads. ``HostKeyAlias`` and ``User`` are
    not used in a command Servonaut builds, but a value with shell syntax is
    refused as well, for a ProxyCommand the member wrote that uses ``%k`` or
    ``%r``. "" when the value is fine or the option is not one of these.
    """
    try:
        if key in ("hostname", "hostkeyalias"):
            check_ssh_host(value)
        elif key == "user" and (_USER_SHELL.search(value) or value.startswith("-")):
            return "holds characters a shell reads as a command"
        elif key == "port" and not (value.isascii() and value.isdigit()):
            return "is not a number"
    except SSHNameError:
        return "holds characters a shell reads as a command"
    return ""


def classify(entry: object) -> Verdict:
    """Judge *entry* as if a team had supplied it."""
    text = canonical(entry)
    parsed = parse_option(entry)
    if parsed is None:
        return Verdict("malformed", "", "", text)
    key = parsed.name.lower()
    unsafe = _unsafe_value(key, parsed.value)
    if unsafe:
        return Verdict("refused", parsed.name, unsafe, text)
    if key in REFUSED_OPTIONS:
        if key in _SWITCHES and parsed.value.lower() in _OFF_VALUES:
            return Verdict("accepted", parsed.name, "", text)
        return Verdict("refused", parsed.name, REFUSED_OPTIONS[key], text)
    if key in ACCEPTED_OPTIONS:
        return Verdict("accepted", parsed.name, "", text)
    return Verdict("unknown", parsed.name, "", text)


# ---------------------------------------------------------------------------
# What the member has recorded and allowed (ssh.team_options)
# ---------------------------------------------------------------------------

def _items(team_options: object) -> List[dict]:
    if not isinstance(team_options, (list, tuple)):
        return []
    return [i for i in team_options if isinstance(i, dict) and isinstance(i.get("option"), str)]


def _item_for(team_options: object, text: str) -> Optional[dict]:
    """The record for *text*; an allowed one wins over a refused duplicate."""
    found: Optional[dict] = None
    for item in _items(team_options):
        if item["option"] == text:
            if item.get("allowed") is True:
                return item
            found = found or item
    return found


def _is_allowed(team_options: object, text: str) -> bool:
    item = _item_for(team_options, text)
    return item is not None and item.get("allowed") is True


def set_allowed(team_options: List[dict], text: str, allowed: bool) -> None:
    """Set the allowed flag of every item whose option text is *text*."""
    for item in team_options:
        if isinstance(item, dict) and item.get("option") == text:
            item["allowed"] = allowed


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def _from_clause(item: Optional[dict]) -> str:
    if item is None or item.get("saved_before") is True:
        return ""
    name = item.get("team_name")
    if isinstance(name, str) and name:
        return f" came from team {shown(name)} and"
    return " came from a team and"


def _refusal_message(
    verdict: Verdict, where: str, item: Optional[dict], *, shared_team: Optional[str] = None,
) -> str:
    saved = item is not None and item.get("saved_before") is True
    if shared_team is not None:
        head, tail = where, (
            "Ask the team to remove it, or allow it by adding it to ssh.team_options "
            "in ~/.servonaut/config.json."
        )
        origin = ""
    elif saved:
        head, origin = where, ""
        tail = (
            "It was saved before Servonaut recorded where settings come from. "
            'If you wrote it yourself, allow it: run "servonaut team options" '
            "or open Settings > Connections."
        )
    else:
        head, origin, tail = where, _from_clause(item), _ALLOW_HINT
    name = shown(verdict.name)
    if verdict.kind == "refused":
        body = f"sets {name}, which {verdict.phrase}."
    elif verdict.kind == "unknown":
        body = f"sets the SSH option {name}, which Servonaut does not recognise."
    else:
        body = "has an SSH option that is not written as Name=Value."
    return f"Not connecting: {head}{origin} {body} {tail}"


def bastion_name_message(profile_name: str, what: str, value: object) -> str:
    """The refusal for a bastion host or user name a shell would read as syntax."""
    if what == "host":
        problem = "contains a space, quote, backslash or shell symbol"
        label = "host"
    else:
        problem = "contains a quote or control character"
        label = "user"
    return (
        f"Not connecting: the bastion {label} name {shown(str(value))!r} in the connection "
        f"profile '{shown(profile_name)}' {problem}. Correct it in Settings > Connections."
    )


# ---------------------------------------------------------------------------
# Judging the entries a connection is about to use
# ---------------------------------------------------------------------------

def judge_entries(
    entries: Iterable[object],
    *,
    where: str,
    team_options: object,
    shared_team: Optional[str] = None,
) -> List[Any]:
    """Return *entries* with every refused team option replaced by a carrier.

    An entry is judged when its canonical text is recorded in *team_options*,
    or when *shared_team* is given (the entries come from a team's record of
    a server, which is always the team's). Everything else is the member's
    own and passes through untouched. *where* names the profile, server or
    record for the message.
    """
    result: List[Any] = []
    for entry in entries:
        text = canonical(entry)
        item = _item_for(team_options, text)
        if shared_team is None and item is None:
            result.append(entry)
            continue
        verdict = classify(entry)
        if verdict.kind == "accepted" or _is_allowed(team_options, text):
            result.append(entry)
            continue
        result.append(RefusedOption(
            _refusal_message(verdict, where, item, shared_team=shared_team)
        ))
    return result


def judge_proxy_command(proxy_command: object, *, where: str, team_options: object) -> Optional[RefusedOption]:
    """The carrier for a profile's ``proxy_command`` field, or None when it may run."""
    entry = proxy_command_entry(proxy_command)
    if entry is None:
        return None
    (judged,) = judge_entries([entry], where=where, team_options=team_options)
    return judged if isinstance(judged, RefusedOption) else None


def raise_if_refused(*option_lists: Optional[Iterable[object]]) -> None:
    """Raise ``SSHOptionRefused`` for the first refused option in any of the lists."""
    for options in option_lists:
        for option in options or ():
            if isinstance(option, RefusedOption):
                raise SSHOptionRefused(option.message)
            if option == REFUSED_OPTION_VALUE:
                raise SSHOptionRefused(
                    "Not connecting: an SSH option from a team was refused. "
                    'To allow it, run "servonaut team options" or open Settings > Connections.'
                )


# ---------------------------------------------------------------------------
# Recording at pull
# ---------------------------------------------------------------------------

def collect_team_options(profiles: Sequence[Any], servers: Sequence[Any]) -> List[str]:
    """Every option text in *profiles* and *servers* that is not accepted from a team."""
    found: List[str] = []
    for profile in profiles:
        entries = [proxy_command_entry(getattr(profile, "proxy_command", None))]
        entries += option_entries(getattr(profile, "extra_ssh_options", None))
        found += _texts_of(entries)
    for server in servers:
        found += _texts_of(option_entries(getattr(server, "extra_ssh_options", None)))
    return list(dict.fromkeys(found))


def _texts_of(entries: Iterable[object]) -> List[str]:
    texts: List[str] = []
    for entry in entries:
        if entry is not None:
            texts += non_accepted_texts(entry)
    return texts


def merge_recorded(
    existing: object, texts: Sequence[str], *, team_id: str, team_slug: str, team_name: str,
) -> List[dict]:
    """The new ``ssh.team_options`` after a pull that carried *texts*.

    One item per distinct text, naming this team; ``allowed`` is kept from an
    item with the same text, else false. Items the member allowed that this
    pull did not carry are kept: those are the member's decisions.
    """
    merged: List[dict] = []
    for text in texts:
        old = _item_for(existing, text)
        merged.append({
            "option": text,
            "team": team_id or team_slug,
            "team_name": team_name,
            "allowed": bool(old is not None and old.get("allowed") is True),
        })
    for item in _items(existing):
        if item.get("allowed") is True and item["option"] not in texts:
            merged.append(dict(item))
    return merged


# ---------------------------------------------------------------------------
# Profiles and servers saved before options were recorded
# ---------------------------------------------------------------------------

def membership(auth_path: Path) -> str:
    """What the sign-in file says about teams: ``none`` (no account), ``member`` or ``alone``.

    A pull needs an account, and the screen that pulls also lists the teams.
    ``none``: the file is missing. ``alone``: the teams were fetched and the
    list is empty. ``member``: anything else, including a file that cannot be
    read and a team list never fetched.
    """
    import json

    if not auth_path.exists():
        return "none"
    try:
        data = json.loads(auth_path.read_text(encoding="utf-8"))
        fetched = data.get("teams_fetched_at") or 0
        if isinstance(fetched, (int, float)) and fetched > 0 and data.get("teams_cached") == []:
            return "alone"
    except (OSError, ValueError, AttributeError):
        return "member"
    return "member"


def baseline_existing_options(config: Any, auth_path: Path) -> int:
    """Record, once, the options already saved that a team may have supplied.

    Returns how many items were recorded. The step is decided only when the
    sign-in file exists. Without it the flag stays unset and the step runs on
    the first load that finds one: the file is also removed when a session is
    revoked, so its absence proves nothing about earlier pulls. Until then the
    saved options keep working, and they are never recorded as a team's by
    a file that is not there.
    """
    ssh = config.ssh
    if ssh.team_options_checked:
        return 0
    state = membership(auth_path)
    if state == "none":
        return 0
    recorded = 0
    if state == "member":
        existing = list(_items(ssh.team_options))
        for text in collect_team_options(config.connection_profiles, config.custom_servers):
            if _item_for(existing, text) is None:
                existing.append({
                    "option": text, "team": "", "team_name": "",
                    "allowed": False, "saved_before": True,
                })
                recorded += 1
        ssh.team_options = existing
    ssh.team_options_checked = True
    return recorded


def origin_label(item: Mapping[str, Any]) -> str:
    """Where a recorded option came from, as the Settings table and the CLI say it."""
    if item.get("saved_before") is True:
        return "Saved before 2.33.1"
    name = item.get("team_name")
    return f"Team {shown(name)}" if isinstance(name, str) and name else "A team"


def team_option_rows(team_options: object) -> List[Mapping[str, Any]]:
    """The recorded items, in order, as the Settings table and the CLI list them."""
    return _items(team_options)
