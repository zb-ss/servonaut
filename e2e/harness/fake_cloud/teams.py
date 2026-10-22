"""Managed teams: members, invitations, roles and shared configs.

A *managed* team (``AccountData.create_team``, or ``POST /api/v1/teams``)
keeps its members the way the service does: an invitation is a pending
member row with a token, an expiry seven days out and an accept URL; the
invitee accepting it (``FakeCloud.accept_invitation``, which stands in for
the browser) turns the row into an active member. Each caller sees the team
through their own role, and the rules are the ones the CLI documents
(``services/team_service.py``, ``screens/team_management.py``):

* owners and admins manage members and shared servers, members and viewers
  read only;
* only the owner invites or makes admins, or changes or removes an admin;
* the owner role is set when the team is created and is never assignable,
  and the owner can be neither removed nor demoted;
* every member row, accepted or pending, takes a seat; a team without seats
  (no Teams subscription) refuses invitations with 402, a full one with 422.

A refusal is a :class:`Refusal`, which the routes answer in the service's
error envelope. Plain data only (no aiohttp): ``AccountData`` holds the
teams under its lock.
"""

from __future__ import annotations

import datetime as dt
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Optional

ROLES = ("owner", "admin", "member", "viewer")
ASSIGNABLE_ROLES = ("admin", "member", "viewer")
MANAGERS = frozenset({"owner", "admin"})
INVITATION_DAYS = 7
DEFAULT_MAX_SEATS = 5
INVITE_PATH = "/invite"
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Refusal(Exception):
    """A request the service refuses: HTTP status, error code and message."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message

    def body(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message}}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(moment: dt.datetime) -> str:
    return moment.replace(microsecond=0).isoformat()


def slugify(name: str) -> str:
    """A team slug from its name, as the service derives it."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "team"


@dataclass
class Member:
    """One member row: an active member, or a pending invitation."""

    id: int
    email: str
    role: str
    invited_at: str
    user_id: Optional[int] = None
    name: Optional[str] = None
    user_email: Optional[str] = None
    accepted_at: Optional[str] = None
    expires_at: Optional[str] = None
    token: Optional[str] = None

    @property
    def accepted(self) -> bool:
        return self.user_id is not None

    def row(self, base_url: str, *, manager: bool) -> dict[str, Any]:
        """The row as ``GET /teams/{slug}`` lists it; accept URLs go to managers only."""
        row: dict[str, Any] = {
            "id": self.id,
            "invitation_email": self.email,
            "role": self.role,
            "is_accepted": self.accepted,
            "invited_at": self.invited_at,
            "accepted_at": self.accepted_at,
            "invitation_expires_at": None if self.accepted else self.expires_at,
            "user": (
                {"id": self.user_id, "name": self.name, "email": self.user_email}
                if self.accepted else None
            ),
        }
        if not self.accepted and manager:
            row["accept_url"] = f"{base_url}{INVITE_PATH}/{self.token}"
        return row


@dataclass
class ManagedTeam:
    """A team whose membership the fake keeps (see the module docstring)."""

    id: str
    slug: str
    name: str
    max_seats: int
    members: list[Member] = field(default_factory=list)
    next_member_id: int = 1

    # -- reading ---------------------------------------------------------------

    def member_of(self, user_id: int) -> Optional[Member]:
        """The accepted member row of *user_id*, if they are one."""
        return next((m for m in self.members if m.user_id == user_id), None)

    def role_of(self, user_id: int) -> Optional[str]:
        member = self.member_of(user_id)
        return member.role if member is not None else None

    def accepted(self) -> list[Member]:
        return [m for m in self.members if m.accepted]

    def summary(self, user_id: int) -> dict[str, Any]:
        """The ``GET /api/v1/teams`` row, through *user_id*'s role."""
        return {
            "id": self.id, "slug": self.slug, "name": self.name,
            "role": self.role_of(user_id), "member_count": len(self.accepted()),
        }

    def detail(self, user_id: int, base_url: str) -> dict[str, Any]:
        """``GET /api/v1/teams/{slug}``, through *user_id*'s role."""
        manager = self.role_of(user_id) in MANAGERS
        return {
            **self.summary(user_id),
            "max_seats": self.max_seats,
            "members": [m.row(base_url, manager=manager) for m in self.members],
        }

    # -- changing -------------------------------------------------------------

    def _manager(self, caller: int) -> str:
        role = self.role_of(caller)
        if role not in MANAGERS:
            raise Refusal(403, "forbidden", "Only team owners and admins can manage this team.")
        return str(role)

    def _target(self, member_id: object) -> Member:
        target = next((m for m in self.members if str(m.id) == str(member_id)), None)
        if target is None:
            raise Refusal(404, "not_found", "Team member not found.")
        return target

    @staticmethod
    def _assignable(role: object) -> str:
        if role == "owner":
            raise Refusal(400, "invalid_role", "The owner role cannot be assigned.")
        if role not in ASSIGNABLE_ROLES:
            raise Refusal(400, "invalid_role", f"Role must be one of: {', '.join(ASSIGNABLE_ROLES)}.")
        return str(role)

    def add_owner(self, user_id: int, email: str, name: str) -> Member:
        now = _iso(_now())
        owner = Member(self._next_id(), email, "owner", now, user_id=user_id, name=name,
                       user_email=email, accepted_at=now)
        self.members.append(owner)
        return owner

    def add_member(self, user_id: int, email: str, name: str, role: str) -> Member:
        """*user_id* is an active member with *role* already (a journey's set-up)."""
        role = self._assignable(role)
        if self.member_of(user_id) is not None:
            raise ValueError(f"user {user_id} is already a member of {self.slug}")
        now = _iso(_now())
        member = Member(self._next_id(), email, role, now, user_id=user_id, name=name,
                        user_email=email, accepted_at=now)
        self.members.append(member)
        return member

    def _next_id(self) -> int:
        member_id, self.next_member_id = self.next_member_id, self.next_member_id + 1
        return member_id

    def invite(self, caller: int, email: object, role: object) -> Member:
        caller_role = self._manager(caller)
        role = self._assignable(role)
        if role == "admin" and caller_role != "owner":
            raise Refusal(403, "forbidden", "Only the team owner can invite admins.")
        if not isinstance(email, str) or not _EMAIL.fullmatch(email.strip()):
            raise Refusal(400, "invalid_email", "A valid e-mail address is required.")
        email = email.strip()
        if any(email.lower() in {m.email.lower(), (m.user_email or "").lower()} for m in self.members):
            raise Refusal(409, "already_member", f"{email} is already a member or invited.")
        if self.max_seats <= 0:
            raise Refusal(402, "subscription_inactive",
                          "The team owner's Teams subscription is not active.")
        if len(self.members) >= self.max_seats:
            raise Refusal(422, "seat_limit_reached",
                          f"This team has used all {self.max_seats} of its seats.")
        now = _now()
        member = Member(self._next_id(), email, role, _iso(now),
                        expires_at=_iso(now + dt.timedelta(days=INVITATION_DAYS)),
                        token=secrets.token_urlsafe(18))
        self.members.append(member)
        return member

    def resend(self, caller: int, member_id: object) -> Member:
        self._manager(caller)
        target = self._target(member_id)
        if target.accepted:
            raise Refusal(409, "already_accepted", "This member has already accepted the invitation.")
        # The token stays; the invitation is valid for another seven days.
        target.expires_at = _iso(_now() + dt.timedelta(days=INVITATION_DAYS))
        return target

    def change_role(self, caller: int, member_id: object, role: object) -> Member:
        caller_role = self._manager(caller)
        target = self._target(member_id)
        if target.role == "owner":
            raise Refusal(400, "owner_role_immutable", "The owner's role cannot be changed.")
        role = self._assignable(role)
        if caller_role != "owner" and "admin" in (role, target.role):
            raise Refusal(403, "forbidden", "Only the team owner can promote or demote admins.")
        target.role = role
        return target

    def remove(self, caller: int, member_id: object) -> Member:
        caller_role = self._manager(caller)
        target = self._target(member_id)
        if target.role == "owner":
            raise Refusal(400, "owner_not_removable", "The team owner cannot be removed.")
        if target.role == "admin" and caller_role != "owner":
            raise Refusal(403, "forbidden", "Only the team owner can remove an admin.")
        self.members.remove(target)
        return target

    def accept(self, email: str, *, user_id: int, name: str, user_email: str) -> Member:
        """The invitee accepted the invitation sent to *email* (the browser step)."""
        pending = next(
            (m for m in self.members if not m.accepted and m.email.lower() == email.lower()), None
        )
        if pending is None:
            raise KeyError(f"no pending invitation for {email} in {self.slug}")
        if self.member_of(user_id) is not None:
            raise ValueError(f"user {user_id} is already a member of {self.slug}")
        expires = dt.datetime.fromisoformat(str(pending.expires_at))
        if expires <= _now():
            raise ValueError(f"the invitation for {email} has expired")
        pending.user_id, pending.name, pending.user_email = user_id, name, user_email
        pending.accepted_at, pending.token = _iso(_now()), None
        return pending
