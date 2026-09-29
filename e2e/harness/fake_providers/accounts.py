"""What the provider fakes share about accounts: who a request is for.

Each fake keeps one state per account (a Hetzner project, an OVH account)
and resolves it from the request's credentials, as the real APIs do. The
route wrapper stores the account's label on the request and
``FakeProviders`` copies it into the request log, so a journey can assert
which account a call was made for. Labels are the fakes' own names for the
accounts; the credentials themselves are never logged.
"""

from __future__ import annotations

from typing import Optional

from aiohttp import web

# The label of the account a request authenticated as (unset when it did not).
ACCOUNT = web.RequestKey("fake_providers_account", str)


def bearer_token(request: web.Request) -> Optional[str]:
    """The token of an ``Authorization: Bearer ...`` header, if there is one."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None
