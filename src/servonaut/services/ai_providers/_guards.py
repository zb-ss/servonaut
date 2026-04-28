"""Belt-and-suspenders entitlement gate for the hosted Servonaut provider.

The server already enforces ``premium_ai`` server-side; these decorators
give the same behaviour client-side so an unauthenticated or free-plan
caller never even reaches the network. This is defense-in-depth — a
clear local error beats a 403 round-trip.

Two flavours:

* :func:`require_premium_ai` — for plain ``async def`` methods that
  ``return`` a value (used on :meth:`ServonautProvider.chat` and
  :meth:`ServonautProvider.analyze`).
* :func:`require_premium_ai_stream` — for ``async def`` *generators*
  (``async def`` with ``yield``). Wrapping a generator with the plain
  decorator silently swallows yields, so streams must use this variant.

Both decorators key off the bound instance's ``_auth`` (or
``_auth_service``) attribute, leaving every positional / keyword
argument untouched.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Awaitable, Callable, TYPE_CHECKING

from servonaut.services.api_client import ForbiddenEntitlementError

if TYPE_CHECKING:
    from servonaut.services.auth_service import AuthService  # noqa: F401


_REQUIRED_FEATURE = "premium_ai"


def _resolve_auth(instance: Any):
    """Return the AuthService bound to ``instance`` or raise.

    The provider stores the auth handle as either ``_auth`` (newer
    convention) or ``_auth_service`` (older). We probe both so the
    decorator works regardless of the field name picked by the caller.
    """
    return (
        getattr(instance, "_auth", None)
        or getattr(instance, "_auth_service", None)
    )


def _check_entitlement(instance: Any) -> None:
    """Synchronous entitlement check shared by both decorators.

    Raises :class:`ForbiddenEntitlementError` (a subclass of
    ``APIError``) so the existing T5 error-handling matrix can handle the
    UX without a special-case path. We match the real backend's error
    code/status pair (``entitlement_required`` / 403) so the same handler
    fires whether the gate trips client-side or server-side.
    """
    auth = _resolve_auth(instance)
    if auth is None or not getattr(auth, "is_authenticated", False):
        raise ForbiddenEntitlementError(
            code="entitlement_required",
            message="You must be logged in to use Servonaut AI.",
            status=403,
        )
    if not auth.has_feature(_REQUIRED_FEATURE):
        raise ForbiddenEntitlementError(
            code="entitlement_required",
            message="Servonaut AI requires the Solo or Teams plan.",
            status=403,
        )


def require_premium_ai(
    method: Callable[..., Awaitable[Any]],
) -> Callable[..., Awaitable[Any]]:
    """Decorator for plain ``async def`` methods.

    Use this on coroutine methods that ``return`` a single result (e.g.
    :meth:`ServonautProvider.chat`, :meth:`ServonautProvider.analyze`).
    Decorating an ``async def`` *generator* with this would coerce the
    generator into a coroutine and silently lose every ``yield``; for
    streams use :func:`require_premium_ai_stream` instead.
    """

    @wraps(method)
    async def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        _check_entitlement(self)
        return await method(self, *args, **kwargs)

    return wrapper


def require_premium_ai_stream(method: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator for ``async def`` generators (``async def`` with ``yield``).

    Performs the entitlement check BEFORE the first yield so the caller
    never sees a partial stream when the gate trips. This is the variant
    to apply once :meth:`ServonautProvider.stream_chat` lands (T2 / Wave
    2 Agent D).
    """

    @wraps(method)
    async def wrapper(self: Any, *args: Any, **kwargs: Any):
        _check_entitlement(self)
        async for item in method(self, *args, **kwargs):
            yield item

    return wrapper


__all__ = [
    "require_premium_ai",
    "require_premium_ai_stream",
]
