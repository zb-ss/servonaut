"""Defensive value objects for hosted AI money data.

The API supplies money as integer micros and server-rendered display strings.
Display fields remain server-authoritative; the local helpers only render
integer minor or micro units exactly with :class:`decimal.Decimal`.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Mapping, Optional


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _string_or_empty(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _currency_code(value: Any) -> str:
    """Return an ASCII three-letter protocol currency code, or ``""``."""
    if not isinstance(value, str):
        return ""
    code = value.upper()
    if len(code) != 3 or any(char < "A" or char > "Z" for char in code):
        return ""
    return code


def safe_terminal_text(value: Any) -> str:
    """Remove terminal control bytes while preserving ordinary Unicode labels.

    API values stay untouched in ``raw`` for cache and JSON consumers. This
    helper is only for server metadata rendered by the CLI.
    """
    if not isinstance(value, str):
        return ""
    return "".join(
        char for char in value if not (ord(char) < 32 or 127 <= ord(char) <= 159)
    )


@dataclass(frozen=True)
class AIHostedBalance:
    """Opaque hosted balance payload with safe display accessors."""

    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, value: Any) -> Optional["AIHostedBalance"]:
        if not isinstance(value, Mapping):
            return None
        return cls(dict(value))

    @property
    def display(self) -> dict[str, str]:
        raw = self.raw.get("display")
        if not isinstance(raw, Mapping):
            return {}
        return {str(key): value for key, value in raw.items() if isinstance(value, str)}

    @property
    def state(self) -> str:
        state = self.raw.get("state")
        return state if isinstance(state, str) and state in {"ok", "degraded", "blocked"} else ""

    @property
    def state_label(self) -> str:
        """Return a stable, human-readable label for a known balance state."""
        return {
            "ok": "Available",
            "degraded": "Running low (faster model)",
            "blocked": "Paused",
        }.get(self.state, "")

    @property
    def currency(self) -> str:
        return _currency_code(self.raw.get("currency"))

    @property
    def reason(self) -> str:
        return _string_or_empty(self.raw.get("reason"))

    @property
    def topup_helps(self) -> Optional[bool]:
        value = self.raw.get("topup_helps")
        return value if isinstance(value, bool) else None

    @property
    def approx_requests_remaining(self) -> Optional[int]:
        value = _int_or_none(self.raw.get("approx_requests_remaining"))
        return value if value is None or value >= 0 else None

    @property
    def payer_is_team(self) -> bool:
        """Whether this balance is the team pool the caller spends from."""
        return self.raw.get("payer_type") == "team"

    @property
    def remaining_label(self) -> str:
        """Name the remaining amount after whose money it is."""
        return "Team balance remaining" if self.payer_is_team else "Balance remaining"

    def member_limit_summary(self) -> str:
        """Return "<limit> (<spent> used)" for a capped team member, else ``""``.

        A member with a per-member limit can spend only that limit, however
        much is left in the team pool, so surfaces show it before the pool.
        """
        limit = safe_terminal_text(self.human_display("member_limit"))
        if not limit:
            return ""
        spent = safe_terminal_text(self.human_display("member_spent"))
        return f"{limit} ({spent} used)" if spent else limit

    def display_value(self, name: str) -> str:
        """Return the untouched server display string, when present."""
        return self.display.get(name, "")

    def human_display(self, name: str) -> str:
        """Prefer safe server display text, then exactly format money micros.

        This is a rendering accessor only: :attr:`raw` remains verbatim for
        cache and JSON consumers. A fallback is available solely for the
        documented money fields when currency and the paired integer micros
        value are both usable.
        """
        display = safe_terminal_text(self.display_value(name))
        if display:
            return display
        micros_field = {
            "remaining": "remaining_micros",
            "spent_this_period": "spent_this_period_micros",
            "allowance": "allowance_micros",
            "allowance_remaining": "allowance_remaining_micros",
            "topup_remaining": "topup_remaining_micros",
            "credit_remaining": "credit_remaining_micros",
            "member_limit": "member_limit_micros",
            "member_spent": "member_spent_micros",
        }.get(name)
        if micros_field is None:
            return ""
        value = self.raw.get(micros_field)
        if (
            name in {"remaining", "allowance_remaining"}
            and isinstance(value, int)
            and not isinstance(value, bool)
        ):
            value = max(0, value)
        return format_micros(value, self.currency)


@dataclass(frozen=True)
class AITopupPack:
    """A server-advertised top-up option; no prices are computed locally."""

    key: str
    label: str
    currency: str
    display_price: str = ""
    display_credit: str = ""
    raw: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, value: Any) -> Optional["AITopupPack"]:
        if not isinstance(value, Mapping):
            return None
        key = _string_or_empty(value.get("key"))
        label = _string_or_empty(value.get("label"))
        if not key or not label:
            return None
        display = value.get("display")
        display_price = ""
        if isinstance(display, Mapping):
            display_price = _string_or_empty(display.get("price"))
        if not display_price:
            display_price = _minor_price_display(
                value.get("price_minor"), _string_or_empty(value.get("currency")),
            )
        display_credit = ""
        if isinstance(display, Mapping):
            display_credit = _string_or_empty(display.get("credit"))
        if not display_credit:
            display_credit = format_micros(
                value.get("credit_micros"), _string_or_empty(value.get("currency")),
            )
        return cls(key=key, label=label,
                   currency=_currency_code(value.get("currency")),
                   display_price=display_price, display_credit=display_credit,
                   raw=dict(value))


def parse_topup_packs(value: Any) -> list[AITopupPack]:
    """Return unique, valid inventory entries in server order."""
    rows = value.get("packs") if isinstance(value, Mapping) else None
    if not isinstance(rows, list):
        return []
    packs: list[AITopupPack] = []
    keys: set[str] = set()
    for row in rows:
        pack = AITopupPack.from_dict(row)
        if pack is not None and pack.key not in keys:
            keys.add(pack.key)
            packs.append(pack)
    return packs


def _money_symbol(code: str) -> str:
    """Match the billing server's supported-currency symbol contract."""
    return {"GBP": "£", "USD": "$", "EUR": "€"}.get(code, f"{code} ")


def _format_money(amount: Decimal, currency: str, *, hide_zero_decimals: bool) -> str:
    """Format a local money fallback exactly; server display strings win."""
    code = _currency_code(currency)
    if not code:
        return ""
    symbol = _money_symbol(code)
    absolute = abs(amount)
    if Decimal(0) < absolute < Decimal("0.005"):
        # MoneyFormatter uses the comparison marker before the currency symbol.
        return f"< {symbol}0.01" if amount > 0 else f"{symbol}0.00"

    sign = "-" if amount < 0 else ""
    value = absolute.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    rounded = f"{value:,.2f}"
    if hide_zero_decimals and rounded.endswith(".00"):
        rounded = rounded[:-3]
    return f"{sign}{symbol}{rounded}"


def _minor_price_display(value: Any, currency: str) -> str:
    """Render an exact minor-unit price without using a float."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return ""
    code = _currency_code(currency)
    if not code:
        return ""
    try:
        amount = Decimal(value) / Decimal(100)
    except (InvalidOperation, ValueError):
        return ""
    return _format_money(amount, code, hide_zero_decimals=True)


def format_micros(value: Any, currency: str) -> str:
    """Render an exact micro-unit fallback without converting it to tokens."""
    code = _currency_code(currency)
    if isinstance(value, bool) or not isinstance(value, int) or not code:
        return ""
    return _format_money(
        Decimal(value) / Decimal(1_000_000), code, hide_zero_decimals=False,
    )


def display_debit(value: Any, currency: str, server_display: Any = None) -> str:
    """Use an additive server debit display, or the exact local fallback."""
    if isinstance(server_display, str) and server_display:
        return server_display
    return format_micros(value, currency)


def cache_hosted_balance(
    auth_service: Any,
    balance: Any,
    debit_micros: Any,
) -> bool:
    """Cache valid hosted accounting from either buffered or SSE responses.

    The balance is copied verbatim; money is never derived from legacy tokens.
    ``last_debit_micros`` is client cache metadata, not an entitlement field.
    """
    token = getattr(auth_service, "_token", None)
    if token is None:
        return False
    current = getattr(token, "entitlements", None)
    if not isinstance(current, dict):
        current = {}
    updated = dict(current)
    changed = False
    if isinstance(balance, Mapping):
        updated["balance"] = dict(balance)
        changed = True
    if isinstance(debit_micros, int) and not isinstance(debit_micros, bool):
        updated["last_debit_micros"] = debit_micros
        changed = True
    if changed:
        token.entitlements = updated
    return changed
