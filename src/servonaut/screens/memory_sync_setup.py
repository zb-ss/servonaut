"""MemorySyncSetupScreen — central entry point for Memory Sync.

The single discovery + setup hub for the Memory Sync feature. Visible to
ALL users from the sidebar; the body adapts to the user's auth + tier +
configured state so a Free user gets a friendly explainer (not a modal),
a Solo user gets a "Set up" button, and a configured user gets a status
dashboard with rotate / disable actions.

Visual language matches the IP Ban screen — rounded `$primary` cards on a
`$surface` background, `bold cyan` title, `text-muted` subtitle. The
primary CTA card uses `$accent` for emphasis.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


# Plan slugs that unlock the basic Memory Sync entitlement.
_BENEFITS_SOLO = [
    ("✓", "$success", "Encrypted backup of every server's memory"),
    ("✓", "$success", "Drift detection across re-probes"),
    ("✓", "$success", "Up to 100 instances, 30-day history"),
    ("·", "$text-muted", "Team sharing, AI summaries, and signed exports — Teams plan"),
]
_BENEFITS_TEAM = [
    ("✓", "$success", "Encrypted backup of every server's memory"),
    ("✓", "$success", "Drift detection across re-probes"),
    ("✓", "$success", "Up to 500 instances per seat, 180-day history"),
    ("✓", "$success", "Share encrypted memory with team-mates"),
    ("✓", "$success", "AI-generated summaries with consent gating"),
    ("✓", "$success", "Signed compliance export tarball"),
]
_BENEFITS_FREE = [
    ("·", "$text-muted", "Encrypted backup of every server's memory"),
    ("·", "$text-muted", "Drift detection across re-probes"),
    ("·", "$text-muted", "AI-queryable fact cache shared across devices"),
]


class MemorySyncSetupScreen(Screen):
    """Setup + status hub for the Memory Sync feature."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("[bold cyan]Memory Sync[/bold cyan]", id="msync_title"),
                Static(
                    "[dim]Encrypted, AI-queryable backup of every server's "
                    "memory across your devices.[/dim]",
                    id="msync_subtitle",
                ),
                # Status pill — set in on_mount based on state
                Static("", id="msync_status"),
                # The body card swaps between explain / setup / locked / ready
                VerticalScroll(id="msync_body"),
                id="msync_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._render_state()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._render_state()

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def _render_state(self) -> None:
        body = self.query_one("#msync_body", VerticalScroll)
        body.remove_children()

        auth = getattr(self.app, "auth_service", None)
        sync = getattr(self.app, "memory_sync_service", None)

        # 1. Not authenticated
        if auth is None or not auth.is_authenticated:
            self._set_status("⚪ Sign in required", "$text-muted")
            body.mount(self._build_logged_out_card())
            return

        # 2. Free tier (no memory_sync entitlement)
        if not auth.has_feature("memory_sync"):
            self._set_status("⚪ Available with Solo plan", "$text-muted")
            body.mount(self._build_upsell_card(auth))
            return

        # 3. Solo+ — figure out configured state
        configured = sync is not None and getattr(sync, "is_configured", False)
        if configured:
            self._set_status("● Active", "$success")
            body.mount(self._build_status_card(auth, sync))
        else:
            self._set_status("⚪ Not set up yet", "$warning")
            body.mount(self._build_setup_card(auth))

    def _set_status(self, text: str, color: str) -> None:
        widget = self.query_one("#msync_status", Static)
        widget.update(f"[{color}]{escape(text)}[/{color}]")

    # ------------------------------------------------------------------
    # Card builders
    # ------------------------------------------------------------------

    def _build_logged_out_card(self) -> Container:
        return Container(
            Static("[bold]Sign in to enable Memory Sync[/bold]", classes="msync_card_title"),
            Static(
                "Memory Sync needs your servonaut.dev account to encrypt and "
                "store your memory snapshots. Free, Solo, and Teams plans all "
                "support keypair enrolment — only the cloud features are tier-gated.",
                classes="msync_card_body",
            ),
            Horizontal(
                Button("Open Login →", variant="primary", id="msync_btn_login"),
                classes="msync_card_actions",
            ),
            classes="msync_card msync_card_primary",
        )

    def _build_upsell_card(self, auth: Any) -> Container:
        plan = (auth._token.plan if getattr(auth, "_token", None) else "free") or "free"
        return Container(
            Container(
                Static(
                    "[bold]What is Memory Sync?[/bold]",
                    classes="msync_card_title",
                ),
                Static(
                    "An encrypted snapshot of every server's runtime profile — "
                    "OS, services, web stack, recent log paths, annotations — "
                    "kept in sync across the devices where you run Servonaut. "
                    "Designed so chat panels and AI agents can answer "
                    "\"what's running on X?\" instantly without an SSH "
                    "round-trip, with end-to-end encryption so even we "
                    "can't read your data.",
                    classes="msync_card_body",
                ),
                self._build_benefits_list(_BENEFITS_FREE),
                classes="msync_card",
            ),
            Container(
                Static("[bold]Available on Solo plan[/bold]", classes="msync_card_title"),
                Static(
                    f"You're on the [bold]{escape(plan)}[/bold] plan. Upgrade to "
                    "Solo ($9/mo) to enable Memory Sync, drift detection, and "
                    "100-instance encrypted backup. Teams ($29/seat) adds team "
                    "sharing, AI summaries, and compliance export.",
                    classes="msync_card_body",
                ),
                Horizontal(
                    Button("Open Billing →", variant="primary", id="msync_btn_billing"),
                    Button("Compare plans", id="msync_btn_compare"),
                    classes="msync_card_actions",
                ),
                classes="msync_card msync_card_primary",
            ),
            classes="msync_card_stack",
        )

    def _build_setup_card(self, auth: Any) -> Container:
        plan = (auth._token.plan if getattr(auth, "_token", None) else "solo") or "solo"
        benefits = _BENEFITS_TEAM if auth.has_feature("memory_team_share") else _BENEFITS_SOLO
        return Container(
            Container(
                Static("[bold]Locked[/bold]", classes="msync_card_title"),
                Static(
                    f"Your [bold]{escape(plan)}[/bold] plan includes Memory Sync. "
                    "Enter your passphrase to unlock the encrypted store on "
                    "this device. First time? You'll be asked to create a "
                    "passphrase — Servonaut wraps your private key with it "
                    "locally, so even we can't read your data. Same passphrase "
                    "unlocks the store on every subsequent launch.",
                    classes="msync_card_body",
                ),
                self._build_benefits_list(benefits),
                Horizontal(
                    Button(
                        "Unlock Memory Sync",
                        variant="primary",
                        id="msync_btn_setup",
                    ),
                    Button("Learn more", id="msync_btn_learn"),
                    classes="msync_card_actions",
                ),
                classes="msync_card msync_card_primary",
            ),
            Container(
                Static("[bold]Heads-up[/bold]", classes="msync_card_title"),
                Static(
                    "Your passphrase wraps the key locally — we never see it. "
                    "If you lose it, your synced data cannot be recovered "
                    "(you'd need to enrol a fresh keypair and re-probe).",
                    classes="msync_card_body msync_card_warning",
                ),
                classes="msync_card",
            ),
            classes="msync_card_stack",
        )

    def _build_status_card(self, auth: Any, sync: Any) -> Container:
        status = getattr(sync, "status", None)
        last_sync = "—"
        used = "—"
        soft_cap = "—"
        pending = 0
        if status is not None:
            last_sync = getattr(status, "last_sync_at", None) or "never"
            quota = getattr(status, "quota", None)
            if quota is not None:
                used = f"{getattr(quota, 'envelopes_used', '?'):,}"
                soft_cap = f"{getattr(quota, 'envelopes_soft_cap', '?'):,}"
            pending = getattr(status, "pending_envelopes", 0)

        fingerprint = "—"
        material = sync.get_key_material() if sync is not None else None
        if material is not None and getattr(material, "public_key", None):
            try:
                from servonaut.services.memory.crypto import fingerprint as fp_func
                fingerprint = fp_func(material.public_key)[:24] + "…"
            except Exception:
                fingerprint = "loaded"

        return Container(
            Container(
                Static("[bold]Status[/bold]", classes="msync_card_title"),
                Vertical(
                    self._kv_row("Last sync", str(last_sync)),
                    self._kv_row("Quota used", f"{used} / {soft_cap} envelopes"),
                    self._kv_row("Pending", f"{pending} envelope(s)"),
                    self._kv_row("Key fingerprint", fingerprint),
                    classes="msync_kv_grid",
                ),
                classes="msync_card msync_card_primary",
            ),
            Container(
                Static("[bold]Actions[/bold]", classes="msync_card_title"),
                Horizontal(
                    Button("Sync now", variant="primary", id="msync_btn_sync_now"),
                    Button("Rotate keypair", id="msync_btn_rotate"),
                    Button("Disable sync", variant="warning", id="msync_btn_disable"),
                    classes="msync_card_actions",
                ),
                Static(
                    "[dim]Disabling stops the background sync loop on this "
                    "device but leaves your encrypted data intact on the "
                    "server. Re-enrol any time to resume.[/dim]",
                    classes="msync_card_body",
                ),
                classes="msync_card",
            ),
            classes="msync_card_stack",
        )

    def _build_benefits_list(self, items: list) -> Container:
        rows = []
        for marker, color, text in items:
            rows.append(
                Static(
                    f"  [{color}]{escape(marker)}[/{color}] {escape(text)}",
                    classes="msync_benefit_row",
                )
            )
        return Container(*rows, classes="msync_benefits")

    def _kv_row(self, label: str, value: str) -> Horizontal:
        return Horizontal(
            Static(f"[dim]{escape(label)}[/dim]", classes="msync_kv_label"),
            Static(escape(value), classes="msync_kv_value"),
            classes="msync_kv_row",
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "msync_btn_login":
            from servonaut.screens.login import LoginScreen
            self.app.switch_screen(LoginScreen(return_to="memory_sync"))
        elif bid == "msync_btn_billing":
            self._open_url("https://servonaut.dev/billing")
        elif bid == "msync_btn_compare":
            self._open_url("https://servonaut.dev/pricing")
        elif bid == "msync_btn_learn":
            self._open_url("https://servonaut.dev/docs/memory-sync")
        elif bid == "msync_btn_setup":
            self.run_worker(
                self._do_setup(),
                group="memory_sync",
                name="msync_setup",
                exclusive=True,
            )
        elif bid == "msync_btn_sync_now":
            self.run_worker(
                self._do_sync_now(),
                group="memory_sync",
                name="msync_sync_now",
                exclusive=True,
            )
        elif bid == "msync_btn_rotate":
            self.run_worker(
                self._do_rotate(),
                group="memory_sync",
                name="msync_rotate",
                exclusive=True,
            )
        elif bid == "msync_btn_disable":
            self._do_disable()

    @staticmethod
    def _open_url(url: str) -> None:
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception as exc:
            logger.warning("Could not open browser: %s", exc)

    async def _do_setup(self) -> None:
        sync = getattr(self.app, "memory_sync_service", None)
        if sync is None:
            self.app.notify("Memory sync service not available.", severity="error")
            return
        self._set_busy("Setting up Memory Sync — fetching settings, enrolling key…")
        try:
            await self.app.bootstrap_memory_cloud()
        except Exception as exc:
            self._clear_busy()
            self._show_setup_error(exc)
            return
        self._clear_busy()
        if sync.is_configured:
            self.app.notify("Memory Sync is now active.", severity="information")
        else:
            self.app.notify(
                "Setup did not complete — try again from the Unlock button.",
                severity="warning",
            )
        self._render_state()

    def _show_setup_error(self, exc: Exception) -> None:
        """Translate the raised exception into a clear, user-facing notify.

        Wrong passphrase shows up as ``DecryptionFailedError`` from the crypto
        layer; tier/maintenance issues come through as typed memory exceptions
        so we can give a routing hint instead of a stack trace dump.
        """
        msg = str(exc) or exc.__class__.__name__
        kind = exc.__class__.__name__
        # Rate-limit detection — covers both api_client.RateLimitedError (HTTP 429)
        # and the memory-domain RateLimited wrapper. Either way the user needs
        # to wait, not retry immediately. Spec §6 caps key endpoints at 3/hour
        # so test-drive iterations burn through the quota fast.
        is_rate_limited = (
            kind in {"RateLimitedError", "RateLimited", "RateLimitTimeoutError"}
            or "rate limit" in msg.lower()
        )
        if is_rate_limited:
            endpoint = getattr(exc, "endpoint", None)
            retry_s = getattr(exc, "retry_after_s", None)
            if endpoint and "keys/me" in str(endpoint):
                label = (
                    "Server rate limit hit on /keys/me (3 attempts per hour). "
                    "Wait ~20 minutes and try again."
                )
            elif retry_s:
                wait_min = max(1, int(retry_s) // 60)
                label = f"Server rate limit hit. Try again in ~{wait_min} min."
            else:
                label = (
                    "Server rate limit hit. Try again in a few minutes "
                    "(spec caps key endpoints at 3 setup attempts per hour)."
                )
        elif kind == "DecryptionFailedError" or "decryption failed" in msg.lower():
            label = "Wrong passphrase — try again."
        elif kind == "BackendMaintenance":
            label = "Memory backend is in maintenance — try again later."
        elif kind == "BetaWaitlist":
            label = "Memory Sync is in beta — your account is not on the allowlist yet."
        elif kind == "UpsellRequired":
            label = "Your plan doesn't include Memory Sync — upgrade to enable."
        elif kind == "WeakPassphraseError":
            label = "Passphrase is too weak — pick a stronger one."
        elif kind == "RuntimeError" and "cancelled" in msg.lower():
            label = "Setup cancelled."
        else:
            label = f"Setup failed: {msg}"
        self.app.notify(label, severity="error", timeout=8)
        try:
            self.query_one("#msync_status", Static).update(
                f"[$error]✗ {escape(label)}[/$error]"
            )
        except Exception:
            pass

    def _set_busy(self, message: str) -> None:
        """Disable primary actions and show a busy indicator."""
        try:
            self.query_one("#msync_status", Static).update(
                f"[$accent]⏳ {escape(message)}[/$accent]"
            )
        except Exception:
            pass
        for btn_id in (
            "msync_btn_setup",
            "msync_btn_sync_now",
            "msync_btn_rotate",
            "msync_btn_disable",
        ):
            try:
                self.query_one(f"#{btn_id}", Button).disabled = True
            except Exception:
                pass

    def _clear_busy(self) -> None:
        for btn_id in (
            "msync_btn_setup",
            "msync_btn_sync_now",
            "msync_btn_rotate",
            "msync_btn_disable",
        ):
            try:
                self.query_one(f"#{btn_id}", Button).disabled = False
            except Exception:
                pass

    # Cap drain iterations so a runaway producer can't loop us forever.
    # 200 batches × 50 envelopes = 10k envelopes per click — well over a
    # full-fleet sweep (47 instances × ~12 modules = ~564 envelopes).
    _MAX_DRAIN_BATCHES = 200

    async def _do_sync_now(self) -> None:
        sync = getattr(self.app, "memory_sync_service", None)
        if sync is None or not sync.is_configured:
            return
        # Bridge: enqueue every locally-cached module that was probed
        # before keypair enrollment (queue would otherwise be empty).
        pending_before = getattr(sync.status, "pending_envelopes", 0)
        self._set_busy("Scanning local memory cache…")
        try:
            queued = sync.backfill_from_local_store()
        except Exception as exc:
            self._clear_busy()
            self.app.notify(
                f"Backfill failed: {escape(str(exc))}", severity="error"
            )
            return
        work_queued = pending_before + queued
        if work_queued:
            self._set_busy(
                f"Encrypting and uploading {work_queued} envelope(s)…"
            )
        else:
            self._set_busy("Draining sync queue…")
        total_accepted = 0
        total_rejected = 0
        try:
            for _ in range(self._MAX_DRAIN_BATCHES):
                result = await sync.drain_now()
                batch_accepted = len(getattr(result, "accepted", []) or [])
                batch_rejected = len(getattr(result, "rejected", []) or [])
                total_accepted += batch_accepted
                total_rejected += batch_rejected
                # Empty result == queue drained or service halted/errored.
                # drain_now re-queues on APIError/RateLimit/etc and returns
                # empty, so we can't distinguish "done" from "stuck" without
                # also checking the status afterwards.
                if batch_accepted == 0 and batch_rejected == 0:
                    break
        except Exception as exc:
            self._clear_busy()
            self.app.notify(f"Sync failed: {escape(str(exc))}", severity="error")
            return
        self._clear_busy()
        # Re-read status after the loop so the message reflects ground truth,
        # not just what drain_now returned. APIError re-queues silently and
        # returns 0/0, so the queue can stay non-empty even when our totals
        # look like "nothing happened".
        status_after = sync.status
        pending_after = getattr(status_after, "pending_envelopes", 0)
        last_error = getattr(status_after, "last_error", None)
        halted_reason = getattr(status_after, "halted_reason", None)

        if total_accepted > 0 and total_rejected == 0:
            self.app.notify(
                f"Synced {total_accepted} envelope(s).",
                severity="information",
            )
        elif total_accepted > 0:
            self.app.notify(
                f"Synced {total_accepted} envelope(s); "
                f"{total_rejected} rejected — see logs.",
                severity="warning",
            )
        elif pending_after > 0:
            # Had work, drained nothing — surface the real cause.
            reason = halted_reason or last_error or "unknown error (see logs)"
            self.app.notify(
                f"{pending_after} envelope(s) queued but none uploaded — "
                f"sync halted: {escape(str(reason))}",
                severity="error",
                timeout=10,
            )
        else:
            self.app.notify(
                "Nothing to sync — local memory cache is empty. Probe a "
                "server first from the Fleet Memory screen.",
                severity="information",
            )

        # Best-effort annotations pull: fetch the latest annotations envelope
        # from the server for every locally-known instance and write it back
        # to disk when the server copy is newer. Never raises; per-instance
        # errors are swallowed so a single unreachable instance can't stall
        # the overall sync UX.
        updated = 0
        findings_updated = 0
        mem = self.app.memory_service
        sync = self.app.memory_sync_service
        if mem is not None and sync is not None:
            for entry in mem.list_all():
                iid = entry.get("instance_id")
                if not iid:
                    continue
                name = entry.get("name", "")
                provider = entry.get("provider", "custom")
                try:
                    if await sync.pull_annotations(iid, name, provider) == "updated":
                        updated += 1
                except Exception:
                    pass  # pull is best-effort; never break the sync UX
                try:
                    if await sync.pull_findings(iid, name, provider) == "updated":
                        findings_updated += 1
                except Exception:
                    pass

        if updated or findings_updated:
            parts = []
            if updated:
                parts.append(f"{updated} annotation(s)")
            if findings_updated:
                parts.append(f"{findings_updated} finding(s)")
            self.app.notify(
                f"{' and '.join(parts)} updated from sync.",
                severity="information",
                markup=False,
            )

        self._render_state()

    async def _do_rotate(self) -> None:
        sync = getattr(self.app, "memory_sync_service", None)
        if sync is None or not sync.is_configured:
            return
        from servonaut.screens.memory_keys import PassphraseEnrolModal
        old_pp = await self.app.push_screen_wait(PassphraseEnrolModal(mode="unlock"))
        if not old_pp:
            return
        new_pp = await self.app.push_screen_wait(PassphraseEnrolModal(mode="enrol"))
        if not new_pp:
            return
        self._set_busy("Rotating keypair — this re-derives the wrap (~1s)…")
        try:
            await sync.rotate_keypair(old_pp, new_pp)
        except Exception as exc:
            self._clear_busy()
            self._show_setup_error(exc)
            return
        self._clear_busy()
        self.app.notify("Keypair rotated.", severity="information")
        self._render_state()

    def _do_disable(self) -> None:
        sync = getattr(self.app, "memory_sync_service", None)
        if sync is None:
            return
        try:
            sync.stop()
        except Exception as exc:
            logger.warning("sync.stop failed: %s", exc)
        # Drop the in-memory keypair so the service flips back to "not configured".
        # The encrypted data on the server is untouched — re-enrol any time.
        try:
            sync._self_pubkey = None  # type: ignore[attr-defined]
            sync._self_privkey = None  # type: ignore[attr-defined]
        except Exception:
            pass
        self.app.notify("Memory Sync disabled on this device.")
        self._render_state()
