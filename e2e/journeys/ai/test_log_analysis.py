"""Journey: fetch a server's log and have your AI provider analyse it.

``a`` on a fleet row opens AI Log Analysis for that server. Fetch Logs
probes which log files are readable over (fake) SSH, the picker offers
them, and the chosen file's tail is loaded into the editor. F5 sends it to
the configured provider (the local OpenAI stand-in); a log larger than the
chunk size goes in overlapping chunks, one request each, and the answers
are shown together with the token count, model and cost estimate.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.ai_chat import plain, seed_byo, web_1_server
from e2e.harness.fake_ai import failure, reply
from e2e.harness.known_gap import KnownGap

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WEB_1 = fleet.WEB_1
LOG_PATH = "/var/log/app.log"
# A neutral application log: private addresses and a public resolver only.
LOG_LINES = [
    f"2030-01-01T10:{minute:02d}:00Z app[311]: upstream 10.0.1.{minute % 7 + 20}:8080 "
    f"{'timed out after 30s' if minute % 3 == 0 else 'responded 200 in 41ms'}"
    for minute in range(18)
] + ["2030-01-01T10:18:00Z app[311]: resolver 9.9.9.9 answered in 12ms"]
LOG = "\n".join(LOG_LINES) + "\n"
CHUNK_SIZE = 900


def _seed(seed, fake_cloud, fake_ai, journey):
    seed_byo(
        seed, fake_cloud, "openai", fake_ai.url, signed_in=False,
        custom_servers=[web_1_server()], ai_chunk_size=CHUNK_SIZE,
    )
    journey.shims.when("ssh", rf"tail -n 200 {LOG_PATH}$", stdout=LOG)
    journey.shims.when("ssh", r"test -r ", stdout=f"{LOG_PATH}\n")


async def _load_log(t) -> object:
    await t.wait_until(lambda: any(r[1] == WEB_1.name for r in t.table_rows("InstanceTable")))
    await t.select_instance(WEB_1.name)
    await t.press("a")
    screen = await t.wait_for_screen("AIAnalysisScreen")
    await t.click("#btn_fetch_logs")
    await t.wait_for_screen("LogPickerModal")
    await t.wait_until(lambda: t.focused_id() == "log_picker_search", desc="picker search")
    # Type to filter; Enter takes the first match.
    await t.type("app")
    await t.press("enter")
    await t.wait_for_screen("AIAnalysisScreen")
    status = screen.query_one("#ai_status")
    await t.wait_until(lambda: "Fetched" in plain(status), desc="the log fetched")
    return screen


async def test_fetch_a_log_and_analyse_it_in_chunks(tui, seed, fake_cloud, fake_ai, journey):
    _seed(seed, fake_cloud, fake_ai, journey)
    fake_ai.script(
        "openai",
        reply("Part one: upstream 10.0.1.x times out every third minute."),
        reply("Part two: DNS is healthy."),
    )
    async with tui() as t:
        screen = await _load_log(t)
        status = plain(screen.query_one("#ai_status"))
        assert status.startswith(f"Fetched {len(LOG_LINES)} lines from {LOG_PATH}.")
        assert screen.query_one("#ai_text_input").text == LOG.strip()
        assert "(2 chunks)" in plain(screen.query_one("#ai_token_estimate"))
        [probe, tail] = [c for c in journey.shims.calls("ssh") if "find " not in c.joined][:2]
        assert f"{WEB_1.username}@{WEB_1.host}" in tail.argv and str(WEB_1.port) in tail.argv

        await t.press("f5")
        output = screen.query_one("#ai_output")
        await t.wait_until(lambda: output.text, desc="the analysis")

        assert output.text == (
            "Part one: upstream 10.0.1.x times out every third minute."
            "\n\n---\n\nPart two: DNS is healthy."
        )
        assert "Analysis complete." in plain(screen.query_one("#ai_status"))
        cost = plain(screen.query_one("#ai_cost_info"))
        assert "Model: gpt-4o-mini" in cost and "Est. cost: $" in cost
        first, second = fake_ai.requests("openai")
        assert first["auth_ok"] and second["auth_ok"]
        prompts = [r["body"]["messages"][0]["content"] for r in (first, second)]
        assert prompts[0].endswith("[Analyzing chunk 1/2]")
        assert prompts[1].endswith("[Analyzing chunk 2/2]")
        sent = [r["body"]["messages"][1]["content"] for r in (first, second)]
        assert LOG_LINES[0] in sent[0] and LOG_LINES[-1] in sent[1]


async def test_a_provider_failure_is_reported_on_the_screen(
    tui, seed, fake_cloud, fake_ai, journey
):
    _seed(seed, fake_cloud, fake_ai, journey)
    fake_ai.script("openai", failure(401, "Incorrect API key provided"))
    async with tui() as t:
        screen = await _load_log(t)
        await t.press("f5")
        status = screen.query_one("#ai_status")
        await t.wait_until(lambda: "Error" in plain(status), desc="the error")
        assert plain(status) == "Error: OpenAI API error (401): Incorrect API key provided"
        assert screen.query_one("#ai_output").text == ""
        # The screen stays usable.
        assert not screen.query_one("#btn_analyze").disabled


@pytest.mark.xfail(
    strict=True,
    raises=KnownGap,
    reason="the provider line says the API key is not set when it is stored per provider",
)
async def test_provider_line_sees_the_configured_key(tui, seed, fake_cloud, fake_ai, journey):
    _seed(seed, fake_cloud, fake_ai, journey)
    async with tui() as t:
        await t.select_instance(WEB_1.name)
        await t.press("a")
        screen = await t.wait_for_screen("AIAnalysisScreen")
        info = plain(screen.query_one("#ai_provider_info"))
        assert "Provider: openai" in info
        if "API Key: not set" in info:
            raise KnownGap("the provider line says 'API Key: not set' for a configured key")
        assert "API Key: set" in info
