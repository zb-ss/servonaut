"""Journey: add, check and remove provider accounts from Settings.

A user with one account per provider adds a second one where they manage
the provider: a Hetzner Cloud project and an OVHcloud account through the
setup wizard, an AWS account from a profile in ``~/.aws/config``. Each new
account is tested against its own provider account before it is saved, its
servers join the fleet as ``label/name`` next to the first account's, and
removing it takes them out again. Labels that are malformed, reserved or
already used by any provider are refused before anything is sent. In demo
mode the panels show stand-ins for account labels and profiles, and on a
narrow terminal the account tables stay readable.
"""

from __future__ import annotations

from typing import Any, Iterable

import pytest

from e2e.harness import aws, fleet
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.fake_providers import ovh as fake_ovh
from e2e.journeys.tui.ovh_ui import plain, press, select_row

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

NARROW = (100, 30)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


async def _open_settings_panel(t: Any, panel_id: str) -> None:
    """Open Settings and the provider's panel, expanding its group if needed."""
    from servonaut.widgets.sidebar_section import SidebarSection

    await t.nav("nav_settings")
    await t.wait_for_screen("SettingsScreen")
    button = t.on_screen(f"#navbtn_{panel_id}")
    section = next(node for node in button.ancestors if isinstance(node, SidebarSection))
    if section.collapsed:
        await t.click(section.query_one("Button.section-header"))
        await t.wait_until(lambda: not section.collapsed, desc=f"{panel_id} group expanded")
    await press(t, button)
    await t.wait_until(
        lambda: t.on_screen(f"#panel_{panel_id}").display, desc=f"the {panel_id} panel"
    )


def _accounts(t: Any, provider: str) -> dict[str, list[str]]:
    """The provider's accounts table as {label: row}."""
    return {
        plain(row[0]): [plain(cell) for cell in row]
        for row in t.table_rows(f"#{provider}_accounts_table")
    }


async def _loaded_accounts(t: Any, provider: str) -> dict[str, list[str]]:
    """The accounts table once the panel has drawn its rows."""
    return await t.wait_until(lambda: _accounts(t, provider), desc=f"{provider} accounts")


async def _focus(t: Any, selector: str) -> Any:
    """Move the focus to *selector*, as tabbing to it would; it scrolls into view.

    The accounts section sits at the foot of its panel, where notifications
    stack up: a pointer click there can land on a toast instead.
    """
    widget = await t.wait_for_widget(selector)
    assert t.is_reachable(widget), f"{selector} is hidden"
    widget.focus()
    await t.wait_until(lambda: widget.has_focus, desc=f"focus on {selector}")
    # Focusing scrolls to where the widget was last laid out. A panel that has
    # only just been shown may not be laid out yet, so the scroll can fall
    # short: ask again until the screen really draws the widget.
    await t.wait_until(lambda: _drawn(widget), desc=f"{selector} scrolled into view")
    await t.settle(1)
    return widget


def _drawn(widget: Any) -> bool:
    """Whether *widget* is on screen; scrolls it into view again when not.

    A scroll that ran before the layout caught up is repeated on the next check.
    """
    if _on_screen(widget):
        return True
    widget.scroll_visible(animate=False)
    return False


def _on_screen(widget: Any) -> bool:
    """Whether the screen draws *widget* at its own top-left cell."""
    from textual.errors import NoWidget

    region = widget.region
    if not (region.height and region.width):
        return False
    try:
        hit, _ = widget.screen.get_widget_at(region.x, region.y)
    except NoWidget:
        return False
    return hit is widget or widget in hit.ancestors


async def _activate(t: Any, selector: str) -> None:
    """Press a button from the keyboard (focus it, then enter)."""
    await _focus(t, selector)
    await t.press("enter")


async def _type_into(t: Any, selector: str, text: str) -> None:
    """Focus an input from the keyboard, clear it and type *text*."""
    field = await _focus(t, selector)
    field.clear()
    await t.type(text)
    await t.wait_until(lambda: field.value == text, desc=f"{selector} == {text!r}")


async def _show_accounts(t: Any, provider: str) -> Any:
    """Bring the provider's accounts table into view with its rows drawn."""
    await _loaded_accounts(t, provider)
    return await _focus(t, f"#{provider}_accounts_table")


def _fleet_names(t: Any) -> set[str]:
    return {plain(row[1]) for row in t.table_rows("InstanceTable")}


async def _fleet(t: Any, *, contains: Iterable[str] = (), lacks: Iterable[str] = ()) -> set[str]:
    """Open the server list and wait until it shows *contains* and none of *lacks*."""
    wanted, unwanted = set(contains), set(lacks)
    await t.nav("nav_list")
    await t.wait_for_screen("InstanceListScreen")
    return await t.wait_until(
        lambda: (names := _fleet_names(t)) >= wanted and not names & unwanted and names,
        desc=f"fleet with {sorted(wanted)} and without {sorted(unwanted)}",
    )


async def _choose(t: Any, selector: str, prompt: str) -> None:
    """Pick the option labelled *prompt* in a dropdown, by keyboard."""
    from textual.widgets import OptionList, Select

    select = await _focus(t, selector)
    assert isinstance(select, Select)
    await t.press("enter")
    await t.wait_until(lambda: select.expanded, desc=f"{selector} open")
    overlay = select.query_one(OptionList)  # the list the dropdown opens

    def highlighted() -> str:
        index = overlay.highlighted
        return "" if index is None else str(overlay.get_option_at_index(index).prompt)

    for _ in range(overlay.option_count + 1):
        if highlighted() == prompt:
            break
        await t.press("down")
        await t.settle(1)
    assert highlighted() == prompt, f"{prompt!r} is not offered by {selector}"
    await t.press("enter")
    await t.wait_until(lambda: not select.expanded, desc=f"{selector} closed")


def _boot_config(seed: Any, **providers: Any) -> None:
    """Providers as given; a fresh AWS cache, so start-up never waits on AWS."""
    seed.config(**providers)
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)


# ---------------------------------------------------------------------------
# Hetzner: a project added from Settings, then removed
# ---------------------------------------------------------------------------


async def test_a_hetzner_project_joins_the_fleet_and_leaves_it(tui, seed, providers):
    fleet.seed_provider_fleet(providers, ovh=False)
    fleet.seed_second_accounts(providers, ovh=False)
    _boot_config(seed, hetzner=seed.hetzner_config())
    label = fleet.HETZNER_SECOND_ACCOUNT
    token = fake_hetzner.token_for(label)
    first_project = {host.name for host in fleet.HETZNER_FLEET} | {fleet.SHARED_NAME}

    async with tui() as t:
        # One project: plain names, as before.
        await t.wait_until(lambda: _fleet_names(t) >= first_project, desc="Hetzner servers")

        await _open_settings_panel(t, "hetzner")
        assert await _loaded_accounts(t, "hetzner") == {"hetzner": ["hetzner", "primary", "set"]}
        await _activate(t, "#btn_hetzner_account_add")
        await t.wait_for_screen("HetznerSetupScreen")

        # Refused before anything is sent: malformed, reserved, and labels
        # other accounts hold (any provider, any case).
        refusals = [
            ("bad label", "must start with a letter or digit"),
            ("custom", "is reserved"),
            ("Hetzner", "already used by Hetzner · hetzner"),
            ("OVH", "already used by OVH · ovh"),
        ]
        for refused, reason in refusals:
            await _type_into(t, "#hetzner_input_label", refused)
            await _type_into(t, "#hetzner_input_token", token)
            await _activate(t, "#btn_hetzner_save")
            await t.wait_for_toast(reason, severity="error")
            assert t.screen_name() == "HetznerSetupScreen"
        assert providers.requests("hetzner", account=label) == []

        # A token of another project is tested, refused, and not saved.
        await _type_into(t, "#hetzner_input_label", label)
        await _type_into(t, "#hetzner_input_token", "hz-token-of-nobody")
        await _activate(t, "#btn_hetzner_save")
        await t.wait_for_toast("The project was not saved: its token does not work", severity="error")
        assert seed.read_config()["hetzner"]["accounts"] == []

        # The project's own token: tested, saved, listed.
        await _type_into(t, "#hetzner_input_token", token)
        await _activate(t, "#btn_hetzner_save")
        await t.wait_for_toast(f"Hetzner project '{label}' saved")
        await t.wait_for_toast(f"Hetzner project '{label}': 2 server\\(s\\) loaded")
        await t.wait_for_screen("SettingsScreen")
        await t.wait_until(
            lambda: _accounts(t, "hetzner").get(label) == [label, "active", "set"],
            desc="the new project in the accounts table",
        )
        saved = seed.read_config()["hetzner"]["accounts"]
        assert [(a["label"], a["api_token"]) for a in saved] == [(label, token)]
        assert providers.requests("hetzner", account=label, method="GET", path="/servers")

        # Two projects: every Hetzner server is shown with its project.
        both = {f"hetzner/{name}" for name in first_project} | {
            f"{label}/{host.name}" for host in fleet.HETZNER_SECOND_FLEET
        }
        await _fleet(t, contains=both)

        # Removing the project asks first, then its servers leave the fleet.
        await _open_settings_panel(t, "hetzner")
        await _show_accounts(t, "hetzner")
        await select_row(t, "#hetzner_accounts_table", 0, label)
        await _activate(t, "#btn_hetzner_account_remove")
        await t.wait_for_screen("SimpleConfirmModal")
        await press(t, "#confirm_yes_btn")
        await t.wait_for_toast(f"Removed Hetzner project '{label}'")
        await t.wait_until(lambda: label not in _accounts(t, "hetzner"), desc="project removed")
        assert seed.read_config()["hetzner"]["accounts"] == []
        await _fleet(t, contains=first_project, lacks={f"{label}/{fleet.SHARED_NAME}"})
        assert not any(name.startswith(f"{label}/") for name in _fleet_names(t))

    assert providers.mutations("hetzner") == []


# ---------------------------------------------------------------------------
# OVH: a second account through the setup wizard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("oauth2", [False, True], ids=["application-key", "oauth2"])
async def test_a_second_ovh_account_is_added_with_the_setup_wizard(tui, seed, providers, oauth2):
    fleet.seed_provider_fleet(providers, hetzner=False)
    _, second = fleet.seed_second_accounts(providers, hetzner=False, ovh_endpoint="ovh-ca")
    _boot_config(seed, ovh=seed.ovh_config())
    label = fleet.OVH_SECOND_ACCOUNT
    keys = fake_ovh.credentials_for(label)

    async with tui() as t:
        await t.wait_until(lambda: fleet.SHARED_NAME in _fleet_names(t), desc="OVH servers")
        await _open_settings_panel(t, "ovh")
        assert (await _loaded_accounts(t, "ovh"))["ovh"][:3] == ["ovh", "primary", "ovh-eu"]
        await _activate(t, "#btn_ovh_account_add")
        await t.wait_for_screen("OVHSetupScreen")

        await _type_into(t, "#ovh_input_label", label)
        await _type_into(t, "#ovh_input_endpoint", "ovh-ca")
        await _type_into(t, "#ovh_input_project_ids", fleet.OVH_SECOND_PROJECT_ID)
        if oauth2:
            await _choose(t, "#ovh_select_auth", "OAuth2 service account")
            await t.wait_until(
                lambda: not t.on_screen("#btn_ovh_request_ck").display,
                desc="application-key fields hidden",
            )
            await _type_into(t, "#ovh_input_client_id", keys.client_id)
            await _type_into(t, "#ovh_input_client_secret", keys.client_secret)
        else:
            await _type_into(t, "#ovh_input_app_key", keys.application_key)
            await _type_into(t, "#ovh_input_app_secret", keys.application_secret)
            await _type_into(t, "#ovh_input_consumer_key", keys.consumer_key)
        await _activate(t, "#btn_ovh_save")

        await t.wait_for_toast(f"OVH connected as: {second.nic_handle}")
        await t.wait_for_toast(f"OVH account '{label}' saved")
        await t.wait_for_toast(f"OVH account '{label}': 2 instance\\(s\\) loaded")
        await t.wait_for_screen("SettingsScreen")
        auth = "OAuth2" if oauth2 else "application key"
        await t.wait_until(
            lambda: _accounts(t, "ovh").get(label) == [label, "active", "ovh-ca", auth, "1"],
            desc="the new account in the accounts table",
        )

        (account,) = seed.read_config()["ovh"]["accounts"]
        assert (account["label"], account["endpoint"]) == (label, "ovh-ca")
        assert account["cloud_project_ids"] == [fleet.OVH_SECOND_PROJECT_ID]
        if oauth2:
            assert (account["client_id"], account["application_key"]) == (keys.client_id, "")
        else:
            assert (account["application_key"], account["client_id"]) == (keys.application_key, "")
        calls = providers.requests("ovh", account=label)
        assert calls and {call["endpoint"] for call in calls} == {"ovh-ca"}

        await _fleet(
            t,
            contains={
                f"ovh/{fleet.SHARED_NAME}",
                f"{label}/{fleet.SHARED_NAME}",
                f"{label}/{fleet.OVH_SECOND_BATCH_3.name}",
            },
        )

    # Nothing at OVH changed (an OAuth2 client fetches its access token by POST).
    changes = [
        call for call in providers.mutations("ovh")
        if call["api_path"] != fake_ovh.OVH_OAUTH2_TOKEN_PATH
    ]
    assert changes == []


# ---------------------------------------------------------------------------
# AWS: an account added from a profile in ~/.aws/config
# ---------------------------------------------------------------------------


async def test_an_aws_account_is_added_from_a_detected_profile(tui, seed, moto):
    label = fleet.AWS_SECOND_ACCOUNT
    moto.seed_fleet([fleet.APP_1, fleet.AWS_WEB_1])
    role_arn = moto.seed_account(aws.SECOND_ACCOUNT, fleet.AWS_SECOND_FLEET)
    seed.aws_profile("base")
    seed.aws_profile(label, role_arn=role_arn, source_profile="base")
    seed.config(aws=seed.aws_config(regions=["us-east-1"]))
    seed.cache(fleet.cache_rows(fleet.APP_1, fleet.AWS_WEB_1), fresh=True)

    async with tui() as t:
        await t.wait_until(lambda: fleet.SHARED_NAME in _fleet_names(t), desc="AWS servers")
        await _open_settings_panel(t, "aws")
        await _show_accounts(t, "aws")
        assert _accounts(t, "aws") == {
            "aws": ["aws", "primary", "default credentials", "us-east-1"]
        }

        await _activate(t, "#btn_aws_account_add_profile")
        await t.wait_until(
            lambda: t.on_screen("#aws_account_form").display, desc="the account form"
        )
        await _choose(t, "#aws_account_detected", label)
        # The profile's name becomes the suggested label.
        assert t.on_screen("#aws_account_profile").value == label
        assert t.on_screen("#aws_account_label").value == label
        await _type_into(t, "#aws_account_regions", "us-east-1")
        await _activate(t, "#btn_aws_account_save")

        await t.wait_for_toast(f"Saved AWS account '{label}'")
        await t.wait_for_toast(r"^AWS: \d+ server\(s\) from 2 accounts\.$")
        await t.wait_until(
            lambda: _accounts(t, "aws").get(label) == [label, "active", label, "us-east-1"],
            desc="the new account in the accounts table",
        )
        (account,) = seed.read_config()["aws"]["accounts"]
        assert (account["label"], account["profile"], account["regions"]) == (
            label, label, ["us-east-1"],
        )

        await _fleet(
            t,
            contains={
                f"aws/{fleet.APP_1.name}",
                f"aws/{fleet.SHARED_NAME}",
                f"{label}/{fleet.SHARED_NAME}",
                f"{label}/{fleet.AWS_SECOND_JOBS_1.name}",
            },
        )

    assert set(moto.describe_names(role_arn=role_arn)) == {h.name for h in fleet.AWS_SECOND_FLEET}


# ---------------------------------------------------------------------------
# Demo mode and a narrow terminal
# ---------------------------------------------------------------------------

# Labels and a profile that name somebody, unlike "prod" or "staging": demo
# mode must not show them. The fake accounts behind them are the harness's
# second accounts.
HETZNER_LABEL = "northwind"
OVH_LABEL = "contoso"
AWS_LABEL = "fabrikam"
AWS_PROFILE = "fabrikam-admin"


def _seed_named_accounts(seed: Any, providers: Any, moto: Any) -> None:
    fleet.seed_provider_fleet(providers)
    fleet.seed_second_accounts(providers)
    role_arn = moto.seed_account(aws.SECOND_ACCOUNT, fleet.AWS_SECOND_FLEET)
    seed.aws_profile("base")
    seed.aws_profile(AWS_PROFILE, role_arn=role_arn, source_profile="base")
    hetzner_token = fake_hetzner.token_for(fleet.HETZNER_SECOND_ACCOUNT)
    ovh_account = seed.ovh_account(fleet.OVH_SECOND_ACCOUNT)
    ovh_account.label = OVH_LABEL
    _boot_config(
        seed,
        aws=seed.aws_config(
            regions=["us-east-1"],
            accounts=[seed.aws_account(AWS_LABEL, AWS_PROFILE, regions=["us-east-1"])],
        ),
        hetzner=seed.hetzner_config(
            accounts=[seed.hetzner_account(HETZNER_LABEL, api_token=hetzner_token)]
        ),
        ovh=seed.ovh_config(accounts=[ovh_account]),
    )
    # Both AWS accounts start from a fresh cache: nothing waits on AWS.
    seed.cache(fleet.cache_rows(*fleet.AWS_SECOND_FLEET), fresh=True, account=AWS_LABEL)


PANELS = {"aws": AWS_LABEL, "hetzner": HETZNER_LABEL, "ovh": OVH_LABEL}


async def test_demo_mode_hides_account_labels_and_profiles(tui, seed, providers, moto, monkeypatch):
    from servonaut.app import ServonautApp

    _seed_named_accounts(seed, providers, moto)
    # What `--demo` sets before the app starts.
    monkeypatch.setattr(ServonautApp, "demo_mode", True)
    hidden = (HETZNER_LABEL, OVH_LABEL, AWS_LABEL, AWS_PROFILE)

    async with tui() as t:
        await t.wait_for_text("DEMO")
        redaction = t.app.redaction_service
        for provider, label in PANELS.items():
            await _open_settings_panel(t, provider)
            await _show_accounts(t, provider)
            stand_in = redaction.redact_account_label(label)
            assert stand_in != label
            shown = await t.wait_for_text(stand_in, "active")
            leaked = [name for name in hidden if name in shown]
            assert not leaked, f"{provider} panel shows {leaked} in demo mode"
            # The forms would show the real names: refused in demo mode.
            await select_row(t, f"#{provider}_accounts_table", 0, stand_in)
            await _activate(t, f"#btn_{provider}_account_edit")
            await t.wait_for_toast("disabled in demo mode", severity="warning")
            assert t.screen_name() == "SettingsScreen"

        # Switching demo mode off shows the real names again (so the check
        # above looked at text that does show them).
        await t.press("ctrl+shift+d")
        await t.wait_for_text(OVH_LABEL)
        await _open_settings_panel(t, "aws")
        await _show_accounts(t, "aws")
        await t.wait_for_text(AWS_LABEL, AWS_PROFILE)


async def test_account_tables_stay_readable_on_a_narrow_terminal(tui, seed, providers, moto):
    _seed_named_accounts(seed, providers, moto)

    async with tui(size=NARROW) as t:
        for provider, label in PANELS.items():
            await _open_settings_panel(t, provider)
            await _show_accounts(t, provider)
            # The label and its state are in view; the table scrolls sideways
            # for the rest.
            await t.wait_for_text(label, "active", "primary")
            # Every action is on screen, not cut off at the panel's edge.
            screen = t.app.screen.region
            for action in ("add", "edit", "remove"):
                button = await _focus(t, f"#btn_{provider}_account_{action}")
                await t.wait_until(
                    lambda: button.region.area and screen.contains_region(button.region),
                    desc=f"{provider} {action} button fully on screen",
                )
                await t.wait_for_text(str(button.label))


async def test_the_accounts_table_is_brought_into_view_after_a_short_scroll(
    tui, seed, providers, moto
):
    """A focus whose scroll fell short (the panel was not laid out yet) is caught up.

    Focusing without scrolling leaves the table where a stale layout would,
    below the fold; the step still brings it into view before reading it.
    """
    _seed_named_accounts(seed, providers, moto)

    async with tui() as t:
        await _open_settings_panel(t, "aws")
        await _loaded_accounts(t, "aws")
        table = t.on_screen("#aws_accounts_table")
        table.focus(scroll_visible=False)
        await t.settle(1)
        assert not _on_screen(table), "the accounts table should start below the fold"
        await _show_accounts(t, "aws")
        await t.wait_for_text(AWS_LABEL, "active")
