"""A bug report never carries the user's server inventory.

A GitHub draft becomes a public issue, so host names, IP addresses, logins,
instance and project ids stay out of it — from the config snapshot, the log
excerpt, the traceback and what the user typed — in and out of demo mode.
The preview is exactly what is sent.
"""
from __future__ import annotations

import dataclasses
import json
import urllib.parse
from pathlib import Path
from typing import List
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import (
    AppConfig,
    ConnectionProfile,
    CustomServer,
    DBProfile,
    IPBanConfig,
)
from servonaut.services.api_client import APIClient
from servonaut.services.bug_report_service import BugReportConsent, BugReportService

HOST = "files.acme-corp.example"
HOST_IP = "9.9.9.9"
LOGIN = "acmeops"
SERVER = "acme-files"
KEY = "~/.ssh/acme_files_key"
AWS_ID = "i-0acme00000000001"
AWS_NAME = "acme-app"
AWS_IP = "8.8.8.8"
PRIVATE_IP = "172.31.5.6"
OVH_PROJECT = "0acme000000000000000000000000001"
HETZNER_ID = "48151623"
BASTION = "bastion.acme-corp.example"
DB_HOST = "db.acme-corp.example"

INVENTORY = (
    HOST, HOST_IP, LOGIN, SERVER, "acme_files_key", AWS_ID, AWS_NAME, AWS_IP,
    PRIVATE_IP, OVH_PROJECT, HETZNER_ID, BASTION, DB_HOST, "acme_default_key",
    "acme-shop-waf", "customer_db",
)

INSTANCES = [
    {"id": AWS_ID, "name": AWS_NAME, "public_ip": AWS_IP, "private_ip": PRIVATE_IP,
     "provider": "aws", "key_name": "acme-deploy"},
    {"id": HETZNER_ID, "name": "acme-cache", "public_ip": "1.1.1.1",
     "provider": "hetzner", "is_hetzner": True},
    {"id": f"{OVH_PROJECT}/987654321", "name": "acme-batch",
     "provider": "ovh", "is_ovh": True},
    {"id": f"custom-{SERVER}", "name": SERVER, "public_ip": HOST, "host": HOST,
     "username": LOGIN, "ssh_key": KEY, "provider": "Acme Hosting", "is_custom": True},
]


def _config() -> AppConfig:
    config = AppConfig()
    config.default_key = "~/.ssh/acme_default_key"
    config.default_username = LOGIN
    config.instance_keys = {AWS_ID: "~/.ssh/acme_mapped_key"}
    config.custom_servers = [CustomServer(
        name=SERVER, host=HOST, username=LOGIN, ssh_key=KEY, provider="Acme Hosting",
        group="acme-prod", tags={"client": "acme"},
    )]
    config.connection_profiles = [ConnectionProfile(
        name="acme-bastion", bastion_host=BASTION, bastion_user=LOGIN,
    )]
    config.db_profiles = [DBProfile(
        instance=AWS_ID, host=DB_HOST, user="acme_dbuser", database="customer_db",
    )]
    config.ip_ban_configs = [IPBanConfig(
        name="acme-shop-waf", method="security_group", security_group_id="sg-0acme01",
    )]
    config.ovh.cloud_project_ids = [OVH_PROJECT]
    config.ai_provider.openai_api_key = "sk-e2e-not-a-real-key-000000000000"
    return config


def _service(tmp_path: Path, log_lines: List[str]) -> BugReportService:
    log = tmp_path / "servonaut.log"
    log.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    config_manager = MagicMock()
    config_manager.get.return_value = _config()
    update_service = MagicMock(current_version="2.27.0")
    update_service.detect_install_method.return_value = "pipx"
    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value={"id": "r-1", "url": "https://example.invalid/r-1"})
    return BugReportService(
        config_manager=config_manager,
        api_client=api,
        auth_service=MagicMock(access_token=None),
        update_service=update_service,
        log_path=log,
    )


LOG = [
    "2026-01-05 10:00:00 INFO servonaut.app: started",
    f"2026-01-05 10:00:01 INFO SSH connect (custom): host={HOST}, user={LOGIN}, key={KEY}",
    f"2026-01-05 10:00:02 ERROR probe {AWS_ID} ({AWS_NAME}) at {AWS_IP} failed",
    f"2026-01-05 10:00:03 ERROR OVH project {OVH_PROJECT}: server {HETZNER_ID} busy",
    "Traceback (most recent call last):",
    '  File "/home/acmeops/app.py", line 1, in <module>',  # leak-guard:allow fabricated path
    f"ConnectionError: {BASTION} refused from {PRIVATE_IP}",
]


def _consent(channel: str = "github") -> BugReportConsent:
    return BugReportConsent(
        include_logs=True, include_config=True, include_anonymous_telemetry=True,
        channel=channel,  # type: ignore[arg-type]
    )


def _leaks(text: str) -> List[str]:
    return [value for value in INVENTORY if value in text]


@pytest.mark.asyncio
async def test_github_draft_and_preview_carry_no_inventory(tmp_path: Path) -> None:
    svc = _service(tmp_path, LOG)
    payload = svc.collect_diagnostics(consent=_consent(), instances=INSTANCES)
    title = f"{AWS_NAME} crashes"
    description = f"Connecting to {SERVER} at {HOST} as {LOGIN} hangs; see docs https://example.org/x"
    preview = svc.render_preview(payload=payload, title=title, description=description)
    receipt = await svc.submit(
        payload=payload, consent=_consent(), title=title, description=description,
    )

    body = urllib.parse.parse_qs(urllib.parse.urlsplit(receipt.url).query)["body"][0]
    sent_title = urllib.parse.parse_qs(urllib.parse.urlsplit(receipt.url).query)["title"][0]
    assert _leaks(preview) == []
    assert _leaks(body) == []
    assert _leaks(sent_title) == []
    # What is sent is the preview (the log excerpt may be cut to fit a URL).
    assert body.startswith(preview.split("## Log excerpt")[0])
    # The report is still useful: structure, secrets markers and the note.
    assert "placeholders" in preview
    assert '"openai_api_key": "<removed:secret-key>"' in preview
    assert '"custom_servers": "<omitted: 1 entry>"' in preview
    assert "https://example.org/x" in preview, "links the user typed are kept"
    assert "ConnectionError:" in preview


@pytest.mark.asyncio
async def test_backend_report_carries_no_inventory(tmp_path: Path) -> None:
    svc = _service(tmp_path, LOG)
    consent = _consent(channel="backend")
    payload = svc.collect_diagnostics(consent=consent, instances=INSTANCES)
    await svc.submit(payload=payload, consent=consent, title=f"{SERVER} breaks",
                     description=f"on {HOST}")
    sent = json.dumps(svc._api_client.post.await_args.kwargs["json"])
    assert _leaks(sent) == []


def test_provider_counts_do_not_name_custom_providers(tmp_path: Path) -> None:
    svc = _service(tmp_path, LOG)
    payload = svc.collect_diagnostics(consent=_consent(), instances=INSTANCES)
    assert payload.instance_count_by_provider == {"aws": 1, "hetzner": 1, "ovh": 1, "custom": 1}


def test_unknown_hosts_and_addresses_are_scrubbed_by_shape(tmp_path: Path) -> None:
    svc = _service(tmp_path, [
        "ERROR fetch https://api.other-customer.example/v1?token=abc failed",
        "ERROR 8.8.4.4 and 2606:4700:4700::1111 unreachable, mail ops@example.org",
    ])
    payload = svc.collect_diagnostics(consent=_consent(), instances=[])
    for value in ("other-customer", "8.8.4.4", "2606:4700", "ops@example.org", "token=abc"):
        assert value not in payload.log_excerpt, value


def test_config_snapshot_keeps_structure_without_inventory(tmp_path: Path) -> None:
    snapshot = _service(tmp_path, LOG).collect_diagnostics(
        consent=_consent(), instances=INSTANCES,
    ).config_snapshot
    flat = json.dumps(snapshot)
    assert _leaks(flat) == []
    for section in ("instance_keys", "custom_servers", "connection_profiles",
                    "db_profiles", "ip_ban_configs"):
        assert snapshot[section] == "<omitted: 1 entry>", section
    assert snapshot["ovh"]["cloud_project_ids"] == "<omitted: 1 entry>"
    assert snapshot["cache_ttl_seconds"] == AppConfig().cache_ttl_seconds


def test_every_inventory_section_exists_in_the_config_schema() -> None:
    """A renamed config field must not silently drop out of the omit list."""
    from servonaut.services.report_scrubber import INVENTORY_SECTIONS, OMITTED_FIELDS

    snapshot = dataclasses.asdict(AppConfig())
    for path in INVENTORY_SECTIONS + OMITTED_FIELDS:
        node = snapshot
        for part in path.split("."):
            assert isinstance(node, dict) and part in node, path
            node = node[part]


def test_scrubber_leaves_ordinary_words_alone() -> None:
    from servonaut.services.report_scrubber import InventoryScrubber

    scrubber = InventoryScrubber.from_inventory(
        [{"id": "custom-web", "name": "web", "username": "root"}], None,
    )
    text = "web_traffic_summary ran; rootfs ok; webhooks fine"
    assert scrubber.scrub_text(text) == text


def _config_with_account_wiring() -> AppConfig:
    config = _config()
    config.ovh.client_id = "acme-oauth-client"
    config.gcp.credentials_path = "~/keys/acme-prod-sa.json"
    config.aws.control_plane_role_arn = "arn:aws:iam::123456789012:role/acme-readonly"  # leak-guard:allow fabricated ARN
    config.aws.control_plane_external_id = "acme-external-7f3a"
    config.aws.control_plane_role_arns = {"123456789012": "arn:aws:iam::123456789012:role/acme-ro"}  # leak-guard:allow fabricated ARN
    return config


ACCOUNT_WIRING = (
    "acme-oauth-client", "acme-prod-sa", "acme-readonly", "acme-external-7f3a", "acme-ro",
    "123456789012",
)


def test_account_wiring_is_left_out_of_the_snapshot(tmp_path: Path) -> None:
    svc = _service(tmp_path, LOG)
    svc._config_manager.get.return_value = _config_with_account_wiring()
    payload = svc.collect_diagnostics(consent=_consent(), instances=INSTANCES)
    snap = payload.config_snapshot
    assert snap["ovh"]["client_id"] == "<omitted>"
    assert snap["gcp"]["credentials_path"] == "<omitted>"
    for field in ("control_plane_role_arn", "control_plane_external_id",
                  "control_plane_role_arns"):
        assert snap["aws"][field] == "<omitted>", field
    preview = svc.render_preview(payload=payload, title="t", description="d")
    assert [v for v in ACCOUNT_WIRING if v in preview] == []


def test_log_text_hides_hosts_arns_and_zones_it_was_never_told_about(tmp_path: Path) -> None:
    svc = _service(tmp_path, [
        "ERROR servonaut.screens.ovh_dns: _load_records('acme-zone.example') failed",
        "ERROR reverse of 10.1.2.3 is mail.other-customer.example",
        "ERROR ns1234567.ip-10-1-2-3.eu unreachable",
        "ERROR assume arn:aws:iam::123456789012:role/acme-readonly denied",  # leak-guard:allow fabricated ARN
        "INFO zone acme.sh listed",
        "ERROR ACME-FILES refused",
    ])
    payload = svc.collect_diagnostics(
        consent=_consent(), instances=INSTANCES, known_hosts=["acme.sh"],
    )
    log = payload.log_excerpt
    for value in ("acme-zone", "other-customer", "ns1234567", "acme-readonly",
                  "123456789012", "acme.sh", "ACME-FILES"):
        assert value not in log, value
    assert "arn:aws:iam::000000000000:role/redacted" in log  # leak-guard:allow placeholder account


def test_code_and_generic_words_are_kept(tmp_path: Path) -> None:
    lines = [
        "ERROR servonaut.app: self.app.push_screen failed in config.json",
        "INFO running as ubuntu in production",
    ]
    svc = _service(tmp_path, lines)
    payload = svc.collect_diagnostics(consent=_consent(), instances=INSTANCES)
    assert payload.log_excerpt == "\n".join(lines)


@pytest.mark.asyncio
async def test_a_draft_cut_to_fit_a_url_still_carries_no_inventory(tmp_path: Path) -> None:
    noise = [f"2026-01-05 10:00:{n % 60:02d} INFO heartbeat {n} ok" for n in range(400)]
    svc = _service(tmp_path, LOG + noise + LOG)
    payload = svc.collect_diagnostics(consent=_consent(), instances=INSTANCES)
    receipt = await svc.submit(
        payload=payload, consent=_consent(), title=f"{SERVER} hangs",
        description=f"see {HOST}",
    )
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(receipt.url).query)
    body = query["body"][0]
    assert "truncated" in body, "fixture must take the truncation path"
    assert _leaks(body) == [] and _leaks(query["title"][0]) == []


def test_hosts_in_paths_and_uncommon_tlds_are_scrubbed(tmp_path: Path) -> None:
    svc = _service(tmp_path, [
        "ERROR nginx: open() /var/www/acmecorp.com/index.php failed",
        "ERROR loading /etc/nginx/sites-enabled/acmecorp.com.conf",
        "WARN upstream shop.acme.berlin and cdn.acme.media timed out",
    ])
    payload = svc.collect_diagnostics(consent=_consent(), instances=[])
    for value in ("acmecorp", "acme.berlin", "acme.media"):
        assert value not in payload.log_excerpt, value
    assert "/var/www/" in payload.log_excerpt and "index.php" in payload.log_excerpt


def test_free_text_config_fields_are_left_out(tmp_path: Path) -> None:
    svc = _service(tmp_path, LOG)
    config = _config()
    config.ai_system_prompt = "You analyse the acmecorp shop servers"
    config.bw_vault_folder = "Acme Corp"
    config.log_viewer_default_paths = ["/var/log/acmecorp/app.log"]
    svc._config_manager.get.return_value = config
    snap = svc.collect_diagnostics(consent=_consent(), instances=INSTANCES).config_snapshot
    assert snap["ai_system_prompt"] == "<omitted>"
    assert snap["bw_vault_folder"] == "<omitted>"
    assert snap["log_viewer_default_paths"] == "<omitted: 1 entry>"
    assert "acme" not in json.dumps(snap).lower().replace("acme-", "")
