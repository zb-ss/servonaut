"""AWS settings panel.

Covers all fields of :class:`~servonaut.config.schema.AWSConfig`:

- Provider enabled switch
- Default region (plain Input)
- EC2 cache TTL + cache/audit paths
- S3 object storage (access key, secret key via EnvVarInput, region Select,
  endpoint URL)
- Control-plane IAM role fields: default ARN, per-account ARN map, external ID
  (EnvVarInput), session name, mutate role ARN, per-account mutate ARN map

On save the panel replicates the legacy S3-rebuild side-effect: it calls
``build_object_storage_services`` and reassigns the three object-storage
service attributes on the app so newly saved credentials take effect without
an app restart.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Input, Select, Static, Switch

from servonaut.screens.settings.base import SettingsPanel, ValidationError
from servonaut.screens.settings.widgets import EnvVarInput, KeyValueEditor
from servonaut.services.object_storage_regions import (
    AWS_S3_DEFAULT_REGION,
    AWS_S3_REGIONS,
)

logger = logging.getLogger(__name__)

# AWS region options for the default_region Input hint and for
# the S3 region Select widget.  The S3 Select uses the full
# AWS_S3_REGIONS list from object_storage_regions.
_DEFAULT_REGION_HINT = "us-east-1"


class AwsPanel(SettingsPanel):
    """AWS provider settings: EC2, S3, and control-plane IAM roles."""

    PANEL_ID = "aws"
    TITLE = "AWS"

    DEFAULT_CSS = """
    AwsPanel .aws-subheader {
        padding: 1 0 0 0;
        color: $text-muted;
        text-style: bold;
    }
    AwsPanel .aws-help {
        color: $text-muted;
        padding: 0 0 1 0;
        height: auto;
    }
    AwsPanel .aws-status {
        height: auto;
        padding: 0 0 1 0;
    }
    AwsPanel #aws_ctrl_plane_arns,
    AwsPanel #aws_mutate_arns {
        height: auto;
        margin: 0 0 1 0;
    }
    """

    def form_rows(self) -> ComposeResult:
        """Yield the AWS form rows."""
        yield Static(
            "AWS EC2 and S3 credentials. Leave blank to use the boto3 default "
            "credential chain (env vars, ~/.aws/credentials, IAM role).",
            classes="aws-help",
        )
        yield Static("", id="aws_status_label", classes="aws-status")

        # --- Enabled switch -------------------------------------------------
        yield Horizontal(
            Static("AWS enabled", classes="label"),
            Switch(id="aws_enabled"),
            classes="setting_row",
        )

        # --- EC2 / instance list --------------------------------------------
        yield Static("EC2", classes="aws-subheader")
        yield Horizontal(
            Static("Default region", classes="label"),
            Input(placeholder=_DEFAULT_REGION_HINT, id="aws_default_region"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Cache TTL (seconds)", classes="label"),
            Input(placeholder="300", id="aws_cache_ttl"),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Cache path", classes="label"),
            Input(
                placeholder="~/.servonaut/aws_cache.json",
                id="aws_cache_path",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Audit path", classes="label"),
            Input(
                placeholder="~/.servonaut/aws_audit.jsonl",
                id="aws_audit_path",
            ),
            classes="setting_row",
        )

        # --- S3 object storage ----------------------------------------------
        yield Static("S3 Object Storage", classes="aws-subheader")
        yield Horizontal(
            Static("Access key", classes="label"),
            EnvVarInput(
                placeholder="AKIA... or $AWS_ACCESS_KEY_ID or file:/path",
                password=True,
                id="aws_s3_access_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Secret key", classes="label"),
            EnvVarInput(
                placeholder="your-secret or $AWS_SECRET_ACCESS_KEY or file:/path",
                password=True,
                id="aws_s3_secret_key",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("S3 region", classes="label"),
            Select(
                [(label, code) for label, code in AWS_S3_REGIONS],
                value=AWS_S3_DEFAULT_REGION,
                allow_blank=False,
                id="aws_s3_region",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("S3 endpoint URL", classes="label"),
            Input(
                placeholder="https://... (leave blank for AWS S3)",
                id="aws_s3_endpoint_url",
            ),
            classes="setting_row",
        )

        # --- Control-plane IAM roles (read) ---------------------------------
        yield Static("Control-plane IAM (read)", classes="aws-subheader")
        yield Horizontal(
            Static("Role ARN", classes="label"),
            Input(
                placeholder="arn:aws:iam::123456789:role/ReadRole (leave blank to use ambient creds)",
                id="aws_ctrl_role_arn",
            ),
            classes="setting_row",
        )
        yield Static("Per-account role ARNs (account_id → role_arn):", classes="label")
        yield KeyValueEditor(
            key_placeholder="account_id",
            value_placeholder="arn:aws:iam::...:role/...",
            id="aws_ctrl_plane_arns",
        )
        yield Horizontal(
            Static("External ID", classes="label"),
            EnvVarInput(
                placeholder="ExternalId or $CTRL_PLANE_EXTERNAL_ID",
                id="aws_ctrl_external_id",
            ),
            classes="setting_row",
        )
        yield Horizontal(
            Static("Session name", classes="label"),
            Input(
                placeholder="servonaut-control-plane",
                id="aws_ctrl_session_name",
            ),
            classes="setting_row",
        )

        # --- Control-plane IAM roles (mutate) -------------------------------
        yield Static("Control-plane IAM (mutate write path)", classes="aws-subheader")
        yield Horizontal(
            Static("Mutate role ARN", classes="label"),
            Input(
                placeholder="arn:aws:iam::123456789:role/WriteRole (leave blank → ambient creds for writes)",
                id="aws_mutate_role_arn",
            ),
            classes="setting_row",
        )
        yield Static("Per-account mutate ARNs (account_id → role_arn):", classes="label")
        yield KeyValueEditor(
            key_placeholder="account_id",
            value_placeholder="arn:aws:iam::...:role/...",
            id="aws_mutate_arns",
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Populate widgets from config and snapshot for dirty tracking."""
        config = self.app.config_manager.get()
        aws = config.aws
        s3 = aws.object_storage

        self.query_one("#aws_enabled", Switch).value = aws.enabled
        self.query_one("#aws_default_region", Input).value = aws.default_region
        self.query_one("#aws_cache_ttl", Input).value = str(aws.cache_ttl_seconds)
        self.query_one("#aws_cache_path", Input).value = aws.cache_path
        self.query_one("#aws_audit_path", Input).value = aws.audit_path

        # S3
        self.query_one("#aws_s3_access_key", EnvVarInput).value = s3.access_key
        self.query_one("#aws_s3_secret_key", EnvVarInput).value = s3.secret_key

        known_regions = {code for _, code in AWS_S3_REGIONS}
        s3_region_sel = self.query_one("#aws_s3_region", Select)
        s3_region_sel.value = (
            s3.region if s3.region in known_regions else AWS_S3_DEFAULT_REGION
        )
        self.query_one("#aws_s3_endpoint_url", Input).value = s3.endpoint_url

        # Control-plane read roles
        self.query_one("#aws_ctrl_role_arn", Input).value = aws.control_plane_role_arn
        self.query_one("#aws_ctrl_plane_arns", KeyValueEditor).set_map(
            aws.control_plane_role_arns
        )
        self.query_one("#aws_ctrl_external_id", EnvVarInput).value = (
            aws.control_plane_external_id
        )
        self.query_one("#aws_ctrl_session_name", Input).value = (
            aws.assume_role_session_name
        )

        # Control-plane mutate roles
        self.query_one("#aws_mutate_role_arn", Input).value = (
            aws.control_plane_mutate_role_arn
        )
        self.query_one("#aws_mutate_arns", KeyValueEditor).set_map(
            aws.control_plane_mutate_role_arns
        )

        self._update_status_label(aws)
        self._snapshot_now()

    def current_values(self) -> Dict[str, Any]:
        """Return current widget values for dirty comparison."""
        try:
            s3_region_sel = self.query_one("#aws_s3_region", Select)
            s3_region = (
                AWS_S3_DEFAULT_REGION
                if s3_region_sel.value is Select.BLANK
                else str(s3_region_sel.value)
            )
            return {
                "enabled": self.query_one("#aws_enabled", Switch).value,
                "default_region": self.query_one("#aws_default_region", Input).value.strip(),
                "cache_ttl_seconds": self.query_one("#aws_cache_ttl", Input).value.strip(),
                "cache_path": self.query_one("#aws_cache_path", Input).value.strip(),
                "audit_path": self.query_one("#aws_audit_path", Input).value.strip(),
                "s3_access_key": self.query_one("#aws_s3_access_key", EnvVarInput).value.strip(),
                "s3_secret_key": self.query_one("#aws_s3_secret_key", EnvVarInput).value.strip(),
                "s3_region": s3_region,
                "s3_endpoint_url": self.query_one("#aws_s3_endpoint_url", Input).value.strip(),
                "ctrl_role_arn": self.query_one("#aws_ctrl_role_arn", Input).value.strip(),
                "ctrl_plane_arns": str(
                    self.query_one("#aws_ctrl_plane_arns", KeyValueEditor).get_map()
                ),
                "ctrl_external_id": self.query_one("#aws_ctrl_external_id", EnvVarInput).value.strip(),
                "ctrl_session_name": self.query_one("#aws_ctrl_session_name", Input).value.strip(),
                "mutate_role_arn": self.query_one("#aws_mutate_role_arn", Input).value.strip(),
                "mutate_arns": str(
                    self.query_one("#aws_mutate_arns", KeyValueEditor).get_map()
                ),
            }
        except Exception:
            return {}

    def collect(self) -> Dict[str, Any]:
        """Validate and return fields to persist.

        Raises:
            ValidationError: When cache TTL is not a non-negative integer.
        """
        cache_ttl_raw = self.query_one("#aws_cache_ttl", Input).value.strip()
        try:
            cache_ttl = int(cache_ttl_raw)
        except ValueError as exc:
            raise ValidationError(
                "aws_cache_ttl", "Cache TTL must be a whole number"
            ) from exc
        if cache_ttl < 0:
            raise ValidationError(
                "aws_cache_ttl", "Cache TTL must be zero or greater"
            )

        s3_region_sel = self.query_one("#aws_s3_region", Select)
        s3_region = (
            AWS_S3_DEFAULT_REGION
            if s3_region_sel.value is Select.BLANK
            else str(s3_region_sel.value)
        )

        ctrl_arns_raw = self.query_one("#aws_ctrl_plane_arns", KeyValueEditor).get_map()
        mutate_arns_raw = self.query_one("#aws_mutate_arns", KeyValueEditor).get_map()

        return {
            "enabled": self.query_one("#aws_enabled", Switch).value,
            "default_region": (
                self.query_one("#aws_default_region", Input).value.strip()
                or _DEFAULT_REGION_HINT
            ),
            "cache_ttl_seconds": cache_ttl,
            "cache_path": (
                self.query_one("#aws_cache_path", Input).value.strip()
                or "~/.servonaut/aws_cache.json"
            ),
            "audit_path": (
                self.query_one("#aws_audit_path", Input).value.strip()
                or "~/.servonaut/aws_audit.jsonl"
            ),
            "s3_access_key": self.query_one("#aws_s3_access_key", EnvVarInput).value.strip(),
            "s3_secret_key": self.query_one("#aws_s3_secret_key", EnvVarInput).value.strip(),
            "s3_region": s3_region,
            "s3_endpoint_url": self.query_one("#aws_s3_endpoint_url", Input).value.strip(),
            "ctrl_role_arn": self.query_one("#aws_ctrl_role_arn", Input).value.strip(),
            "ctrl_plane_arns": {str(k): str(v) for k, v in ctrl_arns_raw.items()},
            "ctrl_external_id": self.query_one("#aws_ctrl_external_id", EnvVarInput).value.strip(),
            "ctrl_session_name": (
                self.query_one("#aws_ctrl_session_name", Input).value.strip()
                or "servonaut-control-plane"
            ),
            "mutate_role_arn": self.query_one("#aws_mutate_role_arn", Input).value.strip(),
            "mutate_arns": {str(k): str(v) for k, v in mutate_arns_raw.items()},
        }

    def persist(self) -> None:
        """Validate via :meth:`collect`, write through config_manager, rebuild S3."""
        fields = self.collect()
        config = self.app.config_manager.get()

        new_s3 = dataclasses.replace(
            config.aws.object_storage,
            access_key=fields["s3_access_key"],
            secret_key=fields["s3_secret_key"],
            region=fields["s3_region"],
            endpoint_url=fields["s3_endpoint_url"],
        )
        new_aws = dataclasses.replace(
            config.aws,
            enabled=fields["enabled"],
            default_region=fields["default_region"],
            cache_ttl_seconds=fields["cache_ttl_seconds"],
            cache_path=fields["cache_path"],
            audit_path=fields["audit_path"],
            object_storage=new_s3,
            control_plane_role_arn=fields["ctrl_role_arn"],
            control_plane_role_arns=fields["ctrl_plane_arns"],
            control_plane_external_id=fields["ctrl_external_id"],
            assume_role_session_name=fields["ctrl_session_name"],
            control_plane_mutate_role_arn=fields["mutate_role_arn"],
            control_plane_mutate_role_arns=fields["mutate_arns"],
        )
        self.app.config_manager.update(aws=new_aws)

        self._rebuild_s3_services()
        self._update_status_label(new_aws)
        self._finish_save("AWS settings saved")

    # ------------------------------------------------------------------
    # Side-effect helpers
    # ------------------------------------------------------------------

    def _rebuild_s3_services(self) -> None:
        """Rebuild object-storage services after save so credentials take effect.

        Mirrors the legacy side-effect at settings.py:2022-2034 so the user
        does not need to restart the app for new S3 credentials to apply.
        """
        try:
            from servonaut.services.object_storage_factory import (
                build_object_storage_services,
            )
            refreshed = self.app.config_manager.get()
            (
                self.app.aws_object_storage_service,
                self.app.hetzner_object_storage_service,
                self.app.ovh_object_storage_service,
            ) = build_object_storage_services(refreshed)
        except Exception as exc:
            logger.warning("S3 service rebuild after AWS settings save failed: %s", exc)

    def _update_status_label(self, aws_config: Any) -> None:
        """Update the status label based on the provided AWS config."""
        try:
            label = self.query_one("#aws_status_label", Static)
        except Exception:
            return
        s3 = aws_config.object_storage
        if s3.access_key or s3.secret_key:
            label.update("[green]Status: S3 credentials configured[/green]")
        else:
            label.update(
                "[dim]Status: Using boto3 default credential chain "
                "(env vars / ~/.aws/credentials / IAM role)[/dim]"
            )

    # ------------------------------------------------------------------
    # Dirty marker refresh
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Refresh the dirty marker on any input edit."""
        self._dirty_watch()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Refresh the dirty marker on S3 region change."""
        self._dirty_watch()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Refresh the dirty marker on enabled toggle."""
        self._dirty_watch()
