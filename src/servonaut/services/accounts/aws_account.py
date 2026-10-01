"""One AWS account: its boto3 session, regions and (lazily) account id."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple

import boto3
from botocore.configloader import load_config, raw_config_parse
from botocore.exceptions import BotoCoreError, ConfigNotFound

from servonaut.config.accounts import AccountRef

logger = logging.getLogger(__name__)

# Environment variables botocore reads credentials, or where to get them, from.
_CREDENTIAL_ENV_VARS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
)
# Profile keys botocore gets credentials from, once it is asked for them.
_CREDENTIAL_KEYS = frozenset({
    "aws_access_key_id",
    "credential_process",
    "role_arn",
    "web_identity_token_file",
    "sso_session",
    "sso_start_url",
    "sso_account_id",
    "sso_role_name",
    "login_session",
})


def ambient_credentials_configured(environ: Mapping[str, str] = os.environ) -> bool:
    """Whether the ambient credential chain has anything to work with, checked offline.

    True for a credential environment variable, a profile named in
    ``AWS_PROFILE`` / ``AWS_DEFAULT_PROFILE`` (using it says what is wrong
    with it), or a ``default`` profile in the shared credentials or config
    file with a key that gives credentials. Nothing is resolved: no instance
    metadata request, no ``credential_process`` run, no SSO token read. A
    machine that has only an instance role therefore counts as not set up.
    """
    if any(environ.get(name) for name in _CREDENTIAL_ENV_VARS):
        return True
    if environ.get("AWS_PROFILE") or environ.get("AWS_DEFAULT_PROFILE"):
        return True
    credentials = _shared_file(environ, "AWS_SHARED_CREDENTIALS_FILE", "credentials")
    config = _shared_file(environ, "AWS_CONFIG_FILE", "config")
    try:
        sections = [
            _parsed(lambda: raw_config_parse(credentials)).get("default", {}),
            _parsed(lambda: load_config(config)).get("profiles", {}).get("default", {}),
        ]
    except (BotoCoreError, OSError):
        return True  # a file botocore cannot read: listing says what is wrong
    return any(_CREDENTIAL_KEYS.intersection(section) for section in sections)


def _shared_file(environ: Mapping[str, str], variable: str, name: str) -> str:
    return os.path.expanduser(environ.get(variable) or str(Path("~") / ".aws" / name))


def _parsed(parse) -> dict:
    """A botocore config parse; empty when the file does not exist."""
    try:
        return parse() or {}
    except ConfigNotFound:
        return {}


class AWSAccountContext:
    """Credentials and scope of one AWS account.

    The primary account without a profile has NO session of its own:
    :meth:`client` then goes through the module-level ``boto3.client``, which
    is byte-for-byte how every AWS call worked before extra accounts existed
    (ambient chain: environment, shared config, instance profile). Every
    other account gets a ``boto3.Session(profile_name=...)``. An explicit
    profile makes botocore ignore credential environment variables, so an
    extra account can never silently reuse the primary account's keys.

    boto3 sessions are not thread-safe, while the clients they create are:
    client creation is serialised with a lock and callers keep the client.
    """

    def __init__(self, ref: AccountRef, profile: str = "", regions: Tuple[str, ...] = ()):
        self.ref = ref
        self.profile = profile
        self.regions: Tuple[str, ...] = tuple(regions)
        self._session: Optional[boto3.session.Session] = None
        self._lock = threading.Lock()
        self._account_id: Optional[str] = None

    @property
    def uses_ambient_credentials(self) -> bool:
        """True when calls go through the process-wide default credential chain."""
        return not self.profile

    def session(self) -> Optional[boto3.session.Session]:
        """This account's boto3 session, or None for the ambient chain."""
        if not self.profile:
            return None
        with self._lock:
            if self._session is None:
                self._session = boto3.session.Session(profile_name=self.profile)
            return self._session

    def client(self, service: str, region: Optional[str] = None, **kwargs: Any) -> Any:
        """Create a boto3 client for this account.

        *region* is a convenience for ``region_name``; either may be given.
        """
        if region:
            kwargs["region_name"] = region
        session = self.session()
        if session is None:
            return boto3.client(service, **kwargs)
        with self._lock:
            return session.client(service, **kwargs)

    def resource(self, service: str, region: Optional[str] = None, **kwargs: Any) -> Any:
        """Create a boto3 resource for this account."""
        if region:
            kwargs["region_name"] = region
        session = self.session()
        if session is None:
            return boto3.resource(service, **kwargs)
        with self._lock:
            return session.resource(service, **kwargs)

    def account_id(self) -> str:
        """The 12-digit account id (``sts:GetCallerIdentity``), cached.

        Blocking; call it from a worker thread. Returns ``""`` when the call
        fails, so a display detail never breaks a fleet refresh.
        """
        if self._account_id is not None:
            return self._account_id
        try:
            identity = self.client("sts").get_caller_identity()
            self._account_id = str(identity.get("Account") or "")
        except Exception as exc:  # display detail only; never fatal
            logger.debug("Could not resolve AWS account id for %s: %s", self.ref.label, exc)
            return ""
        return self._account_id


def aws_client(
    account: Optional["AWSAccountContext"], boto3_module: Any, service: str, **kwargs: Any
) -> Any:
    """A boto3 client for *account*, built the way the caller always built it.

    An account with a profile gets a client from its own session. The
    ambient-chain account (and ``None``) calls ``boto3_module.client`` — the
    caller passes its own module-level ``boto3`` so that behaviour, and every
    test patch of that module, is exactly what it was before extra accounts
    existed.
    """
    if account is not None and not account.uses_ambient_credentials:
        return account.client(service, **kwargs)
    return boto3_module.client(service, **kwargs)

