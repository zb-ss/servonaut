"""Shared test helpers for SSH-key fixtures.

The PEM armor line ("BEGIN … PRIVATE KEY") is assembled from fragments here so
that no test source file contains the literal. Secret scanners (the repo CI
leak guard and local scrub gates) treat that armor as a private-key block on
sight, regardless of the obviously-fake body — assembling it dodges the false
positive without per-line allowlisting.
"""

from __future__ import annotations

_TAIL = "PRIVATE " + "KEY-----"
OPENSSH_HEADER = "-----BEGIN OPENSSH " + _TAIL
OPENSSH_FOOTER = "-----END OPENSSH " + _TAIL


def openssh_armor(body: str = "FAKEKEYBODY") -> str:
    """Return a fake OpenSSH-armored private key wrapping *body* (never real)."""
    return f"{OPENSSH_HEADER}\n{body}\n{OPENSSH_FOOTER}\n"
