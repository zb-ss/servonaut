"""Tests for inside-out Windows Authenticode code signing, argument masking, and verification."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import datetime
from pathlib import Path
import subprocess
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID
import pytest

from scripts.distribution import sign_windows
from scripts.distribution.package_windows import (
    REQUIRED_PAYLOAD_FILES,
    package_windows,
)
from scripts.distribution.sign_windows import (
    SIGNING_PASSWORD_ENV,
    WindowsSigningError,
    main,
    sign_msi,
    sign_payload_binaries,
    verify_signature,
)

_PFX_PASSWORD = "pfx-password-for-tests"


@pytest.fixture
def mock_windows_payload(tmp_path: Path) -> Path:
    payload_dir = tmp_path / "mock-payload"
    payload_dir.mkdir(parents=True)

    for binary_name in REQUIRED_PAYLOAD_FILES:
        target = payload_dir / binary_name
        if binary_name.endswith(".json"):
            target.write_text('{"distribution": "packaged-desktop"}', encoding="utf-8")
        else:
            target.write_bytes(b"MZfakewindowspe")

    # Nested DLLs and PYDs
    internal_dir = payload_dir / "_internal" / "dlls"
    internal_dir.mkdir(parents=True)
    (internal_dir / "libcrypto.dll").write_bytes(b"MZfakecrypto")
    (internal_dir / "libssl.dll").write_bytes(b"MZfakessl")
    (internal_dir / "select.pyd").write_bytes(b"MZfakepyd")

    return payload_dir


class TestSignWindows:
    """Tests covering inside-out signing order and credential masking."""

    def test_inside_out_signing_order(self, mock_windows_payload: Path) -> None:
        signed = sign_payload_binaries(
            mock_windows_payload,
            cert_thumbprint="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
            dry_run=True,
        )

        signed_names = [f.name for f in signed]

        # 1. Nested dynamic libraries must come first
        assert signed_names[:3] == ["libcrypto.dll", "libssl.dll", "select.pyd"]

        # 2. Helper executables must come before main GUI executable
        assert "servonaut.exe" in signed_names[3:5]
        assert "servonaut-desktop-child.exe" in signed_names[3:5]

        # 3. Main GUI launcher must be last
        assert signed_names[-1] == "servonaut-desktop.exe"

    def test_sign_msi_dry_run(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "dist"
        res = package_windows(
            payload_dir=mock_windows_payload,
            output_dir=out_dir,
            product_version="0.2.0",
            dry_run=True,
        )

        signed_msi = sign_msi(
            res.msi_path,
            cert_thumbprint="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
            dry_run=True,
        )
        assert signed_msi == res.msi_path

    def test_verify_signature_dry_run(self, mock_windows_payload: Path) -> None:
        gui_exe = mock_windows_payload / "servonaut-desktop.exe"
        assert verify_signature(gui_exe, dry_run=True) is True

    def test_verify_signature_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            verify_signature(tmp_path / "nonexistent.exe", dry_run=True)

    def test_cli_sign_payload_and_msi(self, mock_windows_payload: Path, tmp_path: Path) -> None:
        out_dir = tmp_path / "dist"
        res = package_windows(
            payload_dir=mock_windows_payload,
            output_dir=out_dir,
            product_version="0.2.0",
            dry_run=True,
        )

        rc = main(
            [
                "--payload-dir",
                str(mock_windows_payload),
                "--msi",
                str(res.msi_path),
                "--thumbprint",
                "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
                "--dry-run",
            ]
        )
        assert rc == 0


@dataclass
class _Call:
    argv: list[str]
    env: Optional[dict[str, str]]


class _FakeWindowsTools:
    """Stand-in for PowerShell and signtool that records every invocation."""

    def __init__(self, *, store_state: str = "added", signtool_rc: int = 0) -> None:
        self.calls: list[_Call] = []
        self._store_state = store_state
        self._signtool_rc = signtool_rc

    def which(self, name: str) -> Optional[str]:
        return {"signtool.exe": "C:/sdk/signtool.exe", "powershell.exe": "C:/ps/powershell.exe"}.get(name)

    def run(self, cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        env = kwargs.get("env")
        self.calls.append(_Call(list(cmd), dict(env) if isinstance(env, dict) else None))
        if Path(cmd[0]).name == "powershell.exe":
            return subprocess.CompletedProcess(cmd, 0, f"{self._store_state}\n", "")
        return subprocess.CompletedProcess(cmd, self._signtool_rc, "", "signtool output")

    def signtool_calls(self) -> list[list[str]]:
        return [c.argv for c in self.calls if Path(c.argv[0]).name == "signtool.exe"]

    def powershell_calls(self) -> list[_Call]:
        return [c for c in self.calls if Path(c.argv[0]).name == "powershell.exe"]


@pytest.fixture
def fake_tools(monkeypatch: pytest.MonkeyPatch) -> _FakeWindowsTools:
    tools = _FakeWindowsTools()
    monkeypatch.setattr(sign_windows.shutil, "which", tools.which)
    monkeypatch.setattr(sign_windows.subprocess, "run", tools.run)
    return tools


@pytest.fixture
def pfx_file(tmp_path: Path) -> tuple[Path, str]:
    """Write a password-protected PFX and return it with its SHA-1 thumbprint."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Code Signing")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pfx = tmp_path / "codesign.pfx"
    pfx.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"test", key, certificate, None, BestAvailableEncryption(_PFX_PASSWORD.encode())
        )
    )
    return pfx, certificate.fingerprint(hashes.SHA1()).hex().upper()


class TestSigningToolRequirements:
    """Dry runs never sign; real runs fail loudly without signtool."""

    def test_dry_run_never_invokes_tools(
        self, mock_windows_payload: Path, fake_tools: _FakeWindowsTools
    ) -> None:
        signed = sign_payload_binaries(
            mock_windows_payload,
            cert_thumbprint="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
            dry_run=True,
        )

        assert signed[-1].name == "servonaut-desktop.exe"
        assert verify_signature(signed[-1], dry_run=True) is True
        assert fake_tools.calls == []

    def test_missing_signtool_raises_outside_dry_run(
        self, mock_windows_payload: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sign_windows.shutil, "which", lambda name: None)
        target = mock_windows_payload / "servonaut.exe"

        with pytest.raises(WindowsSigningError, match="signtool"):
            sign_msi(target, cert_thumbprint="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4")
        with pytest.raises(WindowsSigningError, match="signtool"):
            verify_signature(target)

    def test_osslsigncode_is_not_used_as_a_signtool_substitute(
        self, mock_windows_payload: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            sign_windows.shutil,
            "which",
            lambda name: "/usr/bin/osslsigncode" if name == "osslsigncode" else None,
        )

        def fail_run(*args: object, **kwargs: object) -> None:
            raise AssertionError("no signing tool may run")

        monkeypatch.setattr(sign_windows.subprocess, "run", fail_run)

        with pytest.raises(WindowsSigningError, match="signtool"):
            sign_msi(
                mock_windows_payload / "servonaut.exe",
                cert_thumbprint="A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4",
            )


class TestPfxSigningKeepsSecretsOffArgv:
    """A PFX is imported into the user store and selected by thumbprint."""

    def test_pfx_signing_uses_thumbprint_and_never_puts_password_on_argv(
        self,
        mock_windows_payload: Path,
        fake_tools: _FakeWindowsTools,
        pfx_file: tuple[Path, str],
    ) -> None:
        pfx, thumbprint = pfx_file

        signed = sign_payload_binaries(mock_windows_payload, cert_file=pfx, password=_PFX_PASSWORD)

        assert all(_PFX_PASSWORD not in arg for call in fake_tools.calls for arg in call.argv)
        signtool_calls = fake_tools.signtool_calls()
        assert len(signtool_calls) == len(signed)
        for argv in signtool_calls:
            assert argv[argv.index("/sha1") + 1] == thumbprint
            assert "/p" not in argv and "/f" not in argv

        import_call, remove_call = fake_tools.powershell_calls()
        assert import_call.env is not None and _PFX_PASSWORD in import_call.env.values()
        assert remove_call.env is not None and _PFX_PASSWORD not in remove_call.env.values()
        assert fake_tools.calls[0] is import_call
        assert fake_tools.calls[-1] is remove_call

    def test_imported_certificate_is_removed_when_signing_fails(
        self,
        mock_windows_payload: Path,
        monkeypatch: pytest.MonkeyPatch,
        pfx_file: tuple[Path, str],
    ) -> None:
        tools = _FakeWindowsTools(signtool_rc=1)
        monkeypatch.setattr(sign_windows.shutil, "which", tools.which)
        monkeypatch.setattr(sign_windows.subprocess, "run", tools.run)
        pfx, _ = pfx_file

        with pytest.raises(WindowsSigningError, match="Failed to sign"):
            sign_msi(mock_windows_payload / "servonaut.exe", cert_file=pfx, password=_PFX_PASSWORD)

        assert len(tools.powershell_calls()) == 2
        assert tools.calls[-1] is tools.powershell_calls()[-1]

    def test_certificate_already_in_the_store_is_left_in_place(
        self,
        mock_windows_payload: Path,
        monkeypatch: pytest.MonkeyPatch,
        pfx_file: tuple[Path, str],
    ) -> None:
        tools = _FakeWindowsTools(store_state="present")
        monkeypatch.setattr(sign_windows.shutil, "which", tools.which)
        monkeypatch.setattr(sign_windows.subprocess, "run", tools.run)
        pfx, _ = pfx_file

        sign_msi(mock_windows_payload / "servonaut.exe", cert_file=pfx, password=_PFX_PASSWORD)

        assert len(tools.powershell_calls()) == 1

    def test_wrong_pfx_password_fails_before_touching_the_store(
        self,
        mock_windows_payload: Path,
        fake_tools: _FakeWindowsTools,
        pfx_file: tuple[Path, str],
    ) -> None:
        pfx, _ = pfx_file

        with pytest.raises(WindowsSigningError, match="password"):
            sign_msi(mock_windows_payload / "servonaut.exe", cert_file=pfx, password="wrong")
        assert fake_tools.calls == []

    def test_cli_reads_password_from_environment_only(
        self,
        mock_windows_payload: Path,
        fake_tools: _FakeWindowsTools,
        pfx_file: tuple[Path, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pfx, thumbprint = pfx_file
        monkeypatch.setenv(SIGNING_PASSWORD_ENV, _PFX_PASSWORD)

        rc = main(["--msi", str(mock_windows_payload / "servonaut.exe"), "--cert-file", str(pfx)])

        assert rc == 0
        assert fake_tools.signtool_calls()[0][-2:] == [thumbprint, str((mock_windows_payload / "servonaut.exe").resolve())]
        with pytest.raises(SystemExit) as excinfo:
            main(["--msi", str(pfx), "--cert-file", str(pfx), "--password", _PFX_PASSWORD])
        assert excinfo.value.code == 2


class TestVerifyPayload:
    """--verify --payload-dir checks every signed payload binary."""

    def test_cli_verifies_each_payload_binary(
        self, mock_windows_payload: Path, fake_tools: _FakeWindowsTools
    ) -> None:
        rc = main(["--verify", "--payload-dir", str(mock_windows_payload)])

        assert rc == 0
        verified = [Path(argv[-1]).name for argv in fake_tools.signtool_calls()]
        assert verified == [
            "libcrypto.dll",
            "libssl.dll",
            "select.pyd",
            "servonaut.exe",
            "servonaut-desktop-child.exe",
            "servonaut-desktop.exe",
        ]
        assert all(argv[1:3] == ["verify", "/pa"] for argv in fake_tools.signtool_calls())


def test_store_scripts_are_passed_encoded(
    mock_windows_payload: Path, fake_tools: _FakeWindowsTools, pfx_file: tuple[Path, str]
) -> None:
    pfx, thumbprint = pfx_file

    sign_msi(mock_windows_payload / "servonaut.exe", cert_file=pfx, password=_PFX_PASSWORD)

    import_call, remove_call = fake_tools.powershell_calls()
    import_script = base64.b64decode(import_call.argv[-1]).decode("utf-16-le")
    remove_script = base64.b64decode(remove_call.argv[-1]).decode("utf-16-le")
    assert import_call.argv[-2] == "-EncodedCommand"
    assert "X509Store" in import_script and _PFX_PASSWORD not in import_script
    assert "-DeleteKey" in remove_script
    assert remove_call.env is not None and remove_call.env["SERVONAUT_SIGNING_THUMBPRINT"] == thumbprint
