"""A signed file repository for disposable Ubuntu upgrade fixtures."""

from __future__ import annotations

import gzip
import shutil
import subprocess
from pathlib import Path

TOOL_TIMEOUT = 180


def run(argv: list[str], *, cwd: Path | None = None, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(argv, cwd=cwd, input=input_bytes, capture_output=True, timeout=TOOL_TIMEOUT)
    if result.returncode:
        raise AssertionError(f"{argv[0]} failed\n{(result.stdout + result.stderr).decode(errors='replace')}")
    return result.stdout


class SignedArchive:
    def __init__(self, root: Path) -> None:
        self.public = root / "archive"
        self.pool = self.public / "pool"
        self.suite = self.public / "dists" / "stable"
        self.index = self.suite / "main" / "binary-amd64"
        self.pool.mkdir(parents=True)
        self.index.mkdir(parents=True)
        self.signing_home = root / "signing"
        self.signing_home.mkdir(mode=0o700)
        self.gpg = ["gpg", "--homedir", str(self.signing_home), "--batch"]
        run([*self.gpg, "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-generate-key", "Servonaut upgrade fixture", "rsa2048", "sign", "1d"])
        keyring = root / "fixture-archive.gpg"
        keyring.write_bytes(run([*self.gpg, "--export"]))
        keyring.chmod(0o644)
        sources = root / "fixtures.sources"
        sources.write_text(
            f"Types: deb\nURIs: file:{self.public}\nSuites: stable\nComponents: main\n"
            f"Architectures: amd64\nSigned-By: {keyring}\n",
            encoding="utf-8",
        )
        lists = root / "lists"
        lists.mkdir()
        self.apt = [
            "apt-get", "-o", "Dpkg::Use-Pty=0", "-o", f"Dir::Etc::sourcelist={sources}",
            "-o", "Dir::Etc::sourceparts=-", "-o", f"Dir::State::lists={lists}",
            "-o", "APT::Update::Error-Mode=any",
        ]

    def offer(self, package: Path) -> None:
        shutil.copyfile(package, self.pool / package.name)
        indexes = run(["apt-ftparchive", "packages", "pool"], cwd=self.public)
        (self.index / "Packages").write_bytes(indexes)
        (self.index / "Packages.gz").write_bytes(gzip.compress(indexes, mtime=0))
        release = run([
            "apt-ftparchive", "-o", "APT::FTPArchive::Release::Origin=Servonaut upgrade fixture",
            "-o", "APT::FTPArchive::Release::Suite=stable",
            "-o", "APT::FTPArchive::Release::Codename=stable",
            "-o", "APT::FTPArchive::Release::Architectures=amd64",
            "-o", "APT::FTPArchive::Release::Components=main", "release", "dists/stable",
        ], cwd=self.public)
        (self.suite / "InRelease").write_bytes(run([
            *self.gpg, "--digest-algo", "SHA256", "--clearsign",
        ], input_bytes=release))
        run([*self.apt, "update"])

    def install(self, version: str, *options: str) -> None:
        run([*self.apt, "install", "--yes", "--no-install-recommends", *options, f"servonaut={version}"])
        state = run(["dpkg-query", "-W", "-f=${Version} ${db:Status-Status}", "servonaut"]).decode()
        assert state == f"{version} installed", state
        assert run(["dpkg", "--verify", "servonaut"]) == b""

    def close(self) -> None:
        run(["gpgconf", "--homedir", str(self.signing_home), "--kill", "all"])


def debian_version(package: Path) -> str:
    return run(["dpkg-deb", "--field", str(package), "Version"]).decode().strip()
