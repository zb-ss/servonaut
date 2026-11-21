"""Exercise a fixture-signed local archive using Ubuntu's actual APT client."""

from __future__ import annotations

import importlib
import os
import subprocess
import tempfile
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.packaging.apt.fixtures import FixtureStore, SETTINGS, sample
from apt_archive import (
    ArchiveError, Change, Input, Signer, Publisher, build_indexes, inrelease, release, run,
)

entrypoint = importlib.import_module("apt-publish")
TIMEOUT = SETTINGS.timeout


def package(root: Path, tag: str) -> Input:
    content = root / f"contents-{tag}"
    control = content / "DEBIAN"
    control.mkdir(parents=True)
    from scripts.distribution.package_deb import debian_version

    (control / "control").write_text(
        f"Package: servonaut\nVersion: {debian_version(tag[1:])}\nArchitecture: amd64\n"
        "Maintainer: Archive Fixture <fixture@example.com>\nDescription: APT archive test\n",
        encoding="utf-8",
    )
    output = root / f"built-{tag}.deb"
    run(["dpkg-deb", "--build", "--root-owner-group", str(content), str(output)], timeout=TIMEOUT)
    return sample(root, tag, output.read_bytes())


def apt(root: Path, archive: Path, keyring: Path, suite: str, name: str) -> tuple[list[str], subprocess.CompletedProcess]:
    state = root / name
    state.mkdir(mode=0o755)
    lists = state / "lists"
    lists.mkdir()
    source = state / "archive.sources"
    source.write_text(
        f"Types: deb\nURIs: file:{archive}\nSuites: {suite}\nComponents: main\n"
        f"Architectures: amd64\nSigned-By: {keyring}\n",
        encoding="utf-8",
    )
    options = [
        "-o", f"Dir::Etc::sourcelist={source}",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", f"Dir::State::lists={lists}",
        "-o", "APT::Update::Error-Mode=any",
        "-o", "Acquire::Languages=none",
    ]
    return options, subprocess.run(
        ["apt-get", *options, "update"], capture_output=True, text=True, timeout=TIMEOUT,
    )


def check(root: Path, home: Path) -> None:
    phrase = b"container fixture passphrase"
    owner_home = root / "owner"
    owner_home.mkdir(mode=0o700)
    try:
        fingerprint = entrypoint.fixture_signing(owner_home, phrase, TIMEOUT)
        export = [
            "gpg", "--homedir", str(owner_home), "--batch", "--pinentry-mode", "loopback",
            "--passphrase-fd", "0",
        ]
        secret = run([*export, "--export-secret-subkeys", fingerprint + "!"],
                     input_bytes=phrase + b"\n", timeout=TIMEOUT)
        entrypoint.import_signing_subkey(home, secret, fingerprint, TIMEOUT)
        print("PASS runner imports only the provisioned signing subkey")
    finally:
        with suppress(ArchiveError):
            run(["gpgconf", "--homedir", str(owner_home), "--kill", "all"], timeout=TIMEOUT)
    public_key = root / "public.gpg"
    public_key.write_bytes(run(["gpg", "--homedir", str(home), "--batch", "--export", fingerprint], timeout=TIMEOUT))
    public_key.chmod(0o644)
    signer = Signer(home, public_key, fingerprint, TIMEOUT)
    assert signer.expires_at() > datetime.now(timezone.utc) + timedelta(hours=12)

    final = package(root, "v2.1.0")
    previous = package(root, "v2.0.0")
    rc = package(root, "v2.2.0rc10")
    rc_old = package(root, "v2.2.0rc2")
    archive = root / "archive"
    archive.mkdir(mode=0o755)
    store = FixtureStore(archive)

    def select(inventory):
        selected = {
            "stable": [previous, final],
            "candidate": [previous, final, rc, rc_old],
        }
        return {suite: [item for item in rows if not inventory.blocked(item.package)]
                for suite, rows in selected.items()}

    def sign(plain):
        return signer.sign(plain, phrase)

    publisher = Publisher(store, store, SETTINGS, root, select, build_indexes, sign, signer.verify)
    assert build_indexes([final, previous], root, TIMEOUT) == build_indexes([previous, final], root, TIMEOUT)
    publisher.publish()
    source_options = {}
    for suite, expected in (("stable", "2.1.0"), ("candidate", "2.2.0~rc10")):
        options, result = apt(root, archive, public_key, suite, f"ok-{suite}")
        assert result.returncode == 0, result.stdout + result.stderr
        source_options[suite] = options
        policy = run(["apt-cache", *options, "policy", "servonaut"], timeout=TIMEOUT).decode()
        assert f"Candidate: {expected}" in policy, policy
        install = run(["apt-get", *options, "-s", "install", "servonaut"], timeout=TIMEOUT).decode()
        assert f"Inst servonaut ({expected}" in install, install
        print(f"PASS {suite}: {expected}")

    stable_path = inrelease("stable")
    valid = store.get(stable_path)
    damaged = valid.body.replace(b"Origin: Servonaut", b"Origin: Invalid", 1)
    store.put(stable_path, damaged, etag=valid.etag)
    _, bad = apt(root, archive, public_key, "stable", "bad-signature")
    failure = bad.stdout + bad.stderr
    assert bad.returncode != 0 and "BADSIG" in failure, failure
    print("PASS bad signature rejected")

    expired = release("stable", build_indexes([previous, final], root, TIMEOUT),
                      datetime.now(timezone.utc) - timedelta(days=3), SETTINGS.valid_for, "0" * 32)
    store.put(stable_path, sign(expired), etag=store.get(stable_path).etag)
    _, old = apt(root, archive, public_key, "stable", "expired")
    failure = old.stdout + old.stderr
    assert old.returncode != 0 and "expired" in failure.lower(), failure
    print("PASS expired Release rejected")

    store.put(stable_path, valid.body, etag=store.get(stable_path).etag)
    publisher.publish(Change("withdraw", rc.package.tag, rc.package.sha256))
    assert not (archive / rc.package.key).exists()
    download_dir = root / "download"
    download_dir.mkdir(mode=0o755)
    old_lists = subprocess.run(
        ["apt-get", *source_options["candidate"], "download", "servonaut"],
        capture_output=True, text=True, cwd=download_dir, timeout=TIMEOUT,
    )
    failure = old_lists.stdout + old_lists.stderr
    assert old_lists.returncode != 0 and Path(rc.package.key).name in failure, failure
    assert not tuple(download_dir.glob("*.deb"))
    options, result = apt(root, archive, public_key, "candidate", "withdrawn")
    assert result.returncode == 0, result.stdout + result.stderr
    policy = run(["apt-cache", *options, "policy", "servonaut"], timeout=TIMEOUT).decode()
    assert "Candidate: 2.2.0~rc2" in policy, policy
    print("PASS old lists cannot download the withdrawn .deb and refreshed lists fall back")


def check_expired_signing_key(root: Path) -> None:
    home = root / "expired-key"
    home.mkdir(mode=0o700)
    old = datetime.now(timezone.utc) - timedelta(days=4)
    fake_clock = old.strftime("%Y%m%dT%H%M%S")
    phrase = b"expired fixture passphrase"
    gpg = ["gpg", "--homedir", str(home), "--batch"]
    protected = [*gpg, "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
    try:
        run([*protected, "--faked-system-time", fake_clock,
             "--quick-generate-key", "Retired signing fixture", "rsa2048", "cert", "1y"],
            input_bytes=phrase + b"\n", timeout=TIMEOUT)
        records = run([*gpg, "--with-colons", "--list-keys"], timeout=TIMEOUT).decode().splitlines()
        primary, = [row.split(":")[9] for row in records if row.startswith("fpr:")]
        run([*protected, "--faked-system-time", fake_clock,
             "--quick-add-key", primary, "rsa2048", "sign", "2d"],
            input_bytes=phrase + b"\n", timeout=TIMEOUT)
        records = run([
            *gpg, "--with-colons", "--with-subkey-fingerprint", "--list-keys",
        ], timeout=TIMEOUT).decode().splitlines()
        _, subkey = [row.split(":")[9] for row in records if row.startswith("fpr:")]
        release_file = root / "historical-release"
        release_file.write_bytes(b"Origin: Servonaut\n")
        signed = run([
            *protected, "--faked-system-time", fake_clock, "--local-user", subkey + "!",
            "--digest-algo", "SHA256", "--output", "-", "--clearsign", str(release_file),
        ], input_bytes=phrase + b"\n", timeout=TIMEOUT)
        keyring = root / "retired.gpg"
        keyring.write_bytes(run([*gpg, "--export", primary], timeout=TIMEOUT))
        signer = Signer(home, keyring, subkey, TIMEOUT)
        assert signer.expires_at() < datetime.now(timezone.utc)
        try:
            signer.verify(signed)
        except ArchiveError as error:
            assert "expired" in str(error), error
        else:
            raise AssertionError("An expired signing subkey still verified")
        print("PASS expired signing subkey rejected")
    finally:
        with suppress(ArchiveError):
            run(["gpgconf", "--homedir", str(home), "--kill", "all"], timeout=TIMEOUT)


def main() -> None:
    os.umask(0o022)
    os.environ["LC_ALL"] = "C"
    with tempfile.TemporaryDirectory(prefix="apt-fixture-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        home = root / "keys"
        home.mkdir(mode=0o700)
        try:
            check(root, home)
            check_expired_signing_key(root)
        finally:
            with suppress(ArchiveError):
                run(["gpgconf", "--homedir", str(home), "--kill", "all"], timeout=TIMEOUT)


if __name__ == "__main__":
    main()
