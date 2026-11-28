"""Vault-held config sync key: encryption without a passphrase or salt."""
from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from servonaut.services import config_crypto
from servonaut.services.config_crypto import DecryptionError

KEY = bytes(range(32))


def test_round_trip_has_no_salt():
    env = config_crypto.encrypt_with_key('{"a": 1}', KEY)
    assert set(env) == {"encryption", "data", "iv", "tag"}
    assert config_crypto.decrypt_with_key(env, KEY) == '{"a": 1}'


def test_wrong_key_fails_generically():
    env = config_crypto.encrypt_with_key("secret", KEY)
    with pytest.raises(DecryptionError):
        config_crypto.decrypt_with_key(env, bytes(32))


def test_tampered_tag_fails():
    env = config_crypto.encrypt_with_key("secret", KEY)
    env["tag"] = base64.b64encode(bytes(16)).decode()
    with pytest.raises(DecryptionError):
        config_crypto.decrypt_with_key(env, KEY)


def test_missing_field_and_bad_algorithm_fail():
    env = config_crypto.encrypt_with_key("secret", KEY)
    with pytest.raises(DecryptionError):
        config_crypto.decrypt_with_key({k: v for k, v in env.items() if k != "iv"}, KEY)
    with pytest.raises(DecryptionError):
        config_crypto.decrypt_with_key({**env, "encryption": "none"}, KEY)


def test_key_length_enforced():
    with pytest.raises(ValueError):
        config_crypto.encrypt_with_key("x", b"short")


def test_key_id_vector():
    expected = hmac.new(KEY, b"servonaut-config-sync-key-id-v1", hashlib.sha256).hexdigest()
    assert config_crypto.key_id(KEY) == expected
    assert len(expected) == 64
    assert config_crypto.key_id(bytes(32)) != expected


def test_passphrase_and_vault_schemes_do_not_cross():
    """Different associated data: a vault envelope never opens as a passphrase one."""
    assert config_crypto.VAULT_ASSOCIATED_DATA == b"servonaut-config-vault-v1"
    assert config_crypto.VAULT_ASSOCIATED_DATA != config_crypto.ASSOCIATED_DATA
    env = config_crypto.encrypt_with_key("x", KEY)
    env["salt"] = base64.b64encode(bytes(16)).decode()
    with pytest.raises(DecryptionError):
        config_crypto.decrypt(env, "some-long-passphrase")


def test_generate_key_is_32_random_bytes():
    a, b = config_crypto.generate_key(), config_crypto.generate_key()
    assert len(a) == 32 and a != b
