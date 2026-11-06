"""The memory passphrase policy supplies acceptance and user guidance."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from servonaut.services.memory import crypto


@pytest.fixture
def fallback_policy(monkeypatch):
    monkeypatch.setitem(sys.modules, "zxcvbn", None)


@pytest.mark.parametrize(
    ("passphrase", "score"),
    [
        ("", 0),
        ("abcdefg", 0),
        ("abcdefgh", 1),
        ("abcdefghijk", 1),
        ("abcdefghijkl", 2),
        ("Abcdefghijklmn1", 2),
        ("abcdefghijklmnop", 2),
        ("Abcdefghijklmno1", 3),
        ("Abcdefghijklmno!", 3),
        ("Abcdefghijklmnopqrs1!", 4),
    ],
)
def test_assessment_preserves_fallback_scores(fallback_policy, passphrase, score):
    assessment = crypto.assess_passphrase(passphrase)

    assert assessment.score == score
    assert assessment.acceptable is (score >= crypto.MIN_PW_SCORE)


def test_fallback_guidance_explains_each_failed_rule(fallback_policy):
    assessment = crypto.assess_passphrase("lower1234567")

    assert "Use at least 16 characters." in assessment.requirements
    assert any("at least 3 character types" in rule for rule in assessment.requirements)
    assert assessment.feedback == assessment.requirements


@pytest.mark.parametrize(
    ("passphrase", "requirements_met"),
    [
        ("lower1234567", (False, False)),
        ("abcdefghijklmnop", (True, False)),
        ("Short1!", (False, True)),
        ("Abcdefghijklmno1", (True, True)),
    ],
)
def test_each_fallback_rule_has_an_independent_status(fallback_policy, passphrase, requirements_met):
    assessment = crypto.assess_passphrase(passphrase)

    assert assessment.requirements_met == requirements_met
    assert len(assessment.requirements_met) == len(assessment.requirements)


def test_score_threshold_changes_guidance_and_key_acceptance(fallback_policy, monkeypatch):
    monkeypatch.setattr(crypto, "MIN_PW_SCORE", 4)
    passphrase = "Abcdefghijklmno1"
    assessment = crypto.assess_passphrase(passphrase)

    assert not assessment.acceptable
    assert assessment.minimum_score == 4
    assert "Use at least 20 characters." in assessment.requirements
    assert any("at least 4 character types" in rule for rule in assessment.requirements)
    with pytest.raises(crypto.WeakPassphraseError) as error:
        crypto.wrap_private_key(bytes(32), passphrase)
    assert all(message in str(error.value) for message in assessment.feedback)


def test_fallback_rule_change_updates_guidance_and_key_acceptance(fallback_policy, monkeypatch):
    monkeypatch.setattr(
        crypto, "_FALLBACK_SCORE_RULES", ((8, 0), (12, 0), (18, 4), (20, 4)), raising=False,
    )
    passphrase = "Abcdefghijklmno1"
    assessment = crypto.assess_passphrase(passphrase)

    assert not assessment.acceptable
    assert "Use at least 18 characters." in assessment.requirements
    assert any("at least 4 character types" in rule for rule in assessment.requirements)
    with pytest.raises(crypto.WeakPassphraseError) as error:
        crypto.wrap_private_key(bytes(32), passphrase)
    assert all(message in str(error.value) for message in assessment.feedback)


def test_optional_estimator_supplies_feedback_without_fallback_rules(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "zxcvbn", SimpleNamespace(zxcvbn=lambda _value: {
            "score": 2,
            "feedback": {
                "warning": "This passphrase is common.",
                "suggestions": ["Add another word."],
            },
        }),
    )
    assessment = crypto.assess_passphrase("an example")

    assert not assessment.acceptable
    assert assessment.score == 2
    assert assessment.requirements == ("Use a passphrase with a strength score of at least 3/4.",)
    assert assessment.requirements_met == (False,)
    assert "This passphrase is common." in assessment.feedback
    assert "Add another word." in assessment.feedback
    assert not any("16 characters" in rule for rule in assessment.requirements)


def test_accepted_optional_estimator_does_not_apply_fallback_rules(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "zxcvbn", SimpleNamespace(zxcvbn=lambda _value: {"score": 3, "feedback": {}}),
    )
    assessment = crypto.assess_passphrase("an example")

    assert assessment.acceptable
    assert assessment.requirements_met == (True,)
    assert assessment.feedback == ()
    assert crypto.estimate_pw_score("an example") == assessment.score


@pytest.mark.parametrize("minimum_score", [0, 3])
def test_optional_estimator_failure_rejects_the_passphrase(monkeypatch, minimum_score):
    def unavailable(_value):
        raise ValueError("The estimator cannot check this input.")

    monkeypatch.setattr(crypto, "MIN_PW_SCORE", minimum_score)
    monkeypatch.setitem(sys.modules, "zxcvbn", SimpleNamespace(zxcvbn=unavailable))
    assessment = crypto.assess_passphrase("A" * 73)

    assert not assessment.checked
    assert assessment.requirements_met == (False,)
    assert not assessment.acceptable
    assert assessment.feedback == ("Cannot check passphrase strength. Try a different passphrase.",)
    with pytest.raises(crypto.WeakPassphraseError):
        crypto.wrap_private_key(bytes(32), "A" * 73)
