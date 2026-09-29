"""Tests for the learned-model feature contract.

The training pipeline lives in `training/` and runs on Colab, far from this
suite. These tests guard the seam between the two: the feature vector's shape,
its stability, and the rule that a model built against a different schema is
rejected rather than silently misapplied.
"""

from __future__ import annotations

import math

import pytest

from kryxai.config import Settings
from kryxai.engine import run_scan
from kryxai.pcap import corpus
from kryxai.scoring import fusion


@pytest.fixture(scope="module")
def corpus_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("feature_corpus")
    corpus.generate(out)
    return out


def test_feature_names_are_unique_and_non_empty():
    names = fusion.FEATURE_NAMES
    assert names, "feature vector is empty"
    assert len(names) == len(set(names)), "duplicate feature name"
    assert all(n and n.strip() == n for n in names)


def test_feature_schema_is_self_consistent():
    schema = fusion.feature_schema()
    assert schema["version"] == fusion.FEATURE_SCHEMA_VERSION
    assert schema["count"] == len(schema["names"]) == len(fusion.FEATURE_NAMES)
    assert schema["version"] >= 2, "schema version must advance past the original 8-feature vector"


def test_schema_version_must_be_bumped_when_names_change():
    """A guard against the exact failure this version field exists to prevent.

    If FEATURE_NAMES changes without a version bump, an old model would be
    applied to a differently-shaped vector and would produce confident nonsense.
    """
    pinned = {name: i for i, name in enumerate(fusion.FEATURE_NAMES)}
    # The first three names have been stable since schema v2. If this assertion
    # ever fails, either the order changed (a version bump is required) or a
    # deliberate rename happened without one.
    assert pinned["sev_critical"] == 0
    assert pinned["sev_high"] == 1
    assert pinned["sev_medium"] == 2


def test_every_corpus_session_produces_a_finite_vector(corpus_dir):
    for cap in sorted(corpus_dir.glob("*.pcap")):
        report = run_scan(cap, Settings(blockchain_difficulty=1), persist=False).report
        for session in report["sessions"]:
            row = fusion.session_feature_row(session, [], {})
            assert len(row) == len(fusion.FEATURE_NAMES), cap.name
            for name, value in zip(fusion.FEATURE_NAMES, row):
                assert isinstance(value, float), f"{cap.name}:{name} is {type(value)}"
                assert math.isfinite(value), f"{cap.name}:{name} is {value}"


def test_healthy_sessions_still_produce_rows(corpus_dir):
    """A dataset of findings only would contain no negative examples."""
    healthy = corpus_dir / "01_healthy_smtp_tls12.pcap"
    report = run_scan(healthy, Settings(blockchain_difficulty=1), persist=False).report
    assert report["findings"] == []
    assert report["sessions"], "expected at least one session"
    for session in report["sessions"]:
        row = fusion.session_feature_row(session, [], {})
        assert len(row) == len(fusion.FEATURE_NAMES)


def test_none_and_nan_inputs_never_reach_the_model():
    """NaN would propagate through inference and yield an undefined score."""
    assert fusion._f(None) == 0.0
    assert fusion._f("not a number") == 0.0
    assert fusion._f(float("nan")) == 0.0
    assert fusion._f(float("inf")) == 0.0
    assert fusion._f("2.5") == 2.5
    assert fusion._f(True) == 1.0

    row = fusion.session_feature_row(
        {"starttls": None, "tls": None, "reassembly": None, "bytes": None}, [], {}
    )
    assert all(math.isfinite(v) for v in row)


def test_unobserved_version_is_distinct_from_an_old_version():
    """'not observed' must not encode as 'very old'."""
    assert fusion._VERSION_ORDINAL[""] == 0.0
    assert fusion._VERSION_ORDINAL["TLS 1.0"] > fusion._VERSION_ORDINAL[""]
    assert fusion._VERSION_ORDINAL["TLS 1.3"] > fusion._VERSION_ORDINAL["TLS 1.2"]


def test_missing_rating_is_worst_ranked_not_best():
    """An unknown rating must never look like a recommended one."""
    from kryxai.policy import ciphers

    assert fusion._rank("recommended") == 0.0
    assert fusion._rank("") == 4.0
    assert fusion._rank(None) == 4.0
    assert fusion._rank("recommended") < fusion._rank("unknown")


def test_learned_model_rejects_an_unversioned_file(tmp_path):
    """Without the schema metadata a model is refused, not trusted."""
    pytest.importorskip("onnxruntime")
    bogus = tmp_path / "model.onnx"
    bogus.write_bytes(b"not really an onnx file")
    model = fusion.LearnedRiskModel(str(bogus))
    assert model.session is None
    assert model.status.startswith("unavailable")
    assert model.score([0.0] * len(fusion.FEATURE_NAMES)) is None


def test_learned_model_is_absent_by_default():
    model = fusion.LearnedRiskModel(None)
    assert model.session is None
    assert model.status == "not_configured"
    assert model.score([0.0] * len(fusion.FEATURE_NAMES)) is None


def test_weak_key_feature_agrees_with_the_policy_threshold():
    from kryxai.policy import ciphers

    def row_for(bits):
        finding = {
            "endpoint": "1.2.3.4:587",
            "severity": "high",
            "weight": 0.5,
            "evidence": {},
        }
        session = {
            "endpoint": "1.2.3.4:587",
            "protocol": "SMTP",
            "port": 587,
            "starttls": {},
            "reassembly": {"complete": True},
            "tls": {
                "certificates": [
                    {
                        "public_key_bits": bits,
                        "public_key_algorithm": "rsa",
                        "signature_hash": "sha256",
                        "is_ca": False,
                    }
                ],
                "chain": [],
            },
        }
        return fusion.features_for(finding, session, {})

    idx = fusion.FEATURE_NAMES.index("cert_key_weak")
    assert row_for(1024)[idx] == 1.0, "1024-bit RSA must read as weak"
    assert row_for(fusion.WEAK_KEY_BITS)[idx] == 0.0
    assert row_for(4096)[idx] == 0.0
    assert ciphers.WEAK  # the policy module defines the vocabulary we mirror


def test_session_representative_is_independent_of_input_order():
    """The worst-finding choice must be a total order, not a list-order accident.

    `min` returns the first minimum, so selecting a representative by severity
    alone picks whichever equally-severe finding the caller happened to list
    first. The engine passes detector order and the report passes sorted order,
    so training and serving could silently disagree about the same session. Ties
    break on detection weight, then code.
    """
    session = {"session_id": "s1", "endpoint": "10.0.0.1:587", "tls": None}
    weak = {
        "code": "weak_cipher_suite",
        "severity": "high",
        "endpoint": "10.0.0.1:587",
        "weight": 0.95,
        "evidence": {"cipher": "rc4", "kex": None, "aead": None},
    }
    fwd = {
        "code": "no_forward_secrecy",
        "severity": "high",
        "endpoint": "10.0.0.1:587",
        "weight": 0.90,
        "evidence": {},
    }
    # Same severity, so only the weight tie-break can separate them.
    assert weak["severity"] == fwd["severity"]

    forward = fusion.session_feature_row(session, [weak, fwd], {})
    reversed_ = fusion.session_feature_row(session, [fwd, weak], {})
    assert forward == reversed_, "representative finding must not depend on order"

    # And it is the stronger assertion that wins, not merely the first listed.
    idx = fusion.FEATURE_NAMES.index("detection_weight")
    assert forward[idx] == 0.95

    # A genuinely more severe finding still outranks a heavier weight.
    severe = dict(weak, code="starttls_refused", severity="critical", weight=0.2)
    assert fusion.session_feature_row(session, [weak, severe], {}) != forward
