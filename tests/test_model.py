"""Tests for the optional learned-model integration.

KryxAI must behave identically whether or not a model file is present, and must
refuse a model built against a different feature schema rather than applying it
to a vector it was never trained for. These tests cover both, and they run
without onnx installed: the refusal paths are checked against deliberately
malformed files, so a missing optional dependency does not turn into a skip that
hides a real problem.
"""

from __future__ import annotations

import importlib
import json
import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

from kryxai.config import PACKAGE_DIR, Settings
from kryxai.engine import run_scan
from kryxai.pcap import corpus
from kryxai.scoring import fusion

# Resolved from the installed package, not from this file's location. A test that
# looked for the model next to the tests would skip in a wheel install, where the
# model is present in site-packages but no source tree exists beside the tests.
BUNDLED = PACKAGE_DIR / "scoring" / "risk_model.onnx"
CARD = PACKAGE_DIR / "scoring" / "model_card.json"

onnxruntime = importlib.util.find_spec("onnxruntime") is not None
needs_ort = pytest.mark.skipif(not onnxruntime, reason="onnxruntime not installed")
# These build ONNX fixtures on disk, so they need the onnx writer too, not just
# the runtime.
needs_onnx = pytest.mark.skipif(
    not onnxruntime or importlib.util.find_spec("onnx") is None,
    reason="needs both onnx and onnxruntime to build a fixture",
)


@pytest.fixture
def weak_capture(tmp_path):
    corpus.generate(tmp_path)
    return tmp_path / "04_weak_tls12_no_pfs.pcap"


def _settings(**kw):
    """Rules-only by default, so a test does not silently depend on a model."""
    kw.setdefault("onnx_model_path", "")
    return Settings(blockchain_difficulty=1, **kw)


# ── resolution ──────────────────────────────────────────────────────────────

def test_three_resolution_states():
    assert Settings(onnx_model_path="").resolved_onnx_model_path() == ""
    assert Settings(onnx_model_path="C:/m.onnx").resolved_onnx_model_path() == "C:/m.onnx"
    # The default must resolve to a bundled model when one is installed, or to
    # nothing when it is not. Either way it must never raise.
    Settings().resolved_onnx_model_path()


def test_explicit_empty_never_picks_up_a_bundled_model():
    """Turning the model off has to work even with a model installed."""
    assert Settings(onnx_model_path="").resolved_onnx_model_path() == ""


# ── rules-only is the default behaviour ─────────────────────────────────────

def test_rules_only_scan_reports_no_model(weak_capture):
    report = run_scan(weak_capture, _settings(), persist=False).report
    assert report["model"]["used"] is False
    assert report["model"]["status"] == "not_configured"
    assert report["model"]["model_score_mean"] is None
    for finding in report["findings"]:
        assert finding["risk"]["model_score"] is None


@needs_ort
def test_session_model_score_field_is_always_present(weak_capture):
    """`sessions[].model_score` must exist with or without a model.

    A field that only appears when a model is configured makes the same
    expression mean `undefined` on a rules-only install and a number on one
    with a model, and a consumer cannot distinguish a missing key from a
    deliberate null.
    """
    without = run_scan(weak_capture, _settings(), persist=False).report
    with_model = run_scan(
        weak_capture, Settings(blockchain_difficulty=1), persist=False
    ).report

    for report, expected_null in ((without, True), (with_model, False)):
        assert report["sessions"], "expected sessions"
        for session in report["sessions"]:
            assert "model_score" in session, (
                f"model_score missing from session {session['session_id']}"
            )
            value = session["model_score"]
            if expected_null:
                assert value is None
            else:
                assert isinstance(value, float)


def test_every_finding_records_its_rule_score(weak_capture):
    """The rule score is always present, so a fused total is always checkable."""
    report = run_scan(weak_capture, _settings(), persist=False).report
    assert report["findings"], "expected findings in this capture"
    for finding in report["findings"]:
        risk = finding["risk"]
        assert isinstance(risk["rule_score"], (int, float))
        assert risk["rule_score"] == risk["total"], (
            "with no model the total must be the rule score, not a blend"
        )


def test_model_metadata_is_reported_even_without_a_model(weak_capture):
    report = run_scan(weak_capture, _settings(), persist=False).report
    assert report["model"]["feature_schema_version"] == fusion.FEATURE_SCHEMA_VERSION
    assert report["model"]["feature_count"] == len(fusion.FEATURE_NAMES)
    assert report["model"]["model_schema_version"] is None


# ── refusal paths ───────────────────────────────────────────────────────────

def test_a_missing_model_never_fails_a_scan(weak_capture, tmp_path):
    report = run_scan(
        weak_capture,
        _settings(onnx_model_path=str(tmp_path / "nope.onnx")),
        persist=False,
    ).report
    assert report["findings"], "the scan must still produce findings"
    assert report["model"]["used"] is False
    assert "unavailable" in report["model"]["status"]


def test_a_garbage_file_is_reported_not_raised(weak_capture, tmp_path):
    junk = tmp_path / "junk.onnx"
    junk.write_bytes(b"this is not a model")
    report = run_scan(
        weak_capture, _settings(onnx_model_path=str(junk)), persist=False
    ).report
    assert report["model"]["used"] is False
    assert report["findings"]


class _FakeMeta:
    def __init__(self, mapping):
        self.custom_metadata_map = mapping


class _FakeSession:
    """Stands in for an onnxruntime session so the refusal logic is testable
    without onnx or onnxruntime installed.

    The guards that matter most — refusing an unpinned or stale model — are
    ordinary string comparisons in _check_schema. Requiring a full ONNX
    toolchain to test them would mean the guards went unverified in exactly the
    base install where a user is most likely to be surprised by them.
    """

    def __init__(self, mapping):
        self._meta = _FakeMeta(mapping)

    def get_modelmeta(self):
        return self._meta


def _check(metadata):
    """Run _check_schema against a metadata dict; return the error message or None."""
    loader = fusion.LearnedRiskModel.__new__(fusion.LearnedRiskModel)
    loader.session = _FakeSession(metadata)
    loader.status = "loaded"
    loader.schema_version = None
    try:
        loader._check_schema()
    except Exception as exc:  # noqa: BLE001 - the message is the assertion
        return str(exc)
    return None


GOOD = {
    "kryxai_feature_schema_version": str(fusion.FEATURE_SCHEMA_VERSION),
    "kryxai_feature_names": ",".join(fusion.FEATURE_NAMES),
}


def test_a_correctly_pinned_model_is_accepted():
    assert _check(GOOD) is None


def test_a_model_without_schema_metadata_is_refused():
    """The most dangerous case: a model that loads but was never pinned."""
    message = _check({})
    assert message is not None
    assert "kryxai_feature_schema_version" in message


def test_a_model_with_blank_metadata_is_refused():
    assert _check({**GOOD, "kryxai_feature_schema_version": ""}) is not None


def test_a_non_numeric_schema_version_is_refused():
    assert _check({**GOOD, "kryxai_feature_schema_version": "two"}) is not None


def test_a_model_from_a_different_schema_version_is_refused():
    """The scenario a version bump exists for: a stale model after a rebuild."""
    stale = fusion.FEATURE_SCHEMA_VERSION - 1
    message = _check({**GOOD, "kryxai_feature_schema_version": str(stale)})
    assert message is not None
    assert "retrain" in message.lower()


def test_reordered_feature_names_are_refused():
    """Right count, right version, wrong order: still refused."""
    shuffled = list(reversed(fusion.FEATURE_NAMES))
    assert _check({**GOOD, "kryxai_feature_names": ",".join(shuffled)}) is not None


def test_a_renamed_feature_is_refused():
    renamed = list(fusion.FEATURE_NAMES)
    renamed[0] = "renamed_feature"
    assert _check({**GOOD, "kryxai_feature_names": ",".join(renamed)}) is not None


def test_a_dropped_feature_is_refused():
    truncated = fusion.FEATURE_NAMES[:-1]
    assert _check({**GOOD, "kryxai_feature_names": ",".join(truncated)}) is not None


def test_absent_feature_names_are_refused():
    """A model that omits the names is refused, not trusted on version alone.

    The version is a manual bump that can be forgotten. The names fail loudly
    the moment a feature is renamed, reordered, added or dropped, so a model
    without them cannot be shown to mean the same thing as this build's vector.
    """
    assert "kryxai_feature_names" in _check(
        {"kryxai_feature_schema_version": str(fusion.FEATURE_SCHEMA_VERSION)}
    )


@needs_onnx
def test_a_model_without_schema_metadata_is_refused_end_to_end(tmp_path):
    """The same guard, through a real file that onnxruntime happily loads."""
    import onnx
    import onnxruntime as ort
    from onnx import TensorProto, helper

    x = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, len(fusion.FEATURE_NAMES)])
    y = helper.make_tensor_value_info("out", TensorProto.FLOAT, [None, 1])
    init = helper.make_tensor(
        "w", TensorProto.FLOAT, [len(fusion.FEATURE_NAMES), 1], [0.0] * len(fusion.FEATURE_NAMES)
    )
    graph = helper.make_graph(
        [helper.make_node("MatMul", ["input", "w"], ["out"])], "g", [x], [y], [init]
    )
    path = tmp_path / "unpinned.onnx"
    onnx.save(helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)]), str(path))

    # The file itself is perfectly loadable, which is the point.
    assert ort.InferenceSession(str(path), providers=["CPUExecutionProvider"]) is not None

    model = fusion.LearnedRiskModel(str(path))
    assert model.session is None, "an unpinned model must not be accepted"
    assert "unavailable" in model.status
    assert model.score([0.0] * len(fusion.FEATURE_NAMES)) is None


@needs_onnx
def test_a_stale_model_is_refused_end_to_end(tmp_path):
    """The same version guard, through a real file."""
    import numpy as np
    import onnx
    from onnx import TensorProto, helper

    n = len(fusion.FEATURE_NAMES)
    x = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, n])
    y = helper.make_tensor_value_info("out", TensorProto.FLOAT, [None, 1])
    init = helper.make_tensor("w", TensorProto.FLOAT, [n, 1], [0.0] * n)
    graph = helper.make_graph(
        [helper.make_node("MatMul", ["input", "w"], ["out"])], "g", [x], [y], [init]
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.metadata_props.append(
        onnx.StringStringEntryProto(
            key="kryxai_feature_schema_version", value=str(fusion.FEATURE_SCHEMA_VERSION - 1)
        )
    )
    model.metadata_props.append(
        onnx.StringStringEntryProto(key="kryxai_feature_names", value=",".join(fusion.FEATURE_NAMES))
    )
    path = tmp_path / "stale.onnx"
    onnx.save(model, str(path))

    loader = fusion.LearnedRiskModel(str(path))
    assert loader.session is None
    assert "unavailable" in loader.status
    assert loader.score(np.zeros(n, dtype="float32")) is None


@needs_onnx
def test_reordered_feature_names_are_refused_end_to_end(tmp_path):
    """Right count, right version, wrong order: still refused, via a real file."""
    import onnx
    from onnx import TensorProto, helper

    n = len(fusion.FEATURE_NAMES)
    shuffled = list(reversed(fusion.FEATURE_NAMES))
    x = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, n])
    y = helper.make_tensor_value_info("out", TensorProto.FLOAT, [None, 1])
    init = helper.make_tensor("w", TensorProto.FLOAT, [n, 1], [0.0] * n)
    graph = helper.make_graph(
        [helper.make_node("MatMul", ["input", "w"], ["out"])], "g", [x], [y], [init]
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.metadata_props.append(
        onnx.StringStringEntryProto(
            key="kryxai_feature_schema_version", value=str(fusion.FEATURE_SCHEMA_VERSION)
        )
    )
    model.metadata_props.append(
        onnx.StringStringEntryProto(key="kryxai_feature_names", value=",".join(shuffled))
    )
    path = tmp_path / "reordered.onnx"
    onnx.save(model, str(path))

    loader = fusion.LearnedRiskModel(str(path))
    assert loader.session is None
    assert "unavailable" in loader.status


# ── the installed model, if the notebook has been run ───────────────────────

@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
@needs_ort
def test_an_installed_model_loads_and_scores():
    loader = fusion.LearnedRiskModel(str(BUNDLED))
    assert loader.status == "loaded", loader.status
    assert loader.schema_version == fusion.FEATURE_SCHEMA_VERSION
    value = loader.score([0.0] * len(fusion.FEATURE_NAMES))
    assert value is not None
    assert 0.0 <= value <= 1.0


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
@needs_ort
def test_an_installed_model_scores_a_real_scan(weak_capture):
    # onnx_model_path=None is the auto state, which is what a plain install uses.
    report = run_scan(weak_capture, Settings(blockchain_difficulty=1), persist=False).report
    assert report["model"]["used"] is True
    assert report["model"]["model_schema_version"] == fusion.FEATURE_SCHEMA_VERSION
    assert report["model"]["model_score_mean"] is not None
    for finding in report["findings"]:
        risk = finding["risk"]
        assert risk["model_score"] is not None
        # Both scores recorded, so a reader can check the blend.
        assert risk["rule_score"] is not None


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
@needs_ort
def test_run_scan_scores_the_same_vector_training_saw(weak_capture):
    """The training/serving contract, checked against the real scan path.

    training/dataset.py builds one row per session with
    fusion.session_feature_row(). If run_scan() scored findings individually
    instead, the model would be fed a distribution it was never trained on and
    every assertion here would be comparing the wrong two numbers. This is the
    regression guard for that: it reconstructs the training-time row for each
    session and requires the served score to match exactly.
    """
    import numpy as np

    settings = Settings(blockchain_difficulty=1)
    report = run_scan(weak_capture, settings, persist=False).report
    loader = fusion.LearnedRiskModel(str(BUNDLED))

    from kryxai.scoring import anomaly

    sessions = report["sessions"]
    assert sessions, "expected sessions"
    peers = anomaly.build_baseline(sessions).peer_counts()
    findings_by_session: dict = {}
    for f in report["findings"]:
        findings_by_session.setdefault(str(f.get("session_id") or ""), []).append(f)

    checked = 0
    for session in sessions:
        sid = str(session["session_id"])
        # Recompute exactly what the training pipeline would have produced.
        expected = loader.score(
            fusion.session_feature_row(
                session, findings_by_session.get(sid, []), peers
            )
        )
        served = session.get("model_score")
        assert served is not None, f"clean session {sid} was not model-scored"
        np.testing.assert_allclose(
            served, expected, rtol=0, atol=1e-6, err_msg=f"session {sid} drifted"
        )
        checked += 1

    assert checked == len(sessions)
    assert report["model"]["sessions_scored"] == len(sessions)
    assert report["model"]["sessions_total"] == len(sessions)


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
@needs_ort
def test_a_clean_session_is_still_model_scored(weak_capture):
    """A session with no findings must not silently escape the model.

    These clean examples are the only thing that teaches the model what
    "acceptable" looks like. If they were skipped at serve time, the model would
    be trained on a distribution the product never presents to it.
    """
    report = run_scan(weak_capture, Settings(blockchain_difficulty=1), persist=False).report
    scored_with_findings = {
        str(f.get("session_id") or "")
        for f in report["findings"]
        if f["risk"]["model_score"] is not None
    }
    assert scored_with_findings
    # A clean session has no findings, so it can only appear in the session list.
    all_sessions = {str(s["session_id"]) for s in report["sessions"]}
    clean = [
        s
        for s in report["sessions"]
        if str(s["session_id"]) not in scored_with_findings
    ]
    for s in clean:
        assert s.get("model_score") is not None, f"clean session {s['session_id']} unscored"
    assert set(s["session_id"] for s in clean) <= all_sessions



@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
def test_the_model_card_matches_the_built_model():
    card = json.loads(CARD.read_text(encoding="utf-8"))
    assert card["feature_schema_version"] == fusion.FEATURE_SCHEMA_VERSION
    assert card["feature_names"] == fusion.FEATURE_NAMES
    assert card["limitations"], "a card with no limitations is not a card"
    assert card["trained_on"]["real_network_captures"] == 0


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
def test_the_card_records_a_range_for_every_feature():
    """Serving clamps out-of-range inputs, so an unrecorded feature is unprotectable."""
    card = json.loads(CARD.read_text(encoding="utf-8"))
    ranges = card.get("feature_ranges")
    assert ranges, "card records no feature ranges, so nothing can be clamped"
    missing = [n for n in fusion.FEATURE_NAMES if n not in ranges]
    assert not missing, f"features with no recorded range: {missing}"
    for name, (lo, hi) in ranges.items():
        assert lo <= hi, f"{name} has an inverted range [{lo}, {hi}]"


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
def test_a_multi_session_capture_does_not_saturate_the_score():
    """A clean session must not score 1.0 because the capture is unusual.

    Every training capture holds a single session, so `cross_session_peer_sessions`
    is constant at 1.0 and the model learned nothing about it. Feeding it 11
    without clamping drove the ReLU stack to a saturated 1.0 on sessions with no
    findings at all, which read as maximum risk.
    """
    out = Path(tempfile.mkdtemp())
    corpus.generate(out)
    report = run_scan(out / "17_session_size_outlier.pcap", persist=False).report
    scores = [s["model_score"] for s in report["sessions"] if s["model_score"] is not None]
    assert scores
    assert max(scores) < 0.5, (
        f"an eleven-session capture saturated the model: max={max(scores):.4f}"
    )


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
def test_clamping_is_reported_rather_than_applied_silently():
    out = Path(tempfile.mkdtemp())
    corpus.generate(out)
    report = run_scan(out / "17_session_size_outlier.pcap", persist=False).report
    model = report["model"]
    assert model["feature_ranges_known"] is True
    assert model["sessions_with_clamped_features"] > 0, (
        "an eleven-session capture should have been clamped and said so"
    )
    assert "cross_session_peer_sessions" in model["clamped_features"]


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
def test_a_capture_inside_the_training_range_is_not_clamped():
    """Clamping must not fire on ordinary input, or the flag means nothing."""
    out = Path(tempfile.mkdtemp())
    corpus.generate(out)
    report = run_scan(out / "01_healthy_smtp_tls12.pcap", persist=False).report
    assert report["model"]["sessions_with_clamped_features"] == 0
    assert report["model"]["clamped_features"] == []


@pytest.mark.skipif(not BUNDLED.is_file(), reason="no model installed")
def test_zero_variance_features_are_named_as_a_limitation():
    """A feature the model learned nothing from must be recorded, not implied."""
    card = json.loads(CARD.read_text(encoding="utf-8"))
    const = [n for n, (lo, hi) in card["feature_ranges"].items() if lo == hi]
    assert const, "expected some features to be constant in training"
    text = " ".join(card["limitations"]).lower()
    assert "zero variance" in text, "the card does not disclose constant features"
    loader = fusion.LearnedRiskModel(str(BUNDLED))
    assert set(loader.constant_features) == set(const)


def test_the_model_orders_the_shipped_corpus_coherently(weak_capture, tmp_path):
    """Ordering must hold on real scans, not only on the notebook's own data.

    The notebook's held-out set is generated by the same code as its training
    set, so `held_out_accuracy = 1.0` cannot notice a train/serve mismatch or a
    fixture that does not contain what its name claims. This walks the shipped
    corpus and requires three bands to stay separated, which is the property the
    model is supposed to provide.

    Before the corpus audit this failed: a clean IMAP capture scored 0.2489 while
    a weak-cipher session scored 0.1632, because that IMAP capture contained no
    TLS at all despite being named and documented as a successful upgrade.
    """
    from kryxai.pcap import corpus as corpus_mod

    loader = fusion.LearnedRiskModel(str(BUNDLED))
    assert loader.status == "loaded", loader.status

    corpus_dir = tmp_path / "corpus"
    corpus_mod.generate(corpus_dir)
    settings = Settings(blockchain_difficulty=1)

    clean: List[float] = []
    weak: List[float] = []
    exposure: List[float] = []
    for pcap in sorted(corpus_dir.glob("*.pcap")):
        report = run_scan(pcap, settings, persist=False).report
        by_session: Dict[str, set] = {}
        for f in report["findings"]:
            by_session.setdefault(str(f.get("session_id") or ""), set()).add(f["code"])
        severities_by_session: Dict[str, set] = {}
        for f in report["findings"]:
            severities_by_session.setdefault(
                str(f.get("session_id") or ""), set()
            ).add(f["severity"])

        for session in report["sessions"]:
            score = session.get("model_score")
            assert score is not None, f"{pcap.name}: session unscored"
            sid = str(session.get("session_id") or "")
            # Bucket per session, not per capture: the mixed capture holds a
            # healthy SMTP flow alongside two suppressed ones, and applying the
            # capture's findings to all three sessions would put a clean session
            # in the exposure band.
            codes = by_session.get(sid, set())
            severities = severities_by_session.get(sid, set())
            # `passive_tls13_certificate_not_visible` is info: TLS 1.3 encrypts
            # the certificate, so its absence is a limit of passive analysis
            # rather than a weakness, and that session belongs in the clean band.
            serious = bool(severities & {"critical", "high", "medium"})
            # Exposure is mail that was actually readable on the wire, which is
            # the model's `exposure` band in training/dataset.py: both the
            # "no upgrade offered" profiles and the suppressed-capability ones
            # are labelled exposure. Bucketing only on the suppression code put a
            # plaintext session on an implicit-TLS port into `weak` purely because
            # the middlebox did not have to suppress anything to cause it, and the
            # model then failed a test that had mislabelled it. The band is a
            # property of the traffic, not of which detector noticed.
            exposed = bool(
                codes
                & {
                    "starttls_capability_suppressed",
                    "starttls_not_offered",
                    "cleartext_mail_session",
                    "A3_plaintext_on_implicit_port",
                }
            )
            if exposed:
                exposure.append(score)
            elif serious:
                weak.append(score)
            else:
                clean.append(score)

    assert clean, "expected control captures with no findings"
    assert weak, "expected captures with findings but no exposure"
    assert exposure, "expected captures with mail readable on the wire"

    assert max(clean) < min(weak), (
        f"a clean capture outscores a weak one: clean max={max(clean):.4f} "
        f"weak min={min(weak):.4f}"
    )
    assert max(weak) < min(exposure), (
        f"a weak-crypto session outscores an exposed one: weak max={max(weak):.4f} "
        f"exposure min={min(exposure):.4f}"
    )
