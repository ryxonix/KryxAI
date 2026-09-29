"""Interception evidence: the claim, its limits, and what it must never say."""

from __future__ import annotations

import pytest

from kryxai import interception
from kryxai.pcap.starttls import upgrade_token_for


def _session(**over):
    base = {
        "session_id": "s1",
        "endpoint": "10.0.0.5:587",
        "protocol": "SMTP",
        "port": 587,
        "starttls": {
            "state": "suppressed",
            "advertised": False,
            "upgrade_attempted": False,
            "server_ready": False,
            "tls_established": False,
            "encrypted_bytes": 0,
            "signatures": ["K1_capability_suppression"],
            "obfuscated_tokens": ["XXXXXXXA"],
            "cross_flow_inconsistent": False,
            "confidence": 0.9,
            "remediation": "require TLS on the server",
            "downgrade": True,
        },
    }
    base.update(over)
    return base


# ── the three verdicts ────────────────────────────────────────────────────────


def test_altered_advertisement_is_reported_as_tampered():
    out = interception.build_interception([_session()])
    assert out["verdict"] == "tampered_advertisement"
    assert out["sessions_tampered"] == 1
    assert out["sessions_cleartext"] == 1
    assert out["sessions_upgraded"] == 0


def test_cleartext_with_intact_advertisement_is_not_called_tampering():
    """A misconfigured server that simply never offers TLS is not a middlebox.

    Collapsing these two into one state would put "somebody forgot to configure
    STARTTLS" in the same bucket as "something rewrote the advertisement", which
    is the distinction the whole product rests on.
    """
    s = _session()
    s["starttls"] = dict(s["starttls"], signatures=[], obfuscated_tokens=[])
    s["starttls"]["state"] = "absent"
    out = interception.build_interception([s])
    assert out["verdict"] == "unencrypted_but_unmodified"
    assert out["sessions_tampered"] == 0
    assert out["sessions_cleartext"] == 1


def test_fully_upgraded_clean_capture_reports_no_evidence():
    s = _session()
    s["starttls"] = dict(
        s["starttls"],
        state="completed",
        advertised=True,
        tls_established=True,
        encrypted_bytes=4096,
        signatures=[],
        obfuscated_tokens=[],
        downgrade=False,
    )
    out = interception.build_interception([s])
    assert out["verdict"] == "no_evidence_of_interception"
    assert "reached an established TLS state" in out["headline"]


def test_no_mail_sessions_does_not_crash_or_claim_success():
    out = interception.build_interception(
        [{"session_id": "x", "protocol": "HTTP", "port": 80, "starttls": {}}]
    )
    assert out["sessions_assessed"] == 0
    assert out["verdict"] == "no_evidence_of_interception"
    assert "0 mail session(s)" in out["headline"]


# ── expected-token correctness per protocol ──────────────────────────────────


@pytest.mark.parametrize("protocol", ["SMTP", "IMAP", "POP3"])
def test_expected_token_comes_from_the_detector_not_a_local_table(protocol):
    """The 'expected' column must not drift from what the parser enforced."""
    s = _session(protocol=protocol, port=25)
    out = interception.build_interception([s])
    assert out["sessions"][0]["expected_token"] == upgrade_token_for(protocol)


def test_pop3_evidence_does_not_describe_a_starttls_token():
    """POP3 advertises STLS. A STARTTLS-shaped claim there would be wrong."""
    s = _session(protocol="POP3", port=110)
    out = interception.build_interception([s])
    detail = out["sessions"][0]["signature_details"][0]
    assert out["sessions"][0]["expected_token"] == "STLS"
    assert "STARTTLS" not in detail["title"]
    assert "STARTTLS" not in detail["mechanism"]


# ── the attribution limit ────────────────────────────────────────────────────


def test_report_does_not_attribute_intent():
    """Evidence shows alteration. It cannot show who did it or why.

    "hostile" is allowed to appear, but only inside the sentence that explicitly
    disclaims the distinction. A word-level ban would forbid that disclaimer and
    leave the tool making a stronger claim than a capture supports.
    """
    out = interception.build_interception([_session()])
    claims = out["headline"] + " ".join(d["why_it_matters"] for s in out["sessions"] for d in s["signature_details"])
    for word in ("attacker", "malicious", "hostile", "adversary", "eavesdrop"):
        assert word not in claims.lower(), f"report asserts {word!r} without evidence"


def test_attribution_limit_is_present_in_every_verdict():
    for s in (_session(), _session(starttls={}), _session()):
        out = interception.build_interception([s])
        assert out["attribution_limit"]
        assert "does not attribute intent" in out["attribution_limit"]


def test_why_passive_explains_the_scanner_limitation():
    out = interception.build_interception([_session()])
    text = out["why_passive"]
    assert "receives the rewritten greeting" in text
    assert "before any rewriting" in text


# ── shape ────────────────────────────────────────────────────────────────────


def test_clean_advertisement_is_omitted_rather_than_shown_as_empty():
    """`observed_tokens: null` beats `[]`: an empty list reads as a finding."""
    s = _session()
    s["starttls"] = dict(s["starttls"], signatures=[], obfuscated_tokens=[])
    out = interception.build_interception([s])
    assert out["sessions"][0]["observed_tokens"] is None


def test_every_reported_signature_has_a_description():
    for sig in interception._SIGNATURES:
        detail = interception._SIGNATURES[sig]
        for key in ("title", "reference", "mechanism", "why_it_matters"):
            assert detail.get(key), f"{sig} is missing {key}"


def test_anomalies_are_attached_to_their_own_session():
    s = _session()
    out = interception.build_interception(
        [s],
        anomalies=[
            {"session_id": "s1", "code": "A1_tamper_signature"},
            {"session_id": "s2", "code": "A6_size_outlier"},
        ],
    )
    assert out["sessions"][0]["anomalies"] == ["A1_tamper_signature"]
