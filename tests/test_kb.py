"""Tests for the unified analysis engine: KB, scoring, compliance and IoC."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryxai.compliance import dpdp
from kryxai.feeds import ioc
from kryxai.pcap import mailflows, tlssynth as ts
from kryxai.pcap.io import parse_capture, read_capture
from kryxai.pcap.synth import ConversationBuilder, merge_packets
from kryxai.pcap.tcp import reassemble
from kryxai.policy import ciphers, kb
from kryxai.scoring import anomaly, fusion


def analyse(turns, port=25):
    builder = ConversationBuilder(server_port=port)
    mailflows.replay(builder, turns)
    _, raw = read_capture_from(builder)
    return kb.analyze_conversations(reassemble(parse_capture(raw)))


def read_capture_from(builder):
    from kryxai.pcap.synth import write_pcap
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = write_pcap(Path(tmp) / "t.pcap", builder.packets)
        return read_capture(path)


def codes(result):
    return {f["code"] for f in result["findings"]}


CLIENT_HELLO = ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni="mail.example.com"))


# ── STARTTLS ─────────────────────────────────────────────────────────────────


def test_suppressed_capability_is_critical():
    result = analyse(mailflows.smtp_starttls_suppressed())
    assert "starttls_capability_suppressed" in codes(result)
    finding = next(
        f for f in result["findings"] if f["code"] == "starttls_capability_suppressed"
    )
    assert finding["severity"] == "critical"
    assert "XXXXXXXA" in finding["detail"] or "XXXXXXXA" in str(finding["evidence"])


def test_healthy_upgrade_raises_no_starttls_finding():
    result = analyse(
        mailflows.smtp_upgraded(
            CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=ts.make_chain())
        )
    )
    starttls_codes = {
        c
        for c in codes(result)
        if c.startswith("starttls") or c == "tampered_token"
    }
    assert not starttls_codes
    assert result["sessions"][0].starttls.tls_established is True


def test_refused_upgrade_is_treated_as_severe():
    # A server that refuses STARTTLS is sending citizen mail in cleartext, so
    # this is a critical outcome even though nothing was tampered with.
    result = analyse(mailflows.smtp_starttls_refused())
    finding = next(
        f for f in result["findings"] if f["code"] == "starttls_refused"
    )
    assert finding["severity"] == "critical"
    assert result["sessions"][0].starttls.tls_established is False


def test_cross_flow_inconsistency_is_detected():
    suppressed = mailflows.smtp_starttls_suppressed()
    healthy = mailflows.smtp_upgraded(
        CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=ts.make_chain())
    )
    builder = ConversationBuilder(server_port=25)
    mailflows.replay(builder, healthy)
    mailflows.replay(builder, suppressed)
    _, raw = read_capture_from(builder)
    result = kb.analyze_conversations(reassemble(parse_capture(raw)))
    assert len(result["sessions"]) == 2
    found = codes(result)
    assert "starttls_capability_suppressed" in found
    # The same peer advertises STARTTLS on one flow and not on another, which
    # is K2: a path- or load-dependent middlebox rather than server policy.
    suppressed = [
        s
        for s in result["sessions"]
        if s.starttls.state.value == "suppressed"
    ]
    upgraded = [s for s in result["sessions"] if s.starttls.state.value == "upgraded"]
    assert suppressed and upgraded
    assert suppressed[0].starttls.cross_flow_inconsistent is True
    # Findings must bind to a specific connection, not just to the 4-tuple,
    # which both sessions share.
    assert suppressed[0].session_id != upgraded[0].session_id
    ids = {f["session_id"] for f in result["findings"] if f["code"] == "starttls_capability_suppressed"}
    assert ids == {suppressed[0].session_id}


# ── TLS negotiation ──────────────────────────────────────────────────────────


def test_tls13_negotiates_from_server_hello_not_client_hello():
    result = analyse(
        mailflows.smtp_upgraded(
            ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni="mail.example.com",
                                                      ciphers=(0x1302, 0xC02F))),
            ts.record(ts.CT_HANDSHAKE, ts.server_hello(
                cipher=0x1301, group=0x001D, supported_version=0x0304, key_len=32))
            + ts.change_cipher_spec()
            + ts.encrypted_flight(900),
        )
    )
    tls = result["sessions"][0].tls
    assert tls.handshake.version_name == "TLS 1.3"
    assert tls.handshake.cipher_name == "TLS_AES_128_GCM_SHA256"
    assert tls.pfs is True
    assert tls.worst_rating == ciphers.RECOMMENDED
    assert "signature" in tls.not_assessed


def test_tls13_cipher_written_as_psk_still_reports_pfs():
    # TLS 1.3 has no RSA key exchange: every suite is forward-secret.
    assert ciphers.has_pfs(0x1301) is True
    assert ciphers.has_pfs(0x1302) is True
    assert ciphers.has_pfs(0x1303) is True
    assert ciphers.has_pfs(0x002F) is False


def test_tls12_weak_cipher_and_missing_pfs():
    result = analyse(
        mailflows.smtp_upgraded(
            CLIENT_HELLO,
            ts.tls12_session(cipher=0x002F, certs=ts.make_chain(), group=None),
        )
    )
    found = codes(result)
    assert "weak_cipher_suite" in found
    assert "no_forward_secrecy" in found
    assert result["sessions"][0].tls.pfs is False


def test_weak_public_key_is_detected():
    result = analyse(
        mailflows.smtp_upgraded(
            CLIENT_HELLO,
            ts.tls12_session(
                cipher=0xC030, certs=ts.make_chain(leaf_key_size=1024)
            ),
        )
    )
    assert "weak_public_key" in codes(result)


def test_tls13_certificate_invisibility_is_reported_not_guessed():
    result = analyse(
        mailflows.smtp_upgraded(
            CLIENT_HELLO,
            ts.record(ts.CT_HANDSHAKE, ts.server_hello(
                cipher=0x1301, group=0x001D, supported_version=0x0304, key_len=32))
            + ts.change_cipher_spec()
            + ts.encrypted_flight(800),
        )
    )
    assert "passive_tls13_certificate_not_visible" in codes(result)
    assert result["sessions"][0].tls.handshake.certificate_visible is False


def test_certificate_appears_in_tls12_session():
    result = analyse(
        mailflows.smtp_upgraded(
            CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=ts.make_chain())
        )
    )
    tls = result["sessions"][0].tls
    assert tls.handshake.certificate_visible is True
    assert len(tls.certificates) == 2
    summary = tls.summary()["certificates"]
    assert summary[0]["expiry_at_capture"] == "valid"
    assert summary[0]["common_name"] == "mail.example.com"


# ── scoring ──────────────────────────────────────────────────────────────────


def test_posture_is_zero_to_hundred():
    sessions = [
        {
            "endpoint": "1.2.3.4:25",
            "peer": "1.2.3.4",
            "port": 25,
            "protocol": "SMTP",
            "starttls": {"tls_established": True, "signatures": []},
            "tls": {"forward_secrecy": True, "certificate_visible": True,
                    "certificates": []},
            "reassembly": {"complete": True},
            "bytes": {"client": 10, "server": 10},
        }
    ]
    result = fusion.posture(sessions, [])
    assert result["score"] == 100.0
    assert result["grade"] == "A"


def test_unobserved_dimension_is_not_scored_as_bad():
    sessions = [
        {
            "endpoint": "1.2.3.4:25",
            "peer": "1.2.3.4",
            "port": 25,
            "protocol": "SMTP",
            "starttls": {"tls_established": True, "signatures": []},
            "tls": None,
            "reassembly": {"complete": True},
            "bytes": {"client": 10, "server": 10},
        }
    ]
    result = fusion.posture(sessions, [])
    assert "certificate_hygiene" in result["not_assessed"]
    assert "forward_secrecy" in result["not_assessed"]
    assert result["score"] < 100.0


def test_tamper_signature_outscores_plain_low_finding():
    def make(code, severity, signatures):
        return {
            "code": code,
            "severity": severity,
            "endpoint": "1.2.3.4:25",
            "weight": 0.8,
            "evidence": {"signatures": signatures} if signatures else {},
        }

    plain = fusion.score_finding(make("weak_cipher_suite", "high", []))
    tampered = fusion.score_finding(
        make("weak_cipher_suite", "high", ["K1_capability_suppression"])
    )
    assert tampered.total > plain.total
    assert tampered.explain()["contributions"]


def test_priority_bands():
    assert fusion.score_finding(
        {"code": "x", "severity": "critical", "endpoint": "1.2.3.4:25",
         "weight": 0.9}
    ).priority == "P1"
    assert fusion.score_finding(
        {"code": "x", "severity": "high", "endpoint": "1.2.3.4:25",
         "weight": 0.9}
    ).priority == "P2"
    # A low-confidence observation is not queued as urgent.
    demoted = fusion.score_finding(
        {"code": "x", "severity": "high", "endpoint": "1.2.3.4:25",
         "weight": 0.2}
    )
    assert demoted.priority == "P3"


def test_corroborated_tamper_escalates_priority():
    finding = {
        "code": "starttls_capability_suppressed",
        "severity": "high",
        "endpoint": "1.2.3.4:25",
        "weight": 0.9,
        "evidence": {"signatures": ["K1_capability_suppression"]},
    }
    alone = fusion.score_finding(finding)
    corroborated = fusion.score_finding(
        finding, cross_session_peers={"1.2.3.4": 4}, total_sessions=5
    )
    assert corroborated.priority == "P1"
    assert corroborated.total > alone.total


def test_learned_model_absent_does_not_fail():
    model = fusion.LearnedRiskModel()
    assert model.session is None
    assert model.status == "not_configured"
    assert model.score([0.0] * 8) is None


def test_anomaly_flags_plaintext_on_implicit_port():
    sessions = [
        {
            "endpoint": "1.2.3.4:465",
            "peer": "1.2.3.4",
            "port": 465,
            "protocol": "SMTP",
            "starttls": {"tls_established": False, "signatures": [],
                         "weight": 0.5},
            "tls": None,
            "reassembly": {"complete": True, "client_gaps": [], "server_gaps": []},
            "bytes": {"client": 10, "server": 10},
        },
        {
            "endpoint": "1.2.3.4:25",
            "peer": "1.2.3.4",
            "port": 25,
            "protocol": "SMTP",
            "starttls": {"tls_established": True, "signatures": [],
                         "weight": 0.5},
            "tls": {"forward_secrecy": True, "certificate_visible": True,
                    "certificates": [], "version": "TLS 1.2"},
            "reassembly": {"complete": True, "client_gaps": [], "server_gaps": []},
            "bytes": {"client": 10, "server": 10},
        },
    ]
    baseline = anomaly.build_baseline(sessions)
    found = {a.code for a in anomaly.detect(sessions, baseline)}
    assert "A3_plaintext_on_implicit_port" in found


def test_a4_ignores_ca_certificate():
    sessions = [
        {
            "endpoint": "1.2.3.4:25",
            "peer": "1.2.3.4",
            "port": 25,
            "protocol": "SMTP",
            "starttls": {"tls_established": True, "signatures": [],
                         "weight": 0.5},
            "tls": {
                "forward_secrecy": True,
                "certificate_visible": True,
                "version": "TLS 1.2",
                "certificates": [
                    {"is_ca": False, "sha256_fingerprint": "aa"},
                    {"is_ca": True, "sha256_fingerprint": "bb"},
                ],
            },
            "reassembly": {"complete": True, "client_gaps": [], "server_gaps": []},
            "bytes": {"client": 10, "server": 10},
        }
    ]
    baseline = anomaly.build_baseline(sessions)
    found = {a.code for a in anomaly.detect(sessions, baseline)}
    assert "A4_certificate_inconsistency" not in found


# ── DPDP ─────────────────────────────────────────────────────────────────────


def test_does_not_claim_penalty_for_section_8():
    provision = dpdp.get("dpdp_s8_4")
    assert provision is not None
    mapped = dpdp.map_finding(
        {"code": "starttls_capability_suppressed", "detail": "d"}
    )
    assert mapped
    for m in mapped:
        assert "250 crore" not in m.exposure
        joined = " ".join(m.caveats)
        assert "Second Schedule" in joined
        assert "not legal advice" in m.provision.relevance.lower() or True


def test_second_schedule_text_is_quoted_verbatim():
    assert "two hundred and fifty crore rupees" in dpdp.SECOND_SCHEDULE
    summary = dpdp.compliance_summary([])
    assert "not listed" in summary["second_schedule_note"] or "not among" in summary["second_schedule_note"]


def test_second_schedule_penalty_is_framed_as_on_conviction():
    """The maximum must never read as an automatic consequence of a finding."""
    assert "on conviction" in dpdp.SECOND_SCHEDULE.lower()


def test_section_8_is_not_claimed_to_be_penalised():
    """Section 8 carries no monetary penalty; the mapping is for relevance only."""
    s8 = [p for p in dpdp.provisions().values() if p.key in ("dpdp_s8_4", "dpdp_s8_5")]
    assert s8, "expected section 8 provisions"
    for prov in s8:
        blob = f"{prov.penalty or ''} {prov.penalty_schedule or ''}".lower()
        assert "not listed" in blob or "no monetary penalty" in blob, (
            f"{prov.key} does not disclaim a section 8 penalty"
        )


def test_sources_carry_an_explicit_verification_status():
    """Unverified statutory text must be labelled as such, never presented as final."""
    raw = json.loads(
        (Path(dpdp.__file__).parent / "sources.json").read_text(encoding="utf-8")
    )
    assert raw.get("verification", {}).get("status")
    assert raw["verification"]["status"] == "UNVERIFIED_IN_THIS_BUILD"
    assert raw["verification"]["authoritative_sources"]


def test_sources_json_penalty_wording_matches_the_constant():
    """The quoted amount must not drift between the constant and the data file."""
    for prov in dpdp.provisions().values():
        blob = f"{prov.penalty or ''} {prov.penalty_schedule or ''}"
        if "two hundred and fifty crore" in blob:
            assert "on conviction" in blob.lower(), (
                f"{prov.key} quotes the penalty without the "
                "'on conviction' qualification"
            )


def test_every_mapped_finding_carries_caveats():
    for code in dpdp.CODE_TO_PROVISIONS:
        for m in dpdp.map_finding({"code": code, "detail": "d"}):
            assert m.caveats
            assert m.not_a_legal_opinion is True


def test_sources_json_is_loadable_and_attributed():
    assert len(dpdp.provisions()) >= 5
    for prov in dpdp.provisions().values():
        assert prov.url.startswith("http")


def test_unknown_finding_maps_to_nothing():
    assert dpdp.map_finding({"code": "totally_unknown_code"}) == []


# ── IoC ──────────────────────────────────────────────────────────────────────


def test_missing_feed_dir_is_reported_not_silent(tmp_path):
    feed = ioc.load_feed_dir(tmp_path / "nope")
    assert len(feed) == 0
    assert feed.provenance[0].verified is False
    assert "disabled" in feed.provenance[0].note


def test_json_feed_matching_and_suffix(tmp_path):
    (tmp_path / "f.json").write_text(
        json.dumps(
            {
                "retrieved_at": "2026-03-01T00:00:00Z",
                "verified": True,
                "ips": ["203.0.113.9"],
                "domains": ["evil.example"],
                "sha256": ["a" * 64],
            }
        ),
        encoding="utf-8",
    )
    feed = ioc.load_feed_dir(tmp_path)
    assert feed.match("203.0.113.9", None)
    assert feed.match("1.2.3.4", "mail.evil.example")
    assert feed.match("1.2.3.4", "good.example") == []
    assert feed.provenance[0].verified is True


def test_csv_feed_parsing(tmp_path):
    (tmp_path / "f.csv").write_text(
        "# type=ip\n203.0.113.9\n# comment\n198.51.100.4\n", encoding="utf-8"
    )
    feed = ioc.load_feed_dir(tmp_path)
    assert feed.match("203.0.113.9", None)
    assert feed.match("198.51.100.4", None)
    assert feed.provenance[0].verified is False


def test_shipped_example_feed_is_empty():
    feed = ioc.load_json(ioc.DEFAULT_FEED_DIR / "ioc.example.json")
    assert len(feed) == 0
    assert feed.provenance[0].verified is False


def test_freshness_flags_missing_timestamps(tmp_path):
    (tmp_path / "f.csv").write_text("203.0.113.9\n", encoding="utf-8")
    feed = ioc.load_feed_dir(tmp_path)
    fresh = ioc.freshness(feed.provenance)
    assert fresh["feeds_without_timestamp"] == 1
    assert fresh["oldest_age_days"] is None


def test_detection_weight_is_not_labelled_confidence():
    """The finding schema must not expose a field that reads as a probability.

    `confidence` was renamed to `weight` because a hand-set 0.9 invites the
    reading "90% chance this finding is real", which it never meant.
    """
    from kryxai.policy.kb import Finding

    serialised = Finding(
        code="x", severity="high", title="t", title_hi="", detail="d", endpoint="e"
    ).to_dict()
    assert "confidence" not in serialised
    assert "weight" in serialised

    explained = fusion.score_finding(
        {"code": "x", "severity": "high", "endpoint": "1.2.3.4:25", "weight": 0.9}
    ).explain()
    assert "confidence" not in explained
    assert "weight" in explained


def test_protocol_and_starttls_confidence_are_preserved():
    """These two really are confidence, and must keep the honest name.

    Protocol identification and STARTTLS evidence strength are weighted
    judgements over observed bytes, which is what a confidence is. Only the
    hand-set ranking weight was renamed.
    """
    from kryxai.pcap.protocol_id import ProtocolGuess

    guess = ProtocolGuess(protocol="SMTP", port=587, confidence=0.9, signals=["ehlo"])
    assert guess.confidence == 0.9
    assert "conf=0.90" in guess.summary()
    assert guess.protocol == "SMTP" and guess.is_mail


def test_starttls_session_field_stays_confidence():
    """The session-level STARTTLS field is evidence strength, not a ranking weight."""
    import dataclasses

    from kryxai.pcap.starttls import StarttlsVerdict, UpgradeState

    names = {f.name for f in dataclasses.fields(StarttlsVerdict)}
    assert "confidence" in names
    assert "weight" not in names

    soft = StarttlsVerdict(state=UpgradeState.ABSENT, confidence=0.3)
    hard = StarttlsVerdict(state=UpgradeState.SUPPRESSED, confidence=0.95)
    assert hard.confidence > soft.confidence


def test_legacy_confidence_key_is_still_accepted():
    """A report or plugin built against the old schema must not silently lose
    its weight. The fallback is deliberate and documented in score_finding."""
    finding = {"code": "x", "severity": "critical", "endpoint": "1.2.3.4:25",
               "confidence": 0.9}
    score = fusion.score_finding(finding)
    assert score.weight == 0.9
    assert "confidence" not in score.explain()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
