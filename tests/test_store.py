"""Tests for the evidence store, proof-of-work and the scan engine."""

from __future__ import annotations

import json
import sqlite3
import threading

import pytest

from kryxai.config import Settings
from kryxai.engine import normalize_finding, run_scan
from kryxai.pcap import mailflows, tlssynth as ts
from kryxai.pcap.synth import ConversationBuilder, merge_packets, write_pcap
from kryxai.store import GENESIS_PREV, Store, block_hash, pow_hash, proof_of_work


# ── proof of work ────────────────────────────────────────────────────────────


def test_proof_of_work_returns_nonce_not_digest():
    nonce = proof_of_work(GENESIS_PREV, 0, 3)
    assert isinstance(nonce, int)
    assert pow_hash(GENESIS_PREV, 0, nonce).startswith("000")


def test_proof_of_work_is_reproducible():
    assert proof_of_work("abc", 7, 2) == proof_of_work("abc", 7, 2)


def test_pow_hash_matches_stored_nonce():
    nonce = proof_of_work("deadbeef", 3, 2)
    assert pow_hash("deadbeef", 3, nonce).startswith("00")
    assert pow_hash("deadbeef", 3, nonce + 1) != pow_hash("deadbeef", 3, nonce)


# ── chain ────────────────────────────────────────────────────────────────────


def test_append_and_verify_chain():
    store = Store(":memory:")
    b0 = store.append({"a": 1}, difficulty=1)
    b1 = store.append({"a": 2}, difficulty=1)
    assert b0.index == 0 and b0.prev_hash == GENESIS_PREV
    assert b1.index == 1 and b1.prev_hash == b0.block_hash
    result = store.verify_chain()
    assert result["ok"] is True
    assert result["blocks"] == 2


def test_block_hash_is_order_independent_for_payload_keys():
    a = block_hash(0, GENESIS_PREV, {"x": 1, "y": 2})
    b = block_hash(0, GENESIS_PREV, {"y": 2, "x": 1})
    assert a == b


def test_tampered_payload_breaks_verification(tmp_path):
    path = tmp_path / "chain.db"
    store = Store(path)
    store.append({"value": 1}, difficulty=1)
    store.close()

    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE blocks SET payload_json = ? WHERE block_index = 0",
            (json.dumps({"value": 999}),),
        )
        conn.commit()

    result = Store(path).verify_chain()
    assert result["ok"] is False
    assert result["broken_at"] == 0
    assert result["details"][0]["hash_ok"] is False


def test_difficulty_is_stored_per_block_and_reused():
    store = Store(":memory:")
    store.append({"n": 0}, difficulty=1)
    b = store.append({"n": 1}, difficulty=3)
    assert b.difficulty == 3
    stored = {blk.index: blk.difficulty for blk in store.chain()}
    assert stored == {0: 1, 1: 3}
    # Verification must use the stored value, not recompute the schedule.
    assert store.verify_chain()["ok"] is True


def test_concurrent_appends_produce_one_chain():
    store = Store(":memory:")
    errors: list = []

    def worker(i: int) -> None:
        try:
            store.append({"worker": i}, difficulty=1)
        except Exception as exc:  # pragma: no cover - surfaced by the assert
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    chain = store.chain()
    assert [b.index for b in chain] == list(range(8))
    for prev, nxt in zip(chain, chain[1:]):
        assert nxt.prev_hash == prev.block_hash
    assert store.verify_chain()["ok"] is True


def test_anchors_are_recorded_and_reported():
    store = Store(":memory:")
    b = store.append({"n": 0}, difficulty=1)
    assert store.chain()[0].anchored is False
    store.record_anchor(b.index, "nbf-lite", "tx-abc")
    block = store.chain()[0]
    assert block.anchored is True
    assert block.anchor_tx == "tx-abc"
    assert store.anchors(b.index)[0]["provider"] == "nbf-lite"


def test_empty_chain_verifies():
    assert Store(":memory:").verify_chain() == {
        "ok": True,
        "blocks": 0,
        "broken_at": None,
        "details": [],
    }


# ── finding normalisation ────────────────────────────────────────────────────


def test_normalize_finding_fills_schema_and_translation():
    out = normalize_finding({"code": "weak_cipher_suite", "severity": "high",
                             "endpoint": "10.0.0.1:25", "detail": "d"})
    assert out["finding_id"] and len(out["finding_id"]) == 16
    assert out["title"]
    assert out["title_hi"]
    assert out["translation_complete"] is True
    assert out["deliverable"] == "unassigned"


def test_normalize_finding_rejects_unknown_severity():
    out = normalize_finding({"code": "weak_cipher_suite", "severity": "apocalyptic"})
    assert out["severity"] == "info"


def test_normalize_finding_flags_missing_translation():
    out = normalize_finding({"code": "a_code_nobody_translated"})
    assert out["translation_complete"] is False
    assert out["title_hi"] == ""


def test_normalize_finding_preserves_risk():
    out = normalize_finding({"code": "weak_cipher_suite", "risk": {"total": 12.5}})
    assert out["risk"]["total"] == 12.5


# ── engine ───────────────────────────────────────────────────────────────────


def _capture(tmp_path, name, turns, port=25):
    builder = ConversationBuilder(server_port=port)
    mailflows.replay(builder, turns)
    return write_pcap(tmp_path / name, builder.packets)


def test_run_scan_end_to_end(tmp_path):
    pcap = _capture(
        tmp_path,
        "scan.pcap",
        mailflows.smtp_starttls_suppressed(),
    )
    store = Store(":memory:")
    result = run_scan(pcap, Settings(blockchain_difficulty=1), store=store)

    report = result.report
    assert report["source"]["sha256"]
    assert report["capture"]["packet_count"] > 0
    codes = {f["code"] for f in report["findings"]}
    assert "starttls_capability_suppressed" in codes
    assert 0.0 <= report["posture"]["score"] <= 100.0
    assert report["compliance"]["framework"].startswith("Digital Personal")
    assert result.block_index == 0
    assert store.verify_chain()["ok"] is True


def test_run_scan_without_store_does_not_persist(tmp_path):
    pcap = _capture(tmp_path, "n.pcap", mailflows.smtp_healthy())
    report = run_scan(pcap, persist=False).report
    assert report["evidence"]["block_index"] is None
    assert report["evidence"]["chain_state"] == "not_recorded"


def test_posture_is_bounded(tmp_path):
    pcap = _capture(tmp_path, "p.pcap", mailflows.smtp_healthy())
    report = run_scan(pcap, persist=False).report
    assert 0.0 <= report["posture"]["score"] <= 100.0
    assert report["posture"]["grade"] in {"A", "B", "C", "D", "F"}


def test_same_capture_produces_same_chain_payload(tmp_path):
    turns = mailflows.smtp_healthy()
    a = _capture(tmp_path, "a.pcap", turns)
    b = _capture(tmp_path, "b.pcap", turns)
    from kryxai.engine import _chain_payload

    pa = _chain_payload(run_scan(a, persist=False).report)
    pb = _chain_payload(run_scan(b, persist=False).report)
    assert pa["source_sha256"] == pb["source_sha256"]
    assert pa["findings"] == pb["findings"]


def test_certificates_are_persisted(tmp_path):
    ch = ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni="mail.example.com"))
    pcap = _capture(
        tmp_path,
        "c.pcap",
        mailflows.smtp_upgraded(
            ch, ts.tls12_session(cipher=0xC030, certs=ts.make_chain())
        ),
    )
    store = Store(":memory:")
    result = run_scan(pcap, Settings(blockchain_difficulty=1), store=store)
    scan_id = result.report["evidence"]["scan_id"]
    assert store.get_scan(scan_id) is not None


def test_limitations_state_passive_visibility(tmp_path):
    ch = ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni="mail.example.com"))
    pcap = _capture(
        tmp_path,
        "t13.pcap",
        mailflows.smtp_upgraded(
            ch,
            ts.record(ts.CT_HANDSHAKE, ts.server_hello(cipher=0x1301, group=0x001D,
                                                      supported_version=0x0304, key_len=32))
            + ts.change_cipher_spec()
            + ts.encrypted_flight(1024),
        ),
    )
    report = run_scan(pcap, persist=False).report
    joined = " ".join(report["limitations"]).lower()
    assert "encrypted" in joined
    codes = {f["code"] for f in report["findings"]}
    assert "passive_tls13_certificate_not_visible" in codes


def test_run_scan_matches_ioc_indicator_by_sni(tmp_path):
    """End-to-end domain IoC matching through the SNI the client actually sent.

    Regression: the engine read ``tls["server_name"]`` while the TLS summary
    only ever publishes ``tls["sni"]``, so the lookup silently returned None for
    every session. Unit tests of ``IndicatorSet.match`` still passed, because
    they bypass the engine entirely. This exercises the real path.
    """
    sni = "mail.evil.example"
    feed_dir = tmp_path / "feeds"
    feed_dir.mkdir()
    (feed_dir / "campaign.json").write_text(
        json.dumps(
            {
                "domains": [sni],
                "retrieved_at": "2026-01-01T00:00:00Z",
                "verified": True,
                "note": "operator-supplied test feed",
            }
        ),
        encoding="utf-8",
    )

    ch = ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni=sni))
    pcap = _capture(
        tmp_path,
        "sni_ioc.pcap",
        mailflows.smtp_upgraded(
            ch,
            ts.record(ts.CT_HANDSHAKE, ts.server_hello(cipher=0x1301, group=0x001D))
            + ts.change_cipher_spec()
            + ts.encrypted_flight(1024),
        ),
    )

    settings = Settings(
        ioc_feed_dir=str(feed_dir), blockchain_difficulty=1
    )
    report = run_scan(pcap, settings, persist=False).report

    codes = {f["code"] for f in report["findings"]}
    assert "known_malicious_indicator" in codes, (
        "SNI-scoped IoC indicators must be reachable from the engine"
    )
    hit = next(f for f in report["findings"] if f["code"] == "known_malicious_indicator")
    assert any(sni in str(v) for v in hit.get("evidence", {}).values())


def test_run_scan_indicator_finding_carries_session_id(tmp_path):
    """An IoC hit must be attributable to a specific conversation."""
    feed_dir = tmp_path / "feeds"
    feed_dir.mkdir()
    # Match on the peer IP instead of a domain: the SNI path is covered above.
    builder = ConversationBuilder(server_port=25)
    mailflows.replay(builder, mailflows.smtp_starttls_suppressed())
    pcap = write_pcap(tmp_path / "ip_ioc.pcap", builder.packets)
    server_ip = builder.server_ip

    (feed_dir / "ips.json").write_text(
        json.dumps({"ips": [server_ip], "verified": True}), encoding="utf-8"
    )
    report = run_scan(
        pcap, Settings(ioc_feed_dir=str(feed_dir), blockchain_difficulty=1),
        persist=False,
    ).report

    hits = [f for f in report["findings"] if f["code"] == "known_malicious_indicator"]
    assert hits
    assert all(h.get("session_id") for h in hits)
    assert all(h["session_id"].startswith("c") for h in hits)


def test_report_evidence_block_hash_matches_the_chain(tmp_path):
    """The block hash printed in a report must be the one the chain holds.

    A report that cites a hash the ledger does not contain would let an
    operator "verify" against nothing.
    """
    pcap = _capture(tmp_path, "evidence.pcap", mailflows.smtp_starttls_suppressed())
    store = Store(":memory:")
    report = run_scan(pcap, Settings(blockchain_difficulty=1), store=store).report

    ev = report["evidence"]
    assert ev["chain_id"] == "KryxAIV1"
    assert ev["block_index"] == 0
    assert ev["block_hash"]
    assert ev["block_hash"] == store.chain()[0].block_hash


def test_local_block_is_pending_never_anchored(tmp_path):
    """Proof-of-work is tamper-evident, not externally attested."""
    pcap = _capture(tmp_path, "pending.pcap", mailflows.smtp_starttls_suppressed())
    store = Store(":memory:")
    report = run_scan(pcap, Settings(blockchain_difficulty=1), store=store).report
    assert report["evidence"]["chain_state"] == "pending"
    assert report["evidence"]["external_anchor"] is False
    assert store.chain()[0].anchored is False


def test_scan_without_store_reports_not_recorded(tmp_path):
    pcap = _capture(tmp_path, "nostore.pcap", mailflows.smtp_starttls_suppressed())
    report = run_scan(pcap, persist=False).report
    assert report["evidence"]["chain_state"] == "not_recorded"
    assert report["evidence"]["block_index"] is None
    assert report["evidence"]["block_hash"] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
