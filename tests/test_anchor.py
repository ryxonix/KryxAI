"""External anchoring, report rehydration, and the scan listing.

The gateway is stubbed at the socket boundary rather than by patching the
module internals, so these tests exercise the real request building, the real
response parsing, and the real "never claim what did not happen" behaviour.
"""

from __future__ import annotations

import json
import urllib.error

import pytest
from fastapi.testclient import TestClient

from kryxai import api
from kryxai.anchor import (
    AnchorError,
    anchor_report,
    build_anchor_document,
    canonical_json,
    merkle_root,
    sha256_hex,
)
from kryxai.config import Settings
from kryxai.pcap import corpus
from kryxai.store import Store

SUPPRESSED = "02_star_ttlssuppressed_vodafone_style.pcap"


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def test_canonical_json_is_key_order_independent():
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_canonical_json_keeps_unicode_readable():
    assert "क्रिक्सएआई" in canonical_json({"k": "क्रिक्सएआई"}).decode("utf-8")


def test_merkle_root_is_deterministic_and_leaf_sensitive():
    a, b, c = sha256_hex(b"a"), sha256_hex(b"b"), sha256_hex(b"c")
    assert merkle_root([a, b, c]) == merkle_root([a, b, c])
    assert merkle_root([a, b, c]) != merkle_root([a, c, b])
    assert merkle_root([a]) == a


def test_merkle_root_promotes_odd_nodes_instead_of_duplicating():
    a, b, c = sha256_hex(b"a"), sha256_hex(b"b"), sha256_hex(b"c")
    # c is promoted rather than paired with a copy, so the two levels are
    # (a,b) and (c,c) -- not the duplication an even-padding scheme would use.
    level_one = sha256_hex(bytes.fromhex(a) + bytes.fromhex(b))
    level_two = sha256_hex(bytes.fromhex(c) + bytes.fromhex(c))
    expected = sha256_hex(bytes.fromhex(level_one) + bytes.fromhex(level_two))
    assert merkle_root([a, b, c]) == expected


def test_merkle_root_of_no_leaves_is_defined_not_an_error():
    assert merkle_root([]) == sha256_hex(b"")


# --------------------------------------------------------------------------
# Anchor document
# --------------------------------------------------------------------------


def _report(chain_state="pending"):
    return {
        "chain_id": "KryxAIV1",
        "posture": {"grade": "D", "score": 0.2},
        "findings": [{"id": "starttls_suppressed"}],
        "evidence": {
            "scan_id": "CS-WALKTROUGH-009",
            "block_index": 7,
            "block_hash": "ff" * 32,
            "chain_state": chain_state,
        },
    }


def test_anchor_document_covers_every_chaincode_arg():
    doc = build_anchor_document(_report(), b"payload")
    assert set(doc) >= {
        "scan_id",
        "report_id",
        "case_id",
        "file_sha256",
        "merkle_root",
        "block_hash",
        "timestamp",
        "enc_alg",
        "key_fingerprint",
    }
    assert doc["scan_id"] == "CS-WALKTROUGH-009"
    assert doc["file_sha256"] == sha256_hex(b"payload")
    assert doc["block_hash"] == "ff" * 32


def test_anchor_document_does_not_claim_encryption_it_did_not_apply():
    assert build_anchor_document(_report(), b"p")["enc_alg"] == "none"


def test_anchor_document_merkle_root_is_recomputable_from_the_report():
    report = _report()
    doc = build_anchor_document(report, b"payload")
    leaves = [
        sha256_hex(canonical_json(report[key]))
        for key in sorted(report)
        if key != "evidence"
    ]
    assert doc["merkle_root"] == merkle_root(leaves)


# --------------------------------------------------------------------------
# Gateway stubbing
# --------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture()
def settings(tmp_path):
    return Settings(
        database_path=str(tmp_path / "evidence.db"),
        reports_dir=str(tmp_path / "reports"),
        blockchain_external_anchor=True,
        blockchain_anchor_required=False,
        nbf_gateway_url="http://gateway.test:4000",
    )


def _patch_gateway(monkeypatch, store_handler, chaincode_handler):
    import urllib.request

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        if url.endswith("/store"):
            return store_handler(req)
        if url.endswith("/fabric/v1/invokecc"):
            return chaincode_handler(req)
        raise AssertionError(f"unexpected gateway call {url}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


def _ok(payload):
    return lambda req: FakeResponse(json.dumps(payload).encode("utf-8"))


def _http_error(code=502):
    def handler(req):
        raise urllib.error.HTTPError(req.full_url, code, "boom", {}, None)

    return handler


# --------------------------------------------------------------------------
# anchor_report behaviour
# --------------------------------------------------------------------------


def test_anchor_is_skipped_when_external_anchoring_is_disabled(tmp_path, monkeypatch):
    s = Settings(
        database_path=str(tmp_path / "e.db"),
        blockchain_external_anchor=False,
    )
    _patch_gateway(monkeypatch, _ok({"hash": "cid"}), _ok({"status": "SUCCESS"}))
    store = Store(s.database_path)
    try:
        out = anchor_report(_report(), store, s)
    finally:
        store.close()
    assert out["attempted"] is False
    assert out["anchored"] is False


def test_successful_anchor_promotes_state_and_records_it(tmp_path, monkeypatch):
    s = Settings(
        database_path=str(tmp_path / "e.db"),
        blockchain_external_anchor=True,
        nbf_gateway_url="http://gateway.test:4000",
    )
    _patch_gateway(
        monkeypatch,
        _ok({"hash": "QmTestCID"}),
        _ok({"status": "SUCCESS", "tx_id": "tx-123"}),
    )
    # block_anchors has a foreign key onto blocks, so the block has to exist
    # first. This is what run_scan has already done by the time anchoring runs.
    store = Store(s.database_path)
    block = store.append({"probe": "anchor-test"}, difficulty=1)
    index = block.index
    report = _report()
    report["evidence"]["block_index"] = index
    try:
        out = anchor_report(report, store, s)
        anchors = store.anchors(index)
    finally:
        store.close()
    assert out["anchored"] is True
    assert out["ipfs_cid"] == "QmTestCID"
    assert report["evidence"]["chain_state"] == "anchored"
    assert report["evidence"]["external_anchor"] is True
    assert report["external_anchor"]["tx_id"] == "tx-123"
    assert anchors[0]["provider"] == "nbf-fabric"
    assert anchors[0]["tx_ref"] == "tx-123"


def test_chaincode_failure_leaves_the_report_pending(tmp_path, monkeypatch):
    s = Settings(
        database_path=str(tmp_path / "e.db"),
        blockchain_external_anchor=True,
        nbf_gateway_url="http://gateway.test:4000",
    )
    _patch_gateway(
        monkeypatch, _ok({"hash": "QmTestCID"}), _ok({"status": "FAILED"})
    )
    report = _report()
    store = Store(s.database_path)
    try:
        out = anchor_report(report, store, s)
        anchors = store.anchors(7)
    finally:
        store.close()
    assert out["anchored"] is False
    assert report["evidence"]["chain_state"] == "pending"
    assert report["evidence"].get("external_anchor") is not True
    assert anchors == []


def test_unreachable_gateway_leaves_the_report_pending(tmp_path, monkeypatch):
    s = Settings(
        database_path=str(tmp_path / "e.db"),
        blockchain_external_anchor=True,
        nbf_gateway_url="http://gateway.test:4000",
    )
    _patch_gateway(monkeypatch, _http_error(503), _ok({"status": "SUCCESS"}))
    report = _report()
    store = Store(s.database_path)
    try:
        out = anchor_report(report, store, s)
    finally:
        store.close()
    assert out["anchored"] is False
    assert "503" in out["reason"]
    assert report["evidence"]["chain_state"] == "pending"


def test_a_cid_less_store_response_is_not_treated_as_anchored(
    tmp_path, monkeypatch
):
    s = Settings(
        database_path=str(tmp_path / "e.db"),
        blockchain_external_anchor=True,
        nbf_gateway_url="http://gateway.test:4000",
    )
    _patch_gateway(monkeypatch, _ok({}), _ok({"status": "SUCCESS"}))
    report = _report()
    store = Store(s.database_path)
    try:
        out = anchor_report(report, store, s)
    finally:
        store.close()
    assert out["anchored"] is False
    assert report["evidence"]["chain_state"] == "pending"


def test_anchor_never_raises_on_an_unexpected_error(tmp_path, monkeypatch):
    s = Settings(
        database_path=str(tmp_path / "e.db"),
        blockchain_external_anchor=True,
        nbf_gateway_url="http://gateway.test:4000",
    )

    def boom(req):
        raise ValueError("something entirely unexpected")

    _patch_gateway(monkeypatch, boom, _ok({"status": "SUCCESS"}))
    report = _report()
    store = Store(s.database_path)
    try:
        out = anchor_report(report, store, s)
    finally:
        store.close()
    assert out["anchored"] is False
    assert "ValueError" in out["reason"]


def test_scan_without_an_evidence_block_is_skipped(tmp_path, monkeypatch):
    s = Settings(
        database_path=str(tmp_path / "e.db"),
        blockchain_external_anchor=True,
    )
    _patch_gateway(monkeypatch, _ok({"hash": "c"}), _ok({"status": "SUCCESS"}))
    report = _report()
    report["evidence"]["block_index"] = None
    store = Store(s.database_path)
    try:
        out = anchor_report(report, store, s)
    finally:
        store.close()
    assert out["attempted"] is False
    assert "evidence block" in out["reason"]


def test_anchor_error_is_an_exception_type():
    assert issubclass(AnchorError, RuntimeError)


# --------------------------------------------------------------------------
# Report persistence across a restart
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def captures(tmp_path_factory):
    out = tmp_path_factory.mktemp("corpus")
    corpus.generate(out)
    return out


def _bind(monkeypatch, settings):
    monkeypatch.setattr(api, "global_settings", settings)
    monkeypatch.setattr(api, "_scan_cache", api.OrderedDict())


def _scan(client, path):
    return client.post("/api/v1/scan", json={"path": str(path)})


def test_report_survives_a_process_restart(tmp_path, monkeypatch, captures):
    """The core of reload persistence: a new process, same report."""
    settings = Settings(
        database_path=str(tmp_path / "evidence.db"),
        reports_dir=str(tmp_path / "reports"),
        blockchain_external_anchor=False,
    )
    _bind(monkeypatch, settings)
    with TestClient(api.app) as c:
        body = _scan(c, captures / SUPPRESSED).json()
        scan_id = body["scan_id"]
        before = c.get(f"/api/v1/report/{scan_id}").json()

    # Simulate the restart: fresh in-memory cache, same reports directory.
    _bind(monkeypatch, settings)
    with TestClient(api.app) as c:
        after = c.get(f"/api/v1/report/{scan_id}")
        assert after.status_code == 200
        assert after.json()["evidence"]["scan_id"] == scan_id
        assert after.json()["posture"]["grade"] == before["posture"]["grade"]
        assert len(after.json()["findings"]) == len(before["findings"])


def test_missing_report_still_404s_after_disk_lookup(tmp_path, monkeypatch, captures):
    settings = Settings(
        database_path=str(tmp_path / "evidence.db"),
        reports_dir=str(tmp_path / "reports"),
    )
    _bind(monkeypatch, settings)
    with TestClient(api.app) as c:
        r = c.get("/api/v1/report/does-not-exist")
        assert r.status_code == 404


def test_scans_endpoint_lists_recent_reports(tmp_path, monkeypatch, captures):
    settings = Settings(
        database_path=str(tmp_path / "evidence.db"),
        reports_dir=str(tmp_path / "reports"),
        blockchain_external_anchor=False,
    )
    _bind(monkeypatch, settings)
    with TestClient(api.app) as c:
        assert c.get("/api/v1/scans").json()["scans"] == []
        _scan(c, captures / SUPPRESSED)
        scans = c.get("/api/v1/scans").json()["scans"]
    assert len(scans) == 1
    assert scans[0]["chain_state"] == "pending"
    assert scans[0]["findings"] >= 1


def test_report_lookup_refuses_to_traverse_out_of_the_reports_dir(
    tmp_path, monkeypatch
):
    settings = Settings(reports_dir=str(tmp_path / "reports"))
    secret = tmp_path / "secret.json"
    secret.write_text('{"leaked": true}', encoding="utf-8")
    for bad in ("../secret", "..\\secret", "/etc/passwd", ""):
        assert api._load_report_from_disk(bad, settings) is None


def test_health_reports_the_gateway_only_when_anchoring_is_on(tmp_path, monkeypatch):
    off = Settings(blockchain_external_anchor=False, nbf_gateway_url="http://g:4000")
    _bind(monkeypatch, off)
    with TestClient(api.app) as c:
        assert c.get("/health").json()["anchor_gateway"] is None

    on = Settings(blockchain_external_anchor=True, nbf_gateway_url="http://g:4000")
    _bind(monkeypatch, on)
    with TestClient(api.app) as c:
        assert c.get("/health").json()["anchor_gateway"] == "http://g:4000"
