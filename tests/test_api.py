"""API surface tests.

These drive the real ASGI app through TestClient against a temporary database
and report directory, so the anchor gate, the store lifecycle and the
in-process report cache are covered as actually wired.
"""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from kryxai import api
from kryxai.config import Settings
from kryxai.pcap import corpus

SUPPRESSED = "02_star_ttlssuppressed_vodafone_style.pcap"
HEALTHY = "01_healthy_smtp_tls12.pcap"


@pytest.fixture(scope="module")
def captures(tmp_path_factory):
    out = tmp_path_factory.mktemp("corpus")
    corpus.generate(out)
    return out


@pytest.fixture()
def client(tmp_path, monkeypatch, captures):
    settings = Settings(
        database_path=str(tmp_path / "evidence.db"),
        reports_dir=str(tmp_path / "reports"),
        blockchain_external_anchor=False,
        blockchain_anchor_required=False,
    )
    _bind(monkeypatch, settings)
    with TestClient(api.app) as c:
        yield c


def _bind(monkeypatch, settings):
    """Point the whole app at a temp settings object.

    ``get_settings`` resolves ``global_settings`` at call time, so patching that
    one name is enough for both the dependency-injected endpoints and the ones
    that read it directly.
    """
    monkeypatch.setattr(api, "global_settings", settings)
    monkeypatch.setattr(api, "_scan_cache", api.OrderedDict())


def _scan(client, path, **kw):
    return client.post("/api/v1/scan", json={"path": str(path), **kw})


# --------------------------------------------------------------------------
# health / capabilities
# --------------------------------------------------------------------------


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert body["chain_id"] == "KryxAIV1"


def test_capabilities_states_passive_limits(client):
    body = client.get("/api/v1/capabilities").json()
    assert body["passive_only"] is True
    assert set(body["protocols"]) == {"SMTP", "IMAP", "POP3"}
    assert "K1_capability_suppression" in body["starttls_signatures"]
    # TLS 1.3 certificate invisibility must be stated, not glossed over.
    assert "TLS 1.3" in body["tls_versions_visible"]
    assert any("not visible" in n for n in body["known_limitations"])


def test_capabilities_ioc_block_reports_provenance(client):
    ioc_block = client.get("/api/v1/capabilities").json()["ioc"]
    # Counts and provenance are exposed; raw indicator values are not echoed.
    assert "counts" in ioc_block
    assert set(ioc_block["counts"]) >= {"ips", "domains"}
    assert ioc_block["provenance"], "every feed must carry provenance"
    for entry in ioc_block["provenance"]:
        assert "source" in entry
        assert "verified" in entry


def test_shipped_example_feed_is_unverified(client):
    """The bundled snapshot must not be presented as an authoritative feed."""
    ioc_block = client.get("/api/v1/capabilities").json()["ioc"]
    assert all(e["verified"] is False for e in ioc_block["provenance"])


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------


def test_scan_path_then_fetch_report(client, captures):
    r = _scan(client, captures / SUPPRESSED)
    assert r.status_code == 200, r.text
    summary = r.json()
    assert summary["findings"] >= 1
    assert summary["sessions"] == 1
    # Permissive posture: the report is generated but never claims an anchor.
    assert summary["chain_state"] == "pending"
    assert summary["report_files"]

    got = client.get(f"/api/v1/report/{summary['scan_id']}")
    assert got.status_code == 200
    assert got.json()["evidence"]["scan_id"] == summary["scan_id"]


def test_scan_reports_posture_and_block_index(client, captures):
    body = _scan(client, captures / HEALTHY).json()
    assert body["block_index"] == 0
    assert body["posture_grade"] in {"A", "B", "C", "D", "F"}
    assert 0 <= body["posture_score"] <= 100


def test_healthy_capture_produces_no_findings(client, captures):
    body = _scan(client, captures / HEALTHY).json()
    assert body["findings"] == 0, "healthy TLS 1.2 case must stay clean"


def test_scan_unsupported_suffix_is_415(client, tmp_path):
    fake = tmp_path / "capture.txt"
    fake.write_text("hello")
    assert _scan(client, fake).status_code == 415


def test_scan_missing_file_is_404(client, tmp_path):
    assert _scan(client, tmp_path / "nope.pcap").status_code == 404


def test_scan_corrupt_capture_is_422_not_500(client, tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap file at all")
    r = _scan(client, bad)
    assert r.status_code == 422, r.text


def test_binary_body_to_json_endpoint_is_422_not_500(client, captures):
    """A pcap posted to /api/v1/scan is bytes where a JSON object is expected.

    FastAPI echoes the offending input into the 422 body. Serialising raw
    pcap bytes raises inside the error handler, so the client used to get a
    500 "Internal Server Error" and never learned it had hit the wrong
    endpoint. It must be an ordinary 422 like any other shape mismatch.
    """
    data = (captures / SUPPRESSED).read_bytes()
    assert b"\xff" in data or b"\x00" in data, "fixture should not be valid UTF-8"
    body = (
        b"--X\r\nContent-Disposition: form-data; name=\"capture\"; "
        b"filename=\"a.pcap\"\r\nContent-Type: application/vnd.tcpdump.pcap\r\n\r\n"
        + data
        + b"\r\n--X--\r\n"
    )
    r = client.post(
        "/api/v1/scan",
        content=body,
        headers={"Content-Type": "multipart/form-data; boundary=X"},
    )
    assert r.status_code == 422, r.text
    detail = r.json()["detail"][0]
    assert detail["loc"] == ["body"]
    assert "bytes" in str(detail["input"])


def test_validation_error_truncates_large_text_input(client):
    """A large valid-UTF-8 value must not be echoed back in full."""
    r = client.post(
        "/api/v1/scan", json={"path": "p.pcap", "sign": "not-a-bool-" + "x" * 5000}
    )
    assert r.status_code == 422, r.text
    body = r.text
    assert len(body) < 1000, f"error body should be truncated, got {len(body)} B"
    assert "chars" in body


# --------------------------------------------------------------------------
# upload
# --------------------------------------------------------------------------


def test_upload_capture(client, captures):
    data = (captures / SUPPRESSED).read_bytes()
    r = client.post(
        "/api/v1/upload",
        files={"file": ("sample.pcap", io.BytesIO(data), "application/octet-stream")},
        data={"sign": "false", "lang": "en,hi"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["findings"] >= 1


def test_upload_rejects_bad_suffix(client):
    r = client.post(
        "/api/v1/upload",
        files={"file": ("notes.txt", io.BytesIO(b"x"), "text/plain")},
    )
    assert r.status_code == 415


def test_upload_temp_file_is_cleaned_up(client, captures, monkeypatch):
    from pathlib import Path
    import tempfile

    # Record exactly which directories the endpoint creates, instead of globbing
    # the whole temp dir: an unrelated user directory named "kryxai-*" would
    # otherwise fail this test.
    created: list = []
    real_mkdtemp = tempfile.mkdtemp

    def spy(*a, **kw):
        path = real_mkdtemp(*a, **kw)
        created.append(Path(path))
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", spy)

    data = (captures / HEALTHY).read_bytes()
    client.post(
        "/api/v1/upload",
        files={"file": ("s.pcap", io.BytesIO(data), "application/octet-stream")},
    )
    assert created, "endpoint did not create a temp directory"
    leftover = [p for p in created if p.exists()]
    assert not leftover, f"upload temp directories not removed: {leftover}"


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------


def test_bilingual_html_endpoints(client, captures):
    scan_id = _scan(client, captures / SUPPRESSED).json()["scan_id"]
    for lang in ("en", "hi"):
        r = client.get(f"/api/v1/report/{scan_id}/html?lang={lang}")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert len(r.text) > 500


def test_hindi_report_json_carries_html(client, captures):
    scan_id = _scan(client, captures / SUPPRESSED).json()["scan_id"]
    r = client.get(f"/api/v1/report/{scan_id}?lang=hi")
    assert r.status_code == 200
    assert "html" in r.json()


def test_invalid_lang_is_rejected(client, captures):
    scan_id = _scan(client, captures / SUPPRESSED).json()["scan_id"]
    assert client.get(f"/api/v1/report/{scan_id}?lang=fr").status_code == 422


def test_unknown_scan_id_is_404(client):
    assert client.get("/api/v1/report/nope").status_code == 404
    assert client.get("/api/v1/report/nope/html").status_code == 404


# --------------------------------------------------------------------------
# evidence chain
# --------------------------------------------------------------------------


def test_chain_verify_endpoint(client, captures):
    _scan(client, captures / SUPPRESSED)
    _scan(client, captures / HEALTHY)
    body = client.get("/api/v1/chain").json()
    assert body["ok"] is True
    assert body["chain_id"] == "KryxAIV1"
    # `block_count` and `blocks` must stay distinct types: the count is the
    # machine-checkable number, the list is the detail.
    assert body["block_count"] == 2
    assert isinstance(body["blocks"], list)
    assert [b["index"] for b in body["blocks"]] == [0, 1]
    # Unanchored blocks must never be reported as anchored.
    assert all(b["anchored"] is False for b in body["blocks"])


def test_chain_blocks_carry_hash_linkage(client, captures):
    _scan(client, captures / HEALTHY)
    blocks = client.get("/api/v1/chain").json()["blocks"]
    assert len(blocks) == 1
    b = blocks[0]
    assert b["hash"] and b["prev_hash"] and b["difficulty"] >= 1
    assert b["created_at"]
    # Genesis link must be present so a verifier can follow the chain.
    assert b["prev_hash"] != b["hash"]


# --------------------------------------------------------------------------
# anchor gate
# --------------------------------------------------------------------------


def test_anchor_gate_fails_closed_and_writes_nothing(
    tmp_path, monkeypatch, captures
):
    """With the gate on and no external anchor, no report artifact may appear.

    A 503 that nonetheless left a signed PDF on disk would be exactly the
    dishonesty the gate exists to prevent.
    """
    from pathlib import Path

    reports = tmp_path / "strict"
    settings = Settings(
        database_path=str(tmp_path / "strict.db"),
        reports_dir=str(reports),
        blockchain_external_anchor=False,
        blockchain_anchor_required=True,
    )
    _bind(monkeypatch, settings)

    with TestClient(api.app) as c:
        r = _scan(c, captures / SUPPRESSED)
        assert r.status_code == 503
        assert "unanchored" in r.json()["detail"].lower()
        assert not reports.exists() or not any(reports.iterdir())


def test_anchor_gate_allows_anchored_state(tmp_path, monkeypatch, captures):
    """An 'anchored' chain state must pass the gate, not be blocked on state."""
    from pathlib import Path

    reports = tmp_path / "anchored"
    settings = Settings(
        database_path=str(tmp_path / "anchored.db"),
        reports_dir=str(reports),
        blockchain_external_anchor=True,
        blockchain_anchor_required=True,
    )
    _bind(monkeypatch, settings)

    original = api.run_scan

    def fake(path, s, store=None, persist=True):
        result = original(path, s, store=store, persist=persist)
        result.report["evidence"]["chain_state"] = "anchored"
        return result

    monkeypatch.setattr(api, "run_scan", fake)
    with TestClient(api.app) as c:
        r = _scan(c, captures / SUPPRESSED)
        assert r.status_code == 200, r.text
        assert any(reports.iterdir())


# --------------------------------------------------------------------------
# report cache
# --------------------------------------------------------------------------


def test_report_cache_is_bounded(client, captures, monkeypatch):
    monkeypatch.setattr(api, "_SCAN_CACHE_MAX", 3)
    for _ in range(5):
        _scan(client, captures / HEALTHY)
    assert len(api._scan_cache) <= 3


def test_evicted_report_is_a_clean_404(client, captures, monkeypatch):
    scan_id = _scan(client, captures / SUPPRESSED).json()["scan_id"]
    monkeypatch.setattr(api, "_SCAN_CACHE_MAX", 1)
    _scan(client, captures / HEALTHY)
    # The survivor stays retrievable; the evicted one is a clean 404, not a 500.
    assert client.get(f"/api/v1/report/{scan_id}").status_code in (200, 404)


def test_store_is_closed_after_scan(client, captures, monkeypatch):
    """Each request must release its SQLite handle.

    ``_run_and_store`` imports Store inside the function, so the patch has to go
    on the defining module rather than on the api module.
    """
    import kryxai.store as store_mod

    instances = []

    class TrackingStore(store_mod.Store):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            instances.append(self)

        def close(self):
            super().close()
            self._closed = True

    monkeypatch.setattr(store_mod, "Store", TrackingStore)
    _scan(client, captures / HEALTHY)

    assert instances, "expected the scan to open a Store"
    assert all(getattr(s, "_closed", False) for s in instances), (
        "Store.close() was not called for every request"
    )
