"""HTTP surface for KryxAI.

The API is a thin shell over `kryxai.engine.run_scan`. Everything expensive is
synchronous and local; a scan of a large capture is CPU-bound, so requests run
in a worker thread rather than blocking the event loop.

Anchoring is opt-in by default. When `blockchain_anchor_required` is true, any
endpoint that would return an unanchored report fails closed with 503 instead
of quietly returning a report that is not anchored.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings, settings as global_settings
from .engine import run_scan
from .reports import builder as report_builder

_LOG = logging.getLogger("kryxai.api")

ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap", ".dmp"}
MAX_UPLOAD_BYTES = 512 * 1024 * 1024

app = FastAPI(
    title="KryxAI",
    version=__version__,
    description=(
        "Passive SMTP/IMAP/POP3 mail-security forensics. Observes an existing "
        "capture only; it never probes or probes back."
    ),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=global_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Reports are held in-process only: the SQLite store keeps the evidence chain,
# not the rendered report body, so a restart loses report retrieval until the
# caller re-runs the scan. Bounded so a long-lived server cannot grow without
# limit. Persist report bodies to disk to make retrieval durable.
_SCAN_CACHE_MAX = 64
_scan_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

# Scan ids are hex uuids. Anything else is refused before it reaches the
# filesystem, so a crafted id cannot traverse out of the reports directory.
_SAFE_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _remember(scan_id: str, report: Dict[str, Any]) -> None:
    _scan_cache[scan_id] = report
    _scan_cache.move_to_end(scan_id)
    while len(_scan_cache) > _SCAN_CACHE_MAX:
        _scan_cache.popitem(last=False)


def _recall(scan_id: str) -> Optional[Dict[str, Any]]:
    report = _scan_cache.get(scan_id)
    if report is not None:
        _scan_cache.move_to_end(scan_id)
    return report


def _load_report_from_disk(scan_id: str, settings: Settings) -> Optional[Dict[str, Any]]:
    """Rehydrate a report written by a previous process.

    `reports/<scan_id>.json` is already an artefact of the scan, so recovery
    costs nothing extra. A scan id is a hex uuid in practice, so the name is
    validated before it is joined onto the reports directory: a caller-supplied
    id must never be able to escape that directory.
    """
    if not scan_id or not _SAFE_SCAN_ID.match(scan_id):
        return None
    path = Path(settings.reports_dir) / f"{scan_id}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _recall_or_rehydrate(
    scan_id: str, settings: Settings
) -> Optional[Dict[str, Any]]:
    """In-memory first, then disk. Disk results are re-cached."""
    report = _recall(scan_id)
    if report is not None:
        return report
    report = _load_report_from_disk(scan_id, settings)
    if report is not None:
        _remember(scan_id, report)
    return report


def list_scans(limit: int = 20) -> List[Dict[str, Any]]:
    """Recent reports, newest first, discovered from the reports directory."""
    out_dir = Path(global_settings.reports_dir)
    try:
        files = sorted(
            out_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
        )
    except OSError:
        return []
    scans: List[Dict[str, Any]] = []
    for path in files[:limit]:
        scan_id = path.stem
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
            evidence = summary.get("evidence") or {}
            scans.append(
                {
                    "scan_id": scan_id,
                    "block_index": evidence.get("block_index"),
                    "chain_state": evidence.get("chain_state", "not_recorded"),
                    "posture_grade": (summary.get("posture") or {}).get("grade"),
                    "findings": len(summary.get("findings") or []),
                }
            )
        except (OSError, ValueError, AttributeError):
            continue
    return scans


def get_settings() -> Settings:
    return global_settings


def _require_anchor_gate(state: str) -> None:
    """Fail closed when the deployment demanded an anchor and there isn't one."""
    if not global_settings.blockchain_anchor_required:
        return
    if state != "anchored":
        raise HTTPException(
            status_code=503,
            detail=(
                "This deployment requires an external evidence anchor and the "
                f"report is only '{state}'. No report is returned rather than an "
                "unanchored one."
            ),
        )


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "chain_id": global_settings.chain_id,
        "anchor_required": global_settings.blockchain_anchor_required,
        "external_anchor": global_settings.blockchain_external_anchor,
        "alert_channels": global_settings.active_alert_channels(),
        # `alert_channels` alone reads as "alerting is on". It is not: a
        # deployment with no channel sends nothing, and that is the default.
        # These two make the difference between "would notify" and "will not".
        "alerts_enabled": global_settings.alerts_enabled,
        "alert_min_severity": global_settings.alert_min_severity,
        # Reported so an operator can tell "anchoring is off" from "anchoring is
        # on and pointed at a gateway that is not there" without reading logs.
        "anchor_gateway": global_settings.nbf_gateway_url
        if global_settings.blockchain_external_anchor
        else None,
    }


@app.get("/api/v1/capabilities")
def capabilities() -> Dict[str, Any]:
    """What this deployment can and cannot do, stated up front."""
    from .feeds import ioc

    feed = ioc.load_feed_dir(global_settings.ioc_feed_dir)
    return {
        "protocols": ["SMTP", "IMAP", "POP3"],
        "passive_only": True,
        "starttls_signatures": [
            "K1_capability_suppression",
            "K2_cross_flow_inconsistency",
            "K3_refused_upgrade",
            "K4_plaintext_after_upgrade",
        ],
        "tls_versions_visible": {
            "TLS 1.0/1.1/1.2": "version, cipher, group, signature, certificate",
            "TLS 1.3": (
                "version and cipher only; certificate and handshake signature are "
                "inside encrypted handshake records and are not observable passively"
            ),
        },
        "statutes": ["DPDP Act 2023", "CERT-In Directions 20(3)/2022"],
        "ioc": feed.to_dict(),
        "known_limitations": [
            "TLS 1.3 server certificates are not visible to passive analysis.",
            "A middlebox that rewrites in both directions identically is "
            "indistinguishable from a server without out-of-band comparison.",
            "Encrypted payload content is never decrypted or retained.",
        ],
    }


class ScanRequest(BaseModel):
    path: str = Field(..., description="Absolute path to a pcap or pcapng file")
    sign: bool = Field(True, description="Sign the rendered report")
    lang: List[str] = Field(default_factory=lambda: ["en", "hi"])


class ScanSummary(BaseModel):
    scan_id: str
    block_index: Optional[int]
    posture_grade: str
    posture_score: float
    findings: int
    sessions: int
    chain_state: str
    report_files: Dict[str, str] = Field(default_factory=dict)


@app.post("/api/v1/scan", response_model=ScanSummary)
def scan_file(
    request: ScanRequest,
    settings: Settings = Depends(get_settings),
) -> ScanSummary:
    path = Path(request.path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"capture not found: {path}")
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=415,
            detail=f"unsupported capture type '{path.suffix}'; expected one of "
            f"{sorted(ALLOWED_SUFFIXES)}",
        )
    return _run_and_store(path, settings, request.sign, request.lang)


@app.post("/api/v1/upload", response_model=ScanSummary)
async def upload_capture(
    file: UploadFile = File(...),
    sign: bool = Form(True),
    lang: str = Form("en,hi"),
    settings: Settings = Depends(get_settings),
) -> ScanSummary:
    suffix = Path(file.filename or "capture.pcap").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=415,
            detail=f"unsupported capture type '{suffix}'; expected one of "
            f"{sorted(ALLOWED_SUFFIXES)}",
        )
    tmp = Path(tempfile.mkdtemp(prefix="kryxai-"))
    target = tmp / f"capture{suffix}"
    written = 0
    try:
        with target.open("wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"capture exceeds {MAX_UPLOAD_BYTES} bytes",
                    )
                fh.write(chunk)
    except HTTPException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    try:
        return _run_and_store(
            target, settings, sign, [x for x in lang.split(",") if x]
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run_and_store(
    path: Path, settings: Settings, sign: bool, langs: List[str]
) -> ScanSummary:
    from .anchor import anchor_report
    from .store import Store

    store = Store(settings.database_path)
    try:
        try:
            result = run_scan(path, settings, store=store)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        report = result.report

        # Anchor before the gate, not after. The gate demands chain_state ==
        # "anchored", and nothing but this call can ever produce that, so
        # checking first meant a strict deployment could never pass.
        report["anchor_attempt"] = anchor_report(report, store, settings)
        evidence = report.get("evidence", {})

        # Check the anchor gate BEFORE writing anything. Reporting 503 "no
        # report is returned" while a signed PDF/HTML is already on disk would
        # be exactly the dishonesty the gate exists to prevent.
        _require_anchor_gate(evidence.get("chain_state", "not_recorded"))
    finally:
        # Always release the SQLite handle. Leaving it open leaks one
        # connection (and one WAL file) per request for the process lifetime.
        store.close()

    out_dir = Path(settings.reports_dir)
    paths = report_builder.write(
        report, out_dir, settings, langs=langs, sign_reports=sign
    )
    files = {k: str(v) for k, v in paths.items()}

    scan_id = evidence.get("scan_id") or uuid.uuid4().hex
    _remember(scan_id, report)
    return ScanSummary(
        scan_id=scan_id,
        block_index=evidence.get("block_index"),
        posture_grade=report["posture"]["grade"],
        posture_score=report["posture"]["score"],
        findings=len(report["findings"]),
        sessions=report["counts"]["sessions"],
        chain_state=evidence.get("chain_state", "not_recorded"),
        report_files=files,
    )


@app.get("/api/v1/scans")
def get_scans(limit: int = Query(20, ge=1, le=200)) -> Dict[str, Any]:
    """Recent scans, so a reloaded client can restore what it was looking at."""
    return {"scans": list_scans(limit)}


@app.get("/api/v1/report/{scan_id}")
def get_report(
    scan_id: str,
    lang: str = Query("en", pattern="^(en|hi)$"),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    report = _recall_or_rehydrate(scan_id, settings)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "report not in memory and not on disk; it was not produced by "
                "this deployment, or its report files have been removed"
            ),
        )
    if lang == "hi":
        return {
            "html": report_builder.render_html(report, lang="hi"),
        }
    return report


@app.get("/api/v1/report/{scan_id}/html")
def get_report_html(
    scan_id: str,
    lang: str = Query("en", pattern="^(en|hi)$"),
    settings: Settings = Depends(get_settings),
) -> Any:
    from fastapi.responses import HTMLResponse

    report = _recall_or_rehydrate(scan_id, settings)
    if report is None:
        raise HTTPException(status_code=404, detail="report not in memory or on disk")
    return HTMLResponse(report_builder.render_html(report, lang=lang))


@app.get("/api/v1/chain")
def verify_chain(settings: Settings = Depends(get_settings)) -> Dict[str, Any]:
    from .store import Store

    store = Store(settings.database_path)
    try:
        result = store.verify_chain()
        blocks = store.chain()
    finally:
        store.close()
    return {
        **result,
        "chain_id": settings.chain_id,
        # verify_chain() already returns a `blocks` COUNT. Overwriting it with
        # the list would silently change the field's type for existing clients,
        # so the count is republished as `block_count` and the list keeps
        # `blocks`.
        "block_count": result.get("blocks"),
        "blocks": [
            {
                "index": b.index,
                "hash": b.block_hash,
                "prev_hash": b.prev_hash,
                "difficulty": b.difficulty,
                "anchored": b.anchored,
                "anchor_tx": b.anchor_tx,
                "anchor_provider": b.anchor_provider,
                "created_at": b.created_at,
            }
            for b in blocks
        ],
    }
