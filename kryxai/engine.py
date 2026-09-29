"""Scan orchestration.

`run_scan` is the single entry point: capture in, evidence-bearing report out.
It is deliberately synchronous and dependency-free so that the same function
backs the CLI, the FastAPI surface and the test suite.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import coverage, interception
from .compliance import dpdp
from .config import Settings
from .feeds import ioc
from .i18n import disclaimer, finding_title, safe_stdout
from .pcap.io import linktype_name, parse_capture, read_capture
from .pcap.tcp import reassemble
from .policy import kb
from .scoring import anomaly, fusion
from .store import Store

TOOL_NAME = "KryxAI"
TOOL_VERSION = "0.1.0"
CHAIN_ID = "KryxAIV1"
REPORT_AAD = b"kryxai-report-v1"


@dataclass
class ScanResult:
    report: Dict[str, Any]
    store: Optional[Store] = None
    block_index: Optional[int] = None

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return self.report["findings"]

    @property
    def posture(self) -> Dict[str, Any]:
        return self.report["posture"]


def _sort_key(f: Dict[str, Any]) -> tuple:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    risk = f.get("risk", {}) or {}
    return (order.get(f.get("severity", "info"), 9), -risk.get("total", 0.0), f.get("code", ""), f.get("endpoint") or "")


VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


def normalize_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Give every finding the same shape, whatever produced it.

    Findings arrive from three places that were written independently: the
    protocol/TLS knowledge base, the anomaly baseline, and the IoC matcher.
    Persistence, compliance mapping and the reports all assume one schema, so
    it is enforced here rather than trusted from each producer.
    """
    code = f.get("code", "unclassified")
    titles = finding_title(code)
    endpoint = f.get("endpoint", "")
    detail = f.get("detail", "")
    title = f.get("title") or titles["title"]
    out: Dict[str, Any] = {
        "finding_id": f.get("finding_id")
        or hashlib.sha256(f"{code}|{endpoint}|{title}".encode()).hexdigest()[:16],
        "code": code,
        "severity": f.get("severity", "info")
        if f.get("severity") in VALID_SEVERITIES
        else "info",
        "title": title,
        "title_hi": f.get("title_hi") or titles["title_hi"] or "",
        "translation_complete": bool(f.get("title_hi") or titles["translation_complete"]),
        "detail": detail,
        "endpoint": endpoint,
        "session_id": f.get("session_id", ""),
        "reference": f.get("reference", ""),
        "remediation": f.get("remediation", ""),
        "weight": float(f.get("weight", 0.5)),
        "evidence": f.get("evidence", {}) or {},
        "deliverable": f.get("deliverable", "unassigned"),
    }
    if f.get("risk"):
        out["risk"] = f["risk"]
    return out


def _capture_metadata(source: Path, linktype: int, raw_packets, parsed) -> Dict[str, Any]:
    """Facts about the capture file itself, not about the traffic in it."""
    data = source.read_bytes()
    head = data[:4]
    if head == b"\x0a\x0d\x0d\x0a":
        fmt = "pcapng"
    elif head[:2] in (b"\xd4\xc3", b"\x4d\x3c", b"\xa1\xb2\xc3\xd4"):
        fmt = "pcap"
    else:
        fmt = "unknown"
    timestamps = [p.ts for p in raw_packets if p.ts]
    return {
        "path": str(source),
        "size_bytes": source.stat().st_size if source.exists() else None,
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": fmt,
        "link_type": linktype_name(linktype),
        "truncated": fmt != "unknown" and len(data) < 24,
    }


def run_scan(
    source: Path,
    settings: Optional[Settings] = None,
    store: Optional[Store] = None,
    persist: bool = True,
) -> ScanResult:
    settings = settings or Settings()
    started = time.time()

    linktype, raw_packets = read_capture(source)
    parsed = parse_capture(raw_packets)
    streams = reassemble(parsed)
    analysis = kb.analyze_conversations(streams)

    meta = _capture_metadata(source, linktype, raw_packets, parsed)
    timestamps = sorted(p.ts for p in raw_packets if p.ts)

    sessions: List[Dict[str, Any]] = [s.summary() for s in analysis["sessions"]]
    findings: List[Dict[str, Any]] = list(analysis["findings"])

    feed = ioc.load_feed_dir(settings.ioc_feed_dir if settings else None)
    for s in sessions:
        # The TLS summary exposes the SNI as "sni". Reading "server_name" here
        # silently yields None for every session, which makes domain-scoped IoC
        # indicators unreachable while still looking like it works.
        domain = (s.get("tls") or {}).get("sni")
        hits = feed.match(s["peer"], domain)
        if hits:
            f = ioc.indicator_finding(hits, s["endpoint"])
            f["session_id"] = s["session_id"]
            findings.append(f)

    by_id = {s["session_id"]: s for s in sessions}

    # One baseline, one detection pass. This previously called detect() twice -
    # once bare, once with the baseline - which computed the same thing twice
    # (detect() builds a baseline when given none) and left the two independent
    # invocations free to disagree. The result is also needed by the report, the
    # interception evidence and the coverage table, so it is computed once here
    # and shared.
    baseline = anomaly.build_baseline(sessions)
    report_anomalies = [a.to_dict() for a in anomaly.detect(sessions, baseline)]
    for a in report_anomalies:
        findings.append(a)
    model = fusion.LearnedRiskModel(
        (settings.resolved_onnx_model_path() if settings else None)
    )
    cross_peers = baseline.peer_counts()

    # The model is a *session*-level scorer. training/dataset.py builds exactly
    # one row per session via fusion.session_feature_row(), which represents a
    # session by its most serious finding and still yields a row for a session
    # with no findings at all. Serving has to use the same function on the same
    # inputs, otherwise the model is fed a distribution it was never trained on.
    #
    # Scoring each finding independently would do exactly that, and would skip
    # clean sessions entirely - which are the examples that teach the model what
    # "acceptable" looks like, so a clean session would never be model-scored.
    # Each session is therefore scored once and that score is shared by the
    # findings it contains.
    session_model_scores: Dict[str, float] = {}
    clamped_sessions = 0
    clamped_union: set = set()
    for s in sessions:
        # Always present, always null when unscored. A field that only exists
        # when a model is configured makes `session.model_score` mean undefined
        # on one install and a number on another, and a consumer cannot tell a
        # missing key from a deliberate null.
        s["model_score"] = None
    if model.session is not None:
        by_session: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            by_session.setdefault(str(f.get("session_id") or f.get("endpoint") or ""), []).append(
                f
            )
        for s in sessions:
            rows = by_session.get(str(s["session_id"])) or by_session.get(
                str(s.get("endpoint") or "")
            ) or []
            score = model.score(fusion.session_feature_row(s, rows, cross_peers))
            if score is not None:
                session_model_scores[str(s["session_id"])] = score
                s["model_score"] = score
                # Read after the call: _clamp records what it moved for this
                # score, so the tally cannot be attributed to the wrong session.
                if model.clamped_features:
                    clamped_sessions += 1
                    clamped_union.update(model.clamped_features)

    rule_totals: List[float] = []
    model_scores: List[float] = []
    for f in findings:
        session = by_id.get(f.get("session_id") or "")
        if session is None:
            session = next(
                (s for s in sessions if s["endpoint"] == f.get("endpoint")), None
            )
        model_score = (
            session_model_scores.get(
                str(f.get("session_id") or (session or {}).get("session_id") or "")
            )
        )
        explained = fusion.score_finding(
            f,
            cross_session_peers=cross_peers,
            total_sessions=len(sessions),
            model_score=model_score,
        ).explain()
        f["risk"] = explained
        # Both scores are retained so a reader can audit the fused number rather
        # than take it on trust. When no model is loaded the model score is
        # null, which is the honest representation of "rules only".
        rule_only = fusion.score_finding(
            f,
            cross_session_peers=cross_peers,
            total_sessions=len(sessions),
        ).explain()
        explained["rule_score"] = rule_only["total"]
        explained["model_score"] = model_score
        rule_totals.append(rule_only["total"])
        if model_score is not None:
            model_scores.append(model_score)

    findings.sort(key=_sort_key)
    findings = [normalize_finding(f) for f in findings]

    mail_sessions = [s for s in sessions if s["protocol"] in ("SMTP", "IMAP", "POP3")]
    report: Dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "chain_id": CHAIN_ID,
        "report_aad": REPORT_AAD.decode(),
        "source": meta,
        "capture": {
            "packet_count": len(raw_packets),
            "first_timestamp": timestamps[0] if timestamps else None,
            "last_timestamp": timestamps[-1] if timestamps else None,
            "decoded": len(parsed),
            "undecoded": len(raw_packets) - len(parsed),
            "truncated": meta["truncated"],
        },
        "sessions": sessions,
        "findings": findings,
        "counts": {
            "sessions": len(sessions),
            "mail_sessions": len(mail_sessions),
            "tls_sessions": sum(1 for s in sessions if s.get("tls")),
            "tls_upgraded": sum(1 for s in mail_sessions if s["starttls"]["tls_established"]),
            "findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "by_deliverable": {
                d: sum(1 for f in findings if f.get("deliverable") == d)
                for d in sorted({f.get("deliverable", "unassigned") for f in findings})
            },
        },
        "posture": fusion.posture(sessions, findings),
        # Computed once and reused: the anomaly list is read by the report, the
        # interception evidence and the coverage table, and three independent
        # calls would be three chances for them to disagree.
        "anomalies": report_anomalies,
        "compliance": dpdp.compliance_summary(findings),
        "ioc": {**feed.to_dict(), "freshness": ioc.freshness(feed.provenance)},
        "model": {
            "status": model.status,
            "used": model.session is not None,
            "feature_schema_version": fusion.FEATURE_SCHEMA_VERSION,
            "feature_count": len(fusion.FEATURE_NAMES),
            "model_schema_version": model.schema_version,
            "rule_score_mean": round(sum(rule_totals) / len(rule_totals), 2)
            if rule_totals
            else None,
            # Means are over sessions, not findings, because that is the unit
            # the model was trained and served on. `findings_scored` is separate
            # because a clean session scores no findings yet is still scored.
            # Deliberately one model mean: a findings-weighted mean would differ
            # and be quietly misread as the session-level figure.
            "model_score_mean": (
                round(sum(session_model_scores.values()) / len(session_model_scores), 4)
                if session_model_scores
                else None
            ),
            "sessions_scored": len(session_model_scores),
            "sessions_total": len(sessions),
            "findings_scored": len(model_scores),
            # Recorded rather than applied silently. A session outside the
            # training distribution gets a clamped score, and a reader who sees
            # a non-zero score on a clean session deserves to know that one of the
            # inputs was not one the model has ever seen.
            "sessions_with_clamped_features": clamped_sessions,
            "clamped_features": sorted(clamped_union),
            "constant_training_features": list(model.constant_features),
            "feature_ranges_known": bool(model.ranges),
            "note": (
                "Both the rule score and the model score are recorded so the "
                "fused figure can be checked. 'used' is false whenever no model "
                "file is configured, and the score is then the rules alone. The "
                "model scores one row per session, built from that session's most "
                "serious finding, and every finding in a session carries its "
                "session's score - so a clean session is still model-scored even "
                "though it produces no findings. Means are over sessions."
            ),
        },
        "interception": interception.build_interception(
            sessions, report_anomalies
        ),
        "limitations": _limitations(sessions, len(raw_packets), len(parsed), meta),
        "scan_seconds": round(time.time() - started, 3),
    }

    block_index: Optional[int] = None
    scan_id: Optional[str] = None
    if store is not None and persist:
        scan_id = uuid.uuid4().hex
        store.save_scan(
            scan_id,
            meta["path"],
            meta["sha256"],
            len(raw_packets),
            {
                "counts": report["counts"],
                "posture": report["posture"],
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
            },
        )
        store.save_findings(scan_id, findings)
        certs: List[Dict[str, Any]] = []
        seen: set = set()
        for s in sessions:
            for cert in (s.get("tls") or {}).get("certificates", []):
                fp = cert.get("sha256_fingerprint")
                if fp and fp not in seen:
                    seen.add(fp)
                    certs.append(
                        {
                            "sha256_fingerprint": fp,
                            "subject": cert.get("subject", ""),
                            "issuer": cert.get("issuer", ""),
                            "not_before": cert.get("not_before"),
                            "not_after": cert.get("not_after"),
                            "public_key_algorithm": cert.get("public_key_algorithm", ""),
                            "public_key_bits": cert.get("public_key_bits"),
                            "signature_algorithm": cert.get("signature_algorithm", ""),
                            "der": cert.get("der_b64", ""),
                        }
                    )
        store.save_certificates(scan_id, certs)
        block = store.append(
            _chain_payload(report),
            difficulty=settings.blockchain_difficulty if settings else None,
        )
        block_index = block.index
    else:
        block = None

    report["evidence"] = {
        "scan_id": scan_id,
        "chain_id": report["chain_id"],
        "block_index": block_index,
        "block_hash": block.block_hash if block is not None else None,
        "chain_state": _chain_state(block),
        "external_anchor": bool(getattr(block, "anchored", False)),
    }

    # Requirement coverage is derived after the report is whole, because it
    # reads the evidence sections rather than reproducing them. Report files are
    # only known once builder.write has run, so `written` is filled in by the
    # caller when there is one; it stays None for an in-memory scan and the
    # coverage entry says so rather than claiming an export that never happened.
    report["coverage"] = coverage.build_coverage(report)

    return ScanResult(report=report, store=store, block_index=block_index)


def _chain_state(block) -> str:
    """The honest anchor state of a block.

    A block with no external anchor is `pending`, never `anchored`. A local
    proof-of-work block is tamper-evident, not externally attested, and the
    report must not blur those two things together.
    """
    if block is None:
        return "not_recorded"
    if getattr(block, "anchored", False):
        return "anchored"
    return "pending"


def _chain_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    """The subset of the report that goes on the evidence chain.

    Deliberately excludes anything that varies run to run for identical
    evidence, so that two scans of the same capture anchor to the same block
    content.
    """
    return {
        "tool": report["tool"],
        "version": report["version"],
        "chain_id": report["chain_id"],
        "source_sha256": report["source"]["sha256"],
        "packet_count": report["capture"]["packet_count"],
        "counts": report["counts"],
        "posture": {"score": report["posture"]["score"], "grade": report["posture"]["grade"]},
        "findings": [
            {
                "code": f["code"],
                "severity": f["severity"],
                "endpoint": f.get("endpoint"),
                "deliverable": f.get("deliverable"),
                "priority": (f.get("risk") or {}).get("priority"),
            }
            for f in report["findings"]
        ],
    }


def _limitations(
    sessions: List[Dict[str, Any]],
    packet_count: int,
    decoded_count: int,
    meta: Dict[str, Any],
) -> List[str]:
    notes: List[str] = []
    undecoded = packet_count - decoded_count
    if undecoded:
        notes.append(
            f"{undecoded} of {packet_count} packet(s) could not be decoded to the TCP "
            "layer; they are excluded from analysis rather than guessed at."
        )
    if meta.get("truncated"):
        notes.append(
            "The capture file looks truncated, so the final packets are missing and "
            "session end states may be wrong."
        )
    gapped = [s for s in sessions if not s["reassembly"]["complete"]]
    if gapped:
        notes.append(
            f"{len(gapped)} TCP stream(s) had sequence gaps. Analysis covers the bytes "
            "that were present; a pattern spanning a gap would not be seen."
        )
    tls13 = [
        s
        for s in sessions
        if s.get("tls") and s["tls"].get("version") == "TLS 1.3"
    ]
    if tls13:
        notes.append(
            f"{len(tls13)} TLS 1.3 session(s): server certificates and the handshake "
            "signature are inside encrypted handshake records and cannot be observed "
            "passively. Only ClientHello and ServerHello are visible."
        )
    notes.append(
        "KryxAI observes traffic only. It cannot distinguish a hostile middlebox from a "
        "misconfigured one, and a clean capture is not proof of a clean network path."
    )
    return notes
