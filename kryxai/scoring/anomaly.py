"""Behavioural anomaly detection against a capture-local baseline.

Every baseline here is built from the capture under analysis. Nothing is
compared against an external profile that the user has not supplied, because an
invented "normal" would manufacture anomalies out of nothing.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAD_FLOOR = 1e-9


@dataclass
class Anomaly:
    code: str
    severity: str
    endpoint: str
    detail: str
    observed: Any
    baseline: Any
    rationale: str
    # How strongly this detector asserts the anomaly, 0-1. This is a hand-set
    # ordering weight, NOT a probability: 0.9 does not mean a 90% chance the
    # session is anomalous. It was previously called `confidence`, which read as
    # a calibrated likelihood in reports and invited exactly that reading.
    weight: float = 0.7
    session_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "detail": self.detail,
            "observed": self.observed,
            "baseline": self.baseline,
            "rationale": self.rationale,
            "weight": round(self.weight, 3),
            "session_id": self.session_id,
        }


@dataclass
class CaptureBaseline:
    sessions_per_peer: Dict[str, int] = field(default_factory=dict)
    upgrade_rate_per_peer: Dict[str, float] = field(default_factory=dict)
    versions_seen: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    fingerprints_per_peer: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    ports_per_peer: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    session_sizes: List[int] = field(default_factory=list)
    gap_count: int = 0

    def peer_counts(self) -> Dict[str, int]:
        return dict(self.sessions_per_peer)


def build_baseline(sessions: List[Dict[str, Any]]) -> CaptureBaseline:
    b = CaptureBaseline()
    per_peer_total: Dict[str, int] = defaultdict(int)
    per_peer_upgraded: Dict[str, int] = defaultdict(int)
    for s in sessions:
        peer = s["peer"]
        b.sessions_per_peer[peer] = b.sessions_per_peer.get(peer, 0) + 1
        per_peer_total[peer] += 1
        b.ports_per_peer[peer].add(s["port"])
        total = s["bytes"]["client"] + s["bytes"]["server"]
        b.session_sizes.append(total)
        if not s["reassembly"]["complete"]:
            b.gap_count += 1
        if s["starttls"]["tls_established"]:
            per_peer_upgraded[peer] += 1
        if s["starttls"]["signatures"]:
            pass
        tls = s.get("tls")
        if tls:
            b.versions_seen[peer].append(tls["version"])
            for cert in tls.get("certificates", []):
                # Only leaf identities count towards A4. A normal server sends
                # its leaf plus one or more CA certificates, and treating those
                # as extra identities would fire on every well-configured server.
                if not cert.get("is_ca"):
                    b.fingerprints_per_peer[peer].add(cert["sha256_fingerprint"])
    for peer, total in per_peer_total.items():
        b.upgrade_rate_per_peer[peer] = per_peer_upgraded[peer] / total if total else 0.0
    return b


def detect(sessions: List[Dict[str, Any]], baseline: Optional[CaptureBaseline] = None) -> List[Anomaly]:
    b = baseline or build_baseline(sessions)
    out: List[Anomaly] = []

    for s in sessions:
        peer = s["peer"]
        st = s["starttls"]
        before = len(out)

        if st["signatures"] and s["protocol"] in ("SMTP", "IMAP", "POP3"):
            out.append(
                Anomaly(
                    code="A1_tamper_signature",
                    severity="high",
                    endpoint=s["endpoint"],
                    detail=f"{s['protocol']} session on port {s['port']} carried a passive tamper signature",
                    observed=st["signatures"],
                    baseline="no such signature expected on a compliant path",
                    rationale=(
                        "The capability advertisement itself was observed to differ "
                        "from STARTTLS, which an active scanner could not see."
                    ),
                        weight=max(0.5, st["confidence"]),
                )
            )

        rate = b.upgrade_rate_per_peer.get(peer, 0.0)
        if b.sessions_per_peer.get(peer, 0) >= 2 and st["tls_established"] and rate < 0.99:
            out.append(
                Anomaly(
                    code="A2_partial_upgrade",
                    severity="medium",
                    endpoint=s["endpoint"],
                    detail=(
                        f"peer upgrades on only {rate:.0%} of its sessions in this "
                        "capture"
                    ),
                    observed=True,
                    baseline=f"upgrade rate {rate:.0%} across {b.sessions_per_peer[peer]} sessions",
                    rationale=(
                        "A server that supports TLS on some paths but not others is "
                        "the shape of a path-dependent middlebox."
                    ),
                    weight=0.6,
                )
            )

        ports = b.ports_per_peer.get(peer, set())
        if len(ports) > 1 and s["port"] in (465, 993, 995):
            tls = s.get("tls")
            if not tls or not s["starttls"]["tls_established"]:
                out.append(
                    Anomaly(
                        code="A3_plaintext_on_implicit_port",
                        severity="critical",
                        endpoint=s["endpoint"],
                        detail=f"implicit-TLS port {s['port']} served a plaintext session",
                        observed="plaintext",
                        baseline=f"peer also serves on {sorted(ports)}",
                        rationale=(
                            "Port 465/993/995 are implicit-TLS listeners. A plaintext "
                            "session there means the client believed it was protected "
                            "and was not."
                        ),
                        weight=0.9,
                    )
                )

        if not s["reassembly"]["complete"]:
            out.append(
                Anomaly(
                    code="A5_evidence_gap",
                    severity="low",
                    endpoint=s["endpoint"],
                    detail="TCP stream has gaps, so part of this session was not analysable",
                    observed=s["reassembly"]["client_gaps"] + s["reassembly"]["server_gaps"],
                    baseline="complete stream",
                    rationale="Analysis around a gap can miss a planted pattern.",
                    weight=0.95,
                )
            )

        for a in out[before:]:
            a.session_id = s.get("session_id", "")

    # A4 is a property of the peer, not of one session, so it is emitted once
    # per peer and anchored to the first session that presented a certificate.
    for peer, fps in sorted(b.fingerprints_per_peer.items()):
        if len(fps) <= 1:
            continue
        anchor = next(
            (
                s
                for s in sessions
                if s["peer"] == peer
                and any(
                    not c.get("is_ca")
                    for c in ((s.get("tls") or {}).get("certificates") or [])
                )
            ),
            None,
        )
        out.append(
            Anomaly(
                code="A4_certificate_inconsistency",
                severity="high",
                endpoint=anchor["endpoint"] if anchor else f"{peer}:-",
                detail=f"peer presented {len(fps)} distinct leaf certificates in one capture",
                observed=len(fps),
                baseline="1 leaf certificate per peer",
                rationale=(
                    "Rapid certificate rotation is legitimate; presenting several "
                    "different identities for one peer in a short window warrants "
                    "explanation. A normal chain's CA certificate is not counted."
                ),
                weight=0.55,
                session_id=(anchor or {}).get("session_id", ""),
            )
        )

    if len(b.session_sizes) >= 4:
        mean = statistics.fmean(b.session_sizes)
        stdev = statistics.pstdev(b.session_sizes) or MAD_FLOOR
        for s in sessions:
            total = s["bytes"]["client"] + s["bytes"]["server"]
            if mean > 0:
                z = abs(total - mean) / stdev
                if z > 3.0:
                    out.append(
                        Anomaly(
                            code="A6_session_size_outlier",
                            severity="low",
                            endpoint=s["endpoint"],
                            detail=f"session size {total} B is {z:.1f} sigma from the capture mean",
                            observed=total,
                            baseline=f"mean {int(mean)} B, sd {int(stdev)} B",
                            rationale="An unusually large or small session may carry a different workload.",
                            weight=0.4,
                            session_id=s.get("session_id", ""),
                        )
                    )

    out.sort(key=lambda a: (a.severity, a.code, a.endpoint))
    return out
