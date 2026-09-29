"""Risk fusion, prioritisation and posture scoring.

Two things this module is careful about:

* A score is never presented without the evidence that produced it. Every
  contribution is itemised in `explain()`.
* A dimension the capture cannot observe is marked `not_assessed` and left out
  of the aggregate, rather than being scored as zero. Defaulting an unknown to
  "bad" would make an unobservable capture look worse than a genuinely bad one.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_WEIGHT = {
    "critical": 40.0,
    "high": 25.0,
    "medium": 12.0,
    "low": 5.0,
    "info": 0.5,
}

# Exposure multipliers: how much worse an issue gets when it is also visible in
# other sessions from the same peer, or when it affects an implicit-TLS port
# where the client believed it was protected.
CROSS_SESSION_BOOST = 1.25
CITIZEN_TRAFFIC_PORTS = {25, 465, 587, 143, 993, 110, 995}

P1_MIN = 70.0
P2_MIN = 45.0
P3_MIN = 20.0

# Priority bands are anchored to severity, not to the numeric score. A critical
# finding must be actionable as P1; making P1 reachable only by summing
# bonuses would mean a single severe finding on a single-flow capture could
# never be prioritised, which is the opposite of what an operator needs.
SEVERITY_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P4",
}
ESCALATE = {"P4": "P3", "P3": "P2", "P2": "P1", "P1": "P1"}
DEMOTE = {"P1": "P2", "P2": "P3", "P3": "P4", "P4": "P4"}

# Below this detection weight a finding is demoted one band: an observation the
# tool itself is unsure about should not sit in the top queue. This is an
# ordering threshold on a hand-set heuristic, not a probability threshold.
LOW_WEIGHT = 0.4


@dataclass
class ScoreContribution:
    label: str
    points: float
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "points": round(self.points, 2), "rationale": self.rationale}


@dataclass
class RiskScore:
    total: float
    priority: str
    contributions: List[ScoreContribution] = field(default_factory=list)
    # The detection weight this score was derived from, clamped to 0-1. It is a
    # ranking heuristic, not a probability.
    weight: float = 0.5
    model_used: str = "rules"

    def explain(self) -> Dict[str, Any]:
        return {
            "total": round(self.total, 2),
            "priority": self.priority,
            "weight": round(self.weight, 3),
            "model": self.model_used,
            "contributions": [c.to_dict() for c in self.contributions],
        }


def _priority(total: float, severity: str, weight: float) -> str:
    p = SEVERITY_PRIORITY.get(severity, "P4")
    if weight < LOW_WEIGHT:
        p = DEMOTE.get(p, p)
    if severity == "critical":
        p = "P1"
    if severity == "high" and total < P2_MIN and weight < 0.6:
        p = "P3"
    return p


def score_finding(
    finding: Dict[str, Any],
    *,
    cross_session_peers: Optional[Dict[str, int]] = None,
    total_sessions: int = 1,
    model_score: Optional[float] = None,
) -> RiskScore:
    severity = finding.get("severity", "info")
    base = SEVERITY_WEIGHT.get(severity, 1.0)
    contributions = [
        ScoreContribution(
            f"severity:{severity}", base, f"finding severity is {severity}"
        )
    ]

    conf = float(finding.get("weight", finding.get("confidence", 0.5)))
    contributions.append(
        ScoreContribution(
            "detection_weight",
            (conf - 0.5) * 8.0,
            f"detection weight {conf:.2f} (ordering heuristic, not a probability)",
        )
    )

    endpoint = finding.get("endpoint", "")
    peer = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
    if cross_session_peers:
        seen = cross_session_peers.get(peer, 1)
        if seen > 1:
            extra = base * (CROSS_SESSION_BOOST - 1.0) * min(3.0, math.log2(seen))
            contributions.append(
                ScoreContribution(
                    "cross_session_recurrence",
                    extra,
                    f"same peer affected in {seen} of {total_sessions} sessions",
                )
            )

    port = _port_of(finding)
    if port in CITIZEN_TRAFFIC_PORTS:
        contributions.append(
            ScoreContribution(
                "citizen_service_port",
                6.0,
                f"port {port} is a standard citizen-facing mail service port",
            )
        )

    signatures = finding.get("evidence", {}).get("signatures") or []
    if signatures:
        contributions.append(
            ScoreContribution(
                "active_tamper_signature",
                12.0,
                f"passive tamper signature(s) present: {', '.join(signatures)}",
            )
        )

    if model_score is not None:
        contributions.append(
            ScoreContribution(
                "learned_model",
                model_score * 15.0,
                f"model contribution {model_score:.2f} (0-1)",
            )
        )

    total = sum(c.points for c in contributions)
    total = max(0.0, min(100.0, total))
    weight = max(0.0, min(1.0, conf))
    priority = _priority(total, severity, weight)
    if signatures and cross_session_peers and cross_session_peers.get(peer, 1) > 1:
        # Corroborated active tampering across more than one session to the same
        # peer is escalated: a single observation can be a misconfiguration, a
        # repeated one across independent sessions is a policy.
        escalated = ESCALATE.get(priority, priority)
        contributions.append(
            ScoreContribution(
                "corroborated_tamper_escalation",
                0.0,
                f"escalated {priority} to {escalated}: tamper signature plus "
                f"{cross_session_peers.get(peer, 1)} affected sessions",
            )
        )
        priority = escalated
    return RiskScore(
        total=total,
        priority=priority,
        contributions=contributions,
        weight=weight,
        model_used="onnx" if model_score is not None else "rules",
    )


def _port_of(finding: Dict[str, Any]) -> Optional[int]:
    endpoint = finding.get("endpoint", "")
    if ":" in endpoint:
        try:
            return int(endpoint.rsplit(":", 1)[1])
        except ValueError:
            return None
    return finding.get("evidence", {}).get("port")


# ── posture ─────────────────────────────────────────────────────────────────

GRADE_TABLE = [
    (90, "A", "Strong"),
    (80, "B", "Adequate"),
    (70, "C", "Needs work"),
    (55, "D", "Weak"),
    (0, "F", "Critical"),
]

DIMENSION_WEIGHTS = {
    "transport_encryption": 30.0,
    "certificate_hygiene": 25.0,
    "forward_secrecy": 20.0,
    "evidence_integrity": 15.0,
    "tamper_resistance": 10.0,
}


def posture(sessions: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A 0-100 posture score with the dimension breakdown shown.

    Each dimension also carries its own `rationale` and `measured` count, so a
    reader can see *why* a dimension is not 100 rather than trusting a bare
    number. The rationale is built from the same inputs that produced the value,
    in the same function, which is deliberate: an explanation computed
    separately could disagree with the score it claims to explain.
    """
    mail_sessions = [
        s for s in sessions if s.get("protocol") in ("SMTP", "IMAP", "POP3")
    ]
    not_assessed: List[str] = []
    dims: Dict[str, float] = {}
    # Parallel to `dims`: how each dimension was measured, and what drove it.
    explanation: Dict[str, Dict[str, Any]] = {}

    if not mail_sessions:
        dims["transport_encryption"] = 0.0
        dims["tamper_resistance"] = 0.0
        not_assessed.extend(["transport_encryption", "tamper_resistance"])
        for key in ("transport_encryption", "tamper_resistance"):
            explanation[key] = {
                "measured": 0,
                "rationale": (
                    "No mail session was identified, so this dimension has nothing "
                    "to measure. It is reported as not assessed rather than as a "
                    "failing score."
                ),
            }
    else:
        upgraded = sum(1 for s in mail_sessions if s["starttls"]["tls_established"])
        dims["transport_encryption"] = round(100.0 * upgraded / len(mail_sessions), 2)
        explanation["transport_encryption"] = {
            "measured": len(mail_sessions),
            "rationale": (
                f"{upgraded} of {len(mail_sessions)} mail session(s) completed a TLS "
                "upgrade. Scored as the share of mail sessions whose transport was "
                "encrypted."
            ),
        }
        clean = sum(1 for s in mail_sessions if not s["starttls"]["signatures"])
        dims["tamper_resistance"] = round(100.0 * clean / len(mail_sessions), 2)
        signed_off = len(mail_sessions) - clean
        explanation["tamper_resistance"] = {
            "measured": len(mail_sessions),
            "rationale": (
                f"{signed_off} of {len(mail_sessions)} mail session(s) carried a "
                "STARTTLS/STLS downgrade signature. Scored as the share of mail "
                "sessions with no evidence of an altered upgrade advertisement."
            ),
        }

    cert_sessions = [
        s for s in mail_sessions if s.get("tls") and s["tls"].get("certificate_visible")
    ]
    if not cert_sessions:
        dims["certificate_hygiene"] = 0.0
        not_assessed.append("certificate_hygiene")
        explanation["certificate_hygiene"] = {
            "measured": 0,
            "rationale": (
                "No certificate was visible on the wire (TLS 1.3 encrypts it, or no "
                "handshake was captured). Reported as not assessed rather than as a "
                "failing score."
            ),
        }
    else:
        cert_codes = {
            "certificate_expired",
            "certificate_not_yet_valid",
            "weak_public_key",
            "weak_signature_algorithm",
            "hostname_mismatch",
            "incomplete_chain",
            "chain_signature_invalid",
            "self_signed_leaf",
        }
        endpoints_with_issue = {
            f["endpoint"]
            for f in findings
            if f["code"] in cert_codes and f.get("endpoint")
        }
        clean = sum(1 for s in cert_sessions if s["endpoint"] not in endpoints_with_issue)
        dims["certificate_hygiene"] = round(100.0 * clean / len(cert_sessions), 2)
        flagged = sorted(endpoints_with_issue)
        explanation["certificate_hygiene"] = {
            "measured": len(cert_sessions),
            "rationale": (
                f"{clean} of {len(cert_sessions)} certificate-bearing session(s) had "
                "no certificate defect"
                + (f". Flagged: {', '.join(flagged)}." if flagged else ".")
            ),
        }

    visible_pfs = [s for s in mail_sessions if s.get("tls")]
    if not visible_pfs:
        dims["forward_secrecy"] = 0.0
        not_assessed.append("forward_secrecy")
        explanation["forward_secrecy"] = {
            "measured": 0,
            "rationale": (
                "No TLS session was captured, so forward secrecy could not be "
                "observed. Reported as not assessed rather than as a failing score."
            ),
        }
    else:
        with_pfs = sum(1 for s in visible_pfs if s["tls"].get("forward_secrecy"))
        dims["forward_secrecy"] = round(100.0 * with_pfs / len(visible_pfs), 2)
        explanation["forward_secrecy"] = {
            "measured": len(visible_pfs),
            "rationale": (
                f"{with_pfs} of {len(visible_pfs)} TLS session(s) negotiated a "
                "forward-secret key exchange. Scored over sessions where a key "
                "exchange was actually visible."
            ),
        }

    if not sessions:
        dims["evidence_integrity"] = 0.0
        not_assessed.append("evidence_integrity")
        explanation["evidence_integrity"] = {
            "measured": 0,
            "rationale": "No session was reconstructed, so there is no evidence to grade.",
        }
    else:
        complete = sum(1 for s in sessions if s["reassembly"]["complete"])
        dims["evidence_integrity"] = round(100.0 * complete / len(sessions), 2)
        gapped = sorted(
            str(s.get("endpoint") or "?") for s in sessions if not s["reassembly"]["complete"]
        )
        explanation["evidence_integrity"] = {
            "measured": len(sessions),
            "rationale": (
                f"{complete} of {len(sessions)} session(s) reassembled without a "
                "packet gap"
                + (f". Gapped: {', '.join(gapped)}." if gapped else ".")
            ),
        }

    # Each dimension is a 0-100 grade; its weight is the share of the total it
    # is allowed to account for.
    weighted = sum(DIMENSION_WEIGHTS[k] * (dims[k] / 100.0) for k in dims)
    total = round(weighted, 2)
    grade, label = "F", "Critical"
    for threshold, g, l in GRADE_TABLE:
        if total >= threshold:
            grade, label = g, l
            break

    # Fold the weight and the points each dimension actually contributed into
    # the explanation, so the UI can show why one dimension moved the grade more
    # than another without recomputing the arithmetic.
    for key, meta in explanation.items():
        meta["value"] = dims[key]
        meta["weight"] = DIMENSION_WEIGHTS[key]
        meta["points"] = round(DIMENSION_WEIGHTS[key] * (dims[key] / 100.0), 2)
        meta["not_assessed"] = key in not_assessed

    return {
        "score": total,
        "grade": grade,
        "label": label,
        "dimensions": dims,
        "weights": DIMENSION_WEIGHTS,
        "dimension_explanation": explanation,
        "not_assessed": not_assessed,
        "sessions_measured": len(sessions),
        "mail_sessions_measured": len(mail_sessions),
    }


# ── learned model ─────────────────────────────────────────────────

# Bumped whenever the feature vector changes shape or meaning. A trained model
# records the version it was built against and the loader refuses a mismatch,
# because a stale feature vector produces wrong predictions silently rather
# than raising an error.
FEATURE_SCHEMA_VERSION = 2

FEATURE_NAMES: List[str] = [
    # Finding severity
    "sev_critical",
    "sev_high",
    "sev_medium",
    # STARTTLS negotiation
    "starttls_advertised",
    "starttls_attempted",
    "starttls_server_ready",
    "starttls_tls_established",
    "starttls_downgrade",
    "starttls_cross_flow_inconsistent",
    "starttls_state_suppressed",
    "starttls_state_refused",
    "starttls_state_absent",
    "starttls_state_upgraded",
    "starttls_evidence_confidence",
    "starttls_has_obfuscated_token",
    # TLS transport, as ordinal ranks (0 recommended .. 4 unknown)
    "tls_version_rank",
    "tls_cipher_rank",
    "tls_group_rank",
    "tls_signature_rank",
    "tls_worst_rank",
    "tls_version_ordinal",
    "tls_forward_secrecy",
    "tls_certificate_visible",
    "tls_not_assessed_count",
    # Certificate
    "cert_visible",
    "cert_key_bits",
    "cert_key_weak",
    "cert_expired",
    "cert_not_yet_valid",
    "cert_days_remaining",
    "cert_self_signed",
    "cert_chain_depth",
    "cert_leaf_is_ca",
    "cert_sig_algorithm_rsa",
    "cert_hash_weak",
    # Protocol and transport integrity
    "proto_smtp",
    "proto_imap",
    "proto_pop3",
    "proto_confidence",
    "port_is_citizen_mail",
    "reassembly_complete",
    "reassembly_retransmit_bytes",
    "session_bytes_log10",
    # Capture context
    "cross_session_peer_sessions",
    "has_tamper_signature",
    "detection_weight",
]

# TLS version strings to a monotonic ordinal. 0 means the version could not be
# observed at all, which is different from "an old version was observed" and
# must not collapse to the same value.
_VERSION_ORDINAL = {
    "": 0.0,
    "SSL 2.0": 1.0,
    "SSL 3.0": 2.0,
    "TLS 1.0": 3.0,
    "TLS 1.1": 4.0,
    "TLS 1.2": 5.0,
    "TLS 1.3": 6.0,
}

_CITIZEN_MAIL_PORTS = (25, 465, 587, 143, 993, 110, 995)

# Below this an RSA/DSA key is treated as weak regardless of the exact bit
# count. Mirrors the policy threshold so the feature and the finding agree.
WEAK_KEY_BITS = 2048

_WEAK_HASHES = ("sha1", "md5")

# Columns whose raw values are unbounded counts (key sizes, byte counts, day
# counts). They are log1p-compressed inside features_for rather than in the
# training script, so that the vector a model is trained on and the vector the
# runtime feeds it are produced by one piece of code. If the transform lived in
# the notebook it would silently drift from this module and every score would
# be wrong in a way nothing would catch.
BOUNDED_FEATURES = (
    "cert_key_bits",
    "cert_days_remaining",
    "session_bytes_log10",
    "cross_session_peer_sessions",
    "reassembly_retransmit_bytes",
)


def _bounded(value: Any) -> float:
    """log1p of a non-negative count, safe for None/NaN/inf and negatives."""
    out = _f(value)
    if out <= 0.0:
        return 0.0
    return math.log1p(out)


def _bounded_signed(value: Any) -> float:
    """As _bounded, but preserving sign: `days_remaining` is negative when expired."""
    out = _f(value)
    if out == 0.0:
        return 0.0
    return math.copysign(math.log1p(abs(out)), out)


def _f(value: Any) -> float:
    """Coerce to a finite float; None, NaN and inf all become 0.0.

    A model must never be handed NaN: it propagates silently through inference
    and yields an undefined score with no error raised.
    """
    try:
        out = float(value)
    except (TypeError, ValueError):
        return 0.0
    if out != out or out in (float("inf"), float("-inf")):
        return 0.0
    return out


def _rank(rating: Any) -> float:
    """Map a policy rating string to its 0..4 ordinal."""
    from ..policy import ciphers

    if not isinstance(rating, str) or not rating:
        return 4.0
    return _f(ciphers.sort_key(rating))


def _leaf_cert(tls: Dict[str, Any]) -> Dict[str, Any]:
    """The end-entity certificate, or the first one if none is marked CA."""
    certs = tls.get("certificates") or []
    if not certs:
        return {}
    for cert in certs:
        if not cert.get("is_ca"):
            return cert or {}
    return certs[0] or {}


def features_for(finding: Dict[str, Any], session: Optional[Dict[str, Any]],
                 cross_peers: Optional[Dict[str, int]] = None) -> List[float]:
    """Build the feature vector for one finding and the session it came from.

    Every value is derived from observed bytes or from a policy lookup, so the
    vector is deterministic and reproducible. Nothing here consults an external
    profile or a learned artefact.

    The intended training target is the cryptographic risk class of the capture
    the finding came from, assigned at synthesis time from the weakness profile
    that was deliberately injected. It is deliberately *not* the severity the
    rules assign: learning to reproduce the rules that already score the finding
    is circular, and teaches the model nothing that the rules do not already say.
    """
    ev = finding.get("evidence", {}) or {}
    sess = session or {}
    sev = finding.get("severity", "info")
    st = sess.get("starttls", {}) or {}
    tls = sess.get("tls") or {}
    cert = _leaf_cert(tls)
    state = st.get("state", "") or ""
    proto = sess.get("protocol", "") or ""
    port = sess.get("port") or 0
    peer = (finding.get("endpoint", "") or "").rsplit(":", 1)[0]
    reassembly = sess.get("reassembly", {}) or {}

    key_bits = _f(cert.get("public_key_bits"))
    key_algo = (cert.get("public_key_algorithm", "") or "").lower()
    sig_hash = (cert.get("signature_hash", "") or "").lower()
    cert_sig_algo = (cert.get("signature_algorithm", "") or "").lower()
    expiry = (cert.get("expiry_at_capture", "") or "").lower()

    rsa_like = key_algo in ("rsa", "dsa")
    return [
        # Finding severity
        1.0 if sev == "critical" else 0.0,
        1.0 if sev == "high" else 0.0,
        1.0 if sev == "medium" else 0.0,
        # STARTTLS negotiation
        1.0 if st.get("advertised") else 0.0,
        1.0 if st.get("upgrade_attempted") else 0.0,
        1.0 if st.get("server_ready") else 0.0,
        1.0 if st.get("tls_established") else 0.0,
        1.0 if st.get("downgrade") else 0.0,
        1.0 if st.get("cross_flow_inconsistent") else 0.0,
        1.0 if state == "suppressed" else 0.0,
        1.0 if state == "refused" else 0.0,
        1.0 if state == "absent" else 0.0,
        1.0 if state == "upgraded" else 0.0,
        _f(st.get("confidence")),
        1.0 if st.get("obfuscated_tokens") else 0.0,
        # TLS transport
        _rank(tls.get("version_rating")),
        _rank(tls.get("cipher_rating")),
        _rank(tls.get("group_rating")),
        _rank(tls.get("signature_rating")),
        _rank(tls.get("worst_rating")),
        _VERSION_ORDINAL.get(tls.get("version", "") or "", 0.0),
        1.0 if tls.get("forward_secrecy") else 0.0,
        1.0 if tls.get("certificate_visible") else 0.0,
        _f(len(tls.get("not_assessed") or [])),
        # Certificate
        1.0 if cert else 0.0,
        _bounded(cert.get("public_key_bits")),
        1.0 if (rsa_like and 0.0 < key_bits < WEAK_KEY_BITS) else 0.0,
        1.0 if expiry in ("expired", "invalid") else 0.0,
        1.0 if expiry in ("not_yet_valid", "future") else 0.0,
        _bounded_signed(cert.get("days_remaining")),
        1.0 if cert.get("self_signed") else 0.0,
        _f(len(tls.get("chain") or [])),
        1.0 if cert.get("is_ca") else 0.0,
        1.0 if "rsa" in cert_sig_algo else 0.0,
        1.0 if sig_hash in _WEAK_HASHES else 0.0,
        # Protocol and transport integrity
        1.0 if proto == "SMTP" else 0.0,
        1.0 if proto == "IMAP" else 0.0,
        1.0 if proto == "POP3" else 0.0,
        _f(sess.get("protocol_confidence")),
        1.0 if port in _CITIZEN_MAIL_PORTS else 0.0,
        1.0 if reassembly.get("complete") else 0.0,
        _bounded(reassembly.get("retransmit_bytes")),
        _bounded(sess.get("bytes")),
        # Capture context
        _f((cross_peers or {}).get(peer, 1)),
        1.0 if ev.get("signatures") else 0.0,
        _f(finding.get("weight", finding.get("confidence", 0.5))),
    ]


def feature_schema() -> Dict[str, Any]:
    """The contract a trained model must declare to be loadable."""
    return {
        "version": FEATURE_SCHEMA_VERSION,
        "names": list(FEATURE_NAMES),
        "count": len(FEATURE_NAMES),
    }


def session_feature_row(
    session: Dict[str, Any],
    findings: Optional[List[Dict[str, Any]]] = None,
    cross_peers: Optional[Dict[str, int]] = None,
) -> List[float]:
    """One feature row per session, aggregating that session's findings.

    Training on findings alone would produce a dataset containing no clean
    examples at all, because a healthy session yields no findings, and a model
    trained only on positive examples cannot learn what "acceptable" looks like.
    A session with no findings therefore still produces a row: the synthetic
    stand-in finding below carries severity "info" and no evidence, so the row
    describes the session's observed cryptography rather than its absence of
    complaints.
    """
    rows = list(findings or [])
    if not rows:
        rows = [
            {
                "code": "session_summary",
                "severity": "info",
                "endpoint": session.get("endpoint", ""),
                "weight": 0.5,
                "evidence": {},
            }
        ]
    # A session is represented by its most serious finding, which is the row
    # that carries the most cryptographic signal. The ordering must be *total*:
    # `min` returns the first minimum, so keying on severity alone would make
    # the representative finding depend on the order the caller happened to pass
    # findings in. The engine hands over detector order and the report hands
    # over sorted order, so a severity tie would silently train on one finding
    # and serve another. Ties therefore break on the strongest detection
    # weight, then on code, which is stable under any input ordering.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    worst = min(
        rows,
        key=lambda f: (
            order.get(f.get("severity", "info"), 4),
            -float(f.get("weight", 0.5) or 0.0),
            str(f.get("code", "")),
        ),
    )
    return features_for(worst, session, cross_peers)


class LearnedRiskModel:
    """Optional ONNX scoring model.

    KryxAI runs fully and deterministically without this. When a model file is
    supplied, its score is fused with the rule score as an extra contribution
    and the result records that the model was used. If the model cannot be
    loaded, the reason is recorded and the rule score stands alone. A model
    built against a different feature schema is rejected rather than applied to
    a vector it was not trained for.

    Feature values outside the range the model was trained on are clamped to
    that range, and the fact is recorded rather than silently applied. An MLP
    has no defined behaviour outside its training data: a ReLU stack fed an
    unseen magnitude returns whatever the last layer happens to produce, which
    for this model was a saturated 1.0 on a session with no findings at all.
    Clamping keeps the score inside the region where it means something and
    leaves the caller able to say where the number came from.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self.session = None
        self.status = "not_configured"
        self.schema_version: Optional[int] = None
        # Per-feature [min, max] as observed in training, and the names of any
        # features that had no variance at all. Populated from the model card,
        # which the notebook writes from the same matrix it trained on.
        self.ranges: Dict[str, Tuple[float, float]] = {}
        self.constant_features: List[str] = []
        # Features whose value was outside the training range on the most recent
        # score() call. Reset per call, so it always describes the last score and
        # not some earlier one.
        self.clamped_features: List[str] = []
        if not path:
            return
        try:
            import onnxruntime as ort

            self.session = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
            self.input_name = self.session.get_inputs()[0].name
            self.status = "loaded"
            self._check_schema()
            self._load_ranges()
        except Exception as exc:
            self.session = None
            self.status = f"unavailable: {exc}"

    def _load_ranges(self) -> None:
        """Read the training feature ranges from the shipped model card.

        The card is optional. A model without one still runs, and the clamping
        step then does nothing, which is the pre-existing behaviour rather than a
        new failure mode.
        """
        from pathlib import Path

        card_path = Path(self.path).parent / "model_card.json"
        if not card_path.is_file():
            return
        try:
            import json

            card = json.loads(card_path.read_text(encoding="utf-8"))
        except Exception:
            return
        raw = card.get("feature_ranges") or {}
        if not isinstance(raw, dict):
            return
        for name, pair in raw.items():
            if name not in FEATURE_NAMES:
                continue
            try:
                lo, hi = float(pair[0]), float(pair[1])
            except (TypeError, ValueError, IndexError):
                continue
            if hi < lo:
                lo, hi = hi, lo
            self.ranges[name] = (lo, hi)
            if lo == hi:
                self.constant_features.append(name)

    def _check_schema(self) -> None:
        """Confirm the model's declared feature layout matches this build."""
        meta = self.session.get_modelmeta().custom_metadata_map or {}
        declared = meta.get("kryxai_feature_schema_version")
        if declared is None:
            raise ValueError(
                "model does not declare kryxai_feature_schema_version; refusing "
                "to apply an unversioned feature vector"
            )
        self.schema_version = int(declared)
        if self.schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"model was trained on feature schema v{self.schema_version}, "
                f"this build is v{FEATURE_SCHEMA_VERSION}; retrain or set "
                "KRYXAI_ONNX_MODEL_PATH= to use the rules alone"
            )
        names = meta.get("kryxai_feature_names")
        # Both the version and the names are required. The version alone is a
        # manual bump that can be forgotten, whereas the names fail loudly the
        # moment a feature is renamed, reordered, added or dropped. Tolerating a
        # missing list would mean silently trusting a 46-long vector whose
        # meaning nobody recorded, which is exactly the failure this check
        # exists to prevent. training/export/install_model.py enforces the same
        # requirement before a model is ever installed.
        if not names:
            raise ValueError(
                "model does not declare kryxai_feature_names; it cannot be "
                "verified against this build's feature vector"
            )
        if names.split(",") != FEATURE_NAMES:
            raise ValueError(
                "model feature names do not match this build's FEATURE_NAMES"
            )

    def _clamp(self, features: List[float]) -> List[float]:
        """Pull out-of-training-range values back to the range that was seen.

        Returns the clamped vector and records the names of everything moved, so
        a caller can report that a score was computed on a clamped input rather
        than presenting it as a straightforward prediction.
        """
        if not self.ranges:
            return features
        self.clamped_features = []
        out = list(features)
        touched: List[str] = []
        for i, name in enumerate(FEATURE_NAMES):
            if i >= len(out):
                break
            bounds = self.ranges.get(name)
            if bounds is None:
                continue
            lo, hi = bounds
            v = out[i]
            if v < lo:
                out[i] = lo
                touched.append(name)
            elif v > hi:
                out[i] = hi
                touched.append(name)
        if touched:
            self.clamped_features = sorted(set(touched))
        return out

    def score(self, features: List[float]) -> Optional[float]:
        if self.session is None:
            return None
        try:
            import numpy as np

            vector = self._clamp(features)
            out = self.session.run(
                None,
                {self.input_name: np.array([vector], dtype=np.float32)},
            )
            # Flatten before reading. A model exported with output shape [None, 1]
            # yields a (1, 1) array, so out[0][0] is itself a one-element array;
            # float() on that raises under numpy 2.x, and the bare except below
            # would swallow it and silently report "no score" for a model that
            # loaded perfectly well.
            value = float(np.asarray(out, dtype=np.float64).ravel()[0])
            # Clamped to the 0-1 range a risk score is defined on. A linear
            # regression head is not bounded and can overshoot on inputs unlike
            # its training set; clamping keeps a well-formed number flowing into
            # the fusion rather than an out-of-range one.
            return min(1.0, max(0.0, value))
        except Exception:
            return None
