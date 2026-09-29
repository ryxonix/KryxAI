"""Rewrite the feature-extraction tail of kryxai/scoring/fusion.py.

The old 8-feature vector is replaced with a full cryptographic feature vector
plus a schema version. Everything after the "optional learned model" header is
regenerated so there is no leftover of the previous FEATURE_NAMES/features_for.
"""

import pathlib

NEW_TAIL = '''# \u2500\u2500 learned model \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

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
        _rank(tls.get("signature_rank") if "signature_rank" in tls else tls.get("signature_rating")),
        _rank(tls.get("worst_rating")),
        _VERSION_ORDINAL.get(tls.get("version", "") or "", 0.0),
        1.0 if tls.get("forward_secrecy") else 0.0,
        1.0 if tls.get("certificate_visible") else 0.0,
        _f(len(tls.get("not_assessed") or [])),
        # Certificate
        1.0 if cert else 0.0,
        key_bits,
        1.0 if (rsa_like and 0.0 < key_bits < WEAK_KEY_BITS) else 0.0,
        1.0 if expiry in ("expired", "invalid") else 0.0,
        1.0 if expiry in ("not_yet_valid", "future") else 0.0,
        _f(cert.get("days_remaining")),
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
        _f(reassembly.get("retransmit_bytes")),
        math.log10(_f(sess.get("bytes")) + 1.0),
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


class LearnedRiskModel:
    """Optional ONNX scoring model.

    KryxAI runs fully and deterministically without this. When a model file is
    supplied, its score is fused with the rule score as an extra contribution
    and the result records that the model was used. If the model cannot be
    loaded, the reason is recorded and the rule score stands alone. A model
    built against a different feature schema is rejected rather than applied to
    a vector it was not trained for.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self.session = None
        self.status = "not_configured"
        self.schema_version: Optional[int] = None
        if not path:
            return
        try:
            import onnxruntime as ort

            self.session = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
            self.input_name = self.session.get_inputs()[0].name
            self.status = "loaded"
            self._check_schema()
        except Exception as exc:
            self.session = None
            self.status = f"unavailable: {exc}"

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
        if names and names.split(",") != FEATURE_NAMES:
            raise ValueError(
                "model feature names do not match this build's FEATURE_NAMES"
            )

    def score(self, features: List[float]) -> Optional[float]:
        if self.session is None:
            return None
        try:
            import numpy as np

            out = self.session.run(
                None,
                {self.input_name: np.array([features], dtype=np.float32)},
            )
            return float(out[0][0])
        except Exception:
            return None
'''

p = pathlib.Path("kryxai/scoring/fusion.py")
src = p.read_text(encoding="utf-8")
i = src.find("# \u2500\u2500 optional learned model")
if i < 0:
    raise SystemExit("header not found")
new = src[:i] + NEW_TAIL
p.write_text(new, encoding="utf-8", newline="\n")
print("rewrote tail; new length", len(new.splitlines()), "lines")
