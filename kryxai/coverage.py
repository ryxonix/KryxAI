"""Requirement coverage: what this scan actually proved, and how.

The brief asks for a specific list of outputs. A tool that quietly produced
some of them is hard to audit, and one that claimed all of them regardless
would be worse than either. This module derives coverage from the scan's own
evidence so the answer is checkable rather than asserted.

Two ideas carry the design:

*Evidence, not assertion.* A requirement is demonstrated by something in the
report: a finding code, a negotiated version, an extracted certificate. The
evidence is carried alongside the status so a reviewer can see the
provenance of a green row instead of taking it on trust.

*Absence is not failure.* A capture where every server upgraded cleanly has no
weak-cipher finding, which is the desired outcome, not a missing feature. Such
requirements report ``clean`` with the count of sessions that were examined
and found compliant. Only a requirement the engine has no path to evaluate at
all reports ``not_demonstrated``, and that is a statement about this capture
rather than about the tool.

The three states are deliberately distinct:

``demonstrated``
    The requirement produced positive evidence: a finding, or an artefact
    extracted and described.
``clean``
    The requirement was evaluated across the sessions and nothing adverse was
    found. The scan says so with a count.
``not_demonstrated``
    The engine supports it but this capture contains nothing that exercises it.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

DEMONSTRATED = "demonstrated"
CLEAN = "clean"
NOT_DEMONSTRATED = "not_demonstrated"

_MAIL_PROTOCOLS = ("SMTP", "IMAP", "POP3")


def _codes(findings: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Group finding codes by deliverable tag, dropping the sentinel."""
    out: Dict[str, List[str]] = {}
    for f in findings:
        tag = f.get("deliverable") or ""
        if not tag or tag == "unassigned":
            continue
        out.setdefault(tag, []).append(f["code"])
    for v in out.values():
        v.sort()
    return out


def _mail_sessions(sessions: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [s for s in sessions if s.get("protocol") in _MAIL_PROTOCOLS]


def _tls_sessions(sessions: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [s for s in sessions if s.get("tls")]


def _cert_sessions(sessions: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [s for s in sessions if (s.get("tls") or {}).get("certificates")]


def _all_certs(sessions: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    certs: List[Dict[str, Any]] = []
    for s in sessions:
        certs.extend((s.get("tls") or {}).get("certificates") or [])
    return certs


def _finding_witnesses(
    findings: List[Dict[str, Any]], codes: Iterable[str]
) -> List[str]:
    """Human-readable endpoint+code witnesses for the codes that matched."""
    wanted = set(codes)
    seen: List[str] = []
    for f in findings:
        if f["code"] in wanted:
            wit = f"{f['code']} @ {f.get('endpoint') or 'n/a'}"
            if wit not in seen:
                seen.append(wit)
    return seen


def _entry(
    requirement: str,
    status: str,
    detail: str,
    evidence: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "requirement": requirement,
        "status": status,
        "detail": detail,
        "evidence": evidence or [],
    }


def refresh_export_coverage(
    report: Dict[str, Any], report_files: Dict[str, str]
) -> None:
    """Record the report exports now that they actually exist on disk.

    ``build_coverage`` runs inside ``run_scan``, which is before any file is
    written, so the export row starts as "not demonstrated" with an explanation.
    Reporting it as a failure at that point would be wrong in the other
    direction: the engine does export, it simply has not done it yet. Once
    ``builder.write`` returns, the caller hands the real filenames back here and
    the row is replaced with what was produced.
    """
    cov = report.get("coverage")
    if not cov:
        return

    formats = sorted(
        {str(name).rsplit(".", 1)[-1].lower() for name in report_files.values() if "." in str(name)}
    )
    by_lang: Dict[str, int] = {}
    for name in report_files.values():
        suffix = str(name).rsplit(".", 1)[-1].lower()
        by_lang[suffix] = by_lang.get(suffix, 0) + 1

    for item in cov["items"]:
        if not item["requirement"].startswith("Exportable forensic reports"):
            continue
        if not report_files:
            continue
        item["status"] = DEMONSTRATED
        item["detail"] = (
            "Wrote "
            + ", ".join(f"{n} {fmt}" for fmt, n in sorted(by_lang.items()))
            + " for this scan."
        )
        item["evidence"] = sorted(str(v) for v in report_files.values())[:6]
        break

    cov["report_files"] = {str(k): str(v) for k, v in report_files.items()}
    return None


def build_coverage(
    report: Dict[str, Any],
    report_files: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Derive requirement coverage from a completed scan report."""
    sessions: List[Dict[str, Any]] = report.get("sessions") or []
    findings: List[Dict[str, Any]] = report.get("findings") or []
    anomalies: List[Dict[str, Any]] = report.get("anomalies") or []
    model: Dict[str, Any] = report.get("model") or {}
    compliance: Dict[str, Any] = report.get("compliance") or {}
    posture: Dict[str, Any] = report.get("posture") or {}
    counts: Dict[str, Any] = report.get("counts") or {}

    mail = _mail_sessions(sessions)
    tls = _tls_sessions(sessions)
    certs = _all_certs(sessions)
    by_code = _finding_witnesses(findings, (f["code"] for f in findings))
    tagged = _codes(findings)

    def has(*codes: str) -> bool:
        return any(f["code"] in codes for f in findings)

    items: List[Dict[str, Any]] = []

    # --- 1. protocol identification -------------------------------------
    protos = sorted({s["protocol"] for s in mail if s.get("protocol")})
    items.append(
        _entry(
            "Automatic identification of SMTP, IMAP, and POP3 protocols",
            DEMONSTRATED if protos else NOT_DEMONSTRATED,
            (
                f"Identified {', '.join(protos)} on {len(mail)} of "
                f"{len(sessions)} conversations from greeter and command evidence."
            )
            if protos
            else "No conversation carried a recognised mail greeter.",
            [f"{s['protocol']} on port {s['port']} (confidence {s['protocol_confidence']})"
             for s in mail][:6],
        )
    )

    # --- 2. STARTTLS negotiation ----------------------------------------
    states = [s["starttls"]["state"] for s in mail]
    suppressed = has("starttls_capability_suppressed", "starttls_refused")
    items.append(
        _entry(
            "STARTTLS negotiation detection and validation",
            DEMONSTRATED if suppressed else CLEAN,
            (
                "Capability advertisement diverged from RFC 3207 and the session "
                "continued in plaintext. See the interception evidence below."
            )
            if suppressed
            else (
                f"Evaluated the upgrade state machine on {len(mail)} sessions: "
                + ", ".join(f"{st}={states.count(st)}" for st in sorted(set(states)))
                + "."
            ),
            _finding_witnesses(findings, ("starttls_capability_suppressed", "starttls_refused"))
            or [f"{s['starttls']['state']} on port {s['port']}" for s in mail][:6],
        )
    )

    # --- 3. TCP stream reconstruction ------------------------------------
    complete = sum(1 for s in sessions if s.get("reassembly", {}).get("complete"))
    gaps = sum(
        1
        for s in sessions
        if not s.get("reassembly", {}).get("complete")
    )
    items.append(
        _entry(
            "Complete TCP stream reconstruction",
            CLEAN if gaps == 0 and sessions else DEMONSTRATED,
            (
                f"Reassembled both directions of all {len(sessions)} conversations; "
                f"{complete} had no gaps and {gaps} are reported as partial."
            )
            if gaps
            else f"Reassembled both directions of all {len(sessions)} conversations with no gaps.",
            [f"{s['endpoint']}: {s['bytes']['client']} B up / {s['bytes']['server']} B down"
             for s in sessions][:6],
        )
    )

    # --- 4. TLS handshake reconstruction ---------------------------------
    versions = sorted({s["tls"].get("version") for s in tls if s.get("tls", {}).get("version")})
    items.append(
        _entry(
            "TLS handshake reconstruction and negotiated version detection",
            DEMONSTRATED if versions else NOT_DEMONSTRATED,
            (
                "Reconstructed the handshake and read the negotiated version: "
                + ", ".join(versions)
                + "."
            )
            if versions
            else "No TLS handshake was present to parse in this capture.",
            [
                f"{s['endpoint']}: {s['tls'].get('version')} / {s['tls'].get('cipher_suite')}"
                for s in tls
                if s.get("tls", {}).get("version")
            ][:6],
        )
    )

    # --- 5. cipher suites -------------------------------------------------
    ciphers = sorted({s["tls"].get("cipher_suite") for s in tls if s.get("tls", {}).get("cipher_suite")})
    weak_cipher = has("weak_cipher_suite", "broken_cipher_suite")
    items.append(
        _entry(
            "Identification of negotiated cipher suites",
            DEMONSTRATED if weak_cipher else CLEAN,
            "Rated a negotiated suite against RFC 9325 and flagged it."
            if weak_cipher
            else f"Identified and rated {len(ciphers)} negotiated suite(s): "
            + ", ".join(ciphers)
            + ".",
            _finding_witnesses(findings, ("weak_cipher_suite", "broken_cipher_suite"))
            or ciphers[:6],
        )
    )

    # --- 6. key exchange --------------------------------------------------
    groups = sorted(
        {s["tls"].get("key_exchange_group") for s in tls if s.get("tls", {}).get("key_exchange_group")}
    )
    weak_group = has("weak_key_exchange_group")
    items.append(
        _entry(
            "Identification of key exchange mechanisms",
            DEMONSTRATED if weak_group else CLEAN,
            "Identified the key exchange group and rated it as weak."
            if weak_group
            else "Identified and rated key exchange group(s): "
            + (", ".join(groups) or "TLS 1.3 implies ephemeral key exchange")
            + ".",
            _finding_witnesses(findings, ("weak_key_exchange_group",)) or groups[:6],
        )
    )

    # --- 7. X.509 extraction ---------------------------------------------
    leaves = [c for c in certs if not c.get("is_ca")]
    items.append(
        _entry(
            "Extraction of X.509 certificates",
            DEMONSTRATED if certs else NOT_DEMONSTRATED,
            (
                f"Extracted {len(certs)} certificate(s), {len(leaves)} of them leaf, "
                f"from {len(_cert_sessions(sessions))} session(s)."
            )
            if certs
            else (
                "No certificate was visible. TLS 1.3 encrypts the Certificate message, "
                "so this is expected rather than a failure; see the "
                "passive_tls13_certificate_not_visible finding."
            ),
            [f"{c.get('subject') or 'leaf'} sha256={c.get('sha256_fingerprint', '')[:16]}"
             for c in leaves][:6],
        )
    )

    # --- 8. chain validation ---------------------------------------------
    chain_codes = (
        "incomplete_chain",
        "chain_signature_invalid",
        "self_signed_leaf",
        "unknown_critical_extension",
    )
    chain_hits = has(*chain_codes)
    chain_witnesses = _finding_witnesses(findings, chain_codes)
    items.append(
        _entry(
            "Certificate chain validation",
            DEMONSTRATED if chain_hits else CLEAN,
            "Validated the presented chain and found a defect."
            if chain_hits
            else (
                f"Validated the chain on {len(_cert_sessions(sessions))} session(s): "
                "issuance, signature linkage, basic constraints and critical "
                "extensions all passed."
            ),
            chain_witnesses
            or [f"leaf issued by {c.get('issuer')}" for c in leaves][:6],
        )
    )

    # --- 9. expiry --------------------------------------------------------
    dated = [c for c in certs if c.get("expiry_at_capture") is not None]
    expiry_codes = ("certificate_expired", "certificate_not_yet_valid", "certificate_expiring_soon")
    expiry_hits = has(*expiry_codes)
    items.append(
        _entry(
            "Certificate expiration analysis",
            DEMONSTRATED if expiry_hits else CLEAN,
            "Evaluated validity at capture time and found an out-of-window certificate."
            if expiry_hits
            else (
                f"Evaluated {len(dated)} certificate(s) against the earliest packet "
                "timestamp, not wall-clock time, so the result is reproducible."
            ),
            _finding_witnesses(findings, expiry_codes)
            or [
                f"{c.get('common_name') or 'leaf'}: {c.get('days_remaining')} days remaining at capture"
                for c in dated
            ][:6],
        )
    )

    # --- 10. public key ---------------------------------------------------
    keyed = [c for c in certs if c.get("public_key_algorithm")]
    weak_key = has("weak_public_key")
    items.append(
        _entry(
            "Public key algorithm and key length analysis",
            DEMONSTRATED if weak_key else CLEAN,
            "Identified a public key below the required strength."
            if weak_key
            else "Identified algorithm and length on every visible certificate: "
            + ", ".join(
                sorted(
                    {
                        f"{c['public_key_algorithm']}"
                        + (f"-{c['public_key_bits']}" if c.get("public_key_bits") else "")
                        for c in keyed
                    }
                )
            )
            + ".",
            _finding_witnesses(findings, ("weak_public_key",))
            or [
                f"{c.get('common_name') or 'leaf'}: {c['public_key_algorithm']}"
                + (f" {c['public_key_bits']}-bit" if c.get("public_key_bits") else "")
                for c in keyed
            ][:6],
        )
    )

    # --- 11. signature algorithm -----------------------------------------
    sigged = [c for c in certs if c.get("signature_algorithm")]
    weak_sig = has("weak_signature_algorithm")
    items.append(
        _entry(
            "Digital signature algorithm identification",
            DEMONSTRATED if weak_sig else CLEAN,
            "Identified a deprecated signature algorithm."
            if weak_sig
            else "Read the signature algorithm from every visible certificate: "
            + ", ".join(sorted({str(c["signature_algorithm"]) for c in sigged}))
            + ".",
            _finding_witnesses(findings, ("weak_signature_algorithm",))
            or sorted({str(c["signature_algorithm"]) for c in sigged})[:6],
        )
    )

    # --- 12. weak crypto / deprecated versions ---------------------------
    weak_codes = (
        "weak_tls_version",
        "broken_tls_version",
        "weak_cipher_suite",
        "broken_cipher_suite",
        "weak_key_exchange_group",
        "weak_public_key",
        "weak_signature_algorithm",
    )
    weak_hits = has(*weak_codes)
    rated = [s for s in tls if s.get("tls", {}).get("worst_rating")]
    items.append(
        _entry(
            "Detection of weak cryptographic algorithms and deprecated TLS versions",
            DEMONSTRATED if weak_hits else CLEAN,
            "Flagged a deprecated version, suite, group, key or signature algorithm."
            if weak_hits
            else "Rated every negotiated parameter against RFC 9325 and found none "
            "below the recommended tier: "
            + ", ".join(sorted({str(s["tls"]["worst_rating"]) for s in rated}))
            + ".",
            _finding_witnesses(findings, weak_codes)
            or sorted({str(s["tls"]["worst_rating"]) for s in rated})[:6],
        )
    )

    # --- 13. insecure protocol configuration ------------------------------
    insecure_codes = (
        "starttls_capability_suppressed",
        "starttls_refused",
        "starttls_not_offered",
        "cleartext_mail_session",
        "non_mail_cleartext",
        "insecure_protocol_configuration",
    )
    insecure_hits = has(*insecure_codes)
    cleartext = [s for s in mail if not s["starttls"]["tls_established"]]
    items.append(
        _entry(
            "Identification of insecure protocol configurations",
            DEMONSTRATED if insecure_hits else CLEAN,
            "Identified a listener that left a mail session in cleartext."
            if insecure_hits
            else (
                f"All {len(mail)} mail sessions reached an established TLS state; "
                f"{len(cleartext)} remained cleartext."
            ),
            _finding_witnesses(findings, insecure_codes)
            or [f"{s['endpoint']} upgraded" for s in mail if s["starttls"]["tls_established"]][:6],
        )
    )

    # --- 14. forward secrecy ---------------------------------------------
    pfs_sessions = [
        s for s in tls if s.get("tls", {}).get("forward_secrecy") is not None
    ]
    no_pfs = has("no_forward_secrecy")
    items.append(
        _entry(
            "Forward Secrecy assessment",
            DEMONSTRATED if no_pfs else CLEAN,
            "Assessed a suite that does not provide forward secrecy."
            if no_pfs
            else (
                f"Assessed forward secrecy on {len(pfs_sessions)} session(s); all "
                "negotiated suites provide it."
            ),
            _finding_witnesses(findings, ("no_forward_secrecy",))
            or [
                f"{s['endpoint']}: PFS={s['tls']['forward_secrecy']}"
                for s in pfs_sessions
            ][:6],
        )
    )

    # --- 15. AI risk scoring ---------------------------------------------
    scored = [f for f in findings if f.get("risk")]
    items.append(
        _entry(
            "Cryptographic risk scoring and prioritization",
            DEMONSTRATED if scored else NOT_DEMONSTRATED,
            (
                f"Scored {len(scored)} finding(s) on a 0-100 scale with itemised "
                "contributions and a P1-P4 priority band."
            )
            if scored
            else "No finding reached the scoring stage in this capture.",
            [
                f"{f['code']}: total {f['risk']['total']} ({f['risk']['priority']}), "
                f"primary driver {f['risk'].get('primary') or f['risk'].get('contributions', [{}])[0].get('label', 'n/a')}"
                for f in scored
            ][:6],
        )
    )

    # --- 16. anomaly detection -------------------------------------------
    # Named "baseline" rather than "AI-assisted". The A1-A6 detectors are
    # deterministic thresholds over capture-local statistics - see
    # scoring/anomaly.py - and the optional MLP in scoring/fusion.py is a
    # session risk scorer, not an anomaly model. Labelling this row
    # "AI-assisted" would let a reviewer read an ML claim into a rules result,
    # which is the one thing the rest of this table exists to prevent.
    items.append(
        _entry(
            "Baseline anomaly detection for suspicious TLS sessions",
            DEMONSTRATED if anomalies else CLEAN,
            (
                f"Flagged {len(anomalies)} anomaly/anomalies against capture-local "
                "baselines: "
                + ", ".join(sorted({a["code"] for a in anomalies}))
                + ". Detection is deterministic and threshold-based, not model-based."
            )
            if anomalies
            else (
                f"Compared {len(sessions)} sessions against capture-local baselines "
                "for tamper signatures, partial upgrades, implicit-port plaintext, "
                "certificate inconsistency, evidence gaps and size outliers; none fired. "
                "Detection is deterministic and threshold-based, not model-based."
            ),
            [f"{a['code']} @ {a.get('endpoint') or 'n/a'}: {a.get('detail', '')}" for a in anomalies][:6],
        )
    )

    # --- 17. posture ------------------------------------------------------
    dims = posture.get("dimensions") or {}
    dim_expl = posture.get("dimension_explanation") or {}
    posture_evidence = [
        f"{k}={v} (weight {posture.get('weights', {}).get(k)})"
        for k, v in dims.items()
    ]
    # Show why each dimension is not 100, not just that it is. A bare score is
    # not evidence of an explainable posture, which is what this row claims.
    for key, meta in dim_expl.items():
        if meta.get("rationale"):
            posture_evidence.append(f"{key}: {meta['rationale']}")
    items.append(
        _entry(
            "Cryptographic security posture assessment",
            DEMONSTRATED if posture else NOT_DEMONSTRATED,
            (
                f"Scored {posture.get('score')}/100 (grade {posture.get('grade')}) across "
                f"{len(dims)} weighted dimension(s), each with a per-dimension rationale."
            )
            if posture
            else "Posture was not scored for this capture.",
            posture_evidence,
        )
    )

    # --- 18. prioritized findings + remediation ---------------------------
    prioritized = [f for f in findings if f.get("risk", {}).get("priority")]
    remediation = [f for f in findings if f.get("remediation")]
    items.append(
        _entry(
            "Prioritized security findings and mitigation recommendations",
            DEMONSTRATED if prioritized else NOT_DEMONSTRATED,
            (
                f"Prioritised {len(prioritized)} finding(s) into P1-P4 and attached an "
                f"actionable remediation to {len(remediation)}."
            )
            if prioritized
            else "No finding needed prioritising in this capture.",
            [f"{f['risk']['priority']} {f['code']}: {f.get('remediation', '')}" for f in prioritized][:6],
        )
    )

    # --- 19. compliance ---------------------------------------------------
    provisions = compliance.get("items") or []
    items.append(
        _entry(
            "Statutory mapping (DPDP Act 2023)",
            DEMONSTRATED if provisions else CLEAN,
            (
                f"Mapped {len(provisions)} provision(s) with the quoted statutory "
                "text. This is technical mapping, not a legal opinion."
            )
            if provisions
            else "No finding mapped to a DPDP provision in this capture.",
            [
                f"section {p.get('provision', {}).get('section', 'n/a')}: "
                f"{p.get('observation', '')[:90]}"
                for p in provisions[:6]
            ],
        )
    )

    # --- 20. report exports ----------------------------------------------
    files = report_files or {}
    formats = sorted({name.rsplit(".", 1)[-1].lower() for name in files.values() if "." in name})
    items.append(
        _entry(
            "Exportable forensic reports in JSON, PDF, and HTML formats",
            DEMONSTRATED if files else NOT_DEMONSTRATED,
            (
                "Wrote "
                + ", ".join(sorted(formats))
                + " for this scan."
            )
            if files
            else "This scan was run without persistence, so no report file was written. "
            "The report object itself is what is signed and can be rendered on demand.",
            sorted(files)[:6],
        )
    )

    # --- 21. evidence chain ----------------------------------------------
    # The chain facts live in report["evidence"], not a "chain" key: block_index
    # is only populated once a block has actually been appended, and chain_state
    # is the honest anchor state, which is `pending` rather than `anchored` for a
    # local proof-of-work block.
    evidence_block = report.get("evidence") or {}
    recorded = evidence_block.get("block_index") is not None
    state = evidence_block.get("chain_state")
    items.append(
        _entry(
            "Tamper-evident evidence chain",
            DEMONSTRATED if recorded else NOT_DEMONSTRATED,
            (
                f"Appended block {evidence_block.get('block_index')} to chain "
                f"{evidence_block.get('chain_id') or 'KryxAIV1'}; state {state}. The "
                "block hash is recomputed from the stored payload on read, so a "
                "tampered row fails verification. A local block is tamper-evident, "
                "not externally attested, so the state is reported as "
                f"'{state}' and never as 'anchored'."
            )
            if recorded
            else (
                "No block was recorded for this scan"
                + (
                    " because it ran with --no-chain."
                    if state == "not_recorded"
                    else "."
                )
            ),
            [
                f"block {evidence_block.get('block_index')} "
                f"hash={str(evidence_block.get('block_hash'))[:16]}"
            ]
            if recorded
            else [],
        )
    )

    # --- 22. model provenance --------------------------------------------
    items.append(
        _entry(
            "Optional learned model, provenance recorded",
            DEMONSTRATED if model.get("used") else CLEAN,
            (
                f"ONNX model contributed to {model.get('sessions_scored', 0)} of "
                f"{model.get('sessions_total', 0)} session(s) at feature schema "
                f"v{model.get('feature_schema_version')}."
            )
            if model.get("used")
            else (
                "No model is configured, so the deterministic rule engine scored "
                "every finding on its own. This is the supported default; a model is "
                "opt-in and its absence is recorded rather than inferred."
            ),
            [f"status={model.get('status')}", f"note={model.get('note')}"] if model.get("note") else [f"status={model.get('status')}"],
        )
    )

    # --- 23. interception evidence (the differentiator) -------------------
    # Read from report["interception"] rather than recomputed. The interception
    # block is the authority on whether an advertisement diverged; re-deriving
    # the answer here from starttls.signatures would give two places to disagree
    # about the single most consequential claim in the report.
    ices = report.get("interception") or {}
    tampered = ices.get("sessions_tampered") or 0
    items.append(
        _entry(
            "Downgrade / interception attribution from passive evidence only",
            DEMONSTRATED if tampered else CLEAN,
            (
                f"{ices.get('headline', '')} The divergence is visible only to a "
                "passive observer of the original advertisement: a live scanner "
                "would receive the same rewritten greeting and could not "
                "distinguish it from a compliant server."
            )
            if tampered
            else (
                (ices.get("headline") or "No mail sessions were available to assess.")
                + " Every listener that offered an upgrade offered it intact."
            ),
            [
                f"{s['endpoint']}: expected {s['expected_token']} -> observed "
                f"{s['observed_tokens']} ({'+'.join(s['signatures'])})"
                for s in (ices.get("sessions") or [])
                if s.get("signatures")
            ][:6],
        )
    )

    summary = {DEMONSTRATED: 0, CLEAN: 0, NOT_DEMONSTRATED: 0}
    for it in items:
        summary[it["status"]] = summary.get(it["status"], 0) + 1

    return {
        "items": items,
        "summary": summary,
        "total": len(items),
        # Kept for continuity with counts.by_deliverable, which is derived from
        # finding tags and so cannot see requirements that produced no finding.
        "by_deliverable": tagged,
        "witnesses": by_code[:24],
    }
