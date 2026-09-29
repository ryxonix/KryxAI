"""Interception evidence: the one claim a packet decoder cannot make.

Every passive tool can show that a session is unencrypted. This module
assembles the evidence for the stronger claim: that the *advertisement itself*
was altered, so a client that believed TLS was unavailable was misled. That
distinction is the product.

Why a live scanner cannot make this claim
-----------------------------------------
A scanner that opens its own connection asks the path, and the path answers.
If a TLS-inspecting middlebox is rewriting the capability list, the scanner
receives the rewritten greeting and cannot tell it from a compliant server. It
would have to trust the same channel it is trying to audit.

A passive observer sees the advertisement as the server composed it, before
any rewriting decision is applied to somebody else's session. When the token
occupying the STARTTLS slot is not STARTTLS - a same-length substitute, or a
run of filler characters - the only entity that could have produced it is
something in the path. The server either offered the upgrade or it did not.

This module is therefore careful about attribution. It reports what diverged
and from which reference, and it states plainly that a hostile middlebox and a
misconfigured one are indistinguishable from a capture. Naming an attacker
would be a stronger claim than the evidence supports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .pcap.starttls import upgrade_token_for

# The signature -> plain description and the RFC that defines the expected form.
_SIGNATURES: Dict[str, Dict[str, str]] = {
    "K1_capability_suppression": {
        # Deliberately not "the STARTTLS token": POP3 advertises the upgrade as
        # STLS, so a title naming STARTTLS would misdescribe the POP3 evidence
        # in exactly the session where the reader is checking the details.
        "title": "The capability token occupying the upgrade slot is not the one its protocol defines",
        "reference": "RFC 3207 section 4.2",
        "mechanism": (
            "A device in the path replaced the upgrade token in the EHLO, "
            "CAPABILITY or OK response with a substitute of similar shape."
        ),
        "why_it_matters": (
            "The client reads the rewritten advertisement, concludes that no "
            "upgrade is on offer, and sends the message in cleartext without "
            "warning the sender or the recipient."
        ),
    },
    "K2_cross_flow_inconsistency": {
        "title": "The same peer advertised different capabilities across sessions",
        # Not an RFC clause. The divergence is a comparison between two
        # observations of one server, and no specification promises per-session
        # consistency, so citing a section here would imply a mandate that does
        # not exist.
        "reference": "No RFC requires per-session consistency; observed divergence only",
        "mechanism": (
            "One server address answered with the upgrade in some sessions and "
            "without it in others."
        ),
        "why_it_matters": (
            "A server does not normally change its advertised capabilities "
            "between connections seconds apart. A path-dependent device does."
        ),
    },
    "K3_refused_upgrade": {
        "title": "The upgrade was offered and then refused",
        "reference": "RFC 3207 section 4.2 (454 response)",
        "mechanism": "The client issued the upgrade command and the server rejected it.",
        "why_it_matters": (
            "The upgrade was available and was declined, so a client that "
            "silently continued in cleartext carried a message that was meant to "
            "be protected."
        ),
    },
    "K4_plaintext_after_upgrade": {
        "title": "Payload sent in cleartext after a successful upgrade",
        # A TLS-layer observation, not a STARTTLS one: the handshake is done, so
        # RFC 3207 no longer governs what follows.
        "reference": "RFC 8446 / RFC 5246 (record layer must not carry plaintext)",
        "mechanism": (
            "The handshake completed and a TLS record was observed, yet "
            "subsequent bytes on the wire are not encrypted."
        ),
        "why_it_matters": (
            "Either the client ignored the completed upgrade, or something in "
            "the path re-opened the stream after it was secured."
        ),
    },
}

# The per-protocol expected token is not re-declared here. It is read from
# starttls.upgrade_token_for(), which is the same source the capability parser
# compares against, so the "expected" column shown to a reviewer cannot drift
# from the definition the detector actually enforced.


def build_interception(
    sessions: List[Dict[str, Any]],
    anomalies: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Assemble the interception evidence for a completed scan."""
    anomalies = anomalies or []
    anomaly_by_session: Dict[str, List[Dict[str, Any]]] = {}
    for a in anomalies:
        sid = a.get("session_id") or ""
        anomaly_by_session.setdefault(sid, []).append(a)

    assessed: List[Dict[str, Any]] = []
    tampered_count = 0
    cleartext_count = 0
    upgraded_count = 0

    for s in sessions:
        protocol = s.get("protocol")
        st = s.get("starttls") or {}
        if protocol not in ("SMTP", "IMAP", "POP3"):
            continue

        upgraded_count += 1 if st.get("tls_established") else 0
        cleartext_count += 0 if st.get("tls_established") else 1

        sigs = list(st.get("signatures") or [])
        tokens = list(st.get("obfuscated_tokens") or [])
        if sigs:
            tampered_count += 1

        expected = upgrade_token_for(protocol)
        compared = [t for t in tokens]

        assessed.append(
            {
                "session_id": s.get("session_id", ""),
                "endpoint": s.get("endpoint", ""),
                "protocol": protocol,
                "port": s.get("port"),
                "state": st.get("state"),
                "expected_token": expected,
                # Only present when something was actually substituted; a clean
                # advertisement is not shown as "no tokens" because that would
                # read as a finding rather than as a pass.
                "observed_tokens": compared if compared else None,
                "advertised": bool(st.get("advertised")),
                "tls_established": bool(st.get("tls_established")),
                "encrypted_bytes": st.get("encrypted_bytes", 0),
                "downgrade": bool(st.get("downgrade")),
                "signatures": sigs,
                "signature_details": [
                    {
                        "code": sig,
                        "title": _SIGNATURES.get(sig, {}).get("title", sig),
                        "reference": _SIGNATURES.get(sig, {}).get("reference", ""),
                        "mechanism": _SIGNATURES.get(sig, {}).get("mechanism", ""),
                        "why_it_matters": _SIGNATURES.get(sig, {}).get("why_it_matters", ""),
                    }
                    for sig in sigs
                ],
                "confidence": st.get("confidence", 0.0),
                "remediation": st.get("remediation", ""),
                "anomalies": [a.get("code") for a in anomaly_by_session.get(s.get("session_id", ""), [])],
            }
        )

    detected = [a for a in assessed if a["signatures"]]
    cleartext = [a for a in assessed if not a["tls_established"]]

    if detected:
        headline = (
            f"{len(detected)} of {len(assessed)} mail session(s) carried a STARTTLS "
            "advertisement that does not match the form its protocol defines."
        )
        verdict = "tampered_advertisement"
    elif cleartext:
        headline = (
            f"{len(cleartext)} of {len(assessed)} mail session(s) remained in "
            "cleartext, with no evidence that any advertisement was altered."
        )
        verdict = "unencrypted_but_unmodified"
    else:
        headline = (
            f"All {len(assessed)} mail session(s) reached an established TLS state "
            "and no advertisement diverged from its expected form."
        )
        verdict = "no_evidence_of_interception"

    return {
        "verdict": verdict,
        "headline": headline,
        "sessions_assessed": len(assessed),
        "sessions_tampered": tampered_count,
        "sessions_upgraded": upgraded_count,
        "sessions_cleartext": cleartext_count,
        "sessions": assessed,
        # Stated once, on the record, rather than as a per-finding disclaimer.
        "attribution_limit": (
            "A capture shows that the advertisement was altered. It cannot show "
            "whether the device in the path was hostile, vendor-configured, or "
            "an operator's own inspection proxy, and this report does not "
            "attribute intent. Path-side confirmation is required to name a cause."
        ),
        "why_passive": (
            "A scanner that opens its own connection asks the path, and the path "
            "answers. If something in the path is rewriting the capability list, "
            "the scanner receives the rewritten greeting and cannot distinguish "
            "it from a compliant server. A passive observer sees the "
            "advertisement as the server composed it, before any rewriting "
            "decision is applied to a different session. That is the entire basis "
            "for this claim, and it is why no active connection is needed."
        ),
        "reference": "RFC 3207 / RFC 8314 / RFC 9051",
    }
