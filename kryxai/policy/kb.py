"""The KryxAI analysis engine.

Turns a capture into protocol, STARTTLS, TLS, X.509 and configuration findings,
then scores and ranks them. Every finding carries a stable code, an English and
a Hindi title, a severity and the RFC or section reference it rests on, so a
report can be traced back to a specific published requirement.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from kryxai.pcap import x509 as x509mod
from kryxai.pcap.protocol_id import IMAP, POP3, SMTP, ProtocolGuess, guess_protocol
from kryxai.pcap.starttls import (
    StarttlsVerdict,
    UpgradeState,
    analyze_starttls,
    build_peer_baseline,
)
from kryxai.pcap.tcp import Conversation, reassemble
from kryxai.pcap.tls import TlsHandshake, parse_handshake
from kryxai.policy import ciphers

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

_SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

MAIL_PORTS = {25: SMTP, 465: SMTP, 587: SMTP, 143: IMAP, 993: IMAP, 110: POP3, 995: POP3}

_TITLES_HI = {
    "cleartext_mail_session": "मेल सत्र अनएन्क्रिप्टेड",
    "starttls_capability_suppressed": "STARTTLS क्षमता दबाई गई",
    "starttls_refused": "STARTTLS अस्वीकार किया गया",
    "starttls_not_offered": "STARTTLS प्रस्ताव नहीं",
    "cross_flow_inconsistency": "सत्रों के बीच असंगति",
    "weak_tls_version": "कमजोर TLS संस्करण",
    "broken_tls_version": "असुरक्षित TLS संस्करण",
    "weak_cipher_suite": "कमजोर साइफर सूट",
    "broken_cipher_suite": "असुरक्षित साइफर सूट",
    "no_forward_secrecy": "आगे स secrecy अनुपस्थित",
    "weak_key_exchange_group": "कमजोर key exchange समूह",
    "certificate_expired": "प्रमाणपत्र समाप्त",
    "certificate_not_yet_valid": "प्रमाणपत्र अभी मान्य नहीं",
    "certificate_expiring_soon": "प्रमाणपत्र शीघ्र समाप्त",
    "weak_public_key": "कमजोर सार्वजनिक कुंजी",
    "weak_signature_algorithm": "कमजोर हस्ताक्षर एल्गोरिदम",
    "hostname_mismatch": "होस्टनाम मेल नहीं खाता",
    "incomplete_chain": "अपूर्ण प्रमाणपत्र शृंखला",
    "chain_signature_invalid": "शृंखला हस्ताक्षर अमान्य",
    "self_signed_leaf": "स्वयं हस्ताक्षरित प्रमाणपत्र",
    "unknown_critical_extension": "अज्ञात critical एक्सटेंशन",
    "insufficient_reassembly": "अपूर्ण TCP पुनर्संयोजन",
    "passive_tls13_certificate_not_visible": "TLS 1.3 प्रमाणपत्र दृश्य नहीं",
}


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    title_hi: str
    detail: str
    endpoint: str
    reference: str = ""
    remediation: str = ""
    # How strongly the detector asserts this finding, on a 0-1 scale. This is a
    # hand-set ordering weight, NOT a probability: a value of 0.9 does not mean
    # there is a 90% chance the finding is real. It ranks findings and drives
    # priority demotion when the evidence is soft (a heuristic, an inferred
    # port, a partial reassembly). See `fusion.LOW_WEIGHT`.
    weight: float = 0.5
    evidence: Dict[str, Any] = field(default_factory=dict)
    deliverable: str = ""
    session_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["finding_id"] = hashlib.sha256(
            f"{self.code}|{self.endpoint}|{self.title}".encode()
        ).hexdigest()[:16]
        return d


@dataclass
class TlsAssessment:
    handshake: TlsHandshake
    version_rating: str
    cipher_rating: str
    group_rating: str
    signature_rating: str
    pfs: bool
    certificates: List[x509mod.CertificateInfo]
    chain_links: List[x509mod.ChainLink]
    host: Optional[str]
    capture_time: Optional[datetime]

    @property
    def ratings(self) -> Dict[str, str]:
        return {
            "version": self.version_rating,
            "cipher": self.cipher_rating,
            "group": self.group_rating,
            "signature": self.signature_rating,
        }

    @property
    def not_assessed(self) -> List[str]:
        return [k for k, v in self.ratings.items() if v == ciphers.UNKNOWN]

    @property
    def worst_rating(self) -> str:
        """Worst *assessed* dimension.

        A dimension the capture cannot show is excluded rather than allowed to
        dominate: under TLS 1.3 the handshake signature lives inside encrypted
        handshake traffic, and letting that report as "unknown" would mask a
        perfectly good TLS 1.3 session. The exclusions are published as
        `not_assessed` so the gap stays visible.
        """
        assessed = [v for v in self.ratings.values() if v != ciphers.UNKNOWN]
        if not assessed:
            return ciphers.UNKNOWN
        return ciphers.weakest(assessed)

    def summary(self) -> Dict[str, Any]:
        h = self.handshake
        return {
            "version": h.version_name,
            "cipher_suite": h.cipher_name,
            "key_exchange_group": h.group_name,
            "signature_algorithm": h.signature_name,
            "alpn": h.alpn,
            "sni": h.sni,
            "forward_secrecy": self.pfs,
            "certificate_visible": h.certificate_visible,
            "version_rating": self.version_rating,
            "cipher_rating": self.cipher_rating,
            "group_rating": self.group_rating,
            "signature_rating": self.signature_rating,
            "worst_rating": self.worst_rating,
            "not_assessed": self.not_assessed,
            "certificates": [
                {
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "common_name": c.common_name,
                    "organization": c.organization,
                    "serial": c.serial_hex,
                    "not_before": c.not_before.isoformat() if c.not_before else None,
                    "not_after": c.not_after.isoformat() if c.not_after else None,
                    "is_ca": c.is_ca,
                    "self_signed": c.self_signed,
                    "public_key_algorithm": c.public_key_algorithm,
                    "public_key_bits": c.public_key_bits,
                    "public_key_curve": c.public_key_curve,
                    "signature_algorithm": c.signature_algorithm,
                    "signature_hash": c.signature_hash,
                    "sha256_fingerprint": c.sha256_fingerprint,
                    "expiry_at_capture": x509mod.expiry_status(c, self.capture_time),
                    "days_remaining": x509mod.days_remaining(c, self.capture_time)
                    if self.capture_time
                    else None,
                    "san_dns": c.san_dns,
                    "san_matching": c.san_matching,
                    "der_b64": base64.b64encode(c.der).decode("ascii"),
                }
                for c in self.certificates
            ],
            "chain": [asdict(l) for l in self.chain_links],
        }


@dataclass
class SessionAssessment:
    endpoint: str
    peer: str
    protocol: str
    port: int
    protocol_confidence: float
    protocol_signals: List[str]
    starttls: StarttlsVerdict
    tls: Optional[TlsAssessment]
    first_seen: float
    last_seen: float
    client_bytes: int
    server_bytes: int
    client_gaps: List[Any]
    server_gaps: List[Any]
    retransmit_bytes: int
    out_of_order_segments: int
    session_id: str = ""

    def summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "endpoint": self.endpoint,
            "peer": self.peer,
            "protocol": self.protocol,
            "port": self.port,
            "protocol_confidence": self.protocol_confidence,
            "protocol_signals": self.protocol_signals,
            "starttls": {
                "state": self.starttls.state.value,
                "advertised": self.starttls.advertised,
                "upgrade_attempted": self.starttls.upgrade_command_seen,
                "server_ready": self.starttls.server_ready,
                "tls_established": self.starttls.tls_established,
                "encrypted_bytes": self.starttls.encrypted_bytes,
                "signatures": self.starttls.signatures,
                "obfuscated_tokens": self.starttls.obfuscated_tokens,
                "cross_flow_inconsistent": self.starttls.cross_flow_inconsistent,
                "confidence": self.starttls.confidence,
                "remediation": self.starttls.remediation,
                "downgrade": self.starttls.is_downgrade,
            },
            "tls": self.tls.summary() if self.tls else None,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "bytes": {"client": self.client_bytes, "server": self.server_bytes},
            "reassembly": {
                "client_gaps": [list(g) for g in self.client_gaps],
                "server_gaps": [list(g) for g in self.server_gaps],
                "retransmit_bytes": self.retransmit_bytes,
                "out_of_order_segments": self.out_of_order_segments,
                "complete": not self.client_gaps and not self.server_gaps,
            },
        }


def _endpoint(conv: Conversation) -> str:
    return conv.server.endpoint


def _capture_time(conv: Conversation) -> Optional[datetime]:
    times = [t for _o, _c, t in conv.client.segments] + [t for _o, _c, t in conv.server.segments]
    if not times:
        return None
    return datetime.fromtimestamp(min(times), tz=timezone.utc)


def _parse_tls(conv: Conversation, verdict: StarttlsVerdict, host: Optional[str]):
    # Each direction has its own TLS start offset: the two peers sent different
    # amounts of plaintext before the handshake, so a shared offset slices into
    # the middle of the other direction's stream.
    client_start = verdict.tls_client_offset
    server_start = verdict.tls_server_offset
    client_blob = conv.client.data[client_start:] if client_start is not None else b""
    server_blob = conv.server.data[server_start:] if server_start is not None else b""
    if not client_blob and not server_blob:
        return None
    # Both directions must be parsed together. The ClientHello only states the
    # highest version the client offered; the negotiated version is settled by
    # the ServerHello, and the certificate arrives from the server. Parsing the
    # client half alone reports the offered ceiling as if it were negotiated.
    return parse_handshake(client_blob + server_blob)


def assess_tls(conv: Conversation, verdict: StarttlsVerdict, host: Optional[str]) -> Optional[TlsAssessment]:
    hs = _parse_tls(conv, verdict, host)
    if hs is None or (hs.client_hello is None and hs.server_hello is None):
        return None
    when = _capture_time(conv)
    version_rating = ciphers.version_rating(hs.version)[0]
    cipher = ciphers.lookup(hs.selected_cipher)
    group_rating = ciphers.group_rating(hs.selected_group)[0]
    sig_rating = ciphers.signature_rating(hs.selected_signature_algorithm)[0]
    certs = x509mod.parse_chain(hs.certificates, host=host)
    links = x509mod.verify_links(certs) if certs else []
    return TlsAssessment(
        handshake=hs,
        version_rating=version_rating,
        cipher_rating=cipher.rating,
        group_rating=group_rating,
        signature_rating=sig_rating,
        pfs=cipher.pfs,
        certificates=certs,
        chain_links=links,
        host=host,
        capture_time=when,
    )


def _host_from(verdict: StarttlsVerdict, hs: TlsHandshake) -> Optional[str]:
    if hs.sni:
        return hs.sni
    return None


def _finding(code, severity, detail, endpoint, **kw) -> Finding:
    return Finding(
        code=code,
        severity=severity,
        title=kw.pop("title", code.replace("_", " ").capitalize()),
        title_hi=_TITLES_HI.get(code, kw.pop("title_hi", "")),
        detail=detail,
        endpoint=endpoint,
        **kw,
    )


def _assess_session(
    conv: Conversation,
    guess: ProtocolGuess,
    verdict: StarttlsVerdict,
    session_id: str = "",
):
    endpoint = _endpoint(conv)
    tls = assess_tls(conv, verdict, None)
    if tls is not None and tls.handshake.sni:
        tls.host = tls.handshake.sni
        for cert in tls.certificates:
            cert.san_matching = x509mod.match_san(cert, tls.host)

    findings: List[Finding] = []
    proto = guess.protocol
    is_mail = proto in (SMTP, IMAP, POP3)

    if is_mail and not verdict.tls_established and verdict.is_downgrade:
        severity = CRITICAL if verdict.signatures else HIGH
        code = (
            "starttls_capability_suppressed"
            if verdict.state is UpgradeState.SUPPRESSED
            else "starttls_refused"
            if verdict.state is UpgradeState.REFUSED
            else "cleartext_mail_session"
        )
        findings.append(
            _finding(
                code,
                severity,
                f"{proto} session on port {guess.port} carried data without TLS"
                + (f"; signatures: {', '.join(verdict.signatures)}" if verdict.signatures else ""),
                endpoint,
                title=code.replace("_", " ").capitalize(),
                reference="RFC 3207 / RFC 8314 / RFC 9051",
                remediation=verdict.remediation,
                weight=verdict.confidence,
                evidence={
                    "signatures": verdict.signatures,
                    "obfuscated_tokens": verdict.obfuscated_tokens,
                    "cross_flow_inconsistent": verdict.cross_flow_inconsistent,
                    "state": verdict.state.value,
                },
                deliverable="D2 STARTTLS validation",
            )
        )

    if is_mail and verdict.state is UpgradeState.ABSENT and not verdict.tls_established:
        findings.append(
            _finding(
                "starttls_not_offered",
                MEDIUM,
                f"{proto} listener on port {guess.port} advertised no TLS upgrade",
                endpoint,
                title="STARTTLS not offered",
                reference="RFC 3207 section 4.2",
                remediation=verdict.remediation,
                weight=verdict.confidence,
                evidence={"state": verdict.state.value},
                deliverable="D2 STARTTLS validation",
            )
        )

    if tls is not None:
        findings.extend(_tls_findings(tls, endpoint, proto))
    findings.extend(_reassembly_findings(conv, endpoint, guess))

    if not is_mail and not verdict.tls_established:
        findings.append(
            _finding(
                "non_mail_cleartext",
                INFO,
                f"Conversation on port {guess.port} was not identified as a mail protocol",
                endpoint,
                title="Non-mail cleartext conversation",
                weight=0.3,
                evidence={"protocol": proto, "signals": guess.signals},
                deliverable="D1 protocol identification",
            )
        )

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.code))
    for f in findings:
        f.session_id = session_id
    times = [t for _o, _c, t in conv.client.segments] + [
        t for _o, _c, t in conv.server.segments
    ]
    session = SessionAssessment(
        session_id=session_id,
        endpoint=endpoint,
        peer=conv.server.src_ip,
        protocol=proto,
        port=guess.port,
        protocol_confidence=guess.confidence,
        protocol_signals=list(guess.signals),
        starttls=verdict,
        tls=tls,
        first_seen=min(times) if times else 0.0,
        last_seen=max(times) if times else 0.0,
        client_bytes=len(conv.client.data),
        server_bytes=len(conv.server.data),
        client_gaps=conv.client.gaps,
        server_gaps=conv.server.gaps,
        retransmit_bytes=conv.client.retransmit_bytes + conv.server.retransmit_bytes,
        out_of_order_segments=conv.client.out_of_order_segments
        + conv.server.out_of_order_segments,
    )
    return session, findings


def _tls_findings(tls: TlsAssessment, endpoint: str, proto: str) -> List[Finding]:
    out: List[Finding] = []
    hs = tls.handshake
    d = "D4-D10 TLS/certificate analysis"

    version_name, _, version_ref = ciphers.version_rating(hs.version)
    if version_name == ciphers.BROKEN:
        out.append(
            _finding(
                "broken_tls_version",
                CRITICAL,
                f"{proto} negotiated {hs.version_name}",
                endpoint,
                title=f"Obsolete TLS version ({hs.version_name})",
                reference=version_ref,
                remediation="Disable SSL 3.0 and require TLS 1.2 or higher.",
                weight=0.95,
                evidence={"version": hs.version_name},
                deliverable=d,
            )
        )
    elif version_name == ciphers.WEAK:
        out.append(
            _finding(
                "weak_tls_version",
                HIGH,
                f"{proto} negotiated {hs.version_name}, deprecated by RFC 8996",
                endpoint,
                title=f"Deprecated TLS version ({hs.version_name})",
                reference=version_ref,
                remediation="Require TLS 1.2 as a floor and prefer TLS 1.3.",
                weight=0.95,
                evidence={"version": hs.version_name},
                deliverable=d,
            )
        )

    cipher = ciphers.lookup(hs.selected_cipher)
    if cipher.rating in (ciphers.BROKEN, ciphers.WEAK):
        sev = CRITICAL if cipher.rating == ciphers.BROKEN else HIGH
        code = (
            "broken_cipher_suite" if cipher.rating == ciphers.BROKEN else "weak_cipher_suite"
        )
        out.append(
            _finding(
                code,
                sev,
                f"{proto} negotiated {cipher.name} ({cipher.kex}, {cipher.cipher})",
                endpoint,
                title=f"{cipher.rating.capitalize()} cipher suite ({cipher.name})",
                reference=f"{cipher.reference}; RFC 9325 section 4.1",
                remediation="Restrict the server to AEAD suites with ephemeral key exchange.",
                weight=0.95,
                evidence={"cipher": cipher.name, "kex": cipher.kex, "aead": cipher.aead},
                deliverable=d,
            )
        )

    if hs.selected_cipher is not None and not cipher.pfs and not hs.is_tls13:
        out.append(
            _finding(
                "no_forward_secrecy",
                HIGH,
                f"{proto} used {cipher.name}, which has no forward secrecy",
                endpoint,
                title="No forward secrecy",
                reference="NIST SP 800-52 Rev. 2; RFC 9325 section 4.2",
                remediation="Prefer ECDHE or DHE key exchange, or move to TLS 1.3.",
                weight=0.9,
                evidence={"kex": cipher.kex, "cipher": cipher.name},
                deliverable="D10 PFS assessment",
            )
        )

    if hs.is_tls13 and not cipher.pfs:
        pass

    group_rating, group_name, group_ref = ciphers.group_rating(hs.selected_group)
    if group_rating in (ciphers.WEAK, ciphers.BROKEN, ciphers.UNKNOWN) and hs.selected_group:
        out.append(
            _finding(
                "weak_key_exchange_group",
                MEDIUM if group_rating != ciphers.BROKEN else HIGH,
                f"{proto} used key exchange group {group_name}",
                endpoint,
                title=f"Weak key exchange group ({group_name})",
                reference=group_ref,
                remediation="Use X25519 or NIST P-256 or stronger.",
                weight=0.85,
                evidence={"group": group_name},
                deliverable="D6 key exchange analysis",
            )
        )

    sig_rating, sig_name, sig_ref = ciphers.signature_rating(hs.selected_signature_algorithm)
    if sig_rating in (ciphers.WEAK, ciphers.BROKEN):
        out.append(
            _finding(
                "weak_signature_algorithm",
                MEDIUM,
                f"{proto} handshake signed with {sig_name}",
                endpoint,
                title=f"Weak handshake signature ({sig_name})",
                reference=sig_ref,
                remediation="Require SHA-256 or stronger signature algorithms.",
                weight=0.8,
                evidence={"signature": sig_name},
                deliverable="D9 signature algorithm analysis",
            )
        )

    if not hs.certificates:
        if hs.is_tls13:
            out.append(
                _finding(
                    "passive_tls13_certificate_not_visible",
                    INFO,
                    "TLS 1.3 encrypts the server certificate, so a passive capture "
                    "cannot assess the chain. This is a visibility limit, not a "
                    "passing result.",
                    endpoint,
                    title="Certificate not visible under TLS 1.3",
                    reference="RFC 8446 section 4.4.2",
                    remediation=(
                        "Obtain the certificate out of band, or capture with a "
                        "controlled TLS key log to complete the assessment."
                    ),
                    weight=0.9,
                    evidence={"version": hs.version_name},
                    deliverable="D7-D8 certificate extraction and validation",
                )
            )
        return out

    leaf = tls.certificates[0]
    if tls.capture_time is not None:
        status = x509mod.expiry_status(leaf, tls.capture_time)
        if status == "expired":
            out.append(
                _finding(
                    "certificate_expired",
                    HIGH,
                    f"Leaf certificate {leaf.common_name} was already expired at "
                    f"capture time ({leaf.not_after.isoformat() if leaf.not_after else '?'})",
                    endpoint,
                    title="Expired certificate",
                    reference="RFC 5280 section 4.1.2.5; CAB Forum BR 4.9.1",
                    remediation="Renew the certificate and verify the served chain against a trust store.",
                    weight=0.95,
                    evidence={"not_after": leaf.not_after.isoformat() if leaf.not_after else None},
                    deliverable="D8 validity period",
                )
            )
        elif status == "not_yet_valid":
            out.append(
                _finding(
                    "certificate_not_yet_valid",
                    HIGH,
                    f"Leaf certificate {leaf.common_name} was not yet valid at capture time",
                    endpoint,
                    title="Certificate not yet valid",
                    reference="RFC 5280 section 4.1.2.5",
                    remediation="Check the server clock and the certificate validity window.",
                    weight=0.95,
                    evidence={"not_before": leaf.not_before.isoformat() if leaf.not_before else None},
                    deliverable="D8 validity period",
                )
            )
        else:
            days = x509mod.days_remaining(leaf, tls.capture_time)
            if days is not None and days < 15:
                out.append(
                    _finding(
                        "certificate_expiring_soon",
                        LOW,
                        f"Leaf certificate {leaf.common_name} expires in {days} day(s)",
                        endpoint,
                        title="Certificate expiring soon",
                        reference="CAB Forum BR 4.9.1",
                        remediation="Schedule renewal.",
                        weight=0.9,
                        evidence={"days_remaining": days},
                        deliverable="D8 validity period",
                    )
                )

    if leaf.public_key_algorithm == "rsa" and (leaf.public_key_bits or 0) < x509mod.RSA_MIN_BITS:
        out.append(
            _finding(
                "weak_public_key",
                HIGH,
                f"Leaf certificate uses a {leaf.public_key_bits}-bit RSA key",
                endpoint,
                title=f"Weak public key ({leaf.public_key_bits}-bit RSA)",
                reference="NIST SP 800-57 Part 1; RFC 9325 section 4.2",
                remediation=f"Use at least {x509mod.RSA_MIN_BITS}-bit RSA, or move to ECDSA/Ed25519.",
                weight=0.95,
                evidence={"key": leaf.public_key_algorithm, "bits": leaf.public_key_bits},
                deliverable="D9 public key analysis",
            )
        )
    if leaf.public_key_algorithm == "dsa":
        out.append(
            _finding(
                "weak_public_key",
                HIGH,
                "Leaf certificate uses DSA, which is not permitted for TLS",
                endpoint,
                title="DSA public key",
                reference="RFC 9325 section 4.2",
                remediation="Replace with RSA, ECDSA or Ed25519.",
                weight=0.9,
                evidence={"key": leaf.public_key_algorithm},
                deliverable="D9 public key analysis",
            )
        )
    if leaf.signature_hash in x509mod.WEAK_HASHES:
        out.append(
            _finding(
                "weak_signature_algorithm",
                HIGH,
                f"Leaf certificate is signed with {leaf.signature_hash}",
                endpoint,
                title=f"Weak certificate signature ({leaf.signature_hash})",
                reference="CAB Forum BR 7.1.3; NIST SP 800-131A Rev. 2",
                remediation="Reissue the certificate with SHA-256 or stronger.",
                weight=0.95,
                evidence={"signature": leaf.signature_algorithm, "hash": leaf.signature_hash},
                deliverable="D9 signature algorithm analysis",
            )
        )

    if tls.host and leaf.san_dns and not leaf.san_matching:
        out.append(
            _finding(
                "hostname_mismatch",
                HIGH,
                f"Certificate SANs {leaf.san_dns} do not cover {tls.host}",
                endpoint,
                title="Hostname mismatch",
                reference="RFC 6125; CAB Forum BR 7.1.4",
                remediation="Issue a certificate whose SAN covers the presented hostname.",
                weight=0.9,
                evidence={"host": tls.host, "san": leaf.san_dns},
                deliverable="D8 hostname validation",
            )
        )

    if leaf.self_signed:
        out.append(
            _finding(
                "self_signed_leaf",
                HIGH,
                f"Leaf certificate {leaf.common_name} is self-signed",
                endpoint,
                title="Self-signed leaf certificate",
                reference="RFC 5280 section 6.1",
                remediation="Issue the leaf from a CA the client trusts.",
                weight=0.9,
                evidence={"subject": leaf.subject},
                deliverable="D7 chain validation",
            )
        )

    for link in tls.chain_links:
        if link.is_self_signed:
            continue
        if not link.issuer_found:
            out.append(
                _finding(
                    "incomplete_chain",
                    MEDIUM,
                    f"Issuer for {link.subject} was not presented: {link.detail}",
                    endpoint,
                    title="Incomplete certificate chain",
                    reference="RFC 5246 section 7.4.2",
                    remediation="Configure the server to send the full intermediate chain.",
                    weight=0.85,
                    evidence={"subject": link.subject, "issuer": link.issuer},
                    deliverable="D7 chain validation",
                )
            )
        elif not link.signature_verified:
            out.append(
                _finding(
                    "chain_signature_invalid",
                    HIGH,
                    f"Certificate {link.subject} is not validly signed by the presented issuer: {link.detail}",
                    endpoint,
                    title="Invalid chain signature",
                    reference="RFC 5280 section 6.1.3",
                    remediation="Treat as a probable interception attempt and investigate the path.",
                    weight=0.8,
                    evidence={"subject": link.subject, "detail": link.detail},
                    deliverable="D7 chain validation",
                )
            )

    for cert in tls.certificates:
        if cert.unknown_critical_extensions:
            out.append(
                _finding(
                    "unknown_critical_extension",
                    LOW,
                    f"Certificate {cert.common_name} carries unrecognised critical "
                    f"extensions: {', '.join(cert.unknown_critical_extensions)}",
                    endpoint,
                    title="Unrecognised critical extension",
                    reference="RFC 5280 section 4.2",
                    remediation="Confirm the certificate is intended for this deployment.",
                    weight=0.7,
                    evidence={"extensions": cert.unknown_critical_extensions},
                    deliverable="D7 chain validation",
                )
            )

    return out


def _reassembly_findings(conv: Conversation, endpoint: str, guess: ProtocolGuess) -> List[Finding]:
    out: List[Finding] = []
    gaps = conv.client.gaps + conv.server.gaps
    if gaps:
        out.append(
            _finding(
                "insufficient_reassembly",
                MEDIUM,
                f"TCP stream on {endpoint} has {len(gaps)} gap(s); analysis of the "
                "affected region is incomplete",
                endpoint,
                title="Incomplete TCP reassembly",
                reference="RFC 9293 section 3.8",
                remediation="Collect a capture at the endpoint rather than mid-path to avoid loss.",
                weight=0.9,
                evidence={"gaps": [list(g) for g in gaps]},
                deliverable="D3 TCP stream reconstruction",
            )
        )
    return out


def analyze_conversations(conversations: List[Conversation]) -> Dict[str, Any]:
    guesses = [guess_protocol(c) for c in conversations]
    baseline = build_peer_baseline(conversations, guesses)
    sessions: List[SessionAssessment] = []
    findings: List[Finding] = []
    for index, (conv, guess) in enumerate(zip(conversations, guesses)):
        peer_advertised = baseline.get(conv.server.endpoint)
        verdict = analyze_starttls(conv, guess, peer_advertised_elsewhere=peer_advertised)
        session, session_findings = _assess_session(
            conv, guess, verdict, session_id=f"c{index}"
        )
        sessions.append(session)
        findings.extend(session_findings)
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.code))
    return {
        "sessions": sessions,
        "findings": [f.to_dict() for f in findings],
        "_finding_objects": findings,
    }
