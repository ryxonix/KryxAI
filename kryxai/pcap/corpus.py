"""Synthetic demo corpus.

Every capture here is generated, not captured from a real network. The index
records, for each file, exactly which finding it is meant to produce, so a
reviewer can check the tool's output against a known answer instead of
eyeballing it. Nothing in this directory should be presented as evidence from
a real deployment.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..pcap import mailflows, tlssynth as ts
from ..pcap.synth import ConversationBuilder, merge_packets, write_pcap

CORPUS_VERSION = "1"

CLIENT_HELLO = ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni="mail.example.com"))


@dataclass
class Case:
    name: str
    filename: str
    description: str
    description_hi: str
    expect: List[str] = field(default_factory=list)
    expect_clean: List[str] = field(default_factory=list)
    port: int = 25
    packets: List[Any] = field(default_factory=list, repr=False)
    notes: str = ""
    # When true, the capture must actually contain a completed TLS handshake.
    # `expect_clean` alone cannot catch a fixture that claims to be a successful
    # upgrade but was built without the handshake records: such a capture has no
    # suppressed capability either, so it satisfies every absence assertion while
    # testing nothing.
    expect_tls_upgraded: bool = False


def _builder(case_port: int) -> ConversationBuilder:
    return ConversationBuilder(server_port=case_port)


def _case(
    name: str,
    description: str,
    description_hi: str,
    turns: Sequence[Any],
    *,
    port: int = 25,
    expect: Optional[List[str]] = None,
    expect_clean: Optional[List[str]] = None,
    notes: str = "",
    expect_tls_upgraded: bool = False,
) -> Case:
    builder = _builder(port)
    mailflows.replay(builder, turns)
    return Case(
        name=name,
        filename=f"{name}.pcap",
        description=description,
        description_hi=description_hi,
        expect=expect or [],
        expect_clean=expect_clean or [],
        port=port,
        packets=list(builder.packets),
        notes=notes,
        expect_tls_upgraded=expect_tls_upgraded,
    )


def build_cases() -> List[Case]:
    shared_chain = ts.make_chain()
    weak_chain = ts.make_chain(leaf_key_size=1024)
    expired_chain = ts.make_chain(
        not_before=1500000000, not_after=1600000000, reuse=False
    )
    other_chain = ts.make_chain(leaf_cn="alt.example.net", reuse=False)

    return [
        _case(
            "01_healthy_smtp_tls12",
            "Healthy SMTP submission on port 25: STARTTLS offered, accepted, and "
            "completed with a forward-secret TLS 1.2 session and a valid chain.",
            "स्वस्थ SMTP सबमिशन: STARTTLS प्रस्तुत, स्वीकृत और अग्रिम-गोपनीय TLS 1.2 "
            "सत्र के साथ पूर्ण।",
            mailflows.smtp_upgraded(
                CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=shared_chain)
            ),
            expect_clean=[
                "starttls_capability_suppressed",
                "weak_cipher_suite",
                "no_forward_secrecy",
                "weak_public_key",
            ],
        ),
        _case(
            "02_star_ttlssuppressed_vodafone_style",
            "Documented India-style STARTTLS suppression: the capability "
            "advertisement is rewritten in transit to XXXXXXXA, so the client "
            "never sees STARTTLS. No active probe can detect this; only the "
            "on-path observation of the altered capability can.",
            "भारत में दर्ज STARTTLS दमन: क्षमता घोषणा ट्रांज़िट में XXXXXXXA में "
            "बदल दी गई है, इसलिए क्लाइंट कभी STARTTLS नहीं देखता।",
            mailflows.smtp_starttls_suppressed(),
            port=587,
            expect=["starttls_capability_suppressed", "A1_tamper_signature"],
        ),
        _case(
            "03_starttls_refused",
            "The server advertises STARTTLS and the client requests it, but the "
            "server refuses. Citizen mail then proceeds in cleartext.",
            "सर्वर STARTTLS प्रस्तुत करता है और क्लाइंट अनुरोध करता है, पर सर्वर "
            "अस्वीकार कर देता है। नागरिक मेल स्पष्ट-पाठ में जाती है।",
            mailflows.smtp_starttls_refused(),
            port=587,
            expect=["starttls_refused"],
        ),
        _case(
            "04_weak_tls12_no_pfs",
            "TLS 1.2 with RSA key exchange and a CBC cipher suite: no forward "
            "secrecy, so one server key compromise exposes past sessions.",
            "RSA की एक्सचेंज और CBC साइफ़र स्यूट वाला TLS 1.2: कोई फ़ॉरवर्ड सीक्रेसी "
            "नहीं, इसलिए सर्वर कुंजी के उपयोग से पुराने सत्र उजागर होते हैं।",
            mailflows.smtp_upgraded(
                CLIENT_HELLO,
                ts.tls12_session(cipher=0x002F, certs=shared_chain, group=None),
            ),
            expect=["weak_cipher_suite", "no_forward_secrecy"],
        ),
        _case(
            "05_weak_public_key",
            "Valid TLS 1.2 handshake carrying a 1024-bit RSA leaf certificate, "
            "which is below the current minimum key size.",
            "1024-बिट RSA लीफ़ प्रमाणपत्र वाला मान्य TLS 1.2 हैंडशेक, जो वर्तमान "
            "न्यूनतम कुंजी आकार से कम है।",
            mailflows.smtp_upgraded(
                CLIENT_HELLO,
                ts.tls12_session(cipher=0xC030, certs=weak_chain),
            ),
            expect=["weak_public_key"],
        ),
        _case(
            "06_expired_certificate",
            "Certificate whose validity window closed before the capture time. "
            "KryxAI judges expiry against capture time, not analysis time.",
            "ऐसा प्रमाणपत्र जिसकी वैधता कैप्चर समय से पहले समाप्त हो चुकी है। "
            "KryxAI समाप्ति का आकलन विश्लेषण समय नहीं, कैप्चर समय के आधार पर करता है।",
            mailflows.smtp_upgraded(
                CLIENT_HELLO,
                ts.tls12_session(cipher=0xC030, certs=expired_chain),
            ),
            expect=["certificate_expired"],
            notes="Expiry is evaluated against the capture timestamp.",
        ),
        _case(
            "07_hostname_mismatch",
            "Certificate issued for a different name than the SNI the client "
            "requested, so the session is not authenticated to the intended host.",
            "क्लाइंट के अनुरोधित SNI से भिन्न नाम के लिए जारी प्रमाणपत्र, इसलिए "
            "सत्र अभिप्रेत होस्ट से प्रमाणित नहीं है।",
            mailflows.smtp_upgraded(
                ts.record(
                    ts.CT_HANDSHAKE,
                    ts.client_hello(sni="mail.example.com"),
                ),
                ts.tls12_session(cipher=0xC030, certs=other_chain),
            ),
            expect=["hostname_mismatch"],
        ),
        _case(
            "08_tls13_modern",
            "TLS 1.3 with a modern cipher suite and x25519. The server "
            "certificate and handshake signature are encrypted and therefore "
            "not observable; KryxAI reports that limit rather than guessing.",
            "आधुनिक साइफ़र स्यूट और x25519 वाला TLS 1.3। सर्वर प्रमाणपत्र और "
            "हैंडशेक हस्ताक्षर एन्क्रिप्टेड हैं, इसलिए अवलोकन योग्य नहीं।",
            mailflows.smtp_upgraded(
                CLIENT_HELLO,
                ts.record(
                    ts.CT_HANDSHAKE,
                    ts.server_hello(
                        cipher=0x1301, group=0x001D, supported_version=0x0304,
                        key_len=32,
                    ),
                )
                + ts.change_cipher_spec()
                + ts.encrypted_flight(1500),
            ),
            expect=["passive_tls13_certificate_not_visible"],
            expect_clean=["weak_cipher_suite", "no_forward_secrecy"],
        ),
        _case(
            "09_imap_suppressed",
            "IMAP on port 143 with the STARTTLS capability suppressed in the "
            "CAPABILITY response.",
            "पोर्ट 143 पर IMAP, जिसकी CAPABILITY प्रतिक्रिया में STARTTLS "
            "क्षमता दबाई गई है।",
            mailflows.imap_starttls_suppressed(),
            port=143,
            expect=["starttls_capability_suppressed"],
        ),
        _case(
            "10_pop3_suppressed",
            "POP3 on port 110 with the STLS capability suppressed in the "
            "CAPA response.",
            "पोर्ट 110 पर POP3, जिसकी CAPA प्रतिक्रिया में STLS क्षमता दबाई गई है।",
            mailflows.pop3_stls_suppressed(),
            port=110,
            expect=["starttls_capability_suppressed"],
        ),
        _case(
            "11_imap_healthy",
            "IMAP on port 143 upgrading cleanly to TLS 1.2. Control case for "
            "the IMAP path.",
            "पोर्ट 143 पर IMAP साफ़ तरह TLS 1.2 में अपग्रेड होता है।",
            # The handshake records are required here. Without them this capture
            # ends at "Begin TLS negotiation now" and contains no TLS at all,
            # which is not the case its name and description claim.
            mailflows.imap_healthy(
                client_hello=CLIENT_HELLO,
                server_hello=ts.tls12_session(cipher=0xC030, certs=shared_chain),
            ),
            port=143,
            expect_clean=["starttls_capability_suppressed"],
            expect_tls_upgraded=True,
        ),
        _case(
            "13_pop3_healthy",
            "POP3 on port 110 upgrading cleanly to TLS 1.2. Control case for "
            "the POP3 path, which no other capture exercises.",
            "पोर्ट 110 पर POP3 साफ़ तरह TLS 1.2 में अपग्रेड होता है।",
            mailflows.pop3_healthy(
                client_hello=CLIENT_HELLO,
                server_hello=ts.tls12_session(cipher=0xC030, certs=shared_chain),
            ),
            port=110,
            expect_clean=["starttls_capability_suppressed"],
            expect_tls_upgraded=True,
        ),
    ]


def _mixed_case() -> Case:
    """One capture holding several flows, so per-peer baselines are exercised."""
    shared = ts.make_chain()
    parts: List[Any] = []
    for port, turns in (
        (25, mailflows.smtp_upgraded(
            CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=shared))),
        (587, mailflows.smtp_starttls_suppressed()),
        (110, mailflows.pop3_stls_suppressed()),
    ):
        builder = ConversationBuilder(server_port=port)
        mailflows.replay(builder, turns)
        parts.extend(builder.packets)
    return Case(
        name="12_mixed_mitigations",
        filename="12_mixed_mitigations.pcap",
        description=(
            "A single capture containing a compliant SMTP flow on 25, a "
            "STARTTLS-suppressed SMTP flow on 587 and a suppressed POP3 flow on "
            "110. The same peer mixes compliant and tampered paths, which is the "
            "K2 cross-flow inconsistency signature and cannot be explained as "
            "server policy."
        ),
        description_hi=(
            "एक ही कैप्चर में 25 पर अनुपालनकृत SMTP प्रवाह, 587 पर STARTTLS-दमित "
            "SMTP प्रवाह और 110 पर दमित POP3 प्रवाह।"
        ),
        expect=[
            "starttls_capability_suppressed",
            "A1_tamper_signature",
            "A2_partial_upgrade",
        ],
        port=25,
        packets=parts,
        notes="Same peer, different outcome per flow.",
    )


def _anomaly_cases() -> List[Case]:
    """Captures that genuinely fire the A3-A6 baseline detectors.

    Every anomaly code up to A2 was already demonstrable from the mail captures
    above, which left the detector set looking fully exercised when four of its
    six members had never fired on anything shipped. These four close that gap
    without touching a single threshold in `scoring/anomaly.py`.

    A5 in particular is produced by *deleting a captured packet* rather than by
    making the builder jump its sequence number. The two produce the same gap in
    the reassembled stream, but only the first is a thing that can actually
    happen to a real capture, and a fixture that fabricates the failure it is
    meant to test is worth less than one that simulates the cause.
    """
    shared = ts.make_chain()
    cases: List[Case] = []

    # A3: a plaintext session on an implicit-TLS port. Reaching this needs a
    # second port on the same peer, because "plaintext on 465" is only anomalous
    # when the same address also serves a port where TLS is offered - otherwise
    # it is indistinguishable from a server that simply has nothing to hide.
    a3_parts: List[Any] = []
    _append(a3_parts, 587, 49152, mailflows.smtp_upgraded(
        CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=shared)))
    _append(a3_parts, 465, 49200, mailflows.smtp_no_upgrade())
    cases.append(
        Case(
            name="14_implicit_port_plaintext",
            filename="14_implicit_port_plaintext.pcap",
            description=(
                "The same mail host serves port 587 with STARTTLS offered and "
                "port 465, the implicit-TLS port, in cleartext. A client "
                "connecting to 465 believes it is protected by construction, so "
                "nothing warns it, and a scan of 587 alone would find nothing."
            ),
            description_hi=(
                "एक ही मेल होस्ट पोर्ट 587 पर STARTTLS प्रस्तुत करता है, लेकिन "
                "अंतर्निहित-TLS पोर्ट 465 को स्पष्ट-पाठ में चलाता है।"
            ),
            expect=[
                "A3_plaintext_on_implicit_port",
                "cleartext_mail_session",
                "A2_partial_upgrade",
            ],
            port=587,
            packets=a3_parts,
            notes="Two ports on one peer; only 465 is plaintext.",
        )
    )

    # A4: two genuinely distinct leaf certificates from one peer. make_chain
    # memoises by default precisely so that ordinary captures do not trip this
    # detector, so reuse=False is required to produce a real inconsistency.
    a4_parts = []
    for i, chain in enumerate(
        (ts.make_chain(leaf_cn="mail.example.com", reuse=False),
         ts.make_chain(leaf_cn="mail-2.example.com", reuse=False))
    ):
        _append(a4_parts, 587, 49152 + i, mailflows.smtp_upgraded(
            CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=chain)))
    cases.append(
        Case(
            name="15_certificate_inconsistency",
            filename="15_certificate_inconsistency.pcap",
            description=(
                "One peer presents two different leaf certificates in the same "
                "capture. Rapid rotation is legitimate, so this is reported as a "
                "question to be answered rather than as evidence of interception; "
                "the CA certificates in each chain are not counted."
            ),
            description_hi=(
                "एक ही पीयर एक ही कैप्चर में दो अलग-अलग लीफ़ प्रमाणपत्र "
                "प्रस्तुत करता है। तेज़ी से बदलना वैध हो सकता है।"
            ),
            expect=["A4_certificate_inconsistency"],
            port=587,
            packets=a4_parts,
            notes="Distinct leaf identities from one peer.",
        )
    )

    # A5: drop one packet from the middle of an otherwise complete session.
    builder = ConversationBuilder(server_port=25, client_port=49152)
    mailflows.replay(
        builder,
        mailflows.smtp_upgraded(
            CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=shared)
        ),
    )
    full = list(builder.packets)
    cut = len(full) // 2
    cases.append(
        Case(
            name="16_capture_with_gap",
            filename="16_capture_with_gap.pcap",
            description=(
                "A complete SMTP-to-TLS 1.2 session with one captured packet "
                "missing from the middle, so part of the exchange was never on "
                "the wire. KryxAI reports the gap rather than parsing across it, "
                "because a pattern hidden in the missing range is exactly what "
                "this tool exists to find."
            ),
            description_hi=(
                "बीच से एक पैकेट अनुपस्थित SMTP-to-TLS 1.2 सत्र, जिसका अर्थ "
                "है कि एक्सचेंज का कुछ भाग कभी तार पर नहीं गया।"
            ),
            expect=["A5_evidence_gap"],
            port=25,
            packets=full[:cut] + full[cut + 1:],
            notes=f"Removed packet {cut} of {len(full)} to simulate capture loss.",
        )
    )

    # A6: eleven sessions, ten identical and one carrying a large attachment.
    # The detector divides by a standard deviation that includes the outlier
    # itself, so z for a single extreme value approaches sqrt(k) as it grows
    # without bound; ten peers are needed to clear the 3-sigma line and the
    # threshold was left where it is.
    a6_parts = []
    small = mailflows.smtp_upgraded(
        CLIENT_HELLO, ts.tls12_session(cipher=0xC030, certs=shared)
    )
    for i in range(10):
        _append(a6_parts, 25, 49200 + i, small)
    _append(a6_parts, 25, 49299, small + [
        ("client", b"X" * 60000),
        ("server", b"250 2.0.0 Ok: queued\r\n"),
    ])
    cases.append(
        Case(
            name="17_session_size_outlier",
            filename="17_session_size_outlier.pcap",
            description=(
                "Eleven sessions to the same host, ten of an ordinary size and "
                "one carrying a large body. The size difference may simply mean a "
                "large attachment, which is the intended reading; the value of "
                "the flag is that a session whose volume differs from its peers "
                "is worth a look."
            ),
            description_hi=(
                "एक ही होस्ट से ग्यारह सत्र, दस सामान्य आकार के और एक बड़े "
                "पayload वाला।"
            ),
            expect=["A6_session_size_outlier"],
            port=25,
            packets=a6_parts,
            notes="Ten baseline sessions are required to clear the 3-sigma line.",
        )
    )

    return cases


def _append(
    into: List[Any], port: int, client_port: int, turns: Sequence[Any]
) -> None:
    """Append one conversation with its own client port, so it is a new session.

    Reusing a client port would make the assembler treat both conversations as
    a single stream, which is a different capture from the one intended.
    """
    builder = ConversationBuilder(server_port=port, client_port=client_port)
    mailflows.replay(builder, turns)
    into.extend(builder.packets)


def generate(out_dir: Path) -> Dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = build_cases() + [_mixed_case()] + _anomaly_cases()

    index: List[Dict[str, Any]] = []
    for case in cases:
        path = write_pcap(out_dir / case.filename, case.packets)
        entry = {
            k: v
            for k, v in asdict(case).items()
            if k != "packets"
        }
        entry["size_bytes"] = path.stat().st_size
        index.append(entry)

    manifest = {
        "corpus_version": CORPUS_VERSION,
        "generated_by": "kryxai.pcap.corpus",
        "warning": (
            "Every capture in this directory is synthetically generated. None of it "
            "is traffic from a real network and none of it is evidence of a real "
            "event. The 'expect' lists state which findings each file is designed to "
            "produce; 'expect_clean' lists findings it must NOT produce. "
            "'expect_tls_upgraded' marks captures that must contain a completed TLS "
            "handshake, so a fixture that claims to show a successful upgrade but was "
            "built without one cannot pass. The 'A' prefixes in 'expect' are baseline "
            "anomaly codes, produced by capture-local statistics rather than by the "
            "protocol detectors, and they are named in full so a reader can tell which "
            "layer raised them."
        ),
        "cases": index,
    }
    (out_dir / "index.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return manifest
