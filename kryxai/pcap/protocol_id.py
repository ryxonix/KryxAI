"""Automatic application-layer identification of SMTP, IMAP and POP3.

Identification is evidence-weighted, not port-guessing: a port number is only a
prior, and a plaintext greeter or client command is what actually establishes
the protocol. KryxAI reports the confidence and the signals it used so an
analyst can see *why* a flow was labelled, and it flags disagreement between
the port prior and the observed protocol rather than silently picking one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from kryxai.pcap.models import Conversation

SMTP = "SMTP"
IMAP = "IMAP"
POP3 = "POP3"
UNKNOWN = "UNKNOWN"

# Ports where the session is expected to begin already inside TLS.
SMTP_IMPLICIT_PORTS = {465}
IMAP_IMPLICIT_PORTS = {993}
POP3_IMPLICIT_PORTS = {995}

# Plaintext / submission ports, plus the widely-deployed alternates.
SMTP_PORTS = {25, 465, 587, 2525}
IMAP_PORTS = {143, 993, 1143}
POP3_PORTS = {110, 995, 1110}

ALL_KNOWN_PORTS = SMTP_PORTS | IMAP_PORTS | POP3_PORTS

_IMPLICIT_PORTS = (
    SMTP_IMPLICIT_PORTS | IMAP_IMPLICIT_PORTS | POP3_IMPLICIT_PORTS
)

# TLS record layer: handshake record, then a TLS 1.0-1.3 record version.
_TLS_HANDSHAKE_RECORD = 0x16
_TLS_LEGACY_VERSIONS = {0x0301, 0x0302, 0x0303, 0x0304}
# SSLv2-compatible ClientHello: high bit set on the first byte.
_SSLV2_HELLO = 0x80
_TLS_RECORD_TYPES = frozenset({20, 21, 22, 23})

# ── greeters: what the server sends first ────────────────────────────────────
_GREETER_PATTERNS: Tuple[Tuple[str, "re.Pattern[bytes]"], ...] = (
    (SMTP, re.compile(rb"^220[ -]")),
    (IMAP, re.compile(rb"^\*\s+(OK|PREAUTH|CAPABILITY|BYE)\b")),
    (POP3, re.compile(rb"^\+OK\b")),
)

# ── commands: what the client sends first ────────────────────────────────────
_CLIENT_COMMAND_PATTERNS: Tuple[Tuple[str, "re.Pattern[bytes]"], ...] = (
    (SMTP, re.compile(rb"^(EHLO|HELO|STARTTLS|XHELLO|QUIT)\b")),
    (IMAP, re.compile(rb"^(A\d{1,4}\s+(LOGIN|CAPABILITY|NOOP|ID|STARTTLS|LIST)|CAPABILITY|STARTTLS|LOGOUT|LOGIN)\b", re.I)),
    (POP3, re.compile(rb"^(USER|PASS|APOP|CAPA|STLS|QUIT|STAT)\b", re.I)),
)

# Capability tokens that prove the peer understands a given mail protocol.
_SMTP_CAPABILITY = re.compile(rb"\bSMTP\b", re.I)
_IMAP_CAPABILITY = re.compile(rb"\bIMAP4(?:rev1)?\b", re.I)
_POP3_CAPABILITY = re.compile(rb"\bTOP\b", re.I)


@dataclass
class ProtocolGuess:
    """What KryxAI believes a conversation is, and why."""

    protocol: str = UNKNOWN
    port: int = 0
    confidence: float = 0.0
    signals: List[str] = field(default_factory=list)
    implicit_tls: bool = False
    port_agrees: Optional[bool] = None
    greeter: str = ""

    @property
    def is_mail(self) -> bool:
        return self.protocol != UNKNOWN

    def summary(self) -> str:
        bits = [f"{self.protocol}:{self.port}", f"conf={self.confidence:.2f}"]
        if self.implicit_tls:
            bits.append("implicit-tls")
        if self.port_agrees is False:
            bits.append("port-mismatch")
        if self.signals:
            bits.append("signals=" + ",".join(self.signals))
        return " | ".join(bits)


def looks_like_tls_record(data: bytes) -> bool:
    """True if `data` begins with a TLS/SSL record header."""
    if len(data) < 3:
        return False
    if data[0] in _TLS_RECORD_TYPES and data[1] == 0x03:
        return True
    # SSLv2 ClientHello: first byte has the high bit set.
    return bool(data[0] & _SSLV2_HELLO) and len(data) >= 3


def _first_lines(data: bytes, count: int = 8) -> List[str]:
    out: List[str] = []
    for raw in data.split(b"\n", count)[:count]:
        line = raw.rstrip(b"\r")
        if not line:
            continue
        try:
            out.append(line.decode("utf-8", errors="replace"))
        except Exception:  # pragma: no cover - decode with replace cannot raise
            out.append(repr(line))
    return out


def _match(patterns, data: bytes) -> Optional[str]:
    for name, pattern in patterns:
        if pattern.search(data[:512]):
            return name
    return None


def _capability_evidence(server_text: str) -> List[str]:
    found: List[str] = []
    if _SMTP_CAPABILITY.search(server_text.encode("utf-8", errors="ignore")):
        found.append("smtp")
    if _IMAP_CAPABILITY.search(server_text.encode("utf-8", errors="ignore")):
        found.append("imap")
    if _POP3_CAPABILITY.search(server_text.encode("utf-8", errors="ignore")):
        found.append("pop3")
    return found


def guess_protocol(conv: Conversation, probe_bytes: int = 1024) -> ProtocolGuess:
    """Identify a conversation's application protocol from observed bytes."""
    guess = ProtocolGuess()
    # Each direction's own listening/ephemeral port is its src_port; dst_port is
    # the peer's. Using dst_port would report the client's ephemeral port.
    server_port = conv.server.src_port
    client_port = conv.client.src_port
    guess.port = server_port

    # Which side actually owns which port? The server direction terminates on
    # the listening port; if that assumption fails, fall back to the client.
    server_data = conv.server.data
    client_data = conv.client.data

    if not server_data and client_data and server_port not in ALL_KNOWN_PORTS:
        guess.port = client_port
        server_data, client_data = client_data, server_data
        flipped = True
    else:
        flipped = False

    head = server_data[:probe_bytes]

    # ── 1. implicit TLS: the session begins inside TLS ──────────────────────
    if looks_like_tls_record(head):
        guess.implicit_tls = True
        guess.signals.append("tls-record-at-stream-start")
        expected = (
            IMAP
            if guess.port in IMAP_IMPLICIT_PORTS
            else POP3
            if guess.port in POP3_IMPLICIT_PORTS
            else SMTP
            if guess.port in SMTP_IMPLICIT_PORTS
            else UNKNOWN
        )
        if expected != UNKNOWN:
            guess.protocol = expected
            guess.confidence = 0.90
            guess.signals.append(f"implicit-tls-port-{guess.port}")
        else:
            # TLS on a port that is not an implicit-TLS mail port. The
            # application protocol is genuinely not observable; say so.
            guess.protocol = UNKNOWN
            guess.confidence = 0.20
            guess.signals.append("tls-on-unknown-port")
        guess.port_agrees = expected != UNKNOWN
        if not head:
            guess.signals.append("empty-stream")
        return guess

    # ── 2. server greeter ──────────────────────────────────────────────────
    if head:
        guess.greeter = _first_lines(head, 1)[0] if _first_lines(head, 1) else ""
    greeter_proto = _match(_GREETER_PATTERNS, head)

    # ── 3. client command ──────────────────────────────────────────────────
    cmd_proto = _match(_CLIENT_COMMAND_PATTERNS, client_data[:probe_bytes])

    # ── 4. advertised capabilities (SMTP EHLO reply) ───────────────────────
    server_text = "\n".join(_first_lines(server_data, 12))
    cap_hits = _capability_evidence(server_text)

    votes: Dict[str, float] = {}
    if greeter_proto:
        votes[greeter_proto] = votes.get(greeter_proto, 0.0) + 0.55
        guess.signals.append(f"greeter:{greeter_proto}")
    if cmd_proto:
        votes[cmd_proto] = votes.get(cmd_proto, 0.0) + 0.40
        guess.signals.append(f"client-command:{cmd_proto}")
    for hit in cap_hits:
        votes[hit] = votes.get(hit, 0.0) + 0.20
        guess.signals.append(f"capability:{hit}")

    if not votes:
        guess.confidence = 0.0
        guess.signals.append("no-protocol-evidence")
        if flipped:
            guess.port = client_port
        return guess

    best = max(votes.items(), key=lambda kv: kv[1])
    guess.protocol = best[0]
    guess.confidence = round(min(1.0, best[1]), 3)

    # The port prior only adjusts confidence; it never overrides byte evidence.
    if guess.port in ALL_KNOWN_PORTS:
        port_proto = (
            SMTP
            if guess.port in SMTP_PORTS
            else IMAP
            if guess.port in IMAP_PORTS
            else POP3
        )
        guess.port_agrees = port_proto == guess.protocol
        if guess.port in _IMPLICIT_PORTS and not guess.implicit_tls:
            # A plaintext greeting on an implicit-TLS port is a real
            # misconfiguration and should be visible, not smoothed over.
            guess.signals.append(f"plaintext-on-implicit-port-{guess.port}")
        elif guess.port_agrees:
            guess.confidence = round(min(1.0, guess.confidence + 0.15), 3)
            guess.signals.append(f"port-prior-agrees-{guess.port}")
    else:
        guess.port_agrees = None
        guess.signals.append(f"port-{guess.port}-not-a-known-mail-port")

    if flipped:
        guess.port = client_port
    return guess


def classify(conversations: List[Conversation]) -> List[Tuple[Conversation, ProtocolGuess]]:
    """Identify every conversation in a capture, in capture order."""
    return [(conv, guess_protocol(conv)) for conv in conversations]
