"""Canonical mail-protocol dialogues used by tests and the demo corpus.

Each helper returns a list of `(direction, payload)` turns that a
`ConversationBuilder` can replay, so every scenario in the product is
reproducible from source rather than carried as an opaque binary blob.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from kryxai.pcap.synth import CLIENT, SERVER

CRLF = "\r\n"

Turn = Tuple[str, bytes]


def _lines(*parts: str) -> bytes:
    return (CRLF.join(parts) + CRLF).encode("ascii", errors="replace")


# ── SMTP ─────────────────────────────────────────────────────────────────────

SMTP_GREETER = "220 mail.district.gov.in ESMTP Postfix"


def smtp_ehlo_reply(
    capabilities: Sequence[str] = (
        "PIPELINING",
        "SIZE 10240000",
        "ETRN",
        "STARTTLS",
        "ENHANCEDSTATUSCODES",
        "SMTPUTF8",
    ),
) -> str:
    """Render a 250 capability block."""
    if not capabilities:
        return "250 HELP"
    body = [f"250-{cap}" for cap in capabilities[:-1]]
    body.append(f"250 {capabilities[-1]}")
    return body[0] if len(body) == 1 else CRLF.join(body)


def smtp_healthy() -> List[Turn]:
    return [
        (SERVER, _lines(SMTP_GREETER)),
        (CLIENT, _lines("EHLO collector.district.gov.in")),
        (SERVER, _lines(smtp_ehlo_reply())),
        (CLIENT, _lines("STARTTLS")),
        (SERVER, _lines("220 2.0.0 Ready to start TLS")),
    ]


def smtp_upgraded(client_hello: bytes, server_hello: bytes) -> List[Turn]:
    turns = smtp_healthy()
    turns.extend([(CLIENT, client_hello), (SERVER, server_hello)])
    return turns


def smtp_starttls_suppressed(
    replacement: str = "XXXXXXXA",
    capabilities: Sequence[str] = (
        "PIPELINING",
        "SIZE 10240000",
        "ETRN",
        "STARTTLS",
        "ENHANCEDSTATUSCODES",
        "SMTPUTF8",
    ),
) -> List[Turn]:
    """The capability-suppression scenario.

    The upgrade keyword is replaced in place with a token of the same length.
    This reproduces the shape of the documented Indian ISP behaviour in which
    the EHLO reply advertised `XXXXXXXA` instead of `STARTTLS`, so a compliant
    client never attempts an upgrade and the mail travels in cleartext. No
    client is required to be wrong; the advertisement itself is the evidence.
    """
    swapped = [replacement if cap == "STARTTLS" else cap for cap in capabilities]
    return [
        (SERVER, _lines(SMTP_GREETER)),
        (CLIENT, _lines("EHLO collector.district.gov.in")),
        (SERVER, _lines(smtp_ehlo_reply(swapped))),
        (CLIENT, _lines("MAIL FROM:<rti.officer@district.gov.in>")),
        (SERVER, _lines("250 2.1.0 Ok")),
        (CLIENT, _lines("RCPT TO:<citizen.applicant@gmail.com>")),
        (SERVER, _lines("250 2.1.5 Ok")),
        (CLIENT, _lines("DATA")),
        (SERVER, _lines("354 End data with <CR><LF>.<CR><LF>")),
        (CLIENT, _lines("Subject: RTI-2026-4471", "", "Aadhaar verification failure report attached.", ".")),
        (SERVER, _lines("250 2.0.0 Ok: queued as 4A1F22")),
    ]


def smtp_starttls_refused() -> List[Turn]:
    """Client asks, server refuses, session continues in cleartext."""
    return [
        (SERVER, _lines(SMTP_GREETER)),
        (CLIENT, _lines("EHLO collector.district.gov.in")),
        (SERVER, _lines(smtp_ehlo_reply())),
        (CLIENT, _lines("STARTTLS")),
        (SERVER, _lines("454 4.7.0 TLS not available due to temporary issue")),
        (CLIENT, _lines("AUTH PLAIN AGFiY2VydA==")),
        (SERVER, _lines("235 2.7.0 Authentication successful")),
    ]


def smtp_no_upgrade() -> List[Turn]:
    """No upgrade capability at all; cleartext end to end."""
    return [
        (SERVER, _lines("220 legacy-relay.district.gov.in ESMTP")),
        (CLIENT, _lines("HELO collector.district.gov.in")),
        (SERVER, _lines("250 legacy-relay.district.gov.in")),
        (CLIENT, _lines("MAIL FROM:<result.cell@districtschool.edu.in>")),
        (SERVER, _lines("250 OK")),
    ]


# ── IMAP ─────────────────────────────────────────────────────────────────────

IMAP_GREETER = "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] Dovecot ready."


def imap_healthy(client_hello: Optional[bytes] = None, server_hello: Optional[bytes] = None) -> List[Turn]:
    """An IMAP conversation that advertises STARTTLS and upgrades.

    `client_hello`/`server_hello` are the TLS handshake records. They are
    optional so a caller can build either the "advertised, never upgraded"
    scenario or the full upgrade.

    They are optional because omitting them produces a capture that contains no
    TLS handshake at all: the conversation ends at "Begin TLS negotiation now".
    A capture named or documented as a successful IMAP-to-TLS upgrade that is
    built without them silently contains no certificate, no cipher and no
    version, and every TLS feature reads as zero. That is a fixture that lies
    about what it covers, so pass the handshake whenever the case is meant to
    represent an upgrade.
    """
    turns = [
        (SERVER, _lines(IMAP_GREETER)),
        (CLIENT, _lines("a001 CAPABILITY")),
        (SERVER, _lines("* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED", "a001 OK CAPABILITY completed")),
        (CLIENT, _lines("a002 STARTTLS")),
        (SERVER, _lines("a002 OK Begin TLS negotiation now")),
    ]
    if client_hello is not None and server_hello is not None:
        turns.extend([(CLIENT, client_hello), (SERVER, server_hello)])
    return turns


def imap_starttls_suppressed(replacement: str = "XXXXXXXA") -> List[Turn]:
    greeter = f"* OK [CAPABILITY IMAP4rev1 {replacement} LOGINDISABLED] Dovecot ready."
    return [
        (SERVER, _lines(greeter)),
        (CLIENT, _lines("a001 CAPABILITY")),
        (
            SERVER,
            _lines(
                f"* CAPABILITY IMAP4rev1 {replacement} LOGINDISABLED",
                "a001 OK CAPABILITY completed",
            ),
        ),
        (CLIENT, _lines("a002 LOGIN citizen 2Jk4mQpL0zX9")),
        (SERVER, _lines("a002 OK Logged in")),
    ]


# ── POP3 ─────────────────────────────────────────────────────────────────────

POP3_GREETER = "+OK Dovecot (Ubuntu) ready."


def pop3_healthy(client_hello: Optional[bytes] = None, server_hello: Optional[bytes] = None) -> List[Turn]:
    """A POP3 conversation that advertises STLS and upgrades.

    See `imap_healthy` for why the handshake records are optional: without them
    the capture stops at "+OK Begin TLS negotiation" and contains no TLS.
    """
    turns = [
        (SERVER, _lines(POP3_GREETER)),
        (CLIENT, _lines("CAPA")),
        (SERVER, _lines("+OK", "TOP", "USER", "UIDL", "PIPELINING", "STLS", ".")),
        (CLIENT, _lines("STLS")),
        (SERVER, _lines("+OK Begin TLS negotiation")),
    ]
    if client_hello is not None and server_hello is not None:
        turns.extend([(CLIENT, client_hello), (SERVER, server_hello)])
    return turns


def pop3_stls_suppressed(replacement: str = "XXXXXXXA") -> List[Turn]:
    caps = ["TOP", "USER", "UIDL", "PIPELINING", replacement]
    return [
        (SERVER, _lines(POP3_GREETER)),
        (CLIENT, _lines("CAPA")),
        (SERVER, _lines("+OK", *caps, ".")),
        (CLIENT, _lines("USER citizen")),
        (SERVER, _lines("+OK Password required for citizen")),
        (CLIENT, _lines("PASS 2Jk4mQpL0zX9")),
        (SERVER, _lines("+OK 1 message ready")),
    ]


# ── replay helper ────────────────────────────────────────────────────────────


def replay(builder, turns: Sequence[Turn], dt_ms: float = 12.0):
    """Feed a scripted dialogue into a `ConversationBuilder`."""
    builder.handshake()
    for direction, payload in turns:
        builder.send(direction, payload, dt_ms=dt_ms)
    return builder
