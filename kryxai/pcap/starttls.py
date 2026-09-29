"""STARTTLS negotiation analysis and downgrade / suppression detection.

This module carries the core KryxAI detection: distinguishing a *server that
never offered TLS* from a *server whose capability advertisement was removed
in transit*. The two look identical to an active scanner, because an active
scanner asks the server and the same middlebox answers. A passive capture can
tell them apart, because it sees the advertisement itself.

KryxAI signatures
-----------------
K1  Capability suppression   - a capability token the exact length of STARTTLS
                              that is not STARTTLS. This is the shape of the
                              documented Vodafone India behaviour, where the
                              EHLO reply carried `XXXXXXXA` instead of
                              `STARTTLS`.
K2  Cross-flow inconsistency - the same peer advertised the capability in one
                              session in this capture and not in another.
K3  Refused upgrade          - the client asked, the server refused, and the
                              session carried on in cleartext.
K4  Plaintext after upgrade  - data that is not a TLS record appears after the
                              server's readiness response.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from kryxai.pcap.models import Conversation
from kryxai.pcap.protocol_id import (
    IMAP,
    POP3,
    SMTP,
    ProtocolGuess,
    looks_like_tls_record,
)


class UpgradeState(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    ABSENT = "absent"
    OFFERED = "offered"
    ATTEMPTED = "attempted"
    UPGRADED = "upgraded"
    REFUSED = "refused"
    SUPPRESSED = "suppressed"


# Capability keyword that signals TLS upgrade, per protocol.
_UPGRADE_TOKEN = {POP3: "STLS"}
_DEFAULT_UPGRADE_TOKEN = "STARTTLS"

# A representative slice of the ESMTP keyword space. Used to tell a real
# capability from a mangled one: anything outside this vocabulary that occupies
# exactly the slot of the upgrade token is a candidate substitution.
_KNOWN_CAPABILITIES = {
    "8BITMIME", "AUTH", "AUTH=PLAIN", "AUTH=LOGIN", "AUTH=PLAIN", "AUTH=CRAM-MD5",
    "AUTH=XOAUTH2", "BINARYMIME", "BURL", "CHUNKING", "DSN", "ETRN", "EXPN",
    "HELP", "IMAP4", "IMAP4REV1", "IMAP4REV2", "LOGIN", "LOGINDISABLED",
    "LOGIN-REFERRALS", "MAIL", "MAIL-OPTIONS", "MAILBOX", "MTLS", "MIME",
    "NAMEDSP", "NETSCAPE-DNS-BUG", "NULL", "ONEX", "PIPELINING", "POOM",
    "SIZE", "SMTPUTF8", "SMTPUTF8=MAIL", "SMTPUTF8=RCPT", "SSL", "STARTTLS",
    "SEND", "STATUS-SIZE", "TURN", "URL", "UTF8", "XCLIENT", "XEXCH50",
    "XFORWARD", "XLOOP", "XOAUTH2", "XCLIENT-ADDR", "X-EXCH-50",
    "AUTH=CRAM-MD5", "AUTH=DIGEST-MD5", "AUTH=NTLM", "AUTH=CRAM-SHA-256",
    "AUTH=SCRAM-SHA-256", "AUTH=PLAIN", "STARTTLS", "TRN", "XSTORE",
    # POP3 (RFC 1939 and the common extensions). These were missing entirely,
    # and POP3's upgrade token is the four-character STLS, so any standard
    # four-character capability outside this set was being reported as a
    # substituted upgrade token - a high-severity tamper finding on clean
    # traffic. USER and UIDL are both four characters.
    "APOP", "AUTH", "CAPA", "DELE", "EXPIRE", "IMPLEMENTATION", "INCLUDEDIR",
    "LANG", "LANGUAGE", "LOGIN", "NOOP", "PIPELINING", "RELEASE", "RESET",
    "RESP-CODES", "SASL", "SASL-IR", "SASLLOGIN", "SASLPLAIN", "SASLCRAM-MD5",
    "STLS", "TOP", "UIDL", "USER", "UTF8", "UTF8=USER", "UTF8=ACCEPT",
    "EXPIRE", "USER-ABI", "UTF8=ONLY", "MVIEW", "XCLIENT",
}

_SMTP_REPLY = re.compile(rb"^(\d{3})([ -])")
_SMTP_ERROR = re.compile(rb"^(\d{3})\s")
_SMTP_CIPHERS = re.compile(rb"^220[- ]2?TLS", re.I)
_SMTP_READY = re.compile(rb"^220[\s-]", re.I)
_IMAP_CAPABILITY_LINE = re.compile(rb"\*\s+CAPABILITY\s+(.+)", re.I)
_IMAP_CAPABILITY_OK = re.compile(rb"OK\s+\[CAPABILITY\s+(.+?)\]", re.I)
_POP3_CAPA = re.compile(rb"^CAPA\b", re.I)
_POP3_CAP_LINE = re.compile(rb"^\+OK\b", re.I)
_REPEAT_RUN = re.compile(rb"(.)\1{3,}")


@dataclass
class Capability:
    """One token from a server capability advertisement."""

    name: str
    raw: str
    is_upgrade_token: bool = False
    looks_substituted: bool = False
    note: str = ""


@dataclass
class StarttlsVerdict:
    """The outcome of STARTTLS analysis for one conversation."""

    state: UpgradeState = UpgradeState.ABSENT
    protocol: str = "UNKNOWN"
    port: int = 0
    advertised: bool = False
    upgrade_command_seen: bool = False
    server_ready: bool = False
    tls_established: bool = False
    plaintext_after_upgrade: bool = False
    encrypted_bytes: int = 0
    capabilities: List[Capability] = field(default_factory=list)
    obfuscated_tokens: List[str] = field(default_factory=list)
    cross_flow_inconsistent: bool = False
    peer_advertised_elsewhere: Optional[bool] = None
    confidence: float = 0.0
    signals: List[str] = field(default_factory=list)
    tls_client_offset: Optional[int] = None
    tls_server_offset: Optional[int] = None
    remediation: str = ""

    @property
    def is_downgrade(self) -> bool:
        """True when the session carried data without the TLS it was offered."""
        return self.state in (
            UpgradeState.ABSENT,
            UpgradeState.REFUSED,
            UpgradeState.SUPPRESSED,
        ) and not self.tls_established

    @property
    def signatures(self) -> List[str]:
        found = []
        if self.obfuscated_tokens:
            found.append("K1_capability_suppression")
        if self.cross_flow_inconsistent:
            found.append("K2_cross_flow_inconsistency")
        if self.state is UpgradeState.REFUSED:
            found.append("K3_refused_upgrade")
        if self.plaintext_after_upgrade:
            found.append("K4_plaintext_after_upgrade")
        return found

    def summary(self) -> str:
        bits = [f"{self.protocol}:{self.port}", f"state={self.state.value}"]
        if self.tls_established:
            bits.append(f"encrypted={self.encrypted_bytes}B")
        if self.signatures:
            bits.append("sig=" + "+".join(self.signatures))
        return " | ".join(bits)


def upgrade_token_for(protocol: str) -> str:
    return _UPGRADE_TOKEN.get(protocol, _DEFAULT_UPGRADE_TOKEN)


# ── capability parsing ───────────────────────────────────────────────────────


def _edit_distance_at_most_one(a: str, b: str) -> bool:
    """True when `a` and `b` differ by at most one insert, delete or replace."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for x, y in zip(a, b) if x != y) <= 1
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = j = 0
    skipped = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def _substitution_reasons(raw: str, upgrade_token: str) -> List[str]:
    """Why this token looks like a tampered upgrade capability.

    Only positive evidence counts. Matching the upgrade token's *length* is not
    evidence: POP3's upgrade token is the four-character STLS, and USER, UIDL
    and TOP are ordinary capabilities of the same length. Treating length as
    sufficient produced a high-severity A1_tamper_signature on clean POP3
    traffic, so a length match is now recorded only as corroboration and never
    flags a token on its own.

    Two signals do justify a flag: a repeated-character run, which is the shape
    of a redaction (`XXXXXXXA`), and a single-character difference from the real
    token, which is the shape of a typo or a one-character swap (`S7ARTTLS`).
    """
    reasons: List[str] = []
    if _REPEAT_RUN.search(raw.encode("utf-8", errors="ignore")):
        reasons.append("repeated-character-run")
    if _edit_distance_at_most_one(raw.upper(), upgrade_token.upper()):
        reasons.append("one-character-difference-from-upgrade-token")
    return reasons


def _classify_token(raw: str, upgrade_token: str) -> Capability:
    cap = Capability(name=raw.upper(), raw=raw)
    if cap.name == upgrade_token.upper():
        cap.is_upgrade_token = True
        return cap
    if raw.upper() in _KNOWN_CAPABILITIES:
        return cap
    reasons = _substitution_reasons(raw, upgrade_token)
    if reasons:
        cap.looks_substituted = True
        cap.note = (
            "token is not a known capability and shows "
            + ", ".join(reasons)
        )
    return cap


def _parse_smtp_capabilities(server_bytes: bytes) -> List[Capability]:
    caps: List[Capability] = []
    token = _DEFAULT_UPGRADE_TOKEN
    in_ehlo = False
    for line in server_bytes.split(b"\n"):
        line = line.rstrip(b"\r")
        m = _SMTP_REPLY.match(line)
        if not m:
            continue
        code, sep = m.group(1), m.group(2)
        rest = line[m.end() :].strip()
        if code == b"250" and not in_ehlo:
            # Could be a greeting, a capability list, or something else.
            in_ehlo = True
            if rest and b":" in rest:
                in_ehlo = False
            continue
        if in_ehlo:
            if rest:
                caps.append(_classify_token(rest.split(b" ")[0].decode("latin-1"), token))
            if sep == b" ":
                in_ehlo = False
    return caps


def _parse_imap_capabilities(server_bytes: bytes) -> List[Capability]:
    token = _DEFAULT_UPGRADE_TOKEN
    caps: List[Capability] = []
    for line in server_bytes.split(b"\n"):
        line = line.rstrip(b"\r")
        m = _IMAP_CAPABILITY_LINE.match(line) or _IMAP_CAPABILITY_OK.match(line)
        if not m:
            continue
        for word in m.group(1).split():
            caps.append(_classify_token(word.decode("latin-1"), token))
    return caps


def _parse_pop3_capabilities(server_bytes: bytes) -> List[Capability]:
    token = _UPGRADE_TOKEN[POP3]
    caps: List[Capability] = []
    lines = [ln.rstrip(b"\r") for ln in server_bytes.split(b"\n")]
    for i, line in enumerate(lines):
        if not _POP3_CAP_LINE.match(line):
            continue
        block: List[bytes] = []
        for probe in lines[i + 1 :]:
            if probe == b".":
                break
            block.append(probe)
        else:
            continue
        for entry in block:
            word = entry.split(b" ")[0].decode("latin-1")
            if word:
                caps.append(_classify_token(word, token))
        break
    return caps


def parse_capabilities(protocol: str, server_bytes: bytes) -> List[Capability]:
    if protocol == POP3:
        return _parse_pop3_capabilities(server_bytes)
    if protocol == IMAP:
        return _parse_imap_capabilities(server_bytes)
    if protocol == SMTP:
        return _parse_smtp_capabilities(server_bytes)
    return []


# ── upgrade detection ────────────────────────────────────────────────────────


_TLS_CONTENT_TYPES = frozenset({20, 21, 22, 23})


def _find_tls_offset(direction) -> Optional[int]:
    """Byte offset in a direction's stream where the first TLS record begins.

    Reassembly merges adjacent bytes into contiguous runs, so a record boundary
    can fall anywhere inside a run. The stream is therefore scanned for a
    plausible record header rather than only inspected at segment starts.
    """
    data = direction.data
    end = len(data) - 5
    for i in range(0, end):
        if data[i] not in _TLS_CONTENT_TYPES or data[i + 1] != 0x03:
            continue
        length = int.from_bytes(data[i + 3 : i + 5], "big")
        if 0 < length <= 16640 and i + 5 + length <= len(data):
            return i
    return None


def _count_encrypted_bytes(direction, start_offset: Optional[int]) -> int:
    if start_offset is None:
        return 0
    total = 0
    for offset, chunk, _ts in direction.segments:
        end = offset + len(chunk)
        if end > start_offset:
            total += max(0, min(end, start_offset + 10_000_000) - max(offset, start_offset))
    return total


_SMTP_PLAINTEXT_CMD = re.compile(rb"^(MAIL FROM|RCPT TO|DATA|QUIT|NOOP|RSET|EHLO|HELO)\b", re.I)
_IMAP_PLAINTEXT_CMD = re.compile(rb"^(A\d{1,4} (LOGIN|SELECT|FETCH|SEARCH)|LOGOUT|NOOP)\b", re.I)
_POP3_PLAINTEXT_CMD = re.compile(rb"^(USER|PASS|RETR|STAT|LIST|DELE|QUIT)\b", re.I)


def _detect_plaintext_after_upgrade(
    protocol: str, client_bytes: bytes, after: int
) -> bool:
    """True if cleartext commands follow the point TLS should have taken over."""
    tail = client_bytes[after : after + 2048]
    if not tail:
        return False
    if looks_like_tls_record(tail):
        return False
    if protocol == POP3:
        return bool(_POP3_PLAINTEXT_CMD.match(tail))
    if protocol == IMAP:
        return bool(_IMAP_PLAINTEXT_CMD.match(tail))
    return bool(_SMTP_PLAINTEXT_CMD.match(tail))


def _upgrade_command_offset(
    protocol: str, client_bytes: bytes, token: str
) -> Optional[int]:
    pattern = re.compile(rb"^" + token.encode(), re.I | re.M)
    m = pattern.search(client_bytes)
    return m.start() if m else None


def analyze_starttls(
    conv: Conversation,
    guess: ProtocolGuess,
    peer_advertised_elsewhere: Optional[bool] = None,
) -> StarttlsVerdict:
    """Full STARTTLS analysis for one conversation."""
    verdict = StarttlsVerdict(protocol=guess.protocol, port=guess.port)
    token = upgrade_token_for(guess.protocol)
    server_bytes = conv.server.data
    client_bytes = conv.client.data

    verdict.tls_client_offset = _find_tls_offset(conv.client)
    verdict.tls_server_offset = _find_tls_offset(conv.server)
    verdict.tls_established = (
        verdict.tls_client_offset is not None
        or verdict.tls_server_offset is not None
    )
    verdict.encrypted_bytes = _count_encrypted_bytes(conv.client, verdict.tls_client_offset)

    # An implicit-TLS session has no upgrade phase at all.
    if guess.implicit_tls:
        verdict.state = UpgradeState.UPGRADED if verdict.tls_established else UpgradeState.NOT_APPLICABLE
        verdict.signals.append("implicit-tls-session")
        verdict.confidence = 0.95
        verdict.remediation = (
            "Session is encrypted from the first byte. Review version and cipher "
            "posture only."
        )
        return verdict

    verdict.capabilities = parse_capabilities(guess.protocol, server_bytes)
    verdict.advertised = any(c.is_upgrade_token for c in verdict.capabilities)
    verdict.obfuscated_tokens = [c.raw for c in verdict.capabilities if c.looks_substituted]

    cmd_offset = _upgrade_command_offset(guess.protocol, client_bytes, token)
    verdict.upgrade_command_seen = cmd_offset is not None
    if verdict.upgrade_command_seen:
        verdict.signals.append(f"client-sent-{token.lower()}")

    if verdict.advertised:
        verdict.signals.append("capability-advertised")

    # K1: capability suppression.
    if verdict.obfuscated_tokens:
        verdict.signals.append(
            "K1:upgrade-token-slot-occupied-by-"
            + ",".join(verdict.obfuscated_tokens)
        )

    # K2: the same peer behaved differently elsewhere in this capture.
    verdict.peer_advertised_elsewhere = peer_advertised_elsewhere
    if peer_advertised_elsewhere is True and not verdict.advertised:
        verdict.cross_flow_inconsistent = True
        verdict.signals.append("K2:peer-advertised-upgrade-in-another-session")

    # Did the server accept the command?
    verdict.server_ready = _server_accepted(guess.protocol, server_bytes, client_bytes, token)

    if verdict.tls_established:
        verdict.state = UpgradeState.UPGRADED
        verdict.signals.append("tls-records-observed")
        after = cmd_offset if cmd_offset is not None else 0
        if verdict.plaintext_after_upgrade is False:
            verdict.plaintext_after_upgrade = _detect_plaintext_after_upgrade(
                guess.protocol, client_bytes, after
            )
    elif verdict.upgrade_command_seen and not verdict.server_ready:
        verdict.state = UpgradeState.REFUSED
        verdict.signals.append("K3:upgrade-command-not-accepted")
    elif verdict.obfuscated_tokens or verdict.cross_flow_inconsistent:
        verdict.state = UpgradeState.SUPPRESSED
    elif verdict.advertised:
        verdict.state = UpgradeState.OFFERED
    elif verdict.upgrade_command_seen:
        verdict.state = UpgradeState.OFFERED
    else:
        verdict.state = UpgradeState.ABSENT
        verdict.signals.append("no-upgrade-capability-and-no-upgrade-attempt")

    verdict.confidence = round(_confidence(verdict), 3)
    verdict.remediation = _remediation(verdict)
    return verdict


def _server_accepted(
    protocol: str, server_bytes: bytes, client_bytes: bytes, token: str
) -> bool:
    """Did the server accept the upgrade command?

    The client and server are two independent byte streams, so a command offset
    in one says nothing about a position in the other. Ordering is therefore
    established by line position within the server's own stream: the readiness
    response must appear *after* the capability advertisement it belongs to,
    which also keeps the opening greeting from being mistaken for acceptance.
    """
    if _upgrade_command_offset(protocol, client_bytes, token) is None:
        return False
    lines = [ln.rstrip(b"\r") for ln in server_bytes.split(b"\n")]

    if protocol == POP3:
        for i, line in enumerate(lines):
            if not _POP3_CAP_LINE.match(line):
                continue
            for j in range(i + 1, len(lines)):
                if lines[j] == b".":
                    return any(
                        _POP3_CAP_LINE.match(after)
                        and b"ERR" not in after.upper()[:8]
                        for after in lines[j + 1 :]
                    )
        return False

    if protocol == IMAP:
        cap_end = -1
        for i, line in enumerate(lines):
            if _IMAP_CAPABILITY_LINE.match(line):
                cap_end = i
        if cap_end < 0:
            return False
        return any(
            re.match(rb"^[A-Za-z0-9]{1,10}\s+OK\b", line) for line in lines[cap_end + 1 :]
        )

    cap_end = -1
    for i, line in enumerate(lines):
        if i and line.startswith(b"250"):
            cap_end = i
    if cap_end < 0:
        return False
    return any(_SMTP_READY.match(line) for line in lines[cap_end + 1 :])


def _confidence(v: StarttlsVerdict) -> float:
    if v.state is UpgradeState.UPGRADED:
        return 0.95 if v.tls_client_offset is not None else 0.85
    if v.signatures:
        return 0.9 if v.obfuscated_tokens else 0.75
    if v.state is UpgradeState.OFFERED:
        return 0.8 if v.advertised else 0.5
    if v.state is UpgradeState.NOT_APPLICABLE:
        return 0.9
    return 0.6 if v.capabilities else 0.4


def _remediation(v: StarttlsVerdict) -> str:
    if v.state is UpgradeState.UPGRADED and not v.signatures:
        return "No upgrade-level action required. Assess version and cipher posture."
    if v.obfuscated_tokens:
        return (
            "A capability token occupies the STARTTLS slot but is not STARTTLS. "
            "Inspect the path for a TLS-inspecting middlebox (Cisco ASA "
            "SMTP inspection is enabled by default on some platforms) and, on the "
            "mail server, require TLS and verify peer certificates."
        )
    if v.cross_flow_inconsistent:
        return (
            "This peer advertised the upgrade capability in another session in the "
            "same capture but not in this one. Treat as probable capability "
            "suppression on the path and confirm from a second vantage point."
        )
    if v.state is UpgradeState.REFUSED:
        return (
            "The client requested the upgrade and the server refused; the session "
            "continued in cleartext. Configure mandatory TLS (SMTP: 'REQUIRE TLS' / "
            "'VERIFY'; IMAP: LOGINDISABLED; POP3: STLS required) and alert on "
            "refusal."
        )
    if v.state is UpgradeState.ABSENT:
        return (
            "No upgrade capability observed and the session carried cleartext. "
            "Enable opportunistic or mandatory TLS on this listener."
        )
    if v.state is UpgradeState.OFFERED:
        return (
            "The upgrade was advertised but never attempted by the client. Confirm "
            "client policy is enforcing TLS."
        )
    return ""


def build_peer_baseline(
    conversations: List[Conversation],
    guesses: List[ProtocolGuess],
) -> Dict[str, bool]:
    """Map peer endpoint -> advertised the upgrade capability in this capture.

    Used for K2. A peer seen advertising TLS in one session and not in another
    is the passive tell that a middlebox is rewriting the capability list.
    """
    baseline: Dict[str, bool] = {}
    for conv, guess in zip(conversations, guesses):
        peer = conv.server.endpoint
        advertised = any(
            c.is_upgrade_token
            for c in parse_capabilities(guess.protocol, conv.server.data)
        )
        if peer in baseline:
            baseline[peer] = baseline[peer] or advertised
        else:
            baseline[peer] = advertised
    return baseline
