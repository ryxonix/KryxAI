"""Passive TLS handshake and record parsing.

Scope note that shapes this whole module: a passive observer can read the
ClientHello and ServerHello in every TLS version, but from TLS 1.3 onward the
server certificate is encrypted. KryxAI therefore reports certificate data only
when the capture actually contains it, and flags the TLS 1.3 case as
"not visible to passive analysis" instead of guessing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from kryxai.pcap import tlssynth as ts

TLS_PLAINTEXT = 0
TLS_AFTER_SERVER_HELLO = 1
TLS_AFTER_CLIENT_CERT = 2
TLS_ENCRYPTED = 3
TLS_UNKNOWN = 4


class TlsParseError(Exception):
    pass


@dataclass
class TlsRecord:
    content_type: int
    version: int
    payload: bytes
    offset: int

    @property
    def is_handshake(self) -> bool:
        return self.content_type == ts.CT_HANDSHAKE

    @property
    def is_encrypted_handshake(self) -> bool:
        return self.content_type == ts.CT_APPLICATION_DATA

    @property
    def is_alert(self) -> bool:
        return self.content_type == ts.CT_ALERT


@dataclass
class TlsHandshakeMessage:
    msg_type: int
    body: bytes
    record_offset: int


@dataclass
class TlsHandshake:
    version: Optional[int] = None
    client_hello: Optional[TlsHandshakeMessage] = None
    server_hello: Optional[TlsHandshakeMessage] = None
    certificates: List[bytes] = field(default_factory=list)
    server_key_exchange: Optional[TlsHandshakeMessage] = None
    supported_versions: List[int] = field(default_factory=list)
    offered_ciphers: List[int] = field(default_factory=list)
    selected_cipher: Optional[int] = None
    groups: List[int] = field(default_factory=list)
    selected_group: Optional[int] = None
    signature_algorithms: List[int] = field(default_factory=list)
    selected_signature_algorithm: Optional[int] = None
    sni: Optional[str] = None
    alpn: List[str] = field(default_factory=list)
    session_id_len: int = 0
    session_id_reused: bool = False
    encryption_state: int = TLS_UNKNOWN
    records: List[TlsRecord] = field(default_factory=list)
    truncated: bool = False
    parse_errors: List[str] = field(default_factory=list)

    @property
    def is_tls13(self) -> bool:
        return self.version is not None and self.version >= 0x0304

    @property
    def certificate_visible(self) -> bool:
        return bool(self.certificates)

    @property
    def version_name(self) -> str:
        if self.version is None:
            return "unknown"
        return ts.VERSION_NAMES.get(self.version, f"0x{self.version:04x}")

    @property
    def cipher_name(self) -> str:
        if self.selected_cipher is None:
            return "unknown"
        return CIPHER_NAMES.get(self.selected_cipher, f"0x{self.selected_cipher:04x}")

    @property
    def group_name(self) -> str:
        if self.selected_group is None:
            return "unknown"
        return ts.GROUP_NAMES.get(self.selected_group, f"0x{self.selected_group:04x}")

    @property
    def signature_name(self) -> str:
        if self.selected_signature_algorithm is None:
            return "unknown"
        return ts.SIGNATURE_NAMES.get(
            self.selected_signature_algorithm,
            f"0x{self.selected_signature_algorithm:04x}",
        )


CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
    0xC023: "ECDHE_ECDSA_AES_128_CBC_SHA256",
    0xC024: "ECDHE_ECDSA_AES_256_CBC_SHA384",
    0xC027: "ECDHE_RSA_AES_128_CBC_SHA256",
    0xC028: "ECDHE_RSA_AES_256_CBC_SHA384",
    0xC013: "ECDHE_RSA_AES_256_CBC_SHA",
    0xC014: "ECDHE_RSA_AES_128_CBC_SHA",
    0xC009: "ECDHE_ECDSA_AES_128_CBC_SHA",
    0xC00A: "ECDHE_ECDSA_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009F: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0xC008: "ECDHE_ECDSA_3DES_EDE_CBC_SHA",
    0xC012: "ECDHE_RSA_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x001B: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0002: "TLS_RSA_WITH_RC2_CBC_MD5",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0008: "TLS_RSA_WITH_DES_CBC_MD5",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0033: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
}


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise TlsParseError(f"short read: wanted {n}, have {len(self.d) - self.i}")
        out = self.d[self.i : self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        return struct.unpack("!I", b"\x00" + self.take(3))[0]

    def vec8(self) -> bytes:
        return self.take(self.u8())

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec24(self) -> bytes:
        return self.take(self.u24())

    @property
    def remaining(self) -> int:
        return len(self.d) - self.i


def parse_records_ex(data: bytes, limit: int = 20000) -> Tuple[List[TlsRecord], bool]:
    """Return records plus a flag for a trailing partial record."""
    out: List[TlsRecord] = []
    r = _Reader(data)
    while r.remaining >= 5 and len(out) < limit:
        off = r.i
        ct = r.u8()
        ver = r.u16()
        ln = r.u16()
        if ln > 16640:
            raise TlsParseError(f"implausible TLS record length {ln}")
        if r.remaining < ln:
            return out, True
        payload = r.take(ln)
        out.append(TlsRecord(content_type=ct, version=ver, payload=payload, offset=off))
    return out, r.remaining > 0


def parse_records(data: bytes, limit: int = 20000) -> List[TlsRecord]:
    return parse_records_ex(data, limit)[0]


def _parse_hello_extensions(r: _Reader, hs: TlsHandshake, is_client: bool) -> None:
    if r.remaining < 2:
        return
    ext_total = r.u16()
    end = r.i + ext_total
    while r.i + 4 <= end and r.i + 4 <= len(r.d):
        ext_type = r.u16()
        data = r.vec16()
        if ext_type == ts.EXT_SERVER_NAME:
            try:
                inner = _Reader(data)
                entries = _Reader(inner.vec16())
                while entries.remaining:
                    name_type = entries.u8()
                    host = entries.vec16().decode("utf-8", "replace")
                    if name_type == 0 and hs.sni is None:
                        hs.sni = host
            except TlsParseError:
                pass
        elif ext_type == ts.EXT_SUPPORTED_GROUPS:
            try:
                inner = _Reader(data)
                hs.groups = [
                    struct.unpack("!H", inner.take(2))[0]
                    for _ in range(inner.remaining // 2)
                ]
            except TlsParseError:
                pass
        elif ext_type == ts.EXT_SIGNATURE_ALGORITHMS:
            try:
                inner = _Reader(data)
                hs.signature_algorithms = [
                    struct.unpack("!H", inner.take(2))[0]
                    for _ in range(inner.remaining // 2)
                ]
            except TlsParseError:
                pass
        elif ext_type == ts.EXT_SUPPORTED_VERSIONS:
            try:
                inner = _Reader(data)
                if is_client:
                    versions = inner.vec8()
                    hs.supported_versions = [
                        struct.unpack("!H", versions[i : i + 2])[0]
                        for i in range(0, len(versions) - 1, 2)
                    ]
                else:
                    hs.supported_versions = [inner.u16()]
            except TlsParseError:
                pass
        elif ext_type == ts.EXT_KEY_SHARE:
            try:
                inner = _Reader(data)
                if is_client:
                    hs.groups = hs.groups or []
                else:
                    hs.selected_group = inner.u16()
            except TlsParseError:
                pass
        elif ext_type == ts.EXT_ALPN:
            try:
                inner = _Reader(data)
                pr = _Reader(inner.vec16())
                while pr.remaining:
                    hs.alpn.append(pr.vec8().decode("ascii", "replace"))
            except TlsParseError:
                pass
    r.i = end


def _parse_client_hello(body: bytes, hs: TlsHandshake) -> None:
    r = _Reader(body)
    hs.version = r.u16()
    hs.client_hello = TlsHandshakeMessage(ts.HS_CLIENT_HELLO, body, 0)
    r.take(32)
    sid = r.vec8()
    hs.session_id_len = len(sid)
    suites = r.vec16()
    hs.offered_ciphers = [
        struct.unpack("!H", suites[i : i + 2])[0] for i in range(0, len(suites) - 1, 2)
    ]
    r.vec8()
    _parse_hello_extensions(r, hs, is_client=True)
    if hs.supported_versions:
        hs.version = max(hs.supported_versions)


def _parse_server_hello(body: bytes, hs: TlsHandshake) -> None:
    r = _Reader(body)
    legacy = r.u16()
    r.take(32)
    hs.session_id_len = len(r.vec8())
    hs.selected_cipher = r.u16()
    r.u8()
    if hs.version is None:
        hs.version = legacy
    _parse_hello_extensions(r, hs, is_client=False)
    if hs.supported_versions:
        hs.version = hs.supported_versions[-1]
    hs.server_hello = TlsHandshakeMessage(ts.HS_SERVER_HELLO, body, 0)


def _parse_certificate(body: bytes, hs: TlsHandshake) -> None:
    r = _Reader(body)
    entries = r.vec24()
    inner = _Reader(entries)
    while inner.remaining >= 3:
        ln = inner.u24()
        if ln == 0:
            continue
        try:
            hs.certificates.append(inner.take(ln))
        except TlsParseError:
            return


def _parse_server_key_exchange(body: bytes, hs: TlsHandshake) -> None:
    r = _Reader(body)
    try:
        curve_type = r.u8()
        if curve_type == 3:
            hs.selected_group = r.u16()
        r.vec8()
        if r.remaining >= 2:
            hs.selected_signature_algorithm = r.u16()
    except TlsParseError:
        pass


def parse_handshake(data: bytes) -> TlsHandshake:
    hs = TlsHandshake()
    try:
        hs.records, hs.truncated = parse_records_ex(data)
    except TlsParseError as exc:
        hs.parse_errors.append(str(exc))
        return hs

    pending = b""
    saw_server_hello = False
    for rec in hs.records:
        if rec.content_type == ts.CT_CHANGE_CIPHER_SPEC:
            hs.encryption_state = (
                TLS_AFTER_SERVER_HELLO if saw_server_hello else TLS_AFTER_CLIENT_CERT
            )
            continue
        if rec.content_type == ts.CT_ALERT:
            if len(rec.payload) >= 2 and rec.payload[0] == 2:
                hs.parse_errors.append(f"fatal alert {rec.payload[1]}")
            continue
        if rec.is_encrypted_handshake:
            hs.encryption_state = TLS_ENCRYPTED
            continue
        if not rec.is_handshake:
            continue

        blob = pending + rec.payload
        i = 0
        while i + 4 <= len(blob):
            msg_type = blob[i]
            ln = struct.unpack("!I", b"\x00" + blob[i + 1 : i + 4])[0]
            if i + 4 + ln > len(blob):
                break
            body = blob[i + 4 : i + 4 + ln]
            if msg_type == ts.HS_CLIENT_HELLO and hs.client_hello is None:
                try:
                    _parse_client_hello(body, hs)
                except TlsParseError as exc:
                    hs.parse_errors.append(f"ClientHello: {exc}")
            elif msg_type == ts.HS_SERVER_HELLO and hs.server_hello is None:
                saw_server_hello = True
                try:
                    _parse_server_hello(body, hs)
                except TlsParseError as exc:
                    hs.parse_errors.append(f"ServerHello: {exc}")
            elif msg_type == ts.HS_CERTIFICATE:
                _parse_certificate(body, hs)
            elif msg_type == ts.HS_SERVER_KEY_EXCHANGE:
                hs.server_key_exchange = TlsHandshakeMessage(msg_type, body, rec.offset + i)
                _parse_server_key_exchange(body, hs)
            i += 4 + ln
        if i < len(blob):
            pending = blob[i:]
            hs.truncated = True
        else:
            pending = b""
    if hs.encryption_state == TLS_UNKNOWN and (hs.client_hello or hs.server_hello):
        hs.encryption_state = TLS_PLAINTEXT
    return hs
