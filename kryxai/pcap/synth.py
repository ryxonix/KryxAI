"""Synthetic capture construction.

KryxAI's demo corpus and its test fixtures are generated rather than
downloaded, for two reasons: the corpus has to contain configurations that are
deliberately broken (TLS 1.0, RC4, expired certificates, suppressed
capabilities) and no public capture set is guaranteed to contain them; and a
generated capture is reproducible, so a test failure is always a code defect
rather than a fixture that moved.

Frames are emitted with correct IPv4 and TCP checksums, so the output opens
cleanly in Wireshark and can be diffed against it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from kryxai.pcap.io import LINKTYPE_ETHERNET
from kryxai.pcap.models import ACK, FIN, PSH, RST, SYN, RawPacket

_NG_BYTE_ORDER = 0x1A2B3C4D
_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_EPB = 0x00000006

CLIENT = "client"
SERVER = "server"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_to_bytes(addr: str) -> bytes:
    return bytes(int(p) for p in addr.split("."))


def _ipv4_header(src: str, dst: str, proto: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0x00,
        total_len,
        0x0001,
        0x4000,
        64,
        proto,
        0,
        _ip_to_bytes(src),
        _ip_to_bytes(dst),
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header


def _tcp_header(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> bytes:
    offset_flags = (5 << 12) | flags
    pseudo = _ip_to_bytes(src) + _ip_to_bytes(dst) + struct.pack(
        "!BBH", 0, 6, 20 + len(payload)
    )
    # Sequence numbers are tracked as unbounded Python ints so wrap-around can
    # be exercised; the wire field is 32 bits, so mask on the way out.
    seq &= 0xFFFFFFFF
    ack &= 0xFFFFFFFF
    header = pseudo + struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, 0, 0
    )
    csum = _checksum(header)
    return struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, csum, 0
    )


def _ethernet(src: str, dst: str) -> bytes:
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + struct.pack(
        "!H", 0x0800
    )


def write_pcap(path: str | Path, packets: List[RawPacket], linktype: int = LINKTYPE_ETHERNET) -> Path:
    """Write classic little-endian microsecond pcap."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for pkt in packets:
            sec = int(pkt.ts)
            usec = int(round((pkt.ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            fh.write(
                struct.pack("<IIII", sec, usec, len(pkt.data), len(pkt.data))
            )
            fh.write(pkt.data)
    return path


def write_pcapng(
    path: str | Path, packets: List[RawPacket], linktype: int = LINKTYPE_ETHERNET
) -> Path:
    """Write a minimal but standards-valid pcapng file (SHB + IDB + EPBs)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pad = lambda n: (-n) % 4  # noqa: E731

    shb_body = struct.pack("<IHHq", _NG_BYTE_ORDER, 1, 0, -1)
    shb_total = 12 + len(shb_body) + pad(len(shb_body))
    idb_body = struct.pack("<HHI", linktype, 0, 262144)
    idb_total = 12 + len(idb_body) + pad(len(idb_body))

    with path.open("wb") as fh:
        fh.write(
            struct.pack("<II", _SHB, shb_total)
            + shb_body
            + bytes(pad(len(shb_body)))
            + struct.pack("<I", shb_total)
        )
        fh.write(
            struct.pack("<II", _IDB, idb_total)
            + idb_body
            + bytes(pad(len(idb_body)))
            + struct.pack("<I", idb_total)
        )
        for pkt in packets:
            ticks = int(round(pkt.ts * 1_000_000))
            body = struct.pack(
                "<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(pkt.data), len(pkt.data)
            ) + pkt.data
            total = 12 + len(body) + pad(len(body))
            fh.write(
                struct.pack("<II", _EPB, total)
                + body
                + bytes(pad(len(body)))
                + struct.pack("<I", total)
            )
    return path


@dataclass
class ConversationBuilder:
    """Builds one synthetic TCP conversation as a list of RawPacket."""

    client_ip: str = "10.10.0.10"
    server_ip: str = "10.10.0.20"
    client_port: int = 49152
    server_port: int = 25
    client_isn: int = 1000
    server_isn: int = 5000
    base_ts: float = 1_700_000_000.0
    linktype: int = LINKTYPE_ETHERNET
    mac_client: str = "020000000002"
    mac_server: str = "020000000001"

    _client_seq: int = field(init=False, default=0)
    _server_seq: int = field(init=False, default=0)
    _pending: List[Tuple[str, int, int, int, bytes, float]] = field(
        init=False, default_factory=list
    )

    def __post_init__(self) -> None:
        self._client_seq = self.client_isn
        self._server_seq = self.server_isn

    # ── emission ───────────────────────────────────────────────────────────
    def _frame(
        self,
        direction: str,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
        ts: float,
    ) -> RawPacket:
        if direction == CLIENT:
            src, dst, sport, dport = (
                self.client_ip,
                self.server_ip,
                self.client_port,
                self.server_port,
            )
            mac_src, mac_dst = self.mac_client, self.mac_server
        else:
            src, dst, sport, dport = (
                self.server_ip,
                self.client_ip,
                self.server_port,
                self.client_port,
            )
            mac_src, mac_dst = self.mac_server, self.mac_client

        tcp = _tcp_header(src, dst, sport, dport, seq, ack, flags, payload)
        ip = _ipv4_header(src, dst, 6, len(tcp) + len(payload))
        eth = bytes.fromhex(mac_dst) + bytes.fromhex(mac_src) + struct.pack("!H", 0x0800)
        return RawPacket(
            index=len(self._pending),
            ts=ts,
            data=eth + ip + tcp + payload,
            linktype=self.linktype,
        )

    def _emit(
        self, direction: str, seq: int, ack: int, flags: int, payload: bytes, ts: float
    ) -> None:
        self._pending.append(
            self._frame(direction, seq, ack, flags, payload, ts)
        )

    # ── conversational API ─────────────────────────────────────────────────
    def handshake(self, dt_ms: float = 1.0) -> "ConversationBuilder":
        """SYN, SYN/ACK, ACK. The SYN consumes one sequence number on each side."""
        d = dt_ms / 1000.0
        t = self.base_ts
        self._emit(CLIENT, self.client_isn, 0, SYN, b"", t)
        self._client_seq = self.client_isn + 1

        self._emit(SERVER, self.server_isn, self._client_seq, SYN | ACK, b"", t + d)
        self._server_seq = self.server_isn + 1

        self._emit(CLIENT, self._client_seq, self._server_seq, ACK, b"", t + 2 * d)
        self._ts = t + 2 * d
        return self

    def send(self, direction: str, data: bytes, dt_ms: float = 5.0, flags: int = ACK | PSH) -> "ConversationBuilder":
        """Send `data` from one side, advancing that side's sequence number."""
        t = getattr(self, "_ts", self.base_ts) + dt_ms / 1000.0
        self._ts = t
        if direction == CLIENT:
            seq = self._client_seq
            ack = self._server_seq
        else:
            seq = self._server_seq
            ack = self._client_seq
        self._emit(direction, seq, ack, flags, data, t)
        if direction == CLIENT:
            self._client_seq += len(data)
        else:
            self._server_seq += len(data)
        return self

    def exchange(self, client_data: bytes, server_data: bytes, dt_ms: float = 5.0) -> "ConversationBuilder":
        return self.send(CLIENT, client_data, dt_ms).send(SERVER, server_data, dt_ms)

    def skip(self, n: int, direction: str = CLIENT) -> "ConversationBuilder":
        if direction == CLIENT:
            self._client_seq += n
        else:
            self._server_seq += n
        return self

    def finish(self) -> "ConversationBuilder":
        t = getattr(self, "_ts", self.base_ts) + 0.01
        self._ts = t
        self._emit(CLIENT, self._client_seq, self._server_seq, FIN | ACK, b"", t)
        self._client_seq += 1
        self._emit(SERVER, self._server_seq, self._client_seq, FIN | ACK, b"", t + 0.01)
        self._server_seq += 1
        self._emit(CLIENT, self._client_seq, self._server_seq, ACK, b"", t + 0.02)
        self._ts = t + 0.02
        return self

    # ── output ─────────────────────────────────────────────────────────────
    @property
    def packets(self) -> List[RawPacket]:
        return [pkt for pkt in self._pending]

    def to_pcap(self, path: str | Path) -> Path:
        return write_pcap(path, self._pending, self.linktype)


def merge_packets(*groups: List[RawPacket]) -> List[RawPacket]:
    """Interleave several packet lists by timestamp and renumber them."""
    flat: List[RawPacket] = [p for g in groups for p in g]
    flat.sort(key=lambda p: p.ts)
    return [
        RawPacket(index=i, ts=p.ts, data=p.data, linktype=p.linktype)
        for i, p in enumerate(flat)
    ]
