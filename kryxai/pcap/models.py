"""Immutable data carriers shared across the packet pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

TCP_FLAG_NAMES = (
    (FIN, "FIN"),
    (SYN, "SYN"),
    (RST, "RST"),
    (PSH, "PSH"),
    (ACK, "ACK"),
    (URG, "URG"),
)


@dataclass(frozen=True)
class RawPacket:
    """One captured frame, still link-layer encoded."""

    index: int
    ts: float
    data: bytes
    linktype: int


@dataclass(frozen=True)
class ParsedPacket:
    """A decoded TCP segment."""

    index: int
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes

    @property
    def flag_names(self) -> List[str]:
        return [name for bit, name in TCP_FLAG_NAMES if self.flags & bit]

    @property
    def four_tuple(self) -> Tuple[str, int, str, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def is_syn_only(self) -> bool:
        return bool(self.flags & SYN) and not bool(self.flags & ACK)

    def has_payload(self) -> bool:
        return len(self.payload) > 0


@dataclass
class TcpDirection:
    """Reassembled bytes for one half of a conversation.

    `offset` in `segments` is relative to the sequence number that follows the
    connection's SYN, so it is stable across sequence-number wrap and across
    captures that start mid-connection.
    """

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    isn: Optional[int] = None
    segments: List[Tuple[int, bytes, float]] = field(default_factory=list)
    gaps: List[Tuple[int, int]] = field(default_factory=list)
    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    fin_offset: Optional[int] = None
    retransmit_bytes: int = 0
    out_of_order_segments: int = 0

    @property
    def endpoint(self) -> str:
        return f"{self.src_ip}:{self.src_port}"

    @property
    def peer(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def data(self) -> bytes:
        return b"".join(chunk for _, chunk, _ in self.segments)

    @property
    def first_ts(self) -> Optional[float]:
        return self.segments[0][2] if self.segments else None

    @property
    def last_ts(self) -> Optional[float]:
        return self.segments[-1][2] if self.segments else None

    @property
    def is_complete(self) -> bool:
        return not self.gaps

    def inter_arrivals(self) -> List[float]:
        """Segment arrival deltas in seconds, in capture order."""
        stamps = [ts for _, _, ts in self.segments]
        return [b - a for a, b in zip(stamps, stamps[1:])]

    def head(self, count: int) -> bytes:
        return self.data[:count]


@dataclass
class Conversation:
    """A bidirectional TCP conversation with one client and one server."""

    client: TcpDirection
    server: TcpDirection
    packets_seen: int = 0
    non_tcp_packets: int = 0

    @property
    def is_complete_handshake(self) -> bool:
        return self.client.syn_seen and self.server.syn_seen

    @property
    def key(self) -> str:
        return f"{self.client.endpoint}<->{self.server.endpoint}"
