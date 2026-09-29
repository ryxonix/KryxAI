"""TCP stream reassembly.

Handles sequence-number wrap, retransmissions (byte-exact and partial),
out-of-order delivery, and missing data. Missing ranges are reported as gaps
rather than being silently closed, because a gap means a handshake may be
unparseable and KryxAI must say so instead of guessing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from kryxai.pcap.io import parse_capture, read_capture
from kryxai.pcap.models import (
    ACK,
    Conversation,
    FIN,
    ParsedPacket,
    RST,
    SYN,
    TcpDirection,
)

_SEQ_MOD = 1 << 32
_SEQ_HALF = 1 << 31

Endpoint = Tuple[str, int]


def conversation_key(pkt: ParsedPacket) -> Tuple[Endpoint, Endpoint]:
    """Direction-independent key for a TCP conversation."""
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    return (a, b) if a <= b else (b, a)


def _other(key: Tuple[Endpoint, Endpoint], endpoint: Endpoint) -> Endpoint:
    lo, hi = key
    return hi if endpoint == lo else lo


class _Assembler:
    """Byte buffer plus coverage bitmap for one direction of a stream."""

    def __init__(self) -> None:
        self.base: int = 0
        self.buf = bytearray()
        self.covered = bytearray()
        self.stamps: List[float] = []
        self.max_offset: Optional[int] = None
        self.retransmit_bytes = 0
        self.out_of_order = 0

    def _unwarp(self, seq: int, base_seq: int) -> int:
        off = (seq - base_seq) % _SEQ_MOD
        if self.max_offset is not None:
            if off > self.max_offset + _SEQ_HALF:
                off -= _SEQ_MOD
            elif off < self.max_offset - _SEQ_HALF:
                off += _SEQ_MOD
        if self.max_offset is None or off > self.max_offset:
            self.max_offset = off
        return off

    def add(self, seq: int, payload: bytes, ts: float, base_seq: Optional[int]) -> None:
        if base_seq is None:
            base_seq = seq
            self.base = 0
        prior_max = self.max_offset
        off = self._unwarp(seq, base_seq)
        if prior_max is not None and off < prior_max:
            self.out_of_order += 1

        if not self.buf:
            self.base = off
        start = off - self.base
        if start < 0:
            self.base += start
            self.buf[:0] = bytes(-start)
            self.covered[:0] = bytes(-start)
            self.stamps[:0] = [ts] * (-start)
            start = 0
        end = start + len(payload)
        if end > len(self.buf):
            grow = end - len(self.buf)
            self.buf.extend(bytes(grow))
            self.covered.extend(bytes(grow))
            self.stamps.extend([ts] * grow)

        for i, byte in enumerate(payload):
            pos = start + i
            if self.covered[pos]:
                self.retransmit_bytes += 1
            else:
                self.buf[pos] = byte
                self.covered[pos] = 1
                self.stamps[pos] = ts

    def fin_offset_for(self, seq: int, base_seq: Optional[int]) -> int:
        """Offset of a FIN relative to the stream, without mutating state."""
        if base_seq is None:
            return 0
        return (seq - base_seq) % _SEQ_MOD

    def extract(self, expected_length: Optional[int] = None) -> Tuple[
        List[Tuple[int, bytes, float]], List[Tuple[int, int]]
    ]:
        """Split the buffer into contiguous present runs and missing ranges.

        `expected_length` is the stream length implied by an observed FIN.
        """
        segments: List[Tuple[int, bytes, float]] = []
        gaps: List[Tuple[int, int]] = []
        n = len(self.covered)
        i = 0
        while i < n:
            if self.covered[i]:
                j = i
                while j < n and self.covered[j]:
                    j += 1
                segments.append(
                    (self.base + i, bytes(self.buf[i:j]), self.stamps[i])
                )
                i = j
            else:
                j = i
                while j < n and not self.covered[j]:
                    j += 1
                gaps.append((self.base + i, self.base + j))
                i = j
        if expected_length is not None and expected_length > n:
            if not gaps or gaps[-1][1] != self.base + n:
                gaps.append((self.base + n, self.base + expected_length))
        return segments, gaps


def _direction(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> TcpDirection:
    return TcpDirection(
        src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port
    )


def _split_on_new_connection(
    packets: Iterable[ParsedPacket],
) -> List[Tuple[Tuple[Endpoint, Endpoint], List[ParsedPacket]]]:
    """Bucket packets by 4-tuple, then split each bucket on a new SYN.

    A four-tuple is not a connection. One client opens many sequential
    connections to the same mail server, and a capture that merged them into
    one stream would fabricate a single oversized session and destroy the
    per-flow baseline that the STARTTLS comparison depends on.

    A bare SYN (no ACK) starts a new connection. A SYN/ACK does not, because it
    belongs to the connection the bare SYN opened. Packets that arrive before
    any SYN are kept in the first bucket, since a mid-connection capture has no
    connection start to key on.
    """
    buckets: Dict[Tuple[Endpoint, Endpoint], List[List[ParsedPacket]]] = {}
    order: List[Tuple[Endpoint, Endpoint]] = []
    for pkt in packets:
        key = conversation_key(pkt)
        if key not in buckets:
            buckets[key] = [[]]
            order.append(key)
        current = buckets[key][-1]
        if pkt.is_syn_only() and current:
            buckets[key].append([pkt])
        else:
            current.append(pkt)

    out: List[Tuple[Tuple[Endpoint, Endpoint], List[ParsedPacket]]] = []
    for key in order:
        for group in buckets[key]:
            if group:
                out.append((key, group))
    return out


def reassemble(packets: Iterable[ParsedPacket]) -> List[Conversation]:
    """Group TCP segments into conversations and reassemble both directions."""
    total = 0
    conversations: List[Conversation] = []
    for key, group in _split_on_new_connection(packets):
        total += len(group)
        client_ep, server_ep = _orient(group, key)

        client = _direction(*client_ep, *server_ep)
        server = _direction(*server_ep, *client_ep)
        asm_c = _Assembler()
        asm_s = _Assembler()

        for pkt in group:
            is_client = (pkt.src_ip, pkt.src_port) == client_ep
            target, asm = (client, asm_c) if is_client else (server, asm_s)

            if pkt.flags & SYN:
                target.syn_seen = True
                target.isn = pkt.seq
            if pkt.flags & FIN:
                target.fin_seen = True
                base_seq = (target.isn + 1) % _SEQ_MOD if target.isn is not None else None
                target.fin_offset = asm.fin_offset_for(pkt.seq, base_seq)
            if pkt.flags & RST:
                target.rst_seen = True

            if pkt.has_payload():
                base_seq = None
                if target.isn is not None:
                    base_seq = (target.isn + 1) % _SEQ_MOD
                asm.add(pkt.seq, pkt.payload, pkt.ts, base_seq)

        for target, asm in ((client, asm_c), (server, asm_s)):
            expected = None
            if target.fin_offset is not None:
                expected = target.fin_offset + 1
            segs, gaps = asm.extract(expected)
            target.segments = segs
            target.gaps = gaps
            target.retransmit_bytes = asm.retransmit_bytes
            target.out_of_order_segments = asm.out_of_order

        conversations.append(
            Conversation(
                client=client,
                server=server,
                packets_seen=len(group),
            )
        )
    return conversations


def _orient(
    group: List[ParsedPacket], key: Tuple[Endpoint, Endpoint]
) -> Tuple[Endpoint, Endpoint]:
    """Decide which endpoint is the client.

    Preference order:
      1. the sender of a SYN without ACK (a real client)
      2. the sender of the earliest SYN, tie-broken by (ip, port) so the
         result is stable across runs
    """
    syn_only: Optional[Endpoint] = None
    earliest: Optional[Tuple[float, Endpoint]] = None
    for pkt in group:
        if pkt.flags & SYN and not (pkt.flags & ACK):
            syn_only = (pkt.src_ip, pkt.src_port)
        if pkt.flags & SYN:
            ep = (pkt.src_ip, pkt.src_port)
            if earliest is None or pkt.ts < earliest[0]:
                earliest = (pkt.ts, ep)
    if syn_only is not None:
        return syn_only, _other(key, syn_only)
    if earliest is not None:
        return earliest[1], _other(key, earliest[1])
    # No handshake in the capture (mid-stream capture): deterministic tie-break.
    return key[0], key[1]


def reassemble_file(path: str | Path) -> List[Conversation]:
    """Read a capture from disk and reassemble every conversation in it."""
    _, packets = read_capture(path)
    return reassemble(parse_capture(packets))
