"""Self-contained PCAP and PCAPNG reader plus Ethernet/IP/TCP decoder.

Supports:
  * classic pcap, microsecond and nanosecond, both endiannesses
  * pcapng (SHB / IDB / EPB / SPB), both endiannesses
  * link layers: Ethernet (incl. 802.1Q/QinQ), Linux SLL, Linux SLL2,
    BSD/OpenBSD loopback, and bare IP
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from kryxai.pcap.models import ParsedPacket, RawPacket

# ── pcap magics ──────────────────────────────────────────────────────────────
_MAGIC_US_BE = 0xA1B2C3D4
_MAGIC_US_LE = 0xD4C3B2A1
_MAGIC_NS_BE = 0xA1B23C4D
_MAGIC_NS_LE = 0x4D3CB2A1

# ── pcapng block types ───────────────────────────────────────────────────────
_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_SPB = 0x00000003
_EPB = 0x00000006
_NG_BYTE_ORDER = 0x1A2B3C4D

# ── link types ───────────────────────────────────────────────────────────────
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_SLL = 113
LINKTYPE_LOOP = 108
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_SLL2 = 276
LINKTYPE_RAW_ALT = 12

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_VLAN = 0x8100
_ETHERTYPE_QINQ = 0x88A8
_ETHERTYPE_QINQ_ALT = 0x9100

_IPPROTO_TCP = 6
_IPPROTO_HOPOPT = 0
_IPPROTO_ROUTING = 43
_IPPROTO_FRAGMENT = 44
_IPPROTO_AH = 51
_IPPROTO_ICMPV6 = 58
_IPPROTO_NONE = 59
_IPPROTO_DSTOPTS = 60

LINKTYPE_NAMES = {
    LINKTYPE_NULL: "null",
    LINKTYPE_ETHERNET: "ethernet",
    LINKTYPE_RAW: "raw",
    LINKTYPE_RAW_ALT: "raw",
    LINKTYPE_SLL: "linux_sll",
    LINKTYPE_SLL2: "linux_sll2",
    LINKTYPE_LOOP: "loopback",
    LINKTYPE_IPV4: "ipv4",
    LINKTYPE_IPV6: "ipv6",
}

_MAX_PACKET = 16 * 1024 * 1024


class PcapFormatError(ValueError):
    """Raised when a file is not a capture format KryxAI can read."""


def linktype_name(linktype: int) -> str:
    return LINKTYPE_NAMES.get(linktype, f"linktype_{linktype}")


# ── classic pcap ─────────────────────────────────────────────────────────────


def _read_pcap(fh, size: int) -> Tuple[int, List[RawPacket]]:
    header = fh.read(24)
    if len(header) < 24:
        raise PcapFormatError("file is shorter than a pcap global header")

    magic_be = struct.unpack(">I", header[:4])[0]
    if magic_be in (_MAGIC_US_BE, _MAGIC_NS_BE):
        endian, nano = ">", magic_be == _MAGIC_NS_BE
    else:
        magic_le = struct.unpack("<I", header[:4])[0]
        if magic_le in (_MAGIC_US_BE, _MAGIC_NS_BE):
            endian, nano = "<", magic_le == _MAGIC_NS_BE
        else:
            raise PcapFormatError(
                f"unrecognised pcap magic 0x{header[:4].hex()}; not a pcap or pcapng file"
            )

    _major, _minor, _tz, _sig, _snaplen, network = struct.unpack(
        f"{endian}HHiIII", header[4:24]
    )

    packets: List[RawPacket] = []
    index = 0
    record = struct.Struct(f"{endian}IIII")
    while True:
        rec = fh.read(record.size)
        if not rec:
            break
        if len(rec) < record.size:
            raise PcapFormatError(
                f"truncated packet record #{index} at byte {fh.tell()}"
            )
        ts_sec, ts_frac, incl_len, orig_len = record.unpack(rec)
        if incl_len > _MAX_PACKET:
            raise PcapFormatError(
                f"packet #{index} claims {incl_len} bytes, refusing to allocate"
            )
        data = fh.read(incl_len)
        if len(data) < incl_len:
            raise PcapFormatError(f"truncated packet payload #{index}")
        ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
        packets.append(
            RawPacket(index=index, ts=ts, data=data, linktype=network)
        )
        index += 1
    return network, packets


# ── pcapng ───────────────────────────────────────────────────────────────────


def _read_pcapng(fh, size: int) -> Tuple[int, List[RawPacket]]:
    packets: List[RawPacket] = []
    linktypes: List[int] = []
    endian: Optional[str] = None
    index = 0
    default_iface = 0

    while True:
        head = fh.read(8)
        if not head:
            break
        if len(head) < 8:
            raise PcapFormatError("truncated pcapng block header")

        raw_type = struct.unpack("<I", head[:4])[0]
        if raw_type == _SHB or struct.unpack(">I", head[:4])[0] == _SHB:
            body = fh.read(4)
            if len(body) < 4:
                raise PcapFormatError("truncated pcapng section header")
            bo = struct.unpack("<I", body)[0]
            if bo == _NG_BYTE_ORDER:
                endian = "<"
            elif struct.unpack(">I", body)[0] == _NG_BYTE_ORDER:
                endian = ">"
            else:
                raise PcapFormatError("pcapng byte-order magic is not 0x1A2B3C4D")
            total = struct.unpack(f"{endian}I", head[4:8])[0]
            if total < 16 or total % 4:
                raise PcapFormatError(f"invalid pcapng SHB length {total}")
            skip = total - 12
            fh.read(skip)
            linktypes = []
            default_iface = 0
            continue

        if endian is None:
            raise PcapFormatError("pcapng block seen before any section header")

        block_type = struct.unpack(f"{endian}I", head[:4])[0]
        total = struct.unpack(f"{endian}I", head[4:8])[0]
        if total < 12 or total % 4:
            raise PcapFormatError(f"invalid pcapng block length {total}")
        body_len = total - 12
        raw = fh.read(total - 8)
        if len(raw) < total - 8:
            raise PcapFormatError("truncated pcapng block body")
        body, tail = raw[:-4], raw[-4:]
        if struct.unpack(f"{endian}I", tail)[0] != total:
            raise PcapFormatError(
                "pcapng block trailer length does not match its header"
            )

        if block_type == _IDB:
            if len(body) < 8:
                raise PcapFormatError("pcapng IDB too short")
            linktypes.append(struct.unpack(f"{endian}H", body[:2])[0])
        elif block_type == _EPB:
            if len(body) < 20:
                raise PcapFormatError("pcapng EPB too short")
            iface, ts_hi, ts_lo, caplen, _orig = struct.unpack(
                f"{endian}IIIII", body[:20]
            )
            data = body[20 : 20 + caplen]
            ticks = (ts_hi << 32) | ts_lo
            ts = ticks / 1e6
            link = linktypes[iface] if iface < len(linktypes) else LINKTYPE_ETHERNET
            packets.append(RawPacket(index=index, ts=ts, data=data, linktype=link))
            index += 1
        elif block_type == _SPB:
            if len(body) < 4:
                raise PcapFormatError("pcapng SPB too short")
            orig = struct.unpack(f"{endian}I", body[:4])[0]
            data = body[4:]
            link = linktypes[default_iface] if linktypes else LINKTYPE_ETHERNET
            packets.append(
                RawPacket(
                    index=index,
                    ts=float(index),
                    data=data[:orig] if orig <= len(data) else data,
                    linktype=link,
                )
            )
            index += 1
        # Other block types (NRB, ISB, custom) carry no packet data.

    linktype = linktypes[default_iface] if linktypes else LINKTYPE_ETHERNET
    return linktype, packets


# ── public entry points ──────────────────────────────────────────────────────


def _classify(head: bytes) -> str:
    if len(head) < 4:
        raise PcapFormatError("file is too short to be a capture")
    if struct.unpack("<I", head[:4])[0] == _SHB or struct.unpack(">I", head[:4])[0] == _SHB:
        return "pcapng"
    magic = struct.unpack(">I", head[:4])[0]
    if magic in (_MAGIC_US_BE, _MAGIC_NS_BE):
        return "pcap"
    if struct.unpack("<I", head[:4])[0] in (_MAGIC_US_BE, _MAGIC_NS_BE):
        return "pcap"
    raise PcapFormatError(
        f"unrecognised capture magic 0x{head[:4].hex()}; expected pcap or pcapng"
    )


def read_capture(path: str | Path) -> Tuple[int, List[RawPacket]]:
    """Read a whole capture into memory. Returns (linktype, packets)."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"capture not found: {path}")
    size = path.stat().st_size
    with path.open("rb") as fh:
        kind = _classify(fh.read(4))
        fh.seek(0)
        if kind == "pcapng":
            return _read_pcapng(fh, size)
        return _read_pcap(fh, size)


def iter_packets(path: str | Path) -> Iterator[RawPacket]:
    _, packets = read_capture(path)
    yield from packets


# ── link / network / transport decoding ──────────────────────────────────────


def _decode_ipv4(data: bytes, pkt_index: int, ts: float) -> Optional[ParsedPacket]:
    if len(data) < 20:
        return None
    vihl = data[0]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_length = struct.unpack(">H", data[2:4])[0]
    frag = struct.unpack(">H", data[6:8])[0]
    # A non-zero fragment offset means this datagram is a continuation; TCP
    # header parsing would be meaningless.
    if frag & 0x1FFF:
        return None
    protocol = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])

    end = total_length if 0 < total_length <= len(data) else len(data)
    if protocol != _IPPROTO_TCP:
        return None
    return _decode_tcp(data[ihl:end], pkt_index, ts, src, dst)


def _decode_ipv6(data: bytes, pkt_index: int, ts: float) -> Optional[ParsedPacket]:
    if len(data) < 40:
        return None
    next_header = data[6]
    src = _ipv6_str(data[8:24])
    dst = _ipv6_str(data[24:40])
    payload = data[40:]

    # Walk the extension header chain to the transport header.
    for _ in range(8):
        if next_header in (_IPPROTO_HOPOPT, _IPPROTO_ROUTING, _IPPROTO_DSTOPTS):
            if len(payload) < 8:
                return None
            ext_len = (payload[1] + 1) * 8
            next_header, payload = payload[0], payload[ext_len:]
        elif next_header == _IPPROTO_FRAGMENT:
            if len(payload) < 8:
                return None
            next_header, payload = payload[0], payload[8:]
        elif next_header == _IPPROTO_AH:
            if len(payload) < 2:
                return None
            ext_len = (payload[1] + 2) * 4
            next_header, payload = payload[0], payload[ext_len:]
        else:
            break

    if next_header != _IPPROTO_TCP:
        return None
    return _decode_tcp(payload, pkt_index, ts, src, dst)


def _ipv6_str(raw: bytes) -> str:
    import ipaddress

    return str(ipaddress.IPv6Address(raw))


def _decode_tcp(
    data: bytes, pkt_index: int, ts: float, src: str, dst: str
) -> Optional[ParsedPacket]:
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack = struct.unpack(">HHII", data[:12])
    data_offset = (data[12] >> 4) * 4
    flags = data[13]
    if data_offset < 20 or len(data) < data_offset:
        return None
    payload = data[data_offset:]
    return ParsedPacket(
        index=pkt_index,
        ts=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        payload=payload,
    )


def parse_link(raw: RawPacket) -> Optional[ParsedPacket]:
    """Decode one captured frame down to a TCP segment, or None."""
    link = raw.linktype
    data = raw.data

    if link == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack(">H", data[12:14])[0]
        offset = 14
        while ethertype in (_ETHERTYPE_VLAN, _ETHERTYPE_QINQ, _ETHERTYPE_QINQ_ALT):
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
            offset += 4
        body = data[offset:]
        if ethertype == _ETHERTYPE_IPV4:
            return _decode_ipv4(body, raw.index, raw.ts)
        if ethertype == _ETHERTYPE_IPV6:
            return _decode_ipv6(body, raw.index, raw.ts)
        return None

    if link == LINKTYPE_SLL:
        if len(data) < 16:
            return None
        ethertype = struct.unpack(">H", data[14:16])[0]
        body = data[16:]
        if ethertype == _ETHERTYPE_IPV4:
            return _decode_ipv4(body, raw.index, raw.ts)
        if ethertype == _ETHERTYPE_IPV6:
            return _decode_ipv6(body, raw.index, raw.ts)
        return None

    if link == LINKTYPE_SLL2:
        if len(data) < 20:
            return None
        ethertype = struct.unpack(">H", data[0:2])[0]
        body = data[20:]
        if ethertype == _ETHERTYPE_IPV4:
            return _decode_ipv4(body, raw.index, raw.ts)
        if ethertype == _ETHERTYPE_IPV6:
            return _decode_ipv6(body, raw.index, raw.ts)
        return None

    if link in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(data) < 4:
            return None
        family = struct.unpack("<I", data[:4])[0] & 0x0FFFFFFF
        body = data[4:]
        if family in (2, 24, 28, 30):
            return _decode_ipv4(body, raw.index, raw.ts)
        if family in (10, 23, 26):
            return _decode_ipv6(body, raw.index, raw.ts)
        return None

    if link == LINKTYPE_IPV4:
        return _decode_ipv4(data, raw.index, raw.ts)
    if link == LINKTYPE_IPV6:
        return _decode_ipv6(data, raw.index, raw.ts)
    if link in (LINKTYPE_RAW, LINKTYPE_RAW_ALT):
        if not data:
            return None
        version = data[0] >> 4
        if version == 4:
            return _decode_ipv4(data, raw.index, raw.ts)
        if version == 6:
            return _decode_ipv6(data, raw.index, raw.ts)
        return None

    return None


def parse_capture(packets: List[RawPacket]) -> List[ParsedPacket]:
    """Decode every TCP segment in a capture, preserving capture order."""
    out: List[ParsedPacket] = []
    for raw in packets:
        parsed = parse_link(raw)
        if parsed is not None:
            out.append(parsed)
    return out
