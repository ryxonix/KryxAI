"""Capture reading: pcap, pcapng, endianness, and rejection of garbage."""

import struct

import pytest

from kryxai.pcap.io import PcapFormatError, read_capture
from kryxai.pcap.synth import write_pcap, write_pcapng


def test_pcap_roundtrip_preserves_frames(tmp_path, smtp_healthy_builder):
    path = write_pcap(tmp_path / "a.pcap", smtp_healthy_builder.packets)
    linktype, packets = read_capture(path)

    assert linktype == 1  # ethernet
    assert len(packets) == len(smtp_healthy_builder.packets)
    assert packets[0].data == smtp_healthy_builder.packets[0].data
    # pcap stores microseconds, so timestamps survive to that resolution only.
    for got, want in zip(packets, smtp_healthy_builder.packets):
        assert abs(got.ts - want.ts) < 1e-6


def test_pcapng_roundtrip_preserves_frames(tmp_path, smtp_healthy_builder):
    path = write_pcapng(tmp_path / "a.pcapng", smtp_healthy_builder.packets)
    _linktype, packets = read_capture(path)

    assert len(packets) == len(smtp_healthy_builder.packets)
    assert packets[0].data == smtp_healthy_builder.packets[0].data


def test_pcap_big_endian_is_readable(tmp_path, smtp_healthy_builder):
    """A BE-written capture must decode identically to the LE one."""
    be = tmp_path / "be.pcap"
    with be.open("wb") as fh:
        fh.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for pkt in smtp_healthy_builder.packets:
            sec = int(pkt.ts)
            usec = int(round((pkt.ts - sec) * 1_000_000))
            fh.write(struct.pack(">IIII", sec, usec, len(pkt.data), len(pkt.data)))
            fh.write(pkt.data)

    _lt, packets = read_capture(be)
    assert [p.data for p in packets] == [p.data for p in smtp_healthy_builder.packets]


def test_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_capture(tmp_path / "nope.pcap")


def test_garbage_is_rejected_with_a_clear_message(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture at all, just text" * 4)
    with pytest.raises(PcapFormatError) as exc:
        read_capture(bad)
    assert "magic" in str(exc.value)


def test_truncated_record_is_reported_not_silently_accepted(tmp_path, smtp_healthy_builder):
    path = write_pcap(tmp_path / "t.pcap", smtp_healthy_builder.packets)
    data = path.read_bytes()
    path.write_bytes(data[: len(data) - 12])
    with pytest.raises(PcapFormatError):
        read_capture(path)


def test_absurd_incl_len_is_refused_without_allocating(tmp_path, smtp_healthy_builder):
    path = write_pcap(tmp_path / "huge.pcap", smtp_healthy_builder.packets)
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, 24 + 8, 0x7FFFFFFF)  # incl_len of record 0
    path.write_bytes(bytes(data))
    with pytest.raises(PcapFormatError) as exc:
        read_capture(path)
    assert "refusing to allocate" in str(exc.value)
