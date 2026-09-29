import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kryxai.pcap.io import read_capture  # noqa: E402
from kryxai.pcap.mailflows import replay  # noqa: E402
from kryxai.pcap.synth import ConversationBuilder, merge_packets  # noqa: E402

_TLS_HANDSHAKE_PREFIX = bytes([0x16, 0x03, 0x03])


def fake_tls_record(body: bytes = b"\x01\x00\x00\x2f") -> bytes:
    """A syntactically valid TLS record header wrapping an arbitrary body."""
    return _TLS_HANDSHAKE_PREFIX + len(body).to_bytes(2, "big") + body


@pytest.fixture
def smtp_healthy_builder() -> ConversationBuilder:
    from kryxai.pcap import mailflows

    return replay(ConversationBuilder(server_port=25), mailflows.smtp_healthy())


@pytest.fixture
def smtp_suppressed_builder() -> ConversationBuilder:
    from kryxai.pcap import mailflows

    return replay(
        ConversationBuilder(server_port=25, base_ts=1_700_000_100.0),
        mailflows.smtp_starttls_suppressed(),
    )


@pytest.fixture
def corpus_path(tmp_path) -> Path:
    """A small multi-flow capture covering all three protocols."""
    from kryxai.pcap import mailflows

    groups = [
        replay(
            ConversationBuilder(server_port=25, base_ts=1_700_000_000.0),
            mailflows.smtp_healthy(),
        ).packets,
        replay(
            ConversationBuilder(
                client_port=49200, server_port=25, base_ts=1_700_000_100.0
            ),
            mailflows.smtp_starttls_suppressed(),
        ).packets,
        replay(
            ConversationBuilder(
                server_ip="10.10.0.30", server_port=143, base_ts=1_700_000_200.0
            ),
            mailflows.imap_healthy(),
        ).packets,
        replay(
            ConversationBuilder(
                server_ip="10.10.0.40",
                server_port=110,
                client_port=49321,
                base_ts=1_700_000_300.0,
            ),
            mailflows.pop3_healthy(),
        ).packets,
    ]
    path = tmp_path / "corpus.pcap"
    from kryxai.pcap.synth import write_pcap

    write_pcap(path, merge_packets(*groups))
    return path


@pytest.fixture
def loaded_corpus(corpus_path):
    from kryxai.pcap.io import parse_capture
    from kryxai.pcap.tcp import reassemble

    linktype, packets = read_capture(corpus_path)
    return linktype, packets, reassemble(parse_capture(packets))
