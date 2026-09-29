"""TCP reassembly: correctness, ordering, retransmission, gaps, wrap."""

from kryxai.pcap.io import parse_capture, read_capture
from kryxai.pcap.models import FIN, ParsedPacket, RawPacket
from kryxai.pcap.synth import CLIENT, SERVER, ConversationBuilder, write_pcap
from kryxai.pcap.tcp import reassemble

CLIENT_TEXT = b"EHLO collector.district.gov.in\r\n"
SERVER_TEXT = (
    b"250-mail.district.gov.in\r\n"
    b"250-PIPELINING\r\n"
    b"250-STARTTLS\r\n"
    b"250 SMTPUTF8\r\n"
)


def _one_conversation(builder: ConversationBuilder, packets_override=None):
    packets = packets_override if packets_override is not None else parse_capture(builder.packets)
    conversations = reassemble(packets)
    assert len(conversations) == 1, f"expected 1 conversation, got {len(conversations)}"
    return conversations[0]


def _payload_packets(packets, client_port=49152):
    """Client-to-server payload segments, i.e. what a client sent."""
    return [p for p in packets if p.has_payload() and p.src_port == client_port]


def _replace_payload(pkt: ParsedPacket, payload: bytes) -> ParsedPacket:
    return ParsedPacket(
        index=pkt.index,
        ts=pkt.ts,
        src_ip=pkt.src_ip,
        dst_ip=pkt.dst_ip,
        src_port=pkt.src_port,
        dst_port=pkt.dst_port,
        seq=pkt.seq,
        ack=pkt.ack,
        flags=pkt.flags,
        payload=payload,
    )


def test_client_and_server_bytes_match_exactly():
    b = ConversationBuilder(server_port=25).handshake()
    b.send(CLIENT, CLIENT_TEXT).send(SERVER, SERVER_TEXT)
    conv = _one_conversation(b)

    assert conv.client.data == CLIENT_TEXT
    assert conv.server.data == SERVER_TEXT
    assert conv.is_complete_handshake


def test_client_side_is_the_bare_syn_sender():
    conv = _one_conversation(
        ConversationBuilder(server_port=25).handshake().send(CLIENT, CLIENT_TEXT)
    )
    # Both directions carry a SYN bit (the second is SYN/ACK), so that alone
    # does not identify the client. What identifies it is which side sent the
    # bare SYN: it is the ephemeral-port side, and the listening port belongs
    # to the server.
    assert conv.client.syn_seen and conv.server.syn_seen
    assert conv.client.src_port == 49152
    assert conv.client.dst_port == 25
    assert conv.server.src_port == 25
    assert conv.server.dst_port == 49152


def test_multiple_segments_concatenate_in_order():
    b = ConversationBuilder(server_port=25).handshake()
    for part in (b"AAA", b"BBB", b"CCC", b"DDD"):
        b.send(CLIENT, part)
    conv = _one_conversation(b)
    assert conv.client.data == b"AAABBBCCCDDD"
    assert not conv.client.gaps
    assert conv.client.is_complete


def test_out_of_order_segments_are_reordered():
    b = ConversationBuilder(server_port=25).handshake()
    for part in (b"AAA", b"BBB", b"CCC"):
        b.send(CLIENT, part)
    all_packets = parse_capture(b.packets)
    handshake = all_packets[:3]
    payloads = _payload_packets(all_packets)
    assert len(payloads) == 3
    conv = _one_conversation(
        b, packets_override=handshake + [payloads[2], payloads[0], payloads[1]]
    )

    assert conv.client.data == b"AAABBBCCC"
    assert not conv.client.gaps
    assert conv.client.out_of_order_segments >= 1


def test_retransmission_is_deduplicated_byte_exactly():
    b = ConversationBuilder(server_port=25).handshake()
    b.send(CLIENT, b"EHLO x\r\n")
    packets = parse_capture(b.packets)
    original = _payload_packets(packets)[0]
    conv = _one_conversation(b, packets_override=packets + [original])

    assert conv.client.data == b"EHLO x\r\n"
    assert conv.client.retransmit_bytes == len(original.payload)


def test_partial_overlap_keeps_the_original_bytes():
    b = ConversationBuilder(server_port=25).handshake()
    b.send(CLIENT, b"AAAAABBBB")
    packets = parse_capture(b.packets)
    original = _payload_packets(packets)[0]
    trimmed = _replace_payload(original, original.payload[:6])
    conv = _one_conversation(b, packets_override=packets + [trimmed])

    assert conv.client.data == b"AAAAABBBB"
    assert conv.client.retransmit_bytes == 6


def test_mid_stream_loss_produces_a_located_gap():
    b = ConversationBuilder(server_port=25).handshake()
    b.send(CLIENT, b"AAAAA")
    b.skip(5)  # a five-byte segment is lost in transit
    b.send(CLIENT, b"CCCCC")
    conv = _one_conversation(b)

    assert conv.client.gaps, "a hole in the middle must surface as a gap"
    assert not conv.client.is_complete
    assert conv.client.gaps[0] == (5, 10)
    assert conv.client.data == b"AAAAACCCCC"


def test_trailing_loss_is_detected_using_the_fin_sequence():
    """The FIN says the stream was longer than what arrived."""
    b = ConversationBuilder(server_port=25).handshake()
    b.send(CLIENT, b"AAAAA")
    b.skip(5)  # the final payload segment is lost, but its FIN still arrives
    b.finish()
    conv = _one_conversation(b)

    assert conv.client.gaps, "a lost trailing segment must surface via the FIN"
    assert conv.client.data == b"AAAAA"
    assert conv.client.gaps[0] == (5, 11)


def test_sequence_number_wrap_is_handled():
    b = ConversationBuilder(server_port=25, client_isn=(1 << 32) - 12).handshake()
    b.send(CLIENT, b"EHLO wrap\r\n")
    b.send(CLIENT, b"QUIT\r\n")
    conv = _one_conversation(b)

    assert conv.client.data == b"EHLO wrap\r\nQUIT\r\n"
    assert not conv.client.gaps


def test_capture_starting_mid_stream_still_reassembles():
    """No SYN in the capture: the first payload still defines offset zero."""
    b = ConversationBuilder(server_port=25)
    b.handshake()
    b.send(CLIENT, b"DATA-PAYLOAD-ONE\r\n")
    packets = parse_capture(b.packets)[3:]  # drop SYN/SYN-ACK/ACK
    conv = _one_conversation(b, packets_override=packets)
    assert conv.client.data == b"DATA-PAYLOAD-ONE\r\n"


def test_conversations_are_grouped_and_ordered(loaded_corpus):
    _linktype, _packets, conversations = loaded_corpus
    assert len(conversations) == 4
    assert [c.server.src_port for c in conversations] == [25, 25, 143, 110]


def test_unknown_linktype_yields_no_segments(tmp_path, smtp_healthy_builder):
    junk = [
        RawPacket(index=i, ts=p.ts, data=p.data, linktype=999)
        for i, p in enumerate(smtp_healthy_builder.packets)
    ]
    path = write_pcap(tmp_path / "junk.pcap", junk, linktype=999)
    _lt, packets = read_capture(path)
    assert parse_capture(packets) == []
