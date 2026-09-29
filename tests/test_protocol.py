from kryxai.pcap import mailflows, tlssynth as ts
from kryxai.pcap.io import parse_capture
from kryxai.pcap.protocol_id import (
    IMAP,
    POP3,
    SMTP,
    UNKNOWN,
    classify,
    guess_protocol,
    looks_like_tls_record,
)
from kryxai.pcap.synth import CLIENT, SERVER, ConversationBuilder
from kryxai.pcap.tcp import reassemble


def build(port, turns):
    builder = ConversationBuilder(server_port=port)
    mailflows.replay(builder, turns)
    return reassemble(parse_capture(builder.packets))


def test_smtp_is_identified_from_greeter_and_ehlo():
    conv = build(25, mailflows.smtp_healthy())[0]
    guess = guess_protocol(conv)

    assert guess.protocol == SMTP
    assert guess.port == 25
    assert guess.port_agrees is True
    assert guess.confidence > 0.8
    assert not guess.implicit_tls
    assert "greeter:SMTP" in guess.signals


def test_imap_is_identified():
    conv = build(143, mailflows.imap_healthy())[0]
    guess = guess_protocol(conv)

    assert guess.protocol == IMAP
    assert guess.port == 143
    assert guess.port_agrees is True


def test_pop3_is_identified():
    conv = build(110, mailflows.pop3_healthy())[0]
    guess = guess_protocol(conv)

    assert guess.protocol == POP3
    assert guess.port == 110
    assert guess.port_agrees is True


def test_implicit_tls_on_465_is_identified():
    conv = build(
        465,
        [
            (CLIENT, ts.record(ts.CT_HANDSHAKE, ts.client_hello())),
            (SERVER, ts.record(ts.CT_HANDSHAKE, ts.server_hello())),
        ],
    )[0]
    guess = guess_protocol(conv)

    assert guess.implicit_tls
    assert guess.protocol == SMTP
    assert guess.port == 465


def test_tls_on_a_non_mail_port_is_reported_as_unknown():
    conv = build(
        8080,
        [
            (CLIENT, ts.record(ts.CT_HANDSHAKE, ts.client_hello())),
            (SERVER, ts.record(ts.CT_HANDSHAKE, ts.server_hello())),
        ],
    )[0]
    guess = guess_protocol(conv)

    assert guess.implicit_tls
    assert guess.protocol == UNKNOWN
    assert guess.confidence < 0.5
    assert "tls-on-unknown-port" in guess.signals


def test_plaintext_greeting_on_an_implicit_port_is_surfaced():
    conv = build(465, [(SERVER, b"220 hello\r\n")])[0]
    guess = guess_protocol(conv)

    assert "plaintext-on-implicit-port-465" in guess.signals


def test_protocol_on_a_wrong_port_lowers_confidence_without_overriding_bytes():
    conv = build(8443, mailflows.smtp_healthy())[0]
    guess = guess_protocol(conv)

    assert guess.protocol == SMTP
    assert guess.port_agrees is None
    assert "port-8443-not-a-known-mail-port" in guess.signals


def test_empty_conversation_reports_no_evidence():
    builder = ConversationBuilder(server_port=25)
    builder.handshake()
    conv = reassemble(parse_capture(builder.packets))[0]
    guess = guess_protocol(conv)

    assert guess.confidence == 0.0
    assert "no-protocol-evidence" in guess.signals


def test_classify_returns_every_conversation_in_order():
    convs = build(25, mailflows.smtp_healthy())
    pairs = classify(convs)

    assert len(pairs) == 1
    conv, guess = pairs[0]
    assert conv is convs[0]
    assert guess.protocol == SMTP


def test_looks_like_tls_record_recognises_handshake_and_application_data():
    assert looks_like_tls_record(ts.record(ts.CT_HANDSHAKE, b"x"))
    assert looks_like_tls_record(ts.record(ts.CT_APPLICATION_DATA, b"y"))
    assert looks_like_tls_record(b"\x80\x2e\x01\x03\x01")
    assert not looks_like_tls_record(b"EHLO mail.example.com")
    assert not looks_like_tls_record(b"\x16\x04")
    assert not looks_like_tls_record(b"")


def test_guess_summary_reports_port_and_confidence():
    guess = guess_protocol(build(25, mailflows.smtp_healthy())[0])

    assert "SMTP:25" in guess.summary()
    assert "conf=" in guess.summary()


def test_is_mail_helper():
    assert guess_protocol(build(25, mailflows.smtp_healthy())[0]).is_mail
    assert not guess_protocol(
        build(8080, [(CLIENT, b"GET / HTTP/1.1\r\n")])[0]
    ).is_mail
