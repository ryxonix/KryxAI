import pytest

from kryxai.pcap import tlssynth as ts
from kryxai.pcap.tls import (
    TLS_ENCRYPTED,
    TLS_PLAINTEXT,
    parse_handshake,
    parse_records,
)


def test_tls13_handshake_reports_version_cipher_and_group():
    hs = parse_handshake(ts.tls13_session(group=ts.CURVE_X25519, alpn=["h2", "http/1.1"]))

    assert hs.is_tls13
    assert hs.version_name == "TLS 1.3"
    assert hs.cipher_name == "TLS_AES_128_GCM_SHA256"
    assert hs.group_name == "x25519"
    assert hs.alpn == ["h2", "http/1.1"]
    assert hs.server_hello is not None
    assert hs.client_hello is not None


def test_tls13_reports_no_certificate_rather_than_inventing_one():
    hs = parse_handshake(ts.tls13_session())

    assert hs.is_tls13
    assert hs.certificates == []
    assert not hs.certificate_visible
    assert hs.encryption_state == TLS_ENCRYPTED


def test_tls13_negotiated_group_comes_from_the_server_key_share():
    for group, name in (
        (ts.CURVE_X25519, "x25519"),
        (ts.CURVE_SECP256R1, "secp256r1"),
        (ts.CURVE_SECP384R1, "secp384r1"),
    ):
        key_len = 32 if group == ts.CURVE_X25519 else 65
        hs = parse_handshake(ts.tls13_session(group=group, key_share_len=key_len))
        assert hs.group_name == name


def test_tls12_exposes_the_presented_chain():
    chain = ts.make_chain()
    hs = parse_handshake(ts.tls12_session(certs=chain, cipher=0xC02F))

    assert hs.version_name == "TLS 1.2"
    assert hs.cipher_name == "ECDHE_RSA_AES_128_GCM_SHA256"
    assert hs.certificates == chain
    assert hs.certificate_visible


def test_tls12_server_key_exchange_yields_the_group_and_signature():
    hs = parse_handshake(
        ts.tls12_session(cipher=0xC013, group=ts.CURVE_SECP256R1, certs=ts.make_chain())
    )

    assert hs.group_name == "secp256r1"
    assert hs.server_key_exchange is not None
    assert hs.signature_name == "rsa_pkcs1_sha256"


def test_client_hello_only_still_yields_the_offered_ceiling():
    hello = ts.record(ts.CT_HANDSHAKE, ts.client_hello(supported_versions=[0x0304, 0x0303]))
    hs = parse_handshake(hello)

    assert hs.server_hello is None
    assert hs.is_tls13
    assert hs.supported_versions == [0x0304, 0x0303]
    assert 0x1301 in hs.offered_ciphers
    assert ts.CURVE_X25519 in hs.groups
    assert hs.encryption_state == TLS_PLAINTEXT


def test_sni_is_extracted_from_the_client_hello():
    hello = ts.record(
        ts.CT_HANDSHAKE, ts.client_hello(sni="mail.example.com")
    )
    hs = parse_handshake(hello)

    assert hs.sni == "mail.example.com"


def test_handshake_split_across_two_records_is_reassembled():
    full = ts.record(ts.CT_HANDSHAKE, ts.client_hello(sni="split.example.com"))
    cut = len(full) - 12
    hs = parse_handshake(full[:cut] + full[cut:])

    assert hs.client_hello is not None
    assert hs.sni == "split.example.com"


def test_garbage_after_a_partial_record_does_not_raise():
    hs = parse_handshake(b"\x16\x03\x01\x02\x00ab\x17\x03")

    assert hs.client_hello is None


def test_truncated_record_is_kept_as_trailing_bytes():
    data = ts.record(ts.CT_HANDSHAKE, ts.client_hello())[:-4]
    hs = parse_handshake(data)

    assert hs.client_hello is None
    assert hs.truncated


def test_session_id_length_is_reported():
    hs = parse_handshake(
        ts.record(ts.CT_HANDSHAKE, ts.client_hello(session_id=bytes(range(32))))
    )

    assert hs.session_id_len == 32


def test_record_reader_rejects_an_implausible_length():
    with pytest.raises(Exception):
        parse_records(b"\x16\x03\x01\xff\xff" + bytes(10))


def test_fatal_alert_is_surfaced():
    data = ts.record(ts.CT_ALERT, b"\x02\x40") + ts.record(
        ts.CT_HANDSHAKE, ts.client_hello()
    )
    hs = parse_handshake(data)

    assert any("alert" in e for e in hs.parse_errors)
