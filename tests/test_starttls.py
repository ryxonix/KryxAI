import pytest

from kryxai.pcap import mailflows, tlssynth as ts
from kryxai.pcap.io import parse_capture
from kryxai.pcap.protocol_id import SMTP, guess_protocol
from kryxai.pcap.starttls import (
    UpgradeState,
    _classify_token,
    analyze_starttls,
    build_peer_baseline,
    parse_capabilities,
)
from kryxai.pcap.synth import CLIENT, SERVER, ConversationBuilder
from kryxai.pcap.tcp import reassemble


def run_flow(port, turns):
    builder = ConversationBuilder(server_port=port)
    mailflows.replay(builder, turns)
    convs = reassemble(parse_capture(builder.packets))
    assert len(convs) == 1
    conv = convs[0]
    return conv, guess_protocol(conv)


def test_smtp_healthy_upgrade_is_upgraded():
    turns = mailflows.smtp_healthy()
    turns += mailflows.smtp_upgraded(
        client_hello=ts.record(ts.CT_HANDSHAKE, ts.client_hello()),
        server_hello=ts.record(ts.CT_HANDSHAKE, ts.server_hello()),
    )
    conv, guess = run_flow(25, turns)
    verdict = analyze_starttls(conv, guess)

    assert guess.protocol == SMTP
    assert verdict.state is UpgradeState.UPGRADED
    assert verdict.advertised
    assert verdict.tls_established
    assert verdict.encrypted_bytes > 0
    assert not verdict.is_downgrade
    assert verdict.signatures == []


def test_suppressed_capability_is_detected_by_the_xxxxxxxa_token():
    conv, guess = run_flow(25, mailflows.smtp_starttls_suppressed())
    verdict = analyze_starttls(conv, guess)

    assert verdict.state is UpgradeState.SUPPRESSED
    assert not verdict.advertised
    assert "XXXXXXXA" in verdict.obfuscated_tokens
    assert "K1_capability_suppression" in verdict.signatures
    assert verdict.is_downgrade
    assert "middlebox" in verdict.remediation.lower()


def test_suppression_is_detected_for_any_tampered_token():
    # Only tokens carrying positive evidence of substitution. A redaction has a
    # repeated-character run; a typo or a single-character swap is one edit from
    # the real token. See the limitation test below for the case that is
    # deliberately not claimed.
    for token in ("XXXXXXXA", "STARTTLX", "STARTTLSS", "S7ARTTLS", "STARTTLSX"):
        conv, guess = run_flow(25, mailflows.smtp_starttls_suppressed(replacement=token))
        verdict = analyze_starttls(conv, guess)

        assert "K1_capability_suppression" in verdict.signatures, token
        assert verdict.state is UpgradeState.SUPPRESSED, token
        assert token in verdict.obfuscated_tokens, token


def test_a_same_length_token_with_no_other_signal_is_not_flagged():
    """A documented limit: length alone is not evidence, so it is not claimed.

    `SESSIONS` is the same length as `STARTTLS` and was previously reported as a
    substituted upgrade token purely on that basis. It is equally consistent
    with an ordinary vendor capability, and the same-length rule is what made
    POP3's own `USER` and `UIDL` look like tampering. So a same-length token
    with no repeated run and no one-character difference is no longer flagged.

    The cost is real and worth stating: a middlebox that replaced `STARTTLS`
    with a same-length, non-repeating, plausible-looking token is not detected
    by this rule. K2 cross-flow inconsistency is the remaining route to that
    case.
    """
    conv, guess = run_flow(25, mailflows.smtp_starttls_suppressed(replacement="SESSIONS"))
    verdict = analyze_starttls(conv, guess)

    assert verdict.capabilities, "the token should still be parsed as a capability"
    assert not any(c.looks_substituted for c in verdict.capabilities)
    assert "K1_capability_suppression" not in verdict.signatures


def test_pop3_capabilities_of_the_same_length_as_stls_are_not_flagged():
    """The regression that motivated dropping the same-length rule.

    POP3's upgrade token is the four-character STLS. USER, UIDL and TOP are
    ordinary POP3 capabilities; when the vocabulary was SMTP/IMAP-only and
    length was sufficient evidence, a clean POP3 session produced a
    high-severity A1_tamper_signature on its own CAPA list.
    """
    for token in ("TOP", "USER", "UIDL", "SASL", "EXPIRE", "RESP-CODES", "STLS"):
        cap = _classify_token(token, "STLS")
        assert not cap.looks_substituted, f"{token} was flagged as substituted"


def test_substitution_reasons_are_reported_on_the_capability():
    conv, guess = run_flow(25, mailflows.smtp_starttls_suppressed())
    verdict = analyze_starttls(conv, guess)
    flagged = [c for c in verdict.capabilities if c.looks_substituted]

    assert len(flagged) == 1
    assert "repeated-character-run" in flagged[0].note
    # Length is no longer reported, because it is not a reason.
    assert "same-length" not in flagged[0].note


def test_a_genuine_known_capability_of_the_same_length_is_not_flagged():
    caps = parse_capabilities(
        SMTP, b"250-mail.example.com\r\n250-SSL\r\n250 SIZE 10240000\r\n"
    )
    substituted = [c.raw for c in caps if c.looks_substituted]

    assert substituted == []


def test_refused_upgrade_is_detected_and_keeps_carrying_cleartext():
    conv, guess = run_flow(25, mailflows.smtp_starttls_refused())
    verdict = analyze_starttls(conv, guess)

    assert verdict.upgrade_command_seen
    assert not verdict.tls_established
    assert verdict.state is UpgradeState.REFUSED
    assert "K3_refused_upgrade" in verdict.signatures
    assert verdict.is_downgrade
    assert "REQUIRE TLS" in verdict.remediation


def test_no_upgrade_at_all_is_absent_not_suppressed():
    conv, guess = run_flow(25, mailflows.smtp_no_upgrade())
    verdict = analyze_starttls(conv, guess)

    assert verdict.state is UpgradeState.ABSENT
    assert verdict.signatures == []
    assert verdict.is_downgrade
    assert not verdict.cross_flow_inconsistent


def test_cross_flow_inconsistency_alone_flags_the_second_session():
    healthy = run_flow(25, mailflows.smtp_healthy())
    clean = run_flow(25, mailflows.smtp_no_upgrade())
    baseline = build_peer_baseline([healthy[0], clean[0]], [healthy[1], clean[1]])

    peer = healthy[0].server.endpoint
    assert peer in baseline
    assert baseline[peer] is True

    verdict = analyze_starttls(clean[0], clean[1], peer_advertised_elsewhere=True)
    assert verdict.cross_flow_inconsistent
    assert verdict.signatures == ["K2_cross_flow_inconsistency"]
    assert verdict.state is UpgradeState.SUPPRESSED
    assert "second vantage point" in verdict.remediation


def test_same_session_does_not_trigger_cross_flow_detection():
    healthy = run_flow(25, mailflows.smtp_healthy())
    verdict = analyze_starttls(healthy[0], healthy[1], peer_advertised_elsewhere=True)

    assert not verdict.cross_flow_inconsistent


def test_imap_suppression_is_detected():
    conv, guess = run_flow(143, mailflows.imap_starttls_suppressed())
    verdict = analyze_starttls(conv, guess)

    assert guess.protocol == "IMAP"
    assert verdict.obfuscated_tokens
    assert "K1_capability_suppression" in verdict.signatures


def test_pop3_suppression_uses_the_stls_token():
    conv, guess = run_flow(110, mailflows.pop3_stls_suppressed())
    verdict = analyze_starttls(conv, guess)

    assert guess.protocol == "POP3"
    assert verdict.obfuscated_tokens
    assert "K1_capability_suppression" in verdict.signatures


def test_imap_healthy_upgrade_is_upgraded():
    # Protocol-correct: the IMAP handshake, not SMTP turns bolted onto it. The
    # previous version appended mailflows.smtp_upgraded(), which put SMTP
    # plaintext and an SMTP greeting in front of the TLS records. It passed,
    # and it is why the shipped 11_imap_healthy capture could be built with no
    # handshake at all without any test noticing.
    turns = mailflows.imap_healthy(
        client_hello=ts.record(ts.CT_HANDSHAKE, ts.client_hello()),
        server_hello=ts.tls12_session(cipher=0xC02F, certs=ts.make_chain()),
    )
    conv, guess = run_flow(143, turns)
    verdict = analyze_starttls(conv, guess)

    assert verdict.state is UpgradeState.UPGRADED
    assert verdict.tls_established


def test_pop3_healthy_upgrade_is_upgraded():
    turns = mailflows.pop3_healthy(
        client_hello=ts.record(ts.CT_HANDSHAKE, ts.client_hello()),
        server_hello=ts.tls12_session(cipher=0xC02F, certs=ts.make_chain()),
    )
    conv, guess = run_flow(110, turns)
    verdict = analyze_starttls(conv, guess)

    assert verdict.state is UpgradeState.UPGRADED
    assert verdict.tls_established


def test_an_upgrade_fixture_built_without_a_handshake_is_not_an_upgrade():
    """The omission must be visible, not silent.

    mailflows.imap_healthy() with no handshake records ends at "Begin TLS
    negotiation now". It is a legitimate fixture for the advertised-but-not-
    attempted case, and it must not be mistaken for a completed upgrade.
    """
    conv, guess = run_flow(143, mailflows.imap_healthy())
    verdict = analyze_starttls(conv, guess)

    assert verdict.state is UpgradeState.OFFERED
    assert not verdict.tls_established


def test_implicit_tls_session_has_no_upgrade_phase():
    builder = ConversationBuilder(server_port=465)
    mailflows.replay(
        builder,
        [
            (
                CLIENT,
                ts.record(ts.CT_HANDSHAKE, ts.client_hello()) + ts.encrypted_flight(600),
            ),
            (
                SERVER,
                ts.record(ts.CT_HANDSHAKE, ts.server_hello()) + ts.encrypted_flight(600),
            ),
        ],
    )
    conv = reassemble(parse_capture(builder.packets))[0]
    guess = guess_protocol(conv)
    verdict = analyze_starttls(conv, guess)

    assert guess.implicit_tls
    assert verdict.state is UpgradeState.UPGRADED
    assert "implicit-tls-session" in verdict.signals


def test_confidence_is_higher_for_a_hard_signature_than_a_soft_state():
    suppressed = analyze_starttls(*run_flow(25, mailflows.smtp_starttls_suppressed()))
    absent = analyze_starttls(*run_flow(25, mailflows.smtp_no_upgrade()))

    assert suppressed.confidence > absent.confidence
    assert 0.0 <= absent.confidence <= 1.0


def test_verdict_summary_names_the_protocol_and_state():
    verdict = analyze_starttls(*run_flow(25, mailflows.smtp_starttls_suppressed()))

    assert "SMTP:25" in verdict.summary()
    assert "state=suppressed" in verdict.summary()
    assert "K1" in verdict.summary()
