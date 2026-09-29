from datetime import datetime, timezone

import pytest

from kryxai.pcap import tlssynth as ts
from kryxai.pcap.x509 import (
    days_remaining,
    expiry_status,
    match_san,
    name_matches,
    parse_certificate,
    parse_chain,
    verify_links,
)

CAPTURE = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def test_leaf_fields_are_extracted():
    leaf = parse_certificate(ts.make_chain()[0])

    assert leaf.common_name == "mail.example.com"
    assert "Example Mail Services" in leaf.organization
    assert leaf.is_ca is False
    assert leaf.public_key_algorithm == "rsa"
    assert leaf.public_key_bits == 2048
    assert leaf.signature_hash == "sha256"
    assert leaf.signature_key_family == "rsa"
    assert len(leaf.sha256_fingerprint) == 64
    assert leaf.san_dns == ["mail.example.com", "smtp.mail.example.com", "*.example.com"]


def test_ca_is_flagged_and_self_issued():
    ca = parse_certificate(ts.make_chain()[1])

    assert ca.is_ca is True
    assert ca.self_signed is True
    assert "key_cert_sign" in ca.key_usage


def test_wildcard_matching_rules():
    assert name_matches("*.example.com", "mail.example.com")
    assert name_matches("mail.example.com", "mail.example.com")
    assert not name_matches("*.example.com", "a.b.example.com")
    assert not name_matches("*.example.com", "example.com")
    assert not name_matches("*.example.com", "mail.example.org")
    assert name_matches("MAIL.Example.COM.", "mail.example.com")


def test_san_matching_falls_back_to_common_name():
    der, _ = ts.make_certificate(common_name="legacy.example.com")
    cert = parse_certificate(der)

    assert match_san(cert, "legacy.example.com") == ["legacy.example.com"]
    assert match_san(cert, "other.example.com") == []


def test_expiry_is_judged_against_capture_time_not_now():
    expired_leaf, _ = ts.make_certificate(
        common_name="old.example.com", not_before=1600000000, not_after=1700000000
    )
    cert = parse_certificate(expired_leaf)

    assert expiry_status(cert, CAPTURE) == "expired"
    assert expiry_status(cert, datetime(2021, 1, 1, tzinfo=timezone.utc)) == "valid"


def test_not_yet_valid_is_distinguished_from_expired():
    future_leaf, _ = ts.make_certificate(
        common_name="future.example.com", not_before=2000000000, not_after=2100000000
    )
    cert = parse_certificate(future_leaf)

    assert expiry_status(cert, CAPTURE) == "not_yet_valid"


def test_days_remaining_counts_down_to_expiry():
    start = 1735689600
    leaf, _ = ts.make_certificate(
        common_name="soon.example.com", not_before=start, not_after=start + 30 * 86400
    )
    cert = parse_certificate(leaf)

    assert days_remaining(cert, datetime.fromtimestamp(start, timezone.utc)) == 30
    assert days_remaining(cert, datetime.fromtimestamp(start + 25 * 86400, timezone.utc)) == 5


def test_expiry_status_is_unknown_without_capture_time():
    cert = parse_certificate(ts.make_chain()[0])

    assert expiry_status(cert, None) == "unknown"


def test_key_algorithms_and_sizes_are_reported():
    rsa1024, _ = ts.make_certificate(key_type="rsa", key_size=1024, common_name="weak.example.com")
    ec, _ = ts.make_certificate(key_type="ec", key_size=384, common_name="ec.example.com")
    ed, _ = ts.make_certificate(key_type="ed25519", sig_hash="sha256", common_name="ed.example.com")

    assert parse_certificate(rsa1024).public_key_bits == 1024
    ec_cert = parse_certificate(ec)
    assert ec_cert.public_key_algorithm == "ec"
    assert ec_cert.public_key_bits == 384
    assert ec_cert.public_key_curve == "secp384r1"
    ed_cert = parse_certificate(ed)
    assert ed_cert.public_key_algorithm == "ed25519"
    assert ed_cert.public_key_bits == 256


def test_sha1_signed_certificate_is_visible_as_such():
    der, _ = ts.make_certificate(
        common_name="sha1.example.com", key_type="rsa", key_size=2048
    )
    cert = parse_certificate(ts.relabel_rsa_signature_to_sha1(der))

    assert cert.signature_hash == "sha1"
    assert cert.signature_algorithm == "sha1WithRSAEncryption"


def test_chain_links_verify_from_leaf_to_self_signed_root():
    infos = parse_chain(ts.make_chain(), host="mail.example.com")
    links = verify_links(infos)

    assert len(links) == 2
    leaf_link, root_link = links
    assert leaf_link.issuer_found and leaf_link.signature_verified
    assert not leaf_link.is_self_signed
    assert not leaf_link.at_trust_boundary
    assert root_link.is_self_signed
    assert root_link.signature_verified
    assert root_link.at_trust_boundary
    assert "not a trust anchor" in root_link.detail


def test_truncated_chain_reports_the_missing_issuer():
    only_leaf = ts.make_chain()[0]
    links = verify_links(parse_chain([only_leaf]))

    assert len(links) == 1
    assert not links[0].issuer_found
    assert not links[0].signature_verified
    assert links[0].at_trust_boundary
    assert "truncated" in links[0].detail


def test_mismatched_issuer_is_reported():
    chain_a = ts.make_chain(leaf_cn="a.example.com", ca_cn="CA A")
    chain_b = ts.make_chain(leaf_cn="b.example.com", ca_cn="CA B")
    links = verify_links(parse_chain([chain_a[0], chain_b[1]]))

    assert not links[0].issuer_found
    assert not links[0].signature_verified
    assert "does not match" in links[0].detail


def test_wrong_ca_key_fails_signature_verification():
    ca_der, ca_key = ts.make_certificate(
        common_name="Real CA", is_ca=True, key_type="rsa", key_size=2048
    )
    impostor_der, impostor_key = ts.make_certificate(
        common_name="Real CA", is_ca=True, key_type="rsa", key_size=2048
    )
    leaf, _ = ts.make_certificate(common_name="leaf.example.com", issuer=(ca_der, ca_key))
    presented, _ = ts.make_certificate(
        common_name="Real CA", is_ca=True, key_type="rsa", key_size=2048,
        issuer=(impostor_der, impostor_key),
    )
    links = verify_links(parse_chain([leaf, presented]))

    assert links[0].issuer_found
    assert not links[0].signature_verified
    assert "signature failed" in links[0].detail


def test_unparsable_der_is_reported_not_raised():
    cert = parse_certificate(b"\x30\x82not-a-certificate")

    assert cert.parse_error is not None
    assert cert.common_name == ""
    assert len(cert.sha256_fingerprint) == 64
    links = verify_links([cert])
    assert links[0].signature_verified is False
    assert links[0].depth_ok is False


def test_host_matching_uses_the_configured_host():
    infos = parse_chain(ts.make_chain(leaf_cn="imap.example.com"), host="imap.example.com")

    assert infos[0].matches_host("imap.example.com")
    assert not infos[0].matches_host("smtp.example.com")


def test_expired_leaf_in_a_valid_chain_is_still_link_verified():
    chain = ts.make_chain(not_before=1600000000, not_after=1798761600, leaf_not_after=1700000000)
    infos = parse_chain(chain)
    links = verify_links(infos)

    assert links[0].signature_verified
    assert expiry_status(infos[0], CAPTURE) == "expired"
