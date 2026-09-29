from kryxai.policy import ciphers


def test_tls13_and_modern_aead_suites_are_recommended():
    for cid, name in (
        (0x1301, "TLS_AES_128_GCM_SHA256"),
        (0x1302, "TLS_AES_256_GCM_SHA384"),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
        (0xC02F, "ECDHE_RSA_AES_128_GCM_SHA256"),
        (0xC02B, "ECDHE_ECDSA_AES_128_GCM_SHA256"),
    ):
        info = ciphers.lookup(cid)
        assert info.name == name
        assert info.rating == ciphers.RECOMMENDED, name
        assert info.aead, name


def test_static_rsa_key_exchange_is_weak_and_lacks_pfs():
    for cid in (0x002F, 0x0035, 0x009C, 0x009D):
        info = ciphers.lookup(cid)
        assert info.rating == ciphers.WEAK
        assert not info.pfs, info.name
        assert info.kex == "rsa"


def test_rc4_and_3des_are_broken():
    assert ciphers.lookup(0x0005).rating == ciphers.BROKEN
    assert ciphers.lookup(0x0004).rating == ciphers.BROKEN
    assert ciphers.lookup(0x0002).rating == ciphers.BROKEN
    assert ciphers.lookup(0x000A).rating == ciphers.BROKEN
    assert ciphers.lookup(0x0008).rating == ciphers.BROKEN


def test_export_grade_is_broken():
    assert ciphers.lookup(0x0003).rating == ciphers.BROKEN
    assert ciphers.lookup(0x0006).rating == ciphers.BROKEN
    assert not ciphers.lookup(0x0006).pfs


def test_null_encryption_is_broken():
    assert ciphers.lookup(0x0038).rating == ciphers.BROKEN
    assert "no encryption" in ciphers.lookup(0x0038).name


def test_pfs_is_recognised_for_ephemeral_key_exchange():
    assert ciphers.has_pfs(0xC02F)
    assert ciphers.has_pfs(0xC030)
    assert ciphers.has_pfs(0xCCA9)
    assert not ciphers.has_pfs(0x009C)
    assert not ciphers.has_pfs(0x000A)


def test_unknown_cipher_is_reported_not_guessed():
    info = ciphers.lookup(0xABCD)

    assert info.rating == ciphers.UNKNOWN
    assert info.name == "0xabcd"
    assert not info.pfs
    assert "not in local knowledge base" in info.reference


def test_absent_cipher_is_unknown():
    assert ciphers.lookup(None).rating == ciphers.UNKNOWN
    assert ciphers.has_pfs(None) is False


def test_version_ratings_follow_rfc_8996():
    assert ciphers.version_rating(0x0300)[0] == ciphers.BROKEN
    assert "POODLE" in ciphers.version_rating(0x0300)[2]
    assert ciphers.version_rating(0x0301)[0] == ciphers.WEAK
    assert ciphers.version_rating(0x0302)[0] == ciphers.WEAK
    assert ciphers.version_rating(0x0303)[0] == ciphers.ACCEPTABLE
    assert ciphers.version_rating(0x0304)[0] == ciphers.RECOMMENDED
    assert ciphers.version_rating(None)[0] == ciphers.UNKNOWN
    assert ciphers.version_rating(0x0399)[0] == ciphers.UNKNOWN


def test_group_ratings_prefer_x25519_and_nist_curves():
    assert ciphers.group_rating(0x001D)[0] == ciphers.RECOMMENDED
    assert ciphers.group_rating(0x0017)[0] == ciphers.ACCEPTABLE
    assert ciphers.group_rating(0x0018)[0] == ciphers.ACCEPTABLE
    assert ciphers.group_rating(0x0002)[0] == ciphers.BROKEN
    assert ciphers.group_rating(0x000A)[0] == ciphers.WEAK
    assert ciphers.group_rating(None)[0] == ciphers.UNKNOWN


def test_signature_ratings_flag_sha1():
    assert ciphers.signature_rating(0x0201)[0] == ciphers.WEAK
    assert ciphers.signature_rating(0x0804)[0] == ciphers.RECOMMENDED
    assert ciphers.signature_rating(0x0403)[0] == ciphers.RECOMMENDED
    assert ciphers.signature_rating(0x0807)[0] == ciphers.RECOMMENDED
    assert ciphers.signature_rating(None)[0] == ciphers.UNKNOWN


def test_weakest_picks_the_worst_rating():
    assert ciphers.weakest([ciphers.RECOMMENDED, ciphers.ACCEPTABLE]) == ciphers.ACCEPTABLE
    assert ciphers.weakest([ciphers.ACCEPTABLE, ciphers.BROKEN]) == ciphers.BROKEN
    assert ciphers.weakest([ciphers.RECOMMENDED, ciphers.UNKNOWN]) == ciphers.UNKNOWN
    assert ciphers.weakest([]) == ciphers.UNKNOWN


def test_sort_key_orders_ratings_from_best_to_worst():
    ordered = sorted(
        [ciphers.BROKEN, ciphers.RECOMMENDED, ciphers.WEAK, ciphers.ACCEPTABLE],
        key=ciphers.sort_key,
    )

    assert ordered == [
        ciphers.RECOMMENDED,
        ciphers.ACCEPTABLE,
        ciphers.WEAK,
        ciphers.BROKEN,
    ]


def test_every_cipher_has_a_reference():
    for cid, info in ciphers.CIPHERS.items():
        assert info.reference, info.name
        assert info.rating in (
            ciphers.RECOMMENDED,
            ciphers.ACCEPTABLE,
            ciphers.WEAK,
            ciphers.BROKEN,
        ), info.name
