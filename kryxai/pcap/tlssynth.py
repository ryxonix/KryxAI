"""Builders for TLS records and handshake messages.

Only the structures KryxAI actually inspects are modelled. Everything that is
encrypted on the wire in TLS 1.3 is emitted as opaque filler, because a passive
observer genuinely cannot see it and the corpus must not pretend otherwise.
"""

from __future__ import annotations

import struct
from typing import Iterable, List, Optional, Sequence, Tuple

CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_SERVER_HELLO_DONE = 14
HS_CERTIFICATE_REQUEST = 13

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_SIGNATURE_ALGORITHMS_CERT = 50
EXT_RENEGOTIATION_INFO = 65281

CURVE_SECP256R1 = 0x0017
CURVE_SECP384R1 = 0x0018
CURVE_X25519 = 0x001D
CURVE_X448 = 0x001E
CURVE_SECP521R1 = 0x0019

SIG_RSA_PKCS1_SHA256 = 0x0401
SIG_ECDSA_SECP256R1_SHA256 = 0x0403
SIG_RSA_PSS_RSAE_SHA256 = 0x0804
SIG_RSA_PSS_RSAE_SHA384 = 0x0805
SIG_RSA_PSS_RSAE_SHA512 = 0x0806
SIG_ED25519 = 0x0807
SIG_RSA_PKCS1_SHA1 = 0x0201
SIG_ECDSA_SHA1 = 0x0202
SIG_RSA_PKCS1_MD5 = 0x0201

GROUP_NAMES = {
    CURVE_SECP256R1: "secp256r1",
    CURVE_SECP384R1: "secp384r1",
    CURVE_SECP521R1: "secp521r1",
    CURVE_X25519: "x25519",
    CURVE_X448: "x448",
}

SIGNATURE_NAMES = {
    SIG_RSA_PKCS1_SHA256: "rsa_pkcs1_sha256",
    SIG_RSA_PSS_RSAE_SHA256: "rsa_pss_rsae_sha256",
    SIG_RSA_PSS_RSAE_SHA384: "rsa_pss_rsae_sha384",
    SIG_RSA_PSS_RSAE_SHA512: "rsa_pss_rsae_sha512",
    SIG_ECDSA_SECP256R1_SHA256: "ecdsa_secp256r1_sha256",
    SIG_ED25519: "ed25519",
    SIG_RSA_PKCS1_SHA1: "rsa_pkcs1_sha1",
    SIG_ECDSA_SHA1: "ecdsa_sha1",
}

VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def u8(v: int) -> bytes:
    return struct.pack("!B", v)


def u16(v: int) -> bytes:
    return struct.pack("!H", v)


def u24(v: int) -> bytes:
    return struct.pack("!I", v)[1:]


def u32(v: int) -> bytes:
    return struct.pack("!I", v)


def _vec16(data: bytes) -> bytes:
    return u16(len(data)) + data


def _vec8(data: bytes) -> bytes:
    return u8(len(data)) + data


def _vec24(data: bytes) -> bytes:
    return u24(len(data)) + data


def extension(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + _vec16(data)


def record(content_type: int, payload: bytes, version: int = 0x0303) -> bytes:
    return u8(content_type) + u16(version) + _vec16(payload)


def handshake(msg_type: int, body: bytes) -> bytes:
    return u8(msg_type) + u24(len(body)) + body


def _key_share_ext(group: int, key_len: int) -> bytes:
    entry = u16(group) + _vec16(bytes(key_len))
    return _vec16(entry)


def client_hello(
    *,
    version: int = 0x0303,
    ciphers: Sequence[int] = (0x1301, 0x1302, 0x1303, 0xC02F, 0xC030),
    groups: Sequence[int] = (CURVE_X25519, CURVE_SECP256R1, CURVE_SECP384R1),
    sig_algs: Sequence[int] = (SIG_ECDSA_SECP256R1_SHA256, SIG_RSA_PSS_RSAE_SHA256),
    supported_versions: Optional[Sequence[int]] = None,
    alpn: Optional[Sequence[str]] = None,
    session_id: bytes = b"",
    random: Optional[bytes] = None,
    legacy_only: bool = False,
    key_share_group: int = CURVE_X25519,
    key_share_len: int = 32,
    sni: Optional[str] = None,
) -> bytes:
    rnd = random if random is not None else bytes(range(32))
    exts = b""
    if sni:
        exts += extension(EXT_SERVER_NAME, _vec16(u8(0) + _vec16(sni.encode())))
    if groups:
        exts += extension(EXT_SUPPORTED_GROUPS, _vec16(b"".join(u16(g) for g in groups)))
    exts += extension(EXT_EC_POINT_FORMATS, _vec8(u8(1)))
    exts += extension(EXT_SIGNATURE_ALGORITHMS, _vec16(b"".join(u16(s) for s in sig_algs)))
    if alpn:
        protos = b"".join(_vec8(p.encode()) for p in alpn)
        exts += extension(EXT_ALPN, _vec16(protos))
    if not legacy_only:
        versions = list(supported_versions) if supported_versions else [0x0304, 0x0303]
        exts += extension(
            EXT_SUPPORTED_VERSIONS, _vec8(b"".join(u16(v) for v in versions))
        )
        exts += extension(
            EXT_PSK_KEY_EXCHANGE_MODES, _vec8(u8(1))
        )
        exts += extension(EXT_KEY_SHARE, _key_share_ext(key_share_group, key_share_len))
    body = (
        u16(version)
        + rnd
        + _vec8(session_id)
        + _vec16(b"".join(u16(c) for c in ciphers))
        + _vec8(b"\x00")
        + _vec16(exts)
    )
    return handshake(HS_CLIENT_HELLO, body)


def server_hello(
    *,
    version: int = 0x0303,
    cipher: int = 0x1301,
    group: int = CURVE_X25519,
    key_len: int = 32,
    session_id: bytes = b"",
    random: Optional[bytes] = None,
    supported_version: Optional[int] = None,
) -> bytes:
    rnd = random if random is not None else bytes(range(32, 64))
    exts = b""
    if supported_version is not None:
        exts += extension(EXT_SUPPORTED_VERSIONS, u16(supported_version))
        exts += extension(EXT_KEY_SHARE, u16(group) + _vec16(bytes(key_len)))
    body = (
        u16(version)
        + rnd
        + _vec8(session_id)
        + u16(cipher)
        + u8(0)
        + _vec16(exts)
    )
    return handshake(HS_SERVER_HELLO, body)


def certificate(chain: Iterable[bytes]) -> bytes:
    entries = b"".join(_vec24(der) for der in chain)
    return handshake(HS_CERTIFICATE, _vec24(entries))


def server_key_exchange(
    group: int = CURVE_SECP256R1, key_len: int = 65, sig_alg: int = SIG_RSA_PKCS1_SHA256
) -> bytes:
    params = u8(3) + u16(group) + _vec8(bytes(key_len))
    return handshake(HS_SERVER_KEY_EXCHANGE, params + u16(sig_alg) + _vec16(bytes(256)))


def server_hello_done() -> bytes:
    return handshake(HS_SERVER_HELLO_DONE, b"")


def change_cipher_spec() -> bytes:
    return record(CT_CHANGE_CIPHER_SPEC, b"\x01", 0x0303)


def encrypted_flight(total: int, *, version: int = 0x0303) -> bytes:
    out = b""
    while len(out) < total:
        n = min(1400, total - len(out))
        out += record(CT_APPLICATION_DATA, bytes((i * 7 + 11) % 251 for i in range(n)), version)
    return out


def tls12_session(
    *,
    version: int = 0x0303,
    cipher: int = 0xC02F,
    group: int = CURVE_SECP256R1,
    certs: Sequence[bytes] = (),
    alpn: Optional[Sequence[str]] = None,
    ciphers: Optional[Sequence[int]] = None,
) -> bytes:
    ch = client_hello(
        version=version,
        ciphers=ciphers or (cipher, 0xC030, 0xC013),
        groups=() if group is None else (group,),
        supported_versions=[version],
        alpn=alpn,
        legacy_only=True,
    )
    sh = server_hello(version=version, cipher=cipher, session_id=bytes(range(32)))
    flight = record(CT_HANDSHAKE, ch, version) + record(CT_HANDSHAKE, sh, version)
    if certs:
        flight += record(CT_HANDSHAKE, certificate(certs), version)
    if group is not None:
        flight += record(CT_HANDSHAKE, server_key_exchange(group=group), version)
    flight += record(CT_HANDSHAKE, server_hello_done(), version)
    return flight


def tls13_session(
    *,
    version: int = 0x0304,
    cipher: int = 0x1301,
    group: int = CURVE_X25519,
    alpn: Optional[Sequence[str]] = None,
    ciphers: Optional[Sequence[int]] = None,
    key_share_len: int = 32,
    encrypted: int = 2400,
) -> bytes:
    ch = client_hello(
        version=0x0303,
        ciphers=ciphers or (cipher, 0x1302, 0x1303),
        groups=(group,),
        supported_versions=[version],
        alpn=alpn,
        key_share_group=group,
        key_share_len=key_share_len,
    )
    sh = server_hello(
        version=0x0303,
        cipher=cipher,
        group=group,
        key_len=key_share_len,
        session_id=bytes(range(32)),
        supported_version=version,
    )
    flight = record(CT_HANDSHAKE, ch, 0x0303) + record(CT_HANDSHAKE, sh, 0x0303)
    flight += change_cipher_spec()
    flight += encrypted_flight(encrypted, version=0x0303)
    return flight

def _new_key(key_type: str, key_size: int):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "ec":
        curve = {256: ec.SECP256R1, 384: ec.SECP384R1, 521: ec.SECP521R1}[key_size]
        return ec.generate_private_key(curve())
    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if key_type == "ed448":
        return ed448.Ed448PrivateKey.generate()
    raise ValueError(f"unknown key type {key_type}")


_HASHES = {
    "md5": "MD5",
    "sha1": "SHA1",
    "sha224": "SHA224",
    "sha256": "SHA256",
    "sha384": "SHA384",
    "sha512": "SHA512",
}


def _sign_hash(name: str):
    from cryptography.hazmat.primitives import hashes

    return {
        "md5": hashes.MD5,
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }[name]()


def make_certificate(
    *,
    common_name: str = "mail.example.com",
    organization: str = "Example Mail Services Pvt Ltd",
    organizational_unit: Optional[str] = None,
    country: str = "IN",
    key_type: str = "rsa",
    key_size: int = 2048,
    sig_hash: str = "sha256",
    not_before: int = 1600000000,
    not_after: int = 1900000000,
    is_ca: bool = False,
    dns_names: Sequence[str] = (),
    issuer: Optional[Tuple[bytes, object]] = None,
    serial: int = 0x4B525941,
):
    """Mint a DER certificate and return it with its private key.

    Passing issuer as (issuer_der, issuer_key) signs the certificate under
    that CA instead of making it self-signed.
    """
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec, padding
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives.asymmetric import ed448 as _ed448
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509.oid import NameOID

    key = _new_key(key_type, key_size)
    if issuer is None:
        issuer_name = None
        sign_key = key
    else:
        issuer_der, sign_key = issuer
        issuer_name = x509.load_der_x509_certificate(issuer_der).subject

    subject_parts = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ]
    if organizational_unit:
        subject_parts.append(
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
        )
    subject_parts.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    subject = x509.Name(subject_parts)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name if issuer_name is not None else subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(_dt.datetime.fromtimestamp(not_before, _dt.timezone.utc))
        .not_valid_after(_dt.datetime.fromtimestamp(not_after, _dt.timezone.utc))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not is_ca,
                content_commitment=False,
                key_encipherment=not is_ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns_names]),
            critical=False,
        )

    if isinstance(sign_key, (_ed25519.Ed25519PrivateKey, _ed448.Ed448PrivateKey)):
        cert = builder.sign(sign_key, None)
    elif isinstance(sign_key, _rsa.RSAPrivateKey):
        cert = builder.sign(sign_key, _sign_hash(sig_hash), padding.PKCS1v15())
    elif isinstance(sign_key, _ec.EllipticCurvePrivateKey):
        cert = builder.sign(sign_key, _sign_hash(sig_hash))
    else:
        cert = builder.sign(sign_key, _sign_hash(sig_hash))

    return cert.public_bytes(serialization.Encoding.DER), key


_SHA256_RSA_SIG_OID = bytes.fromhex("06092a864886f70d01010b")
_SHA1_RSA_SIG_OID = bytes.fromhex("06092a864886f70d010105")


def relabel_rsa_signature_to_sha1(der: bytes) -> bytes:
    """Swap a sha256WithRSAEncryption OID for sha1WithRSAEncryption.

    The two encodings are the same length, so the DER stays structurally valid
    and parseable. The signature itself was still made with SHA-256: this exists
    so the parser's SHA-1 detection can be exercised on a modern toolchain that
    refuses to sign with SHA-1, and it is not a way to obtain a genuinely
    SHA-1-signed certificate.
    """
    return der.replace(_SHA256_RSA_SIG_OID, _SHA1_RSA_SIG_OID)


def _default_dns_names(leaf_cn: str) -> Sequence[str]:
    """Derive a realistic SAN set from the common name.

    The wildcard must cover the leaf's own domain. Deriving it from a
    hard-coded parent would silently make an unrelated certificate match, which
    defeats any hostname-mismatch test.
    """
    names = [leaf_cn, "smtp." + leaf_cn]
    labels = leaf_cn.split(".")
    if len(labels) >= 3:
        wildcard = "*." + ".".join(labels[-2:])
        if wildcard != leaf_cn and wildcard not in names:
            names.append(wildcard)
    return tuple(names)


_CHAIN_CACHE: Dict[tuple, List[bytes]] = {}


def make_chain(
    *,
    leaf_cn: str = "mail.example.com",
    ca_cn: str = "Example Mail Root CA",
    leaf_key_type: str = "rsa",
    leaf_key_size: int = 2048,
    ca_key_type: str = "rsa",
    ca_key_size: int = 4096,
    sig_hash: str = "sha256",
    ca_sig_hash: Optional[str] = None,
    not_before: int = 1600000000,
    not_after: int = 1900000000,
    leaf_not_after: Optional[int] = None,
    leaf_dns_names: Optional[Sequence[str]] = None,
    reuse: bool = True,
) -> List[bytes]:
    """Build a leaf+CA chain.

    Results are memoised by their parameters. A real server presents the same
    certificate on every connection, and a synthetic corpus that minted a fresh
    identity per session would trip the certificate-inconsistency anomaly for
    the wrong reason. Pass `reuse=False` when a test needs two genuinely
    distinct chains.
    """
    dns = tuple(leaf_dns_names) if leaf_dns_names is not None else _default_dns_names(leaf_cn)
    key = (
        leaf_cn,
        ca_cn,
        leaf_key_type,
        leaf_key_size,
        ca_key_type,
        ca_key_size,
        sig_hash,
        ca_sig_hash,
        not_before,
        not_after,
        leaf_not_after,
        dns,
    )
    if reuse and key in _CHAIN_CACHE:
        return list(_CHAIN_CACHE[key])

    ca_der, ca_key = make_certificate(
        common_name=ca_cn,
        organization="Example Mail Trust Services",
        key_type=ca_key_type,
        key_size=ca_key_size,
        sig_hash=ca_sig_hash or sig_hash,
        not_before=not_before,
        not_after=not_after + 31536000,
        is_ca=True,
        serial=0x4B52594341,
    )
    leaf_der, _ = make_certificate(
        common_name=leaf_cn,
        key_type=leaf_key_type,
        key_size=leaf_key_size,
        sig_hash=sig_hash,
        not_before=not_before,
        not_after=leaf_not_after if leaf_not_after is not None else not_after,
        dns_names=dns,
        issuer=(ca_der, ca_key),
        serial=0x4B52594C46,
    )
    chain = [leaf_der, ca_der]
    if reuse:
        _CHAIN_CACHE[key] = chain
    return list(chain)
