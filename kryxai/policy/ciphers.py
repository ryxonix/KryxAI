"""Cipher suite and key-exchange knowledge base.

Ratings follow RFC 8996 (deprecating TLS 1.0/1.1 and symmetric suites) and
RFC 9325 (Recommendations for Secure Use of TLS and DTLS), which is the
current NIST-aligned guidance for TLS on the public Internet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

RECOMMENDED = "recommended"
ACCEPTABLE = "acceptable"
WEAK = "weak"
BROKEN = "broken"
UNKNOWN = "unknown"

_RANK = {RECOMMENDED: 0, ACCEPTABLE: 1, WEAK: 2, BROKEN: 3, UNKNOWN: 4}


@dataclass(frozen=True)
class CipherInfo:
    id: int
    name: str
    kex: str
    cipher: str
    mac: str
    aead: bool
    rating: str
    pfs: bool
    reference: str


def _c(
    cid: int,
    name: str,
    kex: str,
    cipher: str,
    mac: str,
    aead: bool,
    rating: str,
    reference: str,
) -> CipherInfo:
    pfs = kex in ("ecdhe", "dhe", "x25519", "x448", "psk-dhe", "psk-ecdhe")
    return CipherInfo(cid, name, kex, cipher, mac, aead, rating, pfs, reference)


CIPHERS: Dict[int, CipherInfo] = {
    c.id: c
    for c in [
        _c(0x1301, "TLS_AES_128_GCM_SHA256", "psk-dhe", "aes-128-gcm", "sha256", True, RECOMMENDED, "RFC 8446"),
        _c(0x1302, "TLS_AES_256_GCM_SHA384", "psk-dhe", "aes-256-gcm", "sha384", True, RECOMMENDED, "RFC 8446"),
        _c(0x1303, "TLS_CHACHA20_POLY1305_SHA256", "psk-dhe", "chacha20-poly1305", "sha256", True, RECOMMENDED, "RFC 8446"),
        _c(0xC02B, "ECDHE_ECDSA_AES_128_GCM_SHA256", "ecdhe", "aes-128-gcm", "sha256", True, RECOMMENDED, "RFC 8422"),
        _c(0xC02C, "ECDHE_ECDSA_AES_256_GCM_SHA384", "ecdhe", "aes-256-gcm", "sha384", True, RECOMMENDED, "RFC 8422"),
        _c(0xC02F, "ECDHE_RSA_AES_128_GCM_SHA256", "ecdhe", "aes-128-gcm", "sha256", True, RECOMMENDED, "RFC 8422"),
        _c(0xC030, "ECDHE_RSA_AES_256_GCM_SHA384", "ecdhe", "aes-256-gcm", "sha384", True, RECOMMENDED, "RFC 8422"),
        _c(0xCCA8, "ECDHE_RSA_CHACHA20_POLY1305_SHA256", "ecdhe", "chacha20-poly1305", "sha256", True, RECOMMENDED, "RFC 7905"),
        _c(0xCCA9, "ECDHE_ECDSA_CHACHA20_POLY1305_SHA256", "ecdhe", "chacha20-poly1305", "sha256", True, RECOMMENDED, "RFC 7905"),
        _c(0xC009, "ECDHE_ECDSA_AES_128_CBC_SHA", "ecdhe", "aes-128-cbc", "sha1", False, ACCEPTABLE, "RFC 8422"),
        _c(0xC00A, "ECDHE_ECDSA_AES_256_CBC_SHA", "ecdhe", "aes-256-cbc", "sha1", False, ACCEPTABLE, "RFC 8422"),
        _c(0xC013, "ECDHE_RSA_AES_256_CBC_SHA", "ecdhe", "aes-256-cbc", "sha1", False, ACCEPTABLE, "RFC 8422"),
        _c(0xC014, "ECDHE_RSA_AES_128_CBC_SHA", "ecdhe", "aes-128-cbc", "sha1", False, ACCEPTABLE, "RFC 8422"),
        _c(0xC023, "ECDHE_ECDSA_AES_128_CBC_SHA256", "ecdhe", "aes-128-cbc", "sha256", False, ACCEPTABLE, "RFC 8422"),
        _c(0xC024, "ECDHE_ECDSA_AES_256_CBC_SHA384", "ecdhe", "aes-256-cbc", "sha384", False, ACCEPTABLE, "RFC 8422"),
        _c(0xC027, "ECDHE_RSA_AES_128_CBC_SHA256", "ecdhe", "aes-128-cbc", "sha256", False, ACCEPTABLE, "RFC 8422"),
        _c(0xC028, "ECDHE_RSA_AES_256_CBC_SHA384", "ecdhe", "aes-256-cbc", "sha384", False, ACCEPTABLE, "RFC 8422"),
        _c(0x0067, "DHE_RSA_AES_128_CBC_SHA", "dhe", "aes-128-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0x006B, "DHE_RSA_AES_256_CBC_SHA", "dhe", "aes-256-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0x0039, "DHE_RSA_AES_128_CBC_SHA256", "dhe", "aes-128-cbc", "sha256", False, WEAK, "RFC 8996"),
        _c(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", "rsa", "aes-128-gcm", "sha256", True, WEAK, "RFC 8996"),
        _c(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", "rsa", "aes-256-gcm", "sha384", True, WEAK, "RFC 8996"),
        _c(0x009E, "TLS_RSA_WITH_AES_128_CBC_SHA256", "rsa", "aes-128-cbc", "sha256", False, WEAK, "RFC 8996"),
        _c(0x009F, "TLS_RSA_WITH_AES_256_CBC_SHA256", "rsa", "aes-256-cbc", "sha256", False, WEAK, "RFC 8996"),
        _c(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", "rsa", "aes-128-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", "rsa", "aes-256-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", "rsa", "aes-128-cbc", "sha256", False, WEAK, "RFC 8996"),
        _c(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", "rsa", "aes-256-cbc", "sha256", False, WEAK, "RFC 8996"),
        _c(0xC008, "ECDHE_ECDSA_3DES_EDE_CBC_SHA", "ecdhe", "3des-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0xC012, "ECDHE_RSA_3DES_EDE_CBC_SHA", "ecdhe", "3des-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0x0016, "DHE_RSA_3DES_EDE_CBC_SHA", "dhe", "3des-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0x001B, "DHE_DSS_3DES_EDE_CBC_SHA", "dhe", "3des-cbc", "sha1", False, WEAK, "RFC 8996"),
        _c(0x000A, "TLS_RSA_3DES_EDE_CBC_SHA", "rsa", "3des-cbc", "sha1", False, BROKEN, "RFC 8996"),
        _c(0x0009, "TLS_RSA_DES_CBC_SHA", "rsa", "des-cbc", "sha1", False, BROKEN, "RFC 8996"),
        _c(0x0008, "TLS_RSA_DES_CBC_MD5", "rsa", "des-cbc", "md5", False, BROKEN, "RFC 8996"),
        _c(0x0005, "TLS_RSA_RC4_128_SHA", "rsa", "rc4", "sha1", False, BROKEN, "RFC 7465"),
        _c(0x0004, "TLS_RSA_RC4_128_MD5", "rsa", "rc4", "md5", False, BROKEN, "RFC 7465"),
        _c(0x0002, "TLS_RSA_RC2_CBC_MD5", "rsa", "rc2-cbc", "md5", False, BROKEN, "RFC 7465"),
        _c(0x0006, "TLS_RSA_RC4_128_SHA_EXPORT", "rsa-export", "rc4", "sha1", False, BROKEN, "RFC 7465"),
        _c(0x0003, "TLS_RSA_RC4_64_MD5_EXPORT", "rsa-export", "rc4", "md5", False, BROKEN, "RFC 7465"),
    ]
}

EXPORT_GRADES = {0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0009, 0x000A, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x001B}

NULL_ENCIPHERS = {0x0000, 0x0001, 0x0002, 0x0038, 0x0039, 0x003A, 0x003B, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D}

VERSION_RATINGS = {
    0x0300: (BROKEN, "SSL 3.0", "RFC 7568 prohibits SSL 3.0; POODLE"),
    0x0301: (WEAK, "TLS 1.0", "RFC 8996 deprecates TLS 1.0; no AEAD, SHA-1 MAC"),
    0x0302: (WEAK, "TLS 1.1", "RFC 8996 deprecates TLS 1.1; no AEAD, SHA-1 MAC"),
    0x0303: (ACCEPTABLE, "TLS 1.2", "RFC 9325 minimum acceptable configuration"),
    0x0304: (RECOMMENDED, "TLS 1.3", "RFC 9325 preferred configuration"),
}

_GROUP_GUIDANCE = "RFC 9325 section 4.1: use X25519 or NIST P-256 or stronger"

GROUP_RATINGS = {
    0x001D: (RECOMMENDED, "x25519", "RFC 8446 named group x25519"),
    0x001E: (ACCEPTABLE, "x448", "RFC 8446 named group x448"),
    0x0017: (ACCEPTABLE, "secp256r1", "NIST P-256, permitted by RFC 9325"),
    0x0018: (ACCEPTABLE, "secp384r1", "NIST P-384, permitted by RFC 9325"),
    0x0019: (ACCEPTABLE, "secp521r1", "NIST P-521, permitted by RFC 9325"),
    0x001A: (WEAK, "brainpoolP256r1", "not in the RFC 9325 preferred set"),
    0x001B: (WEAK, "brainpoolP384r1", "not in the RFC 9325 preferred set"),
    0x001C: (WEAK, "brainpoolP512r1", "not in the RFC 9325 preferred set"),
    0x0016: (WEAK, "secp256k1", "not in the RFC 9325 preferred set"),
    0x0015: (WEAK, "sect163k1", "binary-field curve below 160-bit security"),
    0x0014: (WEAK, "sect163r1", "binary-field curve below 160-bit security"),
    0x0013: (WEAK, "sect163r2", "binary-field curve below 160-bit security"),
    0x0012: (WEAK, "sect193r1", "binary-field curve below 160-bit security"),
    0x0011: (WEAK, "sect193r2", "binary-field curve below 160-bit security"),
    0x0010: (WEAK, "sect233k1", "binary-field curve, not in the RFC 9325 preferred set"),
    0x000E: (WEAK, "sect233r1", "binary-field curve, not in the RFC 9325 preferred set"),
    0x000F: (WEAK, "sect239k1", "binary-field curve, not in the RFC 9325 preferred set"),
    0x000D: (WEAK, "sect283k1", "binary-field curve, not in the RFC 9325 preferred set"),
    0x000C: (WEAK, "sect283r1", "binary-field curve, not in the RFC 9325 preferred set"),
    0x0009: (WEAK, "sect571k1", "binary-field curve, not in the RFC 9325 preferred set"),
    0x0008: (WEAK, "sect571r1", "binary-field curve, not in the RFC 9325 preferred set"),
    0x000A: (WEAK, "secp256k1", "not in the RFC 9325 preferred set"),
    0x0004: (BROKEN, "sect163k1", "below 112-bit security; prohibited by RFC 9325"),
    0x0002: (BROKEN, "sect163r1", "below 112-bit security; prohibited by RFC 9325"),
    0x0005: (WEAK, "secp160k1", "below 128-bit security; prohibited by RFC 9325"),
    0x0003: (WEAK, "secp160r1", "below 128-bit security; prohibited by RFC 9325"),
    0x0001: (WEAK, "secp160r1", "below 128-bit security; prohibited by RFC 9325"),
    0x0000: (BROKEN, "sect163k1", "prohibited by RFC 9325"),
    0x0006: (BROKEN, "sect163r1", "prohibited by RFC 9325"),
    0x0007: (BROKEN, "sect167k1", "prohibited by RFC 9325"),
}

_SIGNATURE_GUIDANCE = "NIST SP 800-131A Rev. 2 requires SHA-256 or stronger"

SIGNATURE_RATINGS = {
    0x0203: (WEAK, "sha1WithRSAEncryption", "SHA-1 is withdrawn by NIST SP 800-131A Rev. 2"),
    0x0201: (WEAK, "rsa_pkcs1_sha1", "SHA-1 is withdrawn by NIST SP 800-131A Rev. 2"),
    0x0202: (WEAK, "ecdsa_sha1", "SHA-1 is withdrawn by NIST SP 800-131A Rev. 2"),
    0x0403: (RECOMMENDED, "ecdsa_secp256r1_sha256", "ECDSA with SHA-256"),
    0x0503: (RECOMMENDED, "ecdsa_secp384r1_sha384", "ECDSA with SHA-384"),
    0x0504: (RECOMMENDED, "ecdsa_secp521r1_sha512", "ECDSA with SHA-512"),
    0x0603: (ACCEPTABLE, "ecdsa_secp521r1_sha512", "ECDSA with SHA-512"),
    0x0401: (ACCEPTABLE, "rsa_pkcs1_sha256", "RSA PKCS#1 with SHA-256"),
    0x0501: (ACCEPTABLE, "rsa_pkcs1_sha384", "RSA PKCS#1 with SHA-384"),
    0x0601: (ACCEPTABLE, "rsa_pkcs1_sha512", "RSA PKCS#1 with SHA-512"),
    0x0804: (RECOMMENDED, "rsa_pss_rsae_sha256", "RSA-PSS with SHA-256"),
    0x0805: (RECOMMENDED, "rsa_pss_rsae_sha384", "RSA-PSS with SHA-384"),
    0x0806: (ACCEPTABLE, "rsa_pss_rsae_sha512", "RSA-PSS with SHA-512"),
    0x0807: (RECOMMENDED, "ed25519", "Ed25519, permitted by RFC 9325"),
    0x0808: (RECOMMENDED, "ed448", "Ed448, permitted by RFC 9325"),
    0x0809: (RECOMMENDED, "ecdsa_brainpoolP256r1_sha256", "permitted by RFC 9325"),
    0x0402: (WEAK, "dsa_sha1", "DSA is not permitted for TLS by RFC 9325"),
}


def lookup(cipher_id: Optional[int]) -> CipherInfo:
    if cipher_id is None:
        return CipherInfo(-1, "none", "none", "none", "none", False, UNKNOWN, False, "n/a")
    info = CIPHERS.get(cipher_id)
    if info is not None:
        return info
    if cipher_id in EXPORT_GRADES:
        return CipherInfo(cipher_id, f"0x{cipher_id:04x} (export grade)", "rsa-export", "unknown", "unknown", False, BROKEN, False, "RFC 7465")
    if cipher_id in NULL_ENCIPHERS:
        return CipherInfo(cipher_id, f"0x{cipher_id:04x} (no encryption)", "none", "null", "none", False, BROKEN, False, "RFC 8996")
    return CipherInfo(cipher_id, f"0x{cipher_id:04x}", "unknown", "unknown", "unknown", False, UNKNOWN, False, "not in local knowledge base")


def rating(cipher_id: Optional[int]) -> str:
    return lookup(cipher_id).rating


def has_pfs(cipher_id: Optional[int]) -> bool:
    return lookup(cipher_id).pfs


def version_rating(version: Optional[int]):
    if version is None:
        return (UNKNOWN, "unknown", "no version negotiated in the observed handshake")
    return VERSION_RATINGS.get(version, (UNKNOWN, f"0x{version:04x}", "version not in local knowledge base"))


def group_rating(group: Optional[int]):
    if group is None:
        return (UNKNOWN, "unknown", "key exchange group not visible in the observed handshake")
    return GROUP_RATINGS.get(group, (WEAK, f"0x{group:04x}", "finite-field or legacy curve; RFC 9325 prefers NIST P-256+ or X25519"))


def signature_rating(sig: Optional[int]):
    if sig is None:
        return (UNKNOWN, "unknown", "signature algorithm not visible in the observed handshake")
    return SIGNATURE_RATINGS.get(sig, (UNKNOWN, f"0x{sig:04x}", "signature algorithm not in local knowledge base"))


def weakest(ratings) -> str:
    worst = None
    for r in ratings:
        if worst is None or _RANK.get(r, 4) > _RANK.get(worst, 4):
            worst = r
    return worst if worst is not None else UNKNOWN


def sort_key(rating_value: str) -> int:
    return _RANK.get(rating_value, 4)
