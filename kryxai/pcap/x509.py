"""X.509 extraction and analysis from passively observed TLS handshakes."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

WEAK_HASHES = {"md5", "md2", "md4", "sha1"}
BROKEN_HASHES = {"md5", "md2", "md4"}

SIGNATURE_ALG_FAMILIES = {
    "md2WithRSAEncryption": ("rsa", "md2"),
    "md5WithRSAEncryption": ("rsa", "md5"),
    "sha1WithRSAEncryption": ("rsa", "sha1"),
    "sha224WithRSAEncryption": ("rsa", "sha224"),
    "sha256WithRSAEncryption": ("rsa", "sha256"),
    "sha384WithRSAEncryption": ("rsa", "sha384"),
    "sha512WithRSAEncryption": ("rsa", "sha512"),
    "sha1WithECDSASignature": ("ecdsa", "sha1"),
    "sha224WithECDSASignature": ("ecdsa", "sha224"),
    "sha256WithECDSASignature": ("ecdsa", "sha256"),
    "sha384WithECDSASignature": ("ecdsa", "sha384"),
    "sha512WithECDSASignature": ("ecdsa", "sha512"),
    "dsaWithSha1": ("dsa", "sha1"),
    "dsaWithSha256": ("dsa", "sha256"),
}

RSA_MIN_BITS = 2048
EC_CURVE_BITS = {"secp192r1": 192, "secp224r1": 224, "secp256r1": 256, "secp384r1": 384, "secp521r1": 521}


class CertificateParseError(Exception):
    pass


@dataclass
class CertificateInfo:
    der: bytes
    subject: str
    issuer: str
    common_name: str
    organization: str
    serial_hex: str
    version: int
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    is_ca: bool
    public_key_algorithm: str
    public_key_bits: Optional[int]
    public_key_curve: Optional[str]
    signature_algorithm: str
    signature_key_family: str
    signature_hash: str
    sha256_fingerprint: str
    sha1_fingerprint: str
    san_dns: List[str] = field(default_factory=list)
    san_ip: List[str] = field(default_factory=list)
    san_matching: List[str] = field(default_factory=list)
    self_signed: bool = False
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    unknown_critical_extensions: List[str] = field(default_factory=list)
    parse_error: Optional[str] = None

    @property
    def subject_cn(self) -> str:
        return self.common_name

    def matches_host(self, host: str) -> bool:
        return host in self.san_matching


def _utc(value) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_certificate(der: bytes) -> CertificateInfo:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
    from cryptography.x509.oid import ExtensionOID

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        return CertificateInfo(
            der=der,
            subject="",
            issuer="",
            common_name="",
            organization="",
            serial_hex="",
            version=0,
            not_before=None,
            not_after=None,
            is_ca=False,
            public_key_algorithm="unknown",
            public_key_bits=None,
            public_key_curve=None,
            signature_algorithm="unknown",
            signature_key_family="unknown",
            signature_hash="unknown",
            sha256_fingerprint=hashlib.sha256(der).hexdigest(),
            sha1_fingerprint=hashlib.sha1(der).hexdigest(),
            parse_error=str(exc),
        )

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_alg = "rsa"
        key_bits = pub.key_size
        curve = None
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_alg = "ec"
        key_bits = pub.curve.key_size
        curve = pub.curve.name
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_alg = "ed25519"
        key_bits = 256
        curve = "ed25519"
    elif isinstance(pub, ed448.Ed448PublicKey):
        key_alg = "ed448"
        key_bits = 448
        curve = "ed448"
    else:
        key_alg = type(pub).__name__.lower()
        key_bits = None
        curve = None

    sig_alg = cert.signature_algorithm_oid._name
    family, digest = SIGNATURE_ALG_FAMILIES.get(sig_alg, (key_alg, "unknown"))
    if cert.signature_hash_algorithm is not None:
        digest = cert.signature_hash_algorithm.name

    def rdn(name: str) -> str:
        vals = cert.subject.get_attributes_for_oid(name)
        return vals[0].value if vals else ""

    from cryptography.x509.oid import NameOID

    cn = rdn(NameOID.COMMON_NAME)
    org = rdn(NameOID.ORGANIZATION_NAME)

    san_dns: List[str] = []
    san_ip: List[str] = []
    key_usage: List[str] = []
    eku: List[str] = []
    unknown_critical: List[str] = []
    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bool(bc.value.ca)
    except x509.ExtensionNotFound:
        pass
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dns = list(san.value.get_values_for_type(x509.DNSName))
        san_ip = [str(v) for v in san.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        for name in (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
        ):
            if getattr(ku.value, name, False):
                key_usage.append(name)
    except x509.ExtensionNotFound:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku = [o.dotted_string for o in ext.value]
    except x509.ExtensionNotFound:
        pass
    for ext in cert.extensions:
        if ext.critical and ext.oid.dotted_string not in {
            "2.5.29.19",
            "2.5.29.15",
            "2.5.29.17",
            "2.5.29.37",
            "2.5.29.14",
        }:
            unknown_critical.append(ext.oid._name or ext.oid.dotted_string)

    return CertificateInfo(
        der=der,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        common_name=cn,
        organization=org,
        serial_hex=f"{cert.serial_number:x}",
        version=cert.version.value,
        not_before=_utc(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before),
        not_after=_utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after),
        is_ca=is_ca,
        public_key_algorithm=key_alg,
        public_key_bits=key_bits,
        public_key_curve=curve,
        signature_algorithm=sig_alg,
        signature_key_family=family,
        signature_hash=digest,
        sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        sha1_fingerprint=cert.fingerprint(hashes.SHA1()).hex(),
        san_dns=san_dns,
        san_ip=san_ip,
        key_usage=key_usage,
        extended_key_usage=eku,
        unknown_critical_extensions=unknown_critical,
        self_signed=cert.subject == cert.issuer,
    )


def name_matches(pattern: str, host: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    host = host.strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not host.endswith(suffix):
            return False
        left = host[: -len(suffix)]
        return left != "" and "." not in left
    return False


def match_san(cert: CertificateInfo, host: str) -> List[str]:
    hits = [d for d in cert.san_dns if name_matches(d, host)]
    if not hits and name_matches(cert.common_name, host):
        hits.append(cert.common_name)
    return hits


def parse_chain(ders: List[bytes], host: Optional[str] = None) -> List[CertificateInfo]:
    infos = [parse_certificate(d) for d in ders]
    for info in infos:
        if host:
            info.san_matching = match_san(info, host)
    return infos


@dataclass
class ChainLink:
    subject: str
    issuer: str
    issuer_found: bool
    signature_verified: bool
    is_self_signed: bool
    at_trust_boundary: bool
    depth_ok: bool
    detail: str = ""


def verify_links(infos: List[CertificateInfo], *, max_depth: int = 10) -> List[ChainLink]:
    """Link consecutive certificates by issuer/subject and verify signatures.

    This validates the presented chain's internal consistency only. It is not a
    PKI trust decision: a passive capture has no trust store context, so a
    self-signed root and an untrusted private CA are reported as observations.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    links: List[ChainLink] = []
    for i, info in enumerate(infos):
        if info.parse_error:
            links.append(
                ChainLink(
                    subject=info.subject or "<unparsed>",
                    issuer=info.issuer,
                    issuer_found=False,
                    signature_verified=False,
                    is_self_signed=False,
                    at_trust_boundary=False,
                    depth_ok=False,
                    detail=info.parse_error,
                )
            )
            continue
        if info.self_signed:
            try:
                cert = x509.load_der_x509_certificate(info.der)
                cert.verify_directly_issued_by(cert)
                ok = True
                detail = "self-issued; not a trust anchor on its own"
            except Exception as exc:
                ok = False
                detail = f"self-issued but signature check failed: {exc}"
            links.append(
                ChainLink(
                    subject=info.subject,
                    issuer=info.issuer,
                    issuer_found=True,
                    signature_verified=ok,
                    is_self_signed=True,
                    at_trust_boundary=True,
                    depth_ok=i <= max_depth,
                    detail=detail,
                )
            )
            continue
        if i + 1 >= len(infos):
            links.append(
                ChainLink(
                    subject=info.subject,
                    issuer=info.issuer,
                    issuer_found=False,
                    signature_verified=False,
                    is_self_signed=False,
                    at_trust_boundary=True,
                    depth_ok=i <= max_depth,
                    detail="chain is truncated: issuer certificate not presented",
                )
            )
            continue
        parent = infos[i + 1]
        issuer_found = parent.subject == info.issuer
        verified = False
        detail = ""
        if issuer_found:
            try:
                child_cert = x509.load_der_x509_certificate(info.der)
                parent_cert = x509.load_der_x509_certificate(parent.der)
                child_cert.verify_directly_issued_by(parent_cert)
                verified = True
            except Exception as exc:
                detail = f"issuer matched but signature failed: {exc}"
        else:
            detail = "presented issuer does not match the next certificate's subject"
        links.append(
            ChainLink(
                subject=info.subject,
                issuer=info.issuer,
                issuer_found=issuer_found,
                signature_verified=verified,
                is_self_signed=False,
                at_trust_boundary=(i + 1 == len(infos)),
                depth_ok=i <= max_depth,
                detail=detail,
            )
        )
    return links


def expiry_status(
    cert: CertificateInfo, capture_time: Optional[datetime]
) -> str:
    if cert.not_before is None or cert.not_after is None or capture_time is None:
        return "unknown"
    if capture_time < cert.not_before:
        return "not_yet_valid"
    if capture_time > cert.not_after:
        return "expired"
    return "valid"


def days_remaining(cert: CertificateInfo, reference: datetime) -> Optional[int]:
    if cert.not_after is None:
        return None
    return int((cert.not_after - reference).total_seconds() // 86400)


def describe_algorithm(alg: str) -> str:
    return {
        "rsa": "RSA",
        "ec": "Elliptic curve",
        "ecdsa": "ECDSA",
        "ed25519": "Ed25519",
        "ed448": "Ed448",
        "dsa": "DSA",
    }.get(alg.lower(), alg)
