"""Detached RSA-3072 signatures over a scan report.

A signature here says one narrow thing: the bytes of this report, in this
canonical form, were produced under a key the operator holds, and nothing has
altered them since. It does not say the analysis was correct, and it is not a
digital signature in the PKI sense - there is no certificate authority here,
just a locally generated key whose fingerprint is printed on the report so a
reader can tell whose key signed it.

Three choices are load-bearing:

* **Canonical JSON.** The signed bytes are produced by sorted keys and fixed
  separators, so the same report always yields the same digest regardless of
  dict insertion order. Without this, a signature would depend on Python's
  ordering rather than on the document.
* **The AAD is inside the signature's domain.** ``REPORT_AAD`` is prefixed to
  the signed bytes so a signature minted for some other KryxAI artefact cannot
  be replayed onto a report, and vice versa.
* **The signature covers itself not at all.** ``signature`` and
  ``signature_verification`` are excluded from the payload, so appending a
  signature to an already-signed report does not invalidate the original one.
  That is what makes ``write`` able to sign, then record its own verification
  verdict, and still have the file on disk verify against its own contents.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from kryxai import CHAIN_ID

# Report signing is deliberately fixed: the AAD from config, the algorithm and
# the key size are not runtime knobs, because a knob here would let an operator
# weaken the signature and still produce a file that claims to be signed.
REPORT_AAD = b"kryxai-report-v1"
SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"
SIGNING_KEY_BITS = 3072

# Keys that describe the signature rather than the findings. Excluded from the
# signed payload so that signing and recording the verification verdict are not
# self-defeating.
_ENVELOPE_KEYS = ("signature", "signature_verification")


@dataclass(frozen=True)
class ReportSignature:
    """A detached signature over one report.

    Field order is the serialisation order and is also the positional order the
    test-suite and the anchor document rely on, so it is declared explicitly
    rather than left to chance.
    """

    algorithm: str
    chain_id: str
    aad: str
    value: str
    created_at: str
    public_key_fingerprint: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "ReportSignature":
        return cls(
            algorithm=str(raw.get("algorithm", "")),
            chain_id=str(raw.get("chain_id", "")),
            aad=str(raw.get("aad", "")),
            value=str(raw.get("value", "")),
            created_at=str(raw.get("created_at", "")),
            public_key_fingerprint=str(raw.get("public_key_fingerprint", "")),
        )


def signing_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    """The part of a report a signature actually covers."""
    return {k: v for k, v in report.items() if k not in _ENVELOPE_KEYS}


def canonical_bytes(payload: Any) -> bytes:
    """Stable bytes for hashing and signing.

    Mirrors :func:`kryxai.anchor.canonical_json` so a report and its Fabric
    anchor digest the same document rather than two subtly different ones.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def fingerprint(public_key: Any) -> str:
    """16 hex characters identifying the signing key.

    Truncated deliberately: the anchor record stores this in a fixed-width
    ledger field, and a full digest buys nothing a reader can act on.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def sign(
    report: Dict[str, Any],
    private_key: Any,
    chain_id: str = CHAIN_ID,
    aad: bytes = REPORT_AAD,
) -> ReportSignature:
    """Sign the report's canonical payload under ``private_key``."""
    signed_bytes = bytes(aad) + canonical_bytes(signing_payload(report))
    raw = private_key.sign(
        signed_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return ReportSignature(
        algorithm=SIGNATURE_ALGORITHM,
        chain_id=chain_id,
        aad=aad.decode("ascii", "replace"),
        value=base64.b64encode(raw).decode("ascii"),
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        public_key_fingerprint=fingerprint(private_key.public_key()),
    )
