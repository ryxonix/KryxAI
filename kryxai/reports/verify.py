"""Verification of a detached report signature.

Every rejection returns a reason rather than a bare ``False``. A signature
check that fails silently is indistinguishable from a report nobody signed, and
an auditor reading "invalid" with no explanation has to assume the worst thing
they can think of. The reasons are therefore specific enough to act on: the
wrong chain id, the wrong AAD, an unrecognised algorithm, a key that does not
match the fingerprint printed on the report, or bytes that genuinely do not
match.

The function never raises for a malformed signature. A corrupt or
hand-edited signature is a *finding about a document*, not an error in the
tool reading it, so it comes back as ``(False, reason)``.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from kryxai import CHAIN_ID

from .sign import (
    REPORT_AAD,
    SIGNATURE_ALGORITHM,
    ReportSignature,
    canonical_bytes,
    fingerprint,
    signing_payload,
)


def verify(
    report: Any,
    signature: Any,
    public_key: Any,
    expected_chain_id: Optional[str] = None,
) -> Tuple[bool, str]:
    """Check ``signature`` against ``report`` and ``public_key``.

    Returns ``(ok, reason)``. On success the reason names what was verified, so
    a caller that records the verdict records a positive claim rather than an
    absence of complaint.
    """
    if not isinstance(report, dict):
        return False, "report is not a JSON object, so there is nothing to verify"

    if signature is None:
        return False, "no signature is present on this report"
    if isinstance(signature, dict):
        signature = ReportSignature.from_dict(signature)
    if not isinstance(signature, ReportSignature):
        return False, f"signature is a {type(signature).__name__}, not a ReportSignature"

    # The chain id and AAD are checked before the cryptography, so a signature
    # minted for a different chain is reported as exactly that rather than as a
    # generic failure. Both are cheap and both are the likelier operator error.
    chain_id = expected_chain_id or str(report.get("chain_id") or CHAIN_ID)
    if signature.chain_id != chain_id:
        return (
            False,
            f"chain id mismatch: the signature names {signature.chain_id!r} but "
            f"this report belongs to {chain_id!r}",
        )

    if signature.aad != REPORT_AAD.decode("ascii"):
        return (
            False,
            f"AAD mismatch: the signature was minted for {signature.aad!r}, not "
            f"for {REPORT_AAD.decode('ascii')!r}, so it covers a different artefact",
        )

    if signature.algorithm != SIGNATURE_ALGORITHM:
        return (
            False,
            f"algorithm mismatch: {signature.algorithm!r} is not the "
            f"{SIGNATURE_ALGORITHM!r} this build produces",
        )

    try:
        actual_fingerprint = fingerprint(public_key)
    except Exception as exc:  # noqa: BLE001 - an unusable key is a verdict, not a crash
        return False, f"public key could not be read: {type(exc).__name__}"

    if signature.public_key_fingerprint != actual_fingerprint:
        return (
            False,
            f"signing key mismatch: the report is fingerprinted "
            f"{signature.public_key_fingerprint} but the supplied key is "
            f"{actual_fingerprint}",
        )

    try:
        raw = base64.b64decode(signature.value, validate=True)
    except (binascii.Error, ValueError):
        return False, "signature value is not valid base64"

    signed_bytes = REPORT_AAD + canonical_bytes(signing_payload(report))
    try:
        public_key.verify(
            raw,
            signed_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return (
            False,
            "signature does not match the report contents: the document was "
            "altered after it was signed",
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"signature could not be checked: {type(exc).__name__}: {exc}"

    return (
        True,
        f"valid {signature.algorithm} signature over chain {signature.chain_id}, "
        f"key {signature.public_key_fingerprint}, signed {signature.created_at}",
    )
