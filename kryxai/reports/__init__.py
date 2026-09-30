"""Report signing, verification and rendering.

The three pieces are separate modules because they have separate contracts:
``sign``/``verify`` are about bytes and are the part that must not drift, while
``builder`` is about presentation and is expected to change. What the rest of
the package imports is re-exported here, so ``from kryxai.reports import sign,
verify`` is the supported spelling and the internal layout is free to move.
"""

from .sign import (
    REPORT_AAD,
    SIGNATURE_ALGORITHM,
    SIGNING_KEY_BITS,
    ReportSignature,
    sign,
    signing_payload,
)
from .verify import verify

__all__ = [
    "REPORT_AAD",
    "SIGNATURE_ALGORITHM",
    "SIGNING_KEY_BITS",
    "ReportSignature",
    "sign",
    "signing_payload",
    "verify",
]
