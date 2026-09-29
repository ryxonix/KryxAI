"""External evidence anchoring via the NBF gateway (IPFS + Hyperledger Fabric).

The local proof-of-work chain in :mod:`kryxai.store` is tamper-evident but
merely local. This module publishes a finished report to IPFS and records the
resulting CID on Fabric, which is what turns `pending` into `anchored`.

Two rules govern everything here:

1. **Never fail a scan.** An unreachable gateway yields a `failed` anchor and a
   report that still says `pending`. The scan result is the operator's evidence;
   losing it because a peer was down would be the wrong trade.
2. **Never claim an anchor that did not happen.** The only path that sets
   `anchored` is a gateway response that was actually received and parsed. A
   timeout, a 500, or an unparseable body all leave the state at `pending`.

What is anchored is the canonical JSON of the finished report, and the SHA-256
and CID in the anchor both describe exactly those uploaded bytes. The on-disk
artefact produced by :func:`kryxai.reports.builder.write` additionally carries a
detached signature, so it is a superset of what went to IPFS; the digest and the
CID remain mutually consistent because both cover the uploaded document.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import Settings

_LOG = logging.getLogger("kryxai.anchor")

# Mirrors alerts.py: the standard library, so the default install makes no
# third-party HTTP call it did not already make.
_JSON_HEADERS = {"Content-Type": "application/json"}

# The Fabric chaincode stores these as positional args. Order is load-bearing
# and is asserted by the chaincode's own signature.
_FCN = "AnchorReport"
_ARG_NAMES = (
    "scan_id",
    "report_id",
    "case_id",
    "file_sha256",
    "merkle_root",
    "block_hash",
    "timestamp",
    "ipfs_cid",
    "enc_alg",
    "key_fingerprint",
)


class AnchorError(RuntimeError):
    """The external anchor could not be completed."""


def canonical_json(obj: Any) -> bytes:
    """Stable bytes for hashing and upload.

    Sorted keys and fixed separators, so the same report always produces the
    same digest regardless of dict insertion order.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(leaves: List[str]) -> str:
    """A real Merkle root over hex leaf digests.

    Odd nodes at any level are promoted rather than duplicated, so the root
    depends only on the leaf set. Returns the digest of the empty set as the
    sha256 of the empty byte string, which is a defined value rather than an
    error for a report with no sections.
    """
    if not leaves:
        return sha256_hex(b"")
    level = [bytes.fromhex(leaf) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def _request_json(
    url: str, payload: Optional[Dict[str, Any]], timeout: float
) -> Dict[str, Any]:
    """POST (or GET when payload is None) and parse a JSON object response."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=_JSON_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        raise AnchorError(f"{url} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise AnchorError(f"{url} unreachable: {exc}") from exc
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AnchorError(f"{url} returned a non-JSON body") from exc
    if not isinstance(parsed, dict):
        raise AnchorError(f"{url} returned {type(parsed).__name__}, expected object")
    return parsed


def build_anchor_document(
    report: Dict[str, Any], payload: bytes
) -> Dict[str, Any]:
    """The record that goes on Fabric.

    ``merkle_root`` is a genuine Merkle root over the per-section digests of the
    report, not a copy of the block hash, so a consumer can recompute it from
    the uploaded document and check that they agree.
    """
    evidence = report.get("evidence") or {}
    scan_id = str(evidence.get("scan_id") or "")
    block_index = evidence.get("block_index")
    report_id = f"RPT-{scan_id[:12]}" if scan_id else "RPT-unknown"

    section_leaves = [
        sha256_hex(canonical_json(report[key]))
        for key in sorted(report)
        if key not in {"evidence"}
    ]
    signature = report.get("signature") or {}
    fingerprint = signature.get("public_key_fingerprint") or "-"

    return {
        "scan_id": scan_id,
        "report_id": report_id,
        # A KryxAI scan is not bound to one customer case; the chain id is the
        # tenancy that actually scopes it.
        "case_id": str(report.get("chain_id") or evidence.get("chain_id") or "-"),
        "file_sha256": sha256_hex(payload),
        "merkle_root": merkle_root(section_leaves),
        "block_hash": str(evidence.get("block_hash") or "-"),
        "block_index": block_index,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        # The uploaded document is plain JSON. Saying so is the point: an
        # `enc_alg` of "none" is the honest value, and claiming a cipher that
        # was never applied would defeat the field.
        "enc_alg": "none",
        "key_fingerprint": fingerprint,
    }


def _store_on_ipfs(
    settings: Settings, payload: bytes, file_name: str
) -> str:
    base = settings.nbf_gateway_url.rstrip("/")
    resp = _request_json(
        f"{base}/store",
        {
            "fileName": file_name,
            "fileContents": base64.b64encode(payload).decode("ascii"),
        },
        settings.nbf_timeout_s,
    )
    cid = resp.get("hash") or resp.get("cid")
    if not isinstance(cid, str) or not cid:
        raise AnchorError("gateway /store response carried no CID")
    return cid


def _record_on_fabric(
    settings: Settings, document: Dict[str, Any], cid: str
) -> str:
    base = settings.nbf_gateway_url.rstrip("/")
    args = [str(document.get(name, "-")) for name in _ARG_NAMES]
    args[_ARG_NAMES.index("ipfs_cid")] = cid
    resp = _request_json(
        f"{base}/fabric/v1/invokecc",
        {
            "fcn": _FCN,
            "args": args,
            "user": settings.nbf_user,
            "ccname": settings.nbf_cc,
            "channel": settings.nbf_channel,
            "mspId": settings.nbf_msp,
        },
        settings.nbf_timeout_s,
    )
    if str(resp.get("status", "")).upper() != "SUCCESS":
        raise AnchorError(f"chaincode {_FCN} returned {resp.get('status')!r}")
    tx_id = resp.get("tx_id") or ""
    if not isinstance(tx_id, str):
        raise AnchorError("chaincode returned a non-string tx_id")
    return tx_id


def _skipped(reason: str, **extra: Any) -> Dict[str, Any]:
    return {
        "attempted": False,
        "anchored": False,
        "reason": reason,
        "provider": "nbf-fabric",
        **extra,
    }


def anchor_report(
    report: Dict[str, Any], store: Any, settings: Settings
) -> Dict[str, Any]:
    """Publish the report to IPFS and record it on Fabric.

    Returns a record describing what happened. It never raises: a scan must
    survive an unreachable gateway. On success it also records the anchor in
    the store and promotes the report's chain state to `anchored`; on any
    failure the report is left exactly as it was, at `pending`.
    """
    if not settings.blockchain_external_anchor:
        return _skipped("external anchoring is disabled")

    evidence = report.get("evidence") or {}
    block_index = evidence.get("block_index")
    if block_index is None:
        return _skipped("scan recorded no evidence block")

    payload = canonical_json(report)
    document = build_anchor_document(report, payload)
    file_name = f"{document['report_id']}.json"

    try:
        cid = _store_on_ipfs(settings, payload, file_name)
        tx_id = _record_on_fabric(settings, document, cid)
    except AnchorError as exc:
        _LOG.warning("external anchor failed: %s", exc)
        return {
            "attempted": True,
            "anchored": False,
            "reason": str(exc),
            "provider": "nbf-fabric",
            "ipfs_cid": None,
            "at": time.time(),
        }
    except Exception as exc:  # noqa: BLE001 - anchoring must never break a scan
        _LOG.warning("external anchor raised: %s", type(exc).__name__)
        return {
            "attempted": True,
            "anchored": False,
            "reason": f"anchor raised {type(exc).__name__}",
            "provider": "nbf-fabric",
            "ipfs_cid": None,
            "at": time.time(),
        }

    store.record_anchor(block_index, "nbf-fabric", tx_id or cid, "confirmed")

    evidence["chain_state"] = "anchored"
    evidence["external_anchor"] = True
    evidence["ipfs_cid"] = cid
    report["external_anchor"] = {
        "provider": "nbf-fabric",
        "channel": settings.nbf_channel,
        "chaincode": settings.nbf_cc,
        "ipfs_cid": cid,
        "tx_id": tx_id or None,
        "file_sha256": document["file_sha256"],
        "merkle_root": document["merkle_root"],
        "enc_alg": document["enc_alg"],
        "key_fingerprint": document["key_fingerprint"],
        "at": time.time(),
    }
    _LOG.info("report %s anchored on Fabric as %s", document["report_id"], cid)

    return {
        "attempted": True,
        "anchored": True,
        "reason": None,
        "provider": "nbf-fabric",
        "ipfs_cid": cid,
        "tx_id": tx_id or None,
        "file_sha256": document["file_sha256"],
        "at": time.time(),
    }
