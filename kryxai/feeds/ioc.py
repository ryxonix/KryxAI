"""Indicator-of-compromise feed access.

There is no verified, documented, machine-readable IoC API published by
CERT-In. This module therefore treats every feed as an operator-supplied
artifact, records where it came from, and reports its age. A feed that cannot
be attributed to a source is loaded but flagged ``unverified`` rather than
presented as authoritative.

No network call is made by default.
"""

from __future__ import annotations

import csv
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

DEFAULT_FEED_DIR = Path(__file__).resolve().parents[1] / "data" / "feeds"


@dataclass
class FeedProvenance:
    source: str
    retrieved_at: Optional[str]
    format: str
    verified: bool
    note: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "retrieved_at": self.retrieved_at,
            "format": self.format,
            "verified": self.verified,
            "note": self.note,
        }


@dataclass
class IndicatorSet:
    ips: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    sha256: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    provenance: List[FeedProvenance] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.sha256) + len(self.urls)

    def merge(self, other: "IndicatorSet") -> None:
        self.ips |= other.ips
        self.domains |= other.domains
        self.sha256 |= other.sha256
        self.urls |= other.urls
        self.provenance.extend(other.provenance)

    def match(self, ip: Optional[str], domain: Optional[str]) -> List[Dict[str, str]]:
        hits: List[Dict[str, str]] = []
        if ip and ip in self.ips:
            hits.append({"type": "ip", "value": ip})
        if domain:
            name = domain.lower().rstrip(".")
            if name in self.domains:
                hits.append({"type": "domain", "value": name})
            for d in self.domains:
                if name.endswith("." + d):
                    hits.append({"type": "domain_suffix", "value": d})
        return hits

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": {
                "ips": len(self.ips),
                "domains": len(self.domains),
                "sha256": len(self.sha256),
                "urls": len(self.urls),
                "total": len(self),
            },
            "provenance": [p.to_dict() for p in self.provenance],
        }


def _normalise(kind: str, value: str) -> Optional[tuple]:
    v = value.strip()
    if not v or v.startswith("#"):
        return None
    kind = kind.lower()
    if kind == "ip":
        parts = v.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return ("ips", v)
        return None
    if kind == "domain":
        return ("domains", v.lower().rstrip("."))
    if kind in ("sha256", "hash"):
        h = v.lower()
        if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
            return ("sha256", h)
        return None
    if kind in ("url", "uri"):
        return ("urls", v)
    return None


def load_csv(path: Path) -> IndicatorSet:
    out = IndicatorSet()
    kind = "ip"
    rows = 0
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                if "type=" in stripped:
                    for token in stripped.lstrip("#").split():
                        if token.startswith("type="):
                            kind = token.split("=", 1)[1]
                continue
            norm = _normalise(kind, stripped.split(",")[0])
            if norm:
                getattr(out, norm[0]).add(norm[1])
                rows += 1
    out.provenance.append(
        FeedProvenance(
            source=path.name,
            retrieved_at=None,
            format="csv",
            verified=False,
            note=(
                f"{rows} indicators parsed. Operator-supplied; attribution and "
                "currency are not established by this loader."
            ),
        )
    )
    return out


BUCKETS = {
    "ips": "ip",
    "domains": "domain",
    "sha256": "sha256",
    "urls": "url",
}


def load_json(path: Path) -> IndicatorSet:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = IndicatorSet()
    for bucket, kind in BUCKETS.items():
        for item in data.get(bucket, []) or []:
            norm = _normalise(kind, str(item))
            if norm:
                getattr(out, norm[0]).add(norm[1])
    out.provenance.append(
        FeedProvenance(
            source=path.name,
            retrieved_at=data.get("retrieved_at"),
            format="json",
            verified=bool(data.get("verified", False)),
            note=data.get(
                "note",
                "No verification metadata present in the feed file.",
            ),
        )
    )
    return out


def load_feed_dir(directory: Optional[Path | str] = None) -> IndicatorSet:
    directory = Path(directory) if directory is not None else DEFAULT_FEED_DIR
    combined = IndicatorSet()
    if not directory.exists():
        combined.provenance.append(
            FeedProvenance(
                source=str(directory),
                retrieved_at=None,
                format="none",
                verified=False,
                note=(
                    "No feed directory present. IoC matching is disabled; the scan "
                    "still runs and reports IoC coverage as unavailable."
                ),
            )
        )
        return combined
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() == ".json":
            combined.merge(load_json(path))
        elif path.suffix.lower() in (".csv", ".txt"):
            combined.merge(load_csv(path))
    return combined


def freshness(provenance: Iterable[FeedProvenance], now: Optional[float] = None) -> Dict[str, Any]:
    now = now or time.time()
    ages: List[float] = []
    unknown = 0
    for p in provenance:
        if not p.retrieved_at:
            unknown += 1
            continue
        try:
            from datetime import datetime, timezone

            ts = datetime.fromisoformat(p.retrieved_at.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            ages.append((now - ts.timestamp()) / 86400.0)
        except ValueError:
            unknown += 1
    return {
        "age_days": [round(a, 2) for a in ages],
        "oldest_age_days": round(max(ages), 2) if ages else None,
        "feeds_without_timestamp": unknown,
        "stale": bool(ages) and max(ages) > 30,
    }


def indicator_finding(hits: List[Dict[str, str]], endpoint: str) -> Dict[str, Any]:
    values = ", ".join(f"{h['type']}={h['value']}" for h in hits)
    return {
        "severity": "critical",
        "code": "known_malicious_indicator",
        "deliverable": "D6 eBPF/IoC correlation",
        "confidence": 0.9,
        "endpoint": endpoint,
        "detail": f"matched operator-supplied indicator(s): {values}",
        "evidence": {"hits": hits, "sha256": hashlib.sha256(values.encode()).hexdigest()[:16]},
    }
