"""SQLite-backed scan store and tamper-evident evidence chain.

The chain is deliberately simple: each block commits to its predecessor's hash
and to its own payload, and every block records the proof-of-work difficulty
that was in force *when that block was created*. Keeping difficulty per block is
what makes verification of a historical chain meaningful; a single mutable
global difficulty cannot verify a chain whose rules changed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS_PREV = "0" * 64
DEFAULT_DIFFICULTY = 4
DIFFICULTY_REDUCTION_AFTER = 16
DIFFICULTY_MIN = 2


class ChainError(Exception):
    pass


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def block_hash(index: int, prev_hash: str, payload: Dict[str, Any]) -> str:
    body = f"{index}:{prev_hash}:{canonical_json(payload)}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def proof_of_work(prev_hash: str, index: int, difficulty: int) -> int:
    """Search for a nonce whose hash of `prev:index:nonce` leads with `difficulty` zeros.

    The nonce is the *searched value*, not the winning hash. `verify_chain`
    reconstructs the hash from the stored nonce, so storing the digest here
    would make every block unverifiable.
    """
    nonce = 0
    target = "0" * difficulty
    while True:
        candidate = hashlib.sha256(f"{prev_hash}:{index}:{nonce}".encode()).hexdigest()
        if candidate.startswith(target):
            return nonce
        nonce += 1


def pow_hash(prev_hash: str, index: int, nonce: int) -> str:
    return hashlib.sha256(f"{prev_hash}:{index}:{nonce}".encode()).hexdigest()


@dataclass
class Block:
    index: int
    prev_hash: str
    payload: Dict[str, Any]
    block_hash: str
    nonce: int
    difficulty: int
    created_at: float
    anchored: bool = False
    anchor_tx: Optional[str] = None
    anchor_provider: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
            "block_hash": self.block_hash,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "created_at": self.created_at,
            "anchored": self.anchored,
            "anchor_tx": self.anchor_tx,
            "anchor_provider": self.anchor_provider,
        }


class Store:
    """Thread-safe SQLite store. One connection per call, WAL journalling."""

    def __init__(self, path: os.PathLike | str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._shared: Optional[sqlite3.Connection] = None
        if self.path == ":memory:":
            self._shared = self._connect()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        if self.path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _conn(self) -> sqlite3.Connection:
        return self._shared if self._shared is not None else self._connect()

    def _release(self, conn: sqlite3.Connection) -> None:
        if self._shared is None:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._conn()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id      TEXT PRIMARY KEY,
                        source_path  TEXT NOT NULL,
                        source_sha256 TEXT NOT NULL,
                        created_at   REAL NOT NULL,
                        packet_count INTEGER NOT NULL,
                        summary_json TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS findings (
                        finding_id  TEXT PRIMARY KEY,
                        scan_id     TEXT NOT NULL REFERENCES scans(scan_id),
                        code        TEXT NOT NULL,
                        severity    TEXT NOT NULL,
                        title       TEXT NOT NULL,
                        title_hi    TEXT NOT NULL,
                        endpoint    TEXT,
                        detail_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_findings_scan
                        ON findings(scan_id, severity);

                    CREATE TABLE IF NOT EXISTS certificates (
                        sha256     TEXT PRIMARY KEY,
                        scan_id    TEXT NOT NULL REFERENCES scans(scan_id),
                        subject    TEXT NOT NULL,
                        issuer     TEXT NOT NULL,
                        not_before TEXT,
                        not_after  TEXT,
                        key_alg    TEXT NOT NULL,
                        key_bits   INTEGER,
                        sig_alg    TEXT NOT NULL,
                        der        BLOB NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS blocks (
                        block_index INTEGER PRIMARY KEY,
                        prev_hash   TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        block_hash  TEXT NOT NULL UNIQUE,
                        nonce       INTEGER NOT NULL,
                        difficulty  INTEGER NOT NULL,
                        created_at  REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS block_anchors (
                        block_index  INTEGER NOT NULL REFERENCES blocks(block_index),
                        provider     TEXT NOT NULL,
                        tx_ref       TEXT NOT NULL,
                        anchored_at  REAL NOT NULL,
                        status       TEXT NOT NULL,
                        PRIMARY KEY (block_index, provider, tx_ref)
                    );
                    """
                )
                conn.commit()
            finally:
                self._release(conn)

    # ── chain ────────────────────────────────────────────────────────────

    def head(self) -> Optional[Block]:
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT * FROM blocks ORDER BY block_index DESC LIMIT 1"
                ).fetchone()
            finally:
                self._release(conn)
        return self._row_to_block(row) if row else None

    @staticmethod
    def _row_to_block(row: sqlite3.Row) -> Block:
        return Block(
            index=row["block_index"],
            prev_hash=row["prev_hash"],
            payload=json.loads(row["payload_json"]),
            block_hash=row["block_hash"],
            nonce=int(row["nonce"]),
            difficulty=row["difficulty"],
            created_at=row["created_at"],
        )

    def current_difficulty(self) -> int:
        head = self.head()
        if head is None:
            return DEFAULT_DIFFICULTY
        upcoming = head.index + 1
        if (upcoming + 1) % DIFFICULTY_REDUCTION_AFTER == 0:
            return max(DIFFICULTY_MIN, head.difficulty - 1)
        return head.difficulty

    def append(self, payload: Dict[str, Any], difficulty: Optional[int] = None) -> Block:
        """Append one block, computing its proof of work under the lock.

        Holding the lock across the read of the head and the write of the new
        block is what prevents two concurrent scans from both claiming the same
        predecessor and forking the chain.
        """
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT * FROM blocks ORDER BY block_index DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    index = 0
                    prev = GENESIS_PREV
                    diff = difficulty if difficulty is not None else DEFAULT_DIFFICULTY
                else:
                    head = self._row_to_block(row)
                    index = head.index + 1
                    prev = head.block_hash
                    if difficulty is not None:
                        diff = difficulty
                    elif (index + 1) % DIFFICULTY_REDUCTION_AFTER == 0:
                        diff = max(DIFFICULTY_MIN, head.difficulty - 1)
                    else:
                        diff = head.difficulty
                nonce = proof_of_work(prev, index, diff)
                digest = block_hash(index, prev, payload)
                created = time.time()
                conn.execute(
                    "INSERT INTO blocks (block_index, prev_hash, payload_json,"
                    " block_hash, nonce, difficulty, created_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (index, prev, canonical_json(payload), digest, nonce, diff, created),
                )
                conn.commit()
            finally:
                self._release(conn)
        return Block(
            index=index,
            prev_hash=prev,
            payload=payload,
            block_hash=digest,
            nonce=nonce,
            difficulty=diff,
            created_at=created,
        )

    def record_anchor(
        self, block_index: int, provider: str, tx_ref: str, status: str = "confirmed"
    ) -> None:
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO block_anchors"
                    " (block_index, provider, tx_ref, anchored_at, status)"
                    " VALUES (?,?,?,?,?)",
                    (block_index, provider, tx_ref, time.time(), status),
                )
                conn.commit()
            finally:
                self._release(conn)

    def anchors(self, block_index: int) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    "SELECT provider, tx_ref, anchored_at, status FROM block_anchors"
                    " WHERE block_index=? ORDER BY anchored_at",
                    (block_index,),
                ).fetchall()
            finally:
                self._release(conn)
        return [dict(r) for r in rows]

    def chain(self) -> List[Block]:
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute("SELECT * FROM blocks ORDER BY block_index").fetchall()
            finally:
                self._release(conn)
        out = []
        for row in rows:
            b = self._row_to_block(row)
            for a in self.anchors(b.index):
                b.anchored = True
                b.anchor_tx = a["tx_ref"]
                b.anchor_provider = a["provider"]
                break
            out.append(b)
        return out

    def verify_chain(self) -> Dict[str, Any]:
        """Re-verify every link, each under the difficulty recorded on its block."""
        blocks = self.chain()
        if not blocks:
            return {"ok": True, "blocks": 0, "broken_at": None, "details": []}
        details: List[Dict[str, Any]] = []
        broken_at: Optional[int] = None
        prev = GENESIS_PREV
        for b in blocks:
            expected = block_hash(b.index, prev, b.payload)
            pow_ok = pow_hash(prev, b.index, b.nonce).startswith("0" * b.difficulty)
            entry = {
                "index": b.index,
                "hash_ok": expected == b.block_hash,
                "pow_ok": pow_ok,
                "difficulty": b.difficulty,
                "anchored": b.anchored,
            }
            details.append(entry)
            if b.prev_hash != prev or not entry["hash_ok"] or not pow_ok:
                broken_at = b.index
                prev = b.block_hash
                break
            prev = b.block_hash
        return {
            "ok": broken_at is None,
            "blocks": len(blocks),
            "broken_at": broken_at,
            "details": details,
        }

    # ── scans and findings ───────────────────────────────────────────────

    def save_scan(
        self,
        scan_id: str,
        source_path: str,
        source_sha256: str,
        packet_count: int,
        summary: Dict[str, Any],
    ) -> None:
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?)",
                    (scan_id, source_path, source_sha256, time.time(), packet_count,
                     canonical_json(summary)),
                )
                conn.commit()
            finally:
                self._release(conn)

    def save_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        with self._lock:
            conn = self._conn()
            try:
                for f in findings:
                    conn.execute(
                        "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?)",
                        (
                            f["finding_id"],
                            scan_id,
                            f["code"],
                            f["severity"],
                            f["title"],
                            f.get("title_hi", ""),
                            f.get("endpoint", ""),
                            canonical_json(f),
                        ),
                    )
                conn.commit()
            finally:
                self._release(conn)

    def save_certificates(self, scan_id: str, certs: List[Dict[str, Any]]) -> None:
        with self._lock:
            conn = self._conn()
            try:
                for c in certs:
                    conn.execute(
                        "INSERT OR REPLACE INTO certificates VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            c["sha256_fingerprint"],
                            scan_id,
                            c["subject"],
                            c["issuer"],
                            c.get("not_before"),
                            c.get("not_after"),
                            c["public_key_algorithm"],
                            c.get("public_key_bits"),
                            c["signature_algorithm"],
                            c["der"],
                        ),
                    )
                conn.commit()
            finally:
                self._release(conn)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT * FROM scans WHERE scan_id=?", (scan_id,)
                ).fetchone()
                if row is None:
                    return None
                out = dict(row)
                out["summary"] = json.loads(out.pop("summary_json"))
                out["findings"] = [
                    json.loads(r["detail_json"])
                    for r in conn.execute(
                        "SELECT detail_json FROM findings WHERE scan_id=?"
                        " ORDER BY severity, code",
                        (scan_id,),
                    ).fetchall()
                ]
                return out
            finally:
                self._release(conn)

    def close(self) -> None:
        with self._lock:
            if self._shared is not None:
                self._shared.close()
                self._shared = None
