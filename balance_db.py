#!/usr/bin/env python3
"""
SQLite balance cache — drop-in replacement for balance_cache.jsonl.

Indexed, crash-safe (WAL mode), concurrent-reader-safe.  Replaces the
linear JSONL scan with indexed lookups — ~1ms per query instead of
scanning 50K lines.

Tables:
    balances  — (chain, address, balance, ts, checked_at, live, settled, raw_json)
    hits      — funded hits for notification tracking
    derivations — cached key→address derivations

Indices on (chain, address), ts, balance for fast filter/sort/search.

All keys and addresses stored COMPLETE — no truncation, ever.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HOME = Path(os.path.expanduser("~"))
DB_PATH = HOME / "balance_cache.db"

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is not None:
        return _conn
    with _lock:
        if _conn is not None:
            return _conn
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
        _init_tables(conn)
        _conn = conn
        return conn


def _init_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS balances (
            chain       TEXT NOT NULL,
            address     TEXT NOT NULL,
            balance     REAL,
            ts          REAL NOT NULL,
            checked_at  TEXT,
            live        INTEGER DEFAULT 0,
            settled     INTEGER DEFAULT 0,
            invalid     INTEGER DEFAULT 0,
            raw_json    TEXT,
            PRIMARY KEY (chain, address)
        );
        CREATE INDEX IF NOT EXISTS idx_balances_ts ON balances(ts);
        CREATE INDEX IF NOT EXISTS idx_balances_balance ON balances(balance);

        CREATE TABLE IF NOT EXISTS hits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            chain       TEXT NOT NULL,
            address     TEXT NOT NULL,
            balance     REAL NOT NULL,
            ts          REAL NOT NULL,
            checked_at  TEXT,
            source      TEXT DEFAULT 'scanner',
            notified    INTEGER DEFAULT 0,
            UNIQUE(chain, address, balance)
        );
        CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts);

        CREATE TABLE IF NOT EXISTS derivations (
            key_type    TEXT NOT NULL,
            key_value   TEXT NOT NULL,
            chain       TEXT NOT NULL,
            address     TEXT NOT NULL,
            derived_at  REAL NOT NULL,
            PRIMARY KEY (key_type, key_value, chain)
        );

        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()


# ── Balance CRUD ─────────────────────────────────────────────────────

def get_balance(chain: str, address: str) -> Optional[Dict[str, Any]]:
    """Return cached balance record or None."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT balance, ts, checked_at, live, settled, invalid, raw_json FROM balances WHERE chain=? AND address=?",
        (chain, address),
    ).fetchone()
    if row is None:
        return None
    rec = {
        "chain": chain,
        "address": address,
        "balance": row[0],
        "ts": row[1],
        "checked_at": row[2],
        "live": bool(row[3]),
        "settled": bool(row[4]),
        "invalid": bool(row[5]),
    }
    if row[6]:
        try:
            extra = json.loads(row[6])
            rec.update(extra)
        except Exception:
            pass
    return rec


def set_balance(chain: str, address: str, rec: Dict[str, Any]) -> None:
    """Insert or update a balance record."""
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO balances
           (chain, address, balance, ts, checked_at, live, settled, invalid, raw_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            chain,
            address,
            rec.get("balance"),
            rec.get("ts", time.time()),
            rec.get("checked_at"),
            int(rec.get("live", False)),
            int(rec.get("settled", False)),
            int(rec.get("invalid", False)),
            json.dumps(rec),
        ),
    )
    conn.commit()


def get_all_balances() -> List[Dict[str, Any]]:
    """Return ALL balance records (for wallet_view compatibility)."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT chain, address, balance, ts, checked_at, live, settled, invalid FROM balances"
    ).fetchall()
    return [
        {
            "chain": r[0],
            "address": r[1],
            "balance": r[2],
            "ts": r[3],
            "checked_at": r[4],
            "live": bool(r[5]),
            "settled": bool(r[6]),
            "invalid": bool(r[7]),
        }
        for r in rows
    ]


def get_balances_dict() -> Dict[Tuple[str, str], Optional[float]]:
    """Return {(chain, address): balance} for fast lookup."""
    conn = _get_conn()
    rows = conn.execute("SELECT chain, address, balance FROM balances").fetchall()
    return {(r[0], r[1]): r[2] for r in rows}


def get_balances_meta() -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Return {(chain, address): meta_dict} with ts, live, settled."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT chain, address, ts, live, settled, checked_at FROM balances"
    ).fetchall()
    result = {}
    for r in rows:
        result[(r[0], r[1])] = {
            "checked_at": r[5],
            "live": bool(r[3]),
            "ts": r[4],
            "settled": bool(r[4]),
        }
    return result


def count_balances() -> int:
    conn = _get_conn()
    return conn.execute("SELECT COUNT(*) FROM balances").fetchone()[0]


def count_nonzero() -> int:
    conn = _get_conn()
    return conn.execute(
        "SELECT COUNT(*) FROM balances WHERE balance IS NOT NULL AND balance > 1e-12"
    ).fetchone()[0]


def count_pending() -> int:
    conn = _get_conn()
    return conn.execute("SELECT COUNT(*) FROM balances WHERE balance IS NULL").fetchone()[0]


# ── Hits (funded wallet tracking) ────────────────────────────────────

def record_hit(chain: str, address: str, balance: float, source: str = "scanner") -> bool:
    """Record a funded hit. Returns True if new (not a duplicate)."""
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO hits (chain, address, balance, ts, checked_at, source) VALUES (?, ?, ?, ?, ?, ?)",
            (
                chain,
                address,
                balance,
                time.time(),
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                source,
            ),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # duplicate


def get_unnotified_hits() -> List[Dict[str, Any]]:
    """Return hits that haven't triggered a notification yet."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, chain, address, balance, ts, checked_at, source FROM hits WHERE notified=0 ORDER BY ts DESC LIMIT 20"
    ).fetchall()
    return [
        {
            "id": r[0],
            "chain": r[1],
            "address": r[2],
            "balance": r[3],
            "ts": r[4],
            "checked_at": r[5],
            "source": r[6],
        }
        for r in rows
    ]


def mark_hits_notified(ids: List[int]) -> None:
    conn = _get_conn()
    conn.executemany("UPDATE hits SET notified=1 WHERE id=?", [(i,) for i in ids])
    conn.commit()


def get_recent_hits(limit: int = 50) -> List[Dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT chain, address, balance, ts, checked_at, source FROM hits ORDER BY ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        {
            "chain": r[0],
            "address": r[1],
            "balance": r[2],
            "ts": r[3],
            "checked_at": r[4],
            "source": r[5],
        }
        for r in rows
    ]


# ── Derivation cache ─────────────────────────────────────────────────

def get_derived(key_type: str, key_value: str) -> Optional[Dict[str, str]]:
    """Return {chain: address} for a cached derivation, or None."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT chain, address FROM derivations WHERE key_type=? AND key_value=?",
        (key_type, key_value),
    ).fetchall()
    if not rows:
        return None
    return {r[0]: r[1] for r in rows}


def set_derived(key_type: str, key_value: str, addrs: Dict[str, str]) -> None:
    """Cache a derivation result."""
    conn = _get_conn()
    now = time.time()
    conn.executemany(
        "INSERT OR REPLACE INTO derivations (key_type, key_value, chain, address, derived_at) VALUES (?, ?, ?, ?, ?)",
        [(key_type, key_value, chain, addr, now) for chain, addr in addrs.items()],
    )
    conn.commit()


# ── Search / filter / sort ──────────────────────────────────────────

def search_addresses(query: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Search addresses by partial match. Query can be any fragment."""
    conn = _get_conn()
    like = f"%{query}%"
    rows = conn.execute(
        """SELECT chain, address, balance, ts, checked_at, live, settled
           FROM balances
           WHERE address LIKE ? OR chain LIKE ?
           ORDER BY COALESCE(balance, 0) DESC
           LIMIT ?""",
        (like, like, limit),
    ).fetchall()
    return [
        {
            "chain": r[0],
            "address": r[1],
            "balance": r[2],
            "ts": r[3],
            "checked_at": r[4],
            "live": bool(r[5]),
            "settled": bool(r[6]),
        }
        for r in rows
    ]


def filter_balances(
    chain: Optional[str] = None,
    min_balance: Optional[float] = None,
    funded_only: bool = False,
    limit: int = 500,
    offset: int = 0,
    sort_by: str = "balance",
) -> Tuple[List[Dict[str, Any]], int]:
    """Filter and sort balances. Returns (rows, total_count)."""
    conn = _get_conn()
    where = []
    params: list = []

    if chain:
        where.append("chain = ?")
        params.append(chain)
    if funded_only or min_balance is not None:
        threshold = max(min_balance or 0, 1e-12 if funded_only else 0)
        where.append("balance IS NOT NULL AND balance > ?")
        params.append(threshold)

    where_clause = ("WHERE " + " AND ".join(where)) if where else ""
    order_map = {
        "balance": "COALESCE(balance, 0) DESC",
        "ts": "ts DESC",
        "chain": "chain ASC, COALESCE(balance, 0) DESC",
    }
    order = order_map.get(sort_by, order_map["balance"])

    count = conn.execute(
        f"SELECT COUNT(*) FROM balances {where_clause}", params
    ).fetchone()[0]

    rows = conn.execute(
        f"SELECT chain, address, balance, ts, checked_at, live, settled FROM balances {where_clause} ORDER BY {order} LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()

    return [
        {
            "chain": r[0],
            "address": r[1],
            "balance": r[2],
            "ts": r[3],
            "checked_at": r[4],
            "live": bool(r[5]),
            "settled": bool(r[6]),
        }
        for r in rows
    ], count


def get_stats() -> Dict[str, Any]:
    """Quick stats for dashboard."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM balances").fetchone()[0]
    nonzero = conn.execute(
        "SELECT COUNT(*) FROM balances WHERE balance IS NOT NULL AND balance > 1e-12"
    ).fetchone()[0]
    pending = conn.execute(
        "SELECT COUNT(*) FROM balances WHERE balance IS NULL"
    ).fetchone()[0]
    last_check = conn.execute(
        "SELECT MAX(ts) FROM balances WHERE live=1"
    ).fetchone()[0]
    hits_count = conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
    chain_totals = {}
    for row in conn.execute(
        "SELECT chain, SUM(balance) FROM balances WHERE balance IS NOT NULL AND balance > 1e-12 GROUP BY chain"
    ).fetchall():
        chain_totals[row[0]] = row[1]

    return {
        "total": total,
        "nonzero": nonzero,
        "pending": pending,
        "hits": hits_count,
        "last_check_ts": last_check,
        "chain_totals": chain_totals,
    }


def import_from_jsonl(jsonl_path: str) -> int:
    """Import existing balance_cache.jsonl into SQLite. Returns count."""
    if not os.path.exists(jsonl_path):
        return 0
    conn = _get_conn()
    count = 0
    with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            chain = rec.get("chain", "?")
            addr = rec.get("address", "")
            if not addr:
                continue
            conn.execute(
                """INSERT OR REPLACE INTO balances
                   (chain, address, balance, ts, checked_at, live, settled, invalid, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    chain,
                    addr,
                    rec.get("balance"),
                    rec.get("ts", time.time()),
                    rec.get("checked_at"),
                    int(rec.get("live", False)),
                    int(rec.get("settled", False)),
                    int(rec.get("invalid", False)),
                    line,
                ),
            )
            count += 1
    conn.commit()
    return count
