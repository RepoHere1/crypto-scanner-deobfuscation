#!/usr/bin/env python3
"""Production learn crawl — expand from REAL wins + live GitHub neighbors.

No longer re-ingests placeholder target files as "discovery".
Pipeline:
  1) Read outcome-scored winners from target_intelligence / scanner memory
  2) Expand same GitHub org + recent repos (live API)
  3) Mine trufflehog for real github URLs only (fake-filtered)
  4) Append LEARNED block to paste_box (deduped, capped, scored)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import requests
except ImportError:
    raise SystemExit("[!] requests required")

HOME = Path.home()
PASTE_BOX = HOME / "paste_box.txt"
LEARN_FILE = HOME / "learn_findings.jsonl"
TRUFFLEHOG_RESULTS = HOME / ".trufflehog_results.jsonl"
TRUFFLEHOG_MASS = HOME / ".trufflehog_mass_results.jsonl"
HIGH_CONFIDENCE = HOME / "high_confidence_hits.jsonl"
MEMORY_FILE = HOME / "crypto_scanner_memory.jsonl"
OUTCOMES_FILE = HOME / ".scan_outcomes.jsonl"
HOT_FILE = HOME / ".hot_targets.json"

BEGIN_LEARN_MARKER = "# === BEGIN LEARNED TARGETS ==="
END_LEARN_MARKER = "# === END LEARNED TARGETS ==="
BEGIN_GEN_MARKER = "# === BEGIN GENERATED TARGETS ==="
END_GEN_MARKER = "# === END GENERATED TARGETS ==="

MAX_LEARN_APPEND = int(os.environ.get("LEARN_APPEND_CAP", "200"))

FAKE_RE = re.compile(
    r"placeholder|example\.com|my-bucket|myuser|myimage|localhost|127\.0\.0\.1|"
    r"your[-_]|xxx|dummy|public-dataset-placeholder|public-bucket-placeholder|"
    r"jenkins\.example|es-\d+\.example|logs-\d+\.example",
    re.I,
)
GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)"
)
GIST_RE = re.compile(r"https?://gist\.github\.com/([A-Za-z0-9_.-]+)/([a-f0-9]+)")
GITLAB_URL_RE = re.compile(
    r"https?://(?:www\.)?gitlab\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)

stats = {
    "sources": 0,
    "new_urls": 0,
    "expanded_orgs": 0,
    "from_outcomes": 0,
    "from_trufflehog": 0,
    "from_live": 0,
    "appended": 0,
    "dropped_fake": 0,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_fake(uri: str) -> bool:
    if not uri or not str(uri).strip() or str(uri).strip().startswith("#"):
        return True
    return bool(FAKE_RE.search(str(uri)))


def load_token() -> str:
    env = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if env.strip():
        return env.strip()
    p = HOME / ".github_token"
    if p.exists():
        return p.read_text(encoding="utf-8", errors="ignore").strip().splitlines()[0].strip()
    return ""


def norm_gh(owner: str, repo: str) -> Optional[str]:
    owner = (owner or "").strip()
    repo = (repo or "").strip().removesuffix(".git")
    if not owner or not repo:
        return None
    if owner.lower() in {"about", "settings", "marketplace", "search", "topics", "orgs"}:
        return None
    u = f"https://github.com/{owner}/{repo}"
    return None if is_fake(u) else u


def extract_urls(text: str) -> List[str]:
    out = []
    if not text:
        return out
    for m in GITHUB_URL_RE.finditer(text):
        u = norm_gh(m.group(1), m.group(2))
        if u:
            out.append(u)
    for m in GIST_RE.finditer(text):
        u = m.group(0).split("#")[0]
        if not is_fake(u):
            out.append(u)
    for m in GITLAB_URL_RE.finditer(text):
        u = f"https://gitlab.com/{m.group(1)}/{m.group(2).removesuffix('.git')}"
        if not is_fake(u):
            out.append(u)
    return out


def load_existing_paste_uris() -> Set[str]:
    seen: Set[str] = set()
    if not PASTE_BOX.exists():
        return seen
    for ln in PASTE_BOX.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if is_fake(s):
            stats["dropped_fake"] += 1
            continue
        seen.add(s.rstrip("/"))
        for u in extract_urls(s):
            seen.add(u)
    return seen



def load_atlas_boost():
    """Repos + orgs from success atlas (funded-balance attributed)."""
    uris, orgs = [], set()
    aq = HOME / ".adaptive_queries.json"
    boost = HOME / ".learn_boost_targets.txt"
    atlas = HOME / ".success_atlas.json"
    try:
        if aq.exists():
            data = json.loads(aq.read_text(encoding="utf-8"))
            for r in data.get("boost_repos") or []:
                if r and not is_fake(r):
                    uris.append(r)
            for o in data.get("boost_orgs") or []:
                if o:
                    orgs.add(str(o))
        if boost.exists():
            for ln in boost.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = ln.strip()
                if s and not s.startswith("#") and not is_fake(s):
                    uris.append(s)
                    m = GITHUB_URL_RE.search(s)
                    if m:
                        orgs.add(m.group(1))
        if atlas.exists():
            data = json.loads(atlas.read_text(encoding="utf-8"))
            for o, _c in data.get("top_orgs") or []:
                if o:
                    orgs.add(str(o))
            for fam in data.get("path_families") or []:
                if fam and str(fam).replace("-", "").isalnum():
                    orgs.add(str(fam))
    except Exception as e:
        print(f"  [adapt] atlas boost load: {e}")
    return uris, orgs


def winners_from_outcomes() -> Tuple[List[str], Set[str]]:
    """Return (uris_to_boost, orgs_to_expand)."""
    uris: List[str] = []
    orgs: Set[str] = set()
    # outcomes log
    if OUTCOMES_FILE.exists():
        for line in OUTCOMES_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-2000:]:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("has_key") or rec.get("has_balance"):
                uri = rec.get("uri") or ""
                if uri and not is_fake(uri):
                    uris.append(uri)
                    m = GITHUB_URL_RE.search(uri)
                    if m:
                        orgs.add(m.group(1))
                        stats["from_outcomes"] += 1
    # memory / high conf
    for path in (MEMORY_FILE, HIGH_CONFIDENCE):
        if not path.exists():
            continue
        try:
            data = path.read_bytes()
            if len(data) > 4_000_000:
                data = data[-4_000_000:]
            for line in data.decode("utf-8", errors="ignore").splitlines()[-3000:]:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                findings = rec.get("findings") or {}
                wallet = findings.get("wallet") or {}
                has_key = bool(
                    wallet.get("wifs") or wallet.get("hex_keys") or wallet.get("seed_phrases")
                    or findings.get("wif") or findings.get("hex_key") or findings.get("seed_phrase")
                )
                if not has_key:
                    continue
                src = rec.get("source_uri") or rec.get("source") or ""
                for u in extract_urls(str(src)) + extract_urls(str(rec.get("source_line") or "")):
                    uris.append(u)
                    m = GITHUB_URL_RE.search(u)
                    if m:
                        orgs.add(m.group(1))
                if src and str(src).startswith("http") and not is_fake(str(src)):
                    uris.append(str(src).split("#")[0])
        except Exception:
            continue
    return uris, orgs


def mine_trufflehog_urls(limit_lines: int = 4000) -> List[str]:
    found: List[str] = []
    for path in (TRUFFLEHOG_RESULTS, TRUFFLEHOG_MASS, HIGH_CONFIDENCE):
        if not path.exists():
            continue
        stats["sources"] += 1
        try:
            data = path.read_bytes()
            if len(data) > 6_000_000:
                data = data[-6_000_000:]
            lines = data.decode("utf-8", errors="ignore").splitlines()[-limit_lines:]
        except Exception:
            continue
        for line in lines:
            try:
                rec = json.loads(line)
                blob = json.dumps(rec)[:5000]
            except Exception:
                blob = line[:2000]
            for u in extract_urls(blob):
                found.append(u)
                stats["from_trufflehog"] += 1
    return found


def gh_get(url: str, token: str, params: Optional[dict] = None):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "RepoHere1-LearnCrawl/3.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.get(url, headers=headers, params=params or {}, timeout=20)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def expand_orgs_live(orgs: Set[str], token: str, per_org: int = 12) -> List[str]:
    out: List[str] = []
    if not token:
        print("  [!] No GITHUB_TOKEN — cannot live-expand orgs")
        return out
    for org in sorted(orgs)[:20]:
        print(f"  [live] expand org {org}")
        data = gh_get(
            f"https://api.github.com/users/{org}/repos",
            token,
            params={"sort": "pushed", "per_page": per_org, "type": "all"},
        )
        if not isinstance(data, list):
            # try org endpoint
            data = gh_get(
                f"https://api.github.com/orgs/{org}/repos",
                token,
                params={"sort": "pushed", "per_page": per_org, "type": "all"},
            )
        if isinstance(data, list):
            stats["expanded_orgs"] += 1
            for repo in data:
                html = repo.get("html_url") or ""
                if html and not is_fake(html):
                    out.append(html)
                    stats["from_live"] += 1
        time.sleep(0.8)
    return out


def live_neighbor_search(token: str, orgs: Set[str]) -> List[str]:
    """Search code in winning orgs for env/wallet files."""
    out: List[str] = []
    if not token or not orgs:
        return out
    for org in sorted(orgs)[:8]:
        q = f"org:{org} filename:.env"
        print(f"  [live] code search {q}")
        data = gh_get(
            "https://api.github.com/search/code",
            token,
            params={"q": q, "per_page": 15},
        )
        if not data:
            time.sleep(2)
            continue
        for it in data.get("items") or []:
            repo = it.get("repository") or {}
            html = repo.get("html_url") or ""
            if html and not is_fake(html):
                out.append(html)
                stats["from_live"] += 1
        time.sleep(2)
    return out


def append_learned(new_uris: List[str], existing: Set[str]) -> int:
    filtered = []
    seen = set(existing)
    for u in new_uris:
        u = u.strip().rstrip("/")
        if not u or is_fake(u) or u in seen:
            if u and is_fake(u):
                stats["dropped_fake"] += 1
            continue
        seen.add(u)
        filtered.append(u)
        if len(filtered) >= MAX_LEARN_APPEND:
            break
    if not filtered:
        return 0

    paste = PASTE_BOX.read_text(encoding="utf-8", errors="ignore") if PASTE_BOX.exists() else ""

    # Remove old LEARNED block if present
    if BEGIN_LEARN_MARKER in paste and END_LEARN_MARKER in paste:
        pre = paste.split(BEGIN_LEARN_MARKER)[0]
        post = paste.split(END_LEARN_MARKER, 1)[1]
        # drop leading newlines of post
        paste = pre.rstrip() + "\n" + post.lstrip("\n")

    block_lines = [
        BEGIN_LEARN_MARKER,
        f"# learn crawl LIVE @ {utc_now()} — winners + org expansion — fakes purged",
        f"# {len(filtered)} new targets",
    ]
    block_lines.extend(filtered)
    block_lines.append(END_LEARN_MARKER)

    # Insert after GENERATED block if present, else append
    if END_GEN_MARKER in paste:
        parts = paste.split(END_GEN_MARKER, 1)
        new_text = parts[0] + END_GEN_MARKER + "\n\n" + "\n".join(block_lines) + "\n" + parts[1].lstrip("\n")
    else:
        new_text = paste.rstrip() + "\n\n" + "\n".join(block_lines) + "\n"

    PASTE_BOX.write_text(new_text, encoding="utf-8")
    stats["appended"] = len(filtered)
    stats["new_urls"] = len(filtered)
    return len(filtered)


def main() -> int:
    print("[+] Learn crawl (production — winners + live expand)")
    token = load_token()
    existing = load_existing_paste_uris()
    print(f"  existing real paste uris: {len(existing)}")

    boost_uris, orgs = winners_from_outcomes()
    atlas_uris, atlas_orgs = load_atlas_boost()
    boost_uris = list(boost_uris) + list(atlas_uris)
    orgs = set(orgs) | set(atlas_orgs)
    print(f"  outcome winners: {len(set(boost_uris))} uris, {len(orgs)} orgs (atlas_orgs={len(atlas_orgs)})")

    mined = mine_trufflehog_urls()
    print(f"  mined from findings: {len(set(mined))} uris")

    live_org = expand_orgs_live(orgs, token)
    live_search = live_neighbor_search(token, orgs)
    print(f"  live expand: {len(set(live_org) | set(live_search))} uris")

    # Priority order: outcome boost → live org → live search → mined
    ordered: List[str] = []
    for batch in (boost_uris, live_org, live_search, mined):
        for u in batch:
            ordered.append(u)

    # Prefer unscanned
    new_only = [u for u in ordered if u.rstrip("/") not in existing]

    appended = append_learned(new_only, existing)

    # Wire intelligence reorder if available
    try:
        sys.path.insert(0, str(HOME))
        from target_intelligence import TargetIntelligence
        ti = TargetIntelligence()
        n = ti.reorder_paste_box()
        print(f"  intelligence reorder: {n} targets")
        # record that learn ran (no fake success)
    except Exception as e:
        print(f"  [!] intelligence reorder skipped: {e}")

    rec = {
        "ts": utc_now(),
        "stats": stats,
        "orgs_expanded": sorted(orgs)[:50],
        "appended": appended,
    }
    with LEARN_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")

    print("\n[+] Learn crawl complete")
    for k, v in stats.items():
        print(f"    {k}: {v}")
    print(f"    Output: {LEARN_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
