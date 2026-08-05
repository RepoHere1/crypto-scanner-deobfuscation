#!/usr/bin/env python3
"""
GitHub Repo Scraper — searches orgs/terms, feeds pipeline.

Reads org names or search terms from ~/paste_box.csv (one per line, or CSV).
Uses GitHub token from ~/.env (GITHUB_TOKEN or GH_TOKEN).
Outputs repos to targets/targets_github.txt and feeds trufflehog pipeline.

Rate-limit aware: watches X-RateLimit-Remaining, sleeps when needed.
Deduplicates: skips repos already in targets file.

Usage:
    python3 ~/github_repo_scraper.py                  # use paste_box.csv
    python3 ~/github_repo_scraper.py --target 9000     # scrape 9000 repos
    python3 ~/github_repo_scraper.py --orgs org1,org2  # specific orgs
    python3 ~/github_repo_scraper.py --search "term"   # search code (slower)
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

HOME = Path(os.path.expanduser("~"))
sys.path.insert(0, str(HOME))

PASTE_CSV = HOME / "paste_box.csv"
TARGETS_FILE = HOME / "targets" / "targets_github.txt"
GITHUB_API = "https://api.github.com"
DEFAULT_TARGET = 9000
PER_PAGE = 100
MAX_PAGES_PER_ORG = 10
RATE_SLEEP = 5

# ── ANSI ────────────────────────────────────────────────────────
B = "\033[1m"; D = "\033[2m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; R = "\033[91m"; W = "\033[0m"


def load_token() -> str:
    """Load GitHub token from ~/.env."""
    env_path = HOME / ".env"
    if env_path.exists():
        for line in env_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_ACCESS_TOKEN"):
                return v.strip().strip('"').strip("'")
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        v = os.environ.get(key, "")
        if v: return v.strip()
    return ""


def load_orgs() -> List[str]:
    """Read org names from paste_box.csv or paste_box.txt."""
    orgs = []
    # Try CSV first
    if PASTE_CSV.exists():
        try:
            with open(PASTE_CSV) as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and row[0].strip():
                        orgs.append(row[0].strip())
        except Exception:
            pass
    # Also try paste_box.txt for org names (one per line)
    txt = HOME / "paste_box.txt"
    if txt.exists():
        try:
            for line in txt.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("http"):
                    # Only take lines that look like org names (single word, no spaces)
                    if re.match(r"^[A-Za-z0-9_.-]{1,39}$", line):
                        orgs.append(line)
        except Exception:
            pass
    return list(dict.fromkeys(orgs))  # deduplicate


def load_existing() -> Set[str]:
    """Load already-scraped repos from targets file."""
    existing = set()
    if TARGETS_FILE.exists():
        for line in TARGETS_FILE.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("https://github.com/"):
                existing.add(line.lower().rstrip(".git").rstrip("/"))
    return existing


def api_get(token: str, path: str) -> Optional[dict]:
    """Make an authenticated GitHub API GET request."""
    url = f"{GITHUB_API}{path}"
    req = Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "RepoHere1-Termux")
    for attempt in range(3):
        try:
            with urlopen(req, timeout=30) as resp:
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                reset_ts = resp.headers.get("X-RateLimit-Reset", "0")
                # Warn if running low
                try:
                    if int(remaining) < 10:
                        reset_dt = datetime.fromtimestamp(int(reset_ts))
                        wait = max(1, (int(reset_ts) - time.time()))
                        print(f"  {Y}Rate limit low ({remaining} left, resets {reset_dt}) — waiting {wait:.0f}s{W}")
                        time.sleep(min(wait, 60))
                except Exception:
                    pass
                return json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 403 and "rate limit" in str(e.read().decode().lower()):
                print(f"  {Y}Rate limited — sleeping 60s{W}")
                time.sleep(60)
                continue
            if e.code == 422:
                return None  # no more results
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            return None
        except URLError:
            if attempt < 2:
                time.sleep(5)
                continue
            return None
    return None


def scrape_org(token: str, org: str, existing: Set[str], target: int, total: int) -> int:
    """Scrape repos for one org name. Returns updated total count."""
    print(f"\n{C}[{org}]{W} scraping...")
    added = 0
    for page in range(1, MAX_PAGES_PER_ORG + 1):
        if total + added >= target:
            break
        data = api_get(token, f"/search/repositories?q=org:{org}+sort:stars+order:desc&per_page={PER_PAGE}&page={page}")
        if not data:
            break
        items = data.get("items", [])
        if not items:
            break
        batch = []
        for item in items:
            url = (item.get("html_url") or "").lower().rstrip(".git").rstrip("/")
            if url and url not in existing:
                batch.append(url)
                existing.add(url)
        if batch:
            with open(TARGETS_FILE, "a") as f:
                for u in batch:
                    f.write(u + "\n")
            added += len(batch)
            print(f"  page {page}: +{len(batch)} repos (total scraped: {total + added})")
        else:
            print(f"  page {page}: 0 new (all duplicates)")
        time.sleep(RATE_SLEEP)
    return added


def search_repos(token: str, query: str, existing: Set[str], target: int, total: int) -> int:
    """Search repos by keyword query. Returns updated total."""
    print(f"\n{C}[search: {query}]{W} searching...")
    added = 0
    for page in range(1, MAX_PAGES_PER_ORG + 1):
        if total + added >= target:
            break
        data = api_get(token, f"/search/repositories?q={query}+sort:stars+order:desc&per_page={PER_PAGE}&page={page}")
        if not data:
            break
        items = data.get("items", [])
        if not items:
            break
        batch = []
        for item in items:
            url = (item.get("html_url") or "").lower().rstrip(".git").rstrip("/")
            if url and url not in existing:
                batch.append(url)
                existing.add(url)
        if batch:
            with open(TARGETS_FILE, "a") as f:
                for u in batch:
                    f.write(u + "\n")
            added += len(batch)
            print(f"  page {page}: +{len(batch)} repos (total scraped: {total + added})")
        else:
            print(f"  page {page}: 0 new")
        time.sleep(RATE_SLEEP)
    return added


def main():
    import argparse
    ap = argparse.ArgumentParser(description="GitHub Repo Scraper — feeds pipeline")
    ap.add_argument("--target", type=int, default=DEFAULT_TARGET, help="target repo count")
    ap.add_argument("--orgs", type=str, help="comma-separated org names")
    ap.add_argument("--search", type=str, help="search query")
    args = ap.parse_args()

    token = load_token()
    if not token:
        # Try to find the token from the script the user pasted
        for env_path in (HOME / ".env", HOME / ".github_token"):
            if env_path.exists():
                token = env_path.read_text().strip()[:100]
                if token:
                    break
        if not token:
            print(f"{R}No GitHub token found. Set GITHUB_TOKEN in ~/.env{W}")
            sys.exit(1)

    TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)

    orgs = []
    if args.orgs:
        orgs = [o.strip() for o in args.orgs.split(",") if o.strip()]
    if not orgs:
        orgs = load_orgs()
    if not orgs and not args.search:
        # Default orgs — high-value crypto targets
        orgs = ["ethereum", "bitcoin", "crypto", "web3", "solidity", "defi",
                "metamask", "trustwallet", "phantom", "solana-labs", "polkadot",
                "cosmos", "avalanche", "maticnetwork", "bnb-chain", "arbitrum",
                "optimism", "zksync", "starkware", "aptos-labs", "sui", "sei",
                "monad", "berachain", "eigenlayer", "lido", "uniswap", "aave",
                "makerdao", "compound", "chainlink", "openzeppelin", "foundry",
                "hardhat", "paradigm", "jump", "wintermute", "alchemy", "infura",
                "quicknode", "ankr", "moralis", "thirdweb"]

    print(f"{B}GITHUB REPO SCRAPER{W}")
    print(f"  Target: {args.target} repos  |  Token: {token[:8]}...{token[-4:]}")
    print(f"  Orgs: {len(orgs)}  |  Output: {TARGETS_FILE}")

    existing = load_existing()
    print(f"  Already scraped: {len(existing)} repos")
    total = len(existing)

    for org in orgs:
        if total >= args.target:
            break
        added = scrape_org(token, org, existing, args.target, total)
        total += added

    if args.search and total < args.target:
        added = search_repos(token, args.search, existing, args.target, total)
        total += added

    # Also search for crypto material keywords
    crypto_queries = [
        "private+key+filename:env",
        "seed+phrase+filename:txt",
        "mnemonic+filename:json",
        "wallet+dat+filename:json",
        "ethereum+private+key",
        "bitcoin+private+key",
    ]
    for q in crypto_queries:
        if total >= args.target:
            break
        added = search_repos(token, q, existing, args.target, total)
        total += added

    print(f"\n{G}Done.{W} Total repos: {total}  |  Saved to: {TARGETS_FILE}")
    print(f"  The crypto scanner will pick these up from targets_github.txt")


if __name__ == "__main__":
    main()
