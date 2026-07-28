#!/usr/bin/env python3
"""
Paste Box - Universal messy-text preprocessor for the crypto scanner pipeline.

Drop any messy text into ~/paste_box.txt (URLs, keys, addresses, seed phrases,
API keys, RPC endpoints, repo names, copy-pasted terminal output, etc.).
This script:

  1. Deobfuscates backspaces / ANSI escape sequences.
  2. Extracts GitHub URLs and bare org/user names -> ~/paste.txt and
     ~/targets/targets_github.txt
  3. Extracts targets for many other platforms (GitLab, HuggingFace, Docker,
     CircleCI, Postman, S3, GCS, Jenkins, Elasticsearch, Syslog) ->
     ~/targets/targets_<platform>.txt
  4. Extracts crypto material (addresses, WIFs, hex keys, seed phrases,
     API keys, tokens) -> ~/.trufflehog_results.jsonl (pseudo-trufflehog JSONL
     so crypto_scanner.py can tail it directly).
  5. Extracts RPC endpoint URLs -> ~/rpc_endpoints.jsonl
  6. Extracts API keys -> ~/api_keys.jsonl

All outputs are deduplicated, so running the script repeatedly is idempotent.

Usage:
    python3 ~/paste_box.py                # process ~/paste_box.txt
    python3 ~/paste_box.py <file>         # process another file
    cat messy.txt | python3 ~/paste_box.py # process stdin
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import yaml  # type: ignore
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

HOME = os.path.expanduser("~")
PASTE_BOX = os.path.join(HOME, "paste_box.txt")
PASTE_OUT = os.path.join(HOME, "paste.txt")
CRYPTO_OUT = os.path.join(HOME, ".trufflehog_results.jsonl")
RPC_OUT = os.path.join(HOME, "rpc_endpoints.jsonl")
API_KEYS_OUT = os.path.join(HOME, "api_keys.jsonl")
TARGETS_DIR = os.path.join(HOME, "targets")

TARGET_FILES: Dict[str, str] = {
    "github": os.path.join(TARGETS_DIR, "targets_github.txt"),
    "gitlab": os.path.join(TARGETS_DIR, "targets_gitlab.txt"),
    "hf": os.path.join(TARGETS_DIR, "targets_hf.txt"),
    "docker": os.path.join(TARGETS_DIR, "targets_docker.txt"),
    "circleci": os.path.join(TARGETS_DIR, "targets_circleci.txt"),
    "postman": os.path.join(TARGETS_DIR, "targets_postman.txt"),
    "s3": os.path.join(TARGETS_DIR, "targets_s3.txt"),
    "gcs": os.path.join(TARGETS_DIR, "targets_gcs.txt"),
    "jenkins": os.path.join(TARGETS_DIR, "targets_jenkins.txt"),
    "elasticsearch": os.path.join(TARGETS_DIR, "targets_elasticsearch.txt"),
    "syslog": os.path.join(TARGETS_DIR, "targets_syslog.txt"),
}

# ---------------------------------------------------------------------------
# Deobfuscation (backspaces + ANSI)
# ---------------------------------------------------------------------------
def deobfuscate(text: str) -> str:
    result = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\b":
            if result:
                result.pop()
            i += 1
        elif ch == "\x1b":
            # skip ANSI CSI sequences \e[...m
            if i + 1 < len(text) and text[i + 1] == "[":
                j = i + 2
                while j < len(text) and text[j] not in "mABCD":
                    j += 1
                if j < len(text):
                    i = j + 1
                    continue
            result.append(ch)
            i += 1
        else:
            result.append(ch)
            i += 1
    return "".join(result)


# ---------------------------------------------------------------------------
# Regex constants
# ---------------------------------------------------------------------------
GITHUB_HTTPS_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?(?:[/?#][^\s]*)?"
)
GITHUB_SSH_RE = re.compile(
    r"git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?"
)

GITLAB_HTTPS_RE = re.compile(
    r"https?://gitlab\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?(?:[/?#][^\s]*)?"
)
GITLAB_SSH_RE = re.compile(
    r"git@gitlab\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?"
)
GITLAB_URI_RE = re.compile(
    r"\bgitlab://([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:[/?#][^\s]*)?"
)

HF_HTTPS_RE = re.compile(
    r"https?://huggingface\.co/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:[/?#][^\s]*)?"
)
HF_BARE_RE = re.compile(
    r"\bhuggingface\.co/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:[/?#][^\s]*)?"
)
HF_URI_RE = re.compile(
    r"\bhuggingface://([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:[/?#][^\s]*)?"
)

DOCKER_HUB_RE = re.compile(
    r"https?://hub\.docker\.com/r/([a-z0-9_.-]+)/([a-z0-9_.-]+)(?:[/?#][^\s]*)?"
)
DOCKER_GHCR_RE = re.compile(
    r"\b(ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+)(?::[a-zA-Z0-9_.-]+)?"
)
DOCKER_IO_RE = re.compile(
    r"\b(docker\.io/[a-z0-9_.-]+/[a-z0-9_.-]+)(?::[a-zA-Z0-9_.-]+)?"
)
DOCKER_URI_RE = re.compile(
    r"\bdocker://([a-z0-9_.-]+)(?::[a-zA-Z0-9_.-]+)?"
)
DOCKER_BARE_RE = re.compile(
    r"\b([a-z0-9][a-z0-9_-]{0,})/([a-z0-9_.-]{1,})\b"
)

CIRCLECI_RE = re.compile(
    r"https?://circleci\.com/gh/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:[/?#][^\s]*)?"
)
CIRCLECI_URI_RE = re.compile(r"\bcircleci://[^\s]+")

POSTMAN_RE = re.compile(
    r"(?:https?://)?(?:www\.)?postman\.com/(?:workspace|collection|team)/[^\s]+"
)
POSTMAN_URI_RE = re.compile(r"\bpostman://[^\s]+")

S3_URI_RE = re.compile(
    r"\bs3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:/[^\s]*)?"
)
S3_WEB_RE = re.compile(
    r"https?://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[^\s]*)?"
)

GCS_URI_RE = re.compile(
    r"\bgs://([a-z0-9][a-z0-9_.-]{1,61}[a-z0-9])(?:/[^\s]*)?"
)
GCS_WEB_RE = re.compile(
    r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9_.-]{1,61}[a-z0-9])(?:/[^\s]*)?"
)

JENKINS_RE = re.compile(
    r"https?://[^\s]+/job/[^\s]+|jenkins://[^\s]+"
)

ELASTICSEARCH_RE = re.compile(
    r"https?://[a-zA-Z0-9_.-]+:9200(?:/\S*)?|es://[^\s]+|elasticsearch://[^\s]+"
)

SYSLOG_RE = re.compile(
    r"syslog://[^\s]+|tcp\+tls://[^\s]+"
)

# owner/repo where owner looks like a real platform username (no dots/underscores)
OWNER_REPO_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([A-Za-z0-9_.-]{1,})\b"
)
BARE_NAME_RE = re.compile(r"\b@?([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\b")
VERSION_LIKE_RE = re.compile(r"^v?\d+(?:\.\d+)*$")

BTC_ADDR_RE = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{8,87})\b")
ETH_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
LTC_ADDR_RE = re.compile(r"\b([LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{8,87})\b")
SOL_ADDR_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
DOGE_ADDR_RE = re.compile(r"\bD[5KL][1-9A-HJ-NP-Za-km-z]{32,34}\b")
XRP_ADDR_RE = re.compile(r"\b[rR][1-9A-HJ-NP-Za-km-z]{25,34}\b")
TON_ADDR_RE = re.compile(r"\b[UE]Q[a-zA-Z0-9_-]{46}\b")
AVAX_ADDR_RE = re.compile(r"\b[XC][1-9A-HJ-NP-Za-km-z]{33}\b")
WIF_RE = re.compile(r"\b([5][1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})\b")
HEX_KEY_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
SEED_RE = re.compile(r"\b([a-z]{3,}(?:\s+[a-z]{3,}){11,23})\b", re.IGNORECASE)

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]+\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}(?:-[a-zA-Z0-9]{24})?\b")
STRIPE_KEY_RE = re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b")
GENERIC_SECRET_RE = re.compile(
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
    re.IGNORECASE,
)
RPC_RE = re.compile(
    r"(?:https?|wss?)://[a-zA-Z0-9_.-]*(?:alchemy|ankr|infura|quicknode|helius|"
    r"publicnode|blastapi|cloudflare|solana|ethereum|binance|avax|polygon|"
    r"bitcoin|core|getblock|nodereal|chainstack|figment|lb\.drpc)[a-zA-Z0-9_.:/=?&\-]*",
    re.IGNORECASE,
)

COMMON_WORDS = {
    "check", "scan", "all", "repos", "in", "org", "user", "the", "and", "for",
    "with", "https", "http", "git", "com", "api", "v2", "www", "app", "web",
    "get", "post", "put", "delete", "json", "html", "txt", "raw", "blob",
    "co", "io", "org", "net", "github", "gitlab", "huggingface", "docker",
    "circleci", "postman", "jenkins", "elasticsearch", "syslog", "s3", "gcs",
    "storage", "googleapis", "amazonaws", "job", "workspace", "collection",
    "team", "hub", "ghcr", "localhost", "example", "test", "prod", "dev",
    "repo", "repos", "filesystem",
}

ALL_PLATFORM_URL_RES = [
    GITHUB_HTTPS_RE,
    GITHUB_SSH_RE,
    GITLAB_HTTPS_RE,
    GITLAB_SSH_RE,
    GITLAB_URI_RE,
    HF_HTTPS_RE,
    HF_BARE_RE,
    HF_URI_RE,
    DOCKER_HUB_RE,
    DOCKER_GHCR_RE,
    DOCKER_IO_RE,
    DOCKER_URI_RE,
    CIRCLECI_RE,
    CIRCLECI_URI_RE,
    POSTMAN_RE,
    POSTMAN_URI_RE,
    S3_URI_RE,
    S3_WEB_RE,
    GCS_URI_RE,
    GCS_WEB_RE,
    JENKINS_RE,
    ELASTICSEARCH_RE,
    SYSLOG_RE,
]

PLATFORM_JSON_KEYS: Dict[str, List[str]] = {
    "github": ["github_org", "github_orgs", "github_user", "github_users",
               "github_repo", "github_repos", "url", "urls"],
    "gitlab": ["gitlab", "gitlab_org", "gitlab_orgs", "gitlab_repo", "gitlab_repos"],
    "hf": ["huggingface", "hf", "huggingface_repo", "huggingface_repos", "hf_repo"],
    "docker": ["docker", "docker_image", "docker_images", "container", "containers"],
    "circleci": ["circleci", "circleci_repo", "circleci_repos"],
    "postman": ["postman", "postman_workspace", "postman_workspaces",
                "postman_collection", "postman_collections", "postman_team", "postman_teams"],
    "s3": ["s3", "s3_bucket", "s3_buckets"],
    "gcs": ["gcs", "gcs_bucket", "gcs_buckets", "google_storage"],
    "jenkins": ["jenkins", "jenkins_job", "jenkins_jobs"],
    "elasticsearch": ["elasticsearch", "elastic", "es"],
    "syslog": ["syslog"],
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _url_spans(text: str, regexes: List[re.Pattern]) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    for regex in regexes:
        for m in regex.finditer(text):
            spans.append((m.start(), m.end()))
    return spans


def _overlaps(spans: List[Tuple[int, int]], start: int, end: int) -> bool:
    for s, e in spans:
        if not (end <= s or start >= e):
            return True
    return False


def _looks_like_version(value: str) -> bool:
    return bool(VERSION_LIKE_RE.match(value))


def _valid_owner_repo(owner: str, repo: str) -> bool:
    low_owner = owner.lower()
    low_repo = repo.lower()
    if low_owner in COMMON_WORDS or low_repo in COMMON_WORDS:
        return False
    if _looks_like_version(owner) or _looks_like_version(repo):
        return False
    if "." in owner or "_" in owner:
        return False
    if owner.startswith(".") or owner.endswith(".") or repo.startswith(".") or repo.endswith("."):
        return False
    if owner.startswith("-") or owner.endswith("-") or repo.startswith("-") or repo.endswith("-"):
        return False
    if ".." in owner or ".." in repo:
        return False
    return True


def _is_bare_org_candidate(cand: str, line: str) -> bool:
    """Heuristic filters to keep bare org/user names and drop secrets/fragments."""
    if cand.isdigit():
        return False
    if "_" in cand:
        return False
    if len(cand) > 39:
        return False
    if len(cand) >= 16 and all(ch in "0123456789abcdefABCDEF" for ch in cand):
        return False
    # skip lines that look like URLs, assignments, labels, or other platform paths
    if any(ch in line for ch in (":", "=", "//", ".", "/")):
        return False
    return True


# ---------------------------------------------------------------------------
# JSON key-hint extraction (safe, read-only)
# ---------------------------------------------------------------------------
def extract_json_targets(text: str) -> Dict[str, Set[str]]:
    """If the paste starts with a JSON object, pull string values out by known keys."""
    targets: Dict[str, Set[str]] = {p: set() for p in TARGET_FILES}
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return targets
    try:
        data = json.loads(text[start : end + 1])
    except Exception:
        return targets
    if not isinstance(data, dict):
        return targets
    for key, value in data.items():
        klow = key.lower()
        for platform, aliases in PLATFORM_JSON_KEYS.items():
            if klow in aliases:
                if isinstance(value, list):
                    targets[platform].update(
                        str(v).strip() for v in value if isinstance(v, (str, int, float))
                    )
                elif isinstance(value, str):
                    targets[platform].add(value.strip())
                break
    return targets


# ---------------------------------------------------------------------------
# Platform extractors
# ---------------------------------------------------------------------------
def extract_github(text: str) -> Tuple[Set[str], Set[str]]:
    urls: Set[str] = set()
    orgs: Set[str] = set()

    for m in GITHUB_HTTPS_RE.finditer(text):
        urls.add(f"https://github.com/{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in GITHUB_SSH_RE.finditer(text):
        urls.add(f"https://github.com/{m.group(1)}/{m.group(2)}".rstrip("/"))

    spans = _url_spans(text, ALL_PLATFORM_URL_RES)

    for m in OWNER_REPO_RE.finditer(text):
        if _overlaps(spans, m.start(), m.end()):
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start : line_end if line_end != -1 else len(text)]
        llow = line.lower().lstrip()
        # Skip lines that are clearly for other platforms (custom schemes, standard URLs).
        if llow.startswith((
            "gitlab://", "huggingface://", "docker://", "circleci://", "postman://",
            "s3://", "gs://", "jenkins://", "elasticsearch://", "syslog://", "es://", "tcp+tls://",
        )):
            continue
        if llow.startswith("docker "):
            continue
        if any(d in llow for d in (
            "hub.docker.com/r/", "ghcr.io/", "docker.io/", "gitlab.com/", "huggingface.co/",
        )):
            continue
        owner, repo = m.group(1), m.group(2)
        if not _valid_owner_repo(owner, repo):
            continue
        urls.add(f"https://github.com/{owner}/{repo}".rstrip("/"))

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for cand in BARE_NAME_RE.findall(line):
            low = cand.lower()
            if low in COMMON_WORDS or len(cand) < 2:
                continue
            if not _is_bare_org_candidate(cand, line):
                continue
            orgs.add(cand)

    return urls, orgs


def extract_gitlab(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in GITLAB_HTTPS_RE.finditer(text):
        targets.add(f"https://gitlab.com/{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in GITLAB_SSH_RE.finditer(text):
        targets.add(f"https://gitlab.com/{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in GITLAB_URI_RE.finditer(text):
        targets.add(f"https://gitlab.com/{m.group(1)}/{m.group(2)}".rstrip("/"))

    # Bare owner/repo on lines that begin with "gitlab" (e.g. gitlab-org/...).
    for line in text.splitlines():
        llow = line.lower().lstrip()
        if not (llow.startswith("gitlab://") or llow.startswith("gitlab.com/") or llow.startswith("gitlab")):
            continue
        clean = GITLAB_HTTPS_RE.sub(" ", line)
        clean = GITLAB_SSH_RE.sub(" ", clean)
        clean = GITLAB_URI_RE.sub(" ", clean)
        for m in OWNER_REPO_RE.finditer(clean):
            owner, repo = m.group(1), m.group(2)
            if not _valid_owner_repo(owner, repo):
                continue
            targets.add(f"https://gitlab.com/{owner}/{repo}".rstrip("/"))
    return targets


def extract_huggingface(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in HF_HTTPS_RE.finditer(text):
        targets.add(f"https://huggingface.co/{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in HF_BARE_RE.finditer(text):
        targets.add(f"https://huggingface.co/{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in HF_URI_RE.finditer(text):
        targets.add(f"https://huggingface.co/{m.group(1)}/{m.group(2)}".rstrip("/"))

    # Bare owner/repo on lines that begin with "huggingface".
    for line in text.splitlines():
        llow = line.lower().lstrip()
        if not (llow.startswith("huggingface://") or llow.startswith("huggingface.co/") or llow.startswith("huggingface")):
            continue
        clean = HF_HTTPS_RE.sub(" ", line)
        clean = HF_BARE_RE.sub(" ", clean)
        clean = HF_URI_RE.sub(" ", clean)
        for m in OWNER_REPO_RE.finditer(clean):
            owner, repo = m.group(1), m.group(2)
            if not _valid_owner_repo(owner, repo):
                continue
            targets.add(f"https://huggingface.co/{owner}/{repo}".rstrip("/"))
    return targets


def _valid_docker_part(value: str) -> bool:
    if not value or value.startswith("-") or value.endswith("-"):
        return False
    if value.startswith(".") or value.endswith("."):
        return False
    if ".." in value:
        return False
    return bool(re.fullmatch(r"[a-z0-9_.-]+", value))


def extract_docker(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in DOCKER_HUB_RE.finditer(text):
        targets.add(f"{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in DOCKER_GHCR_RE.finditer(text):
        targets.add(m.group(1).rstrip("/"))
    for m in DOCKER_IO_RE.finditer(text):
        targets.add(m.group(1).rstrip("/"))
    for m in DOCKER_URI_RE.finditer(text):
        targets.add(m.group(1).rstrip("/"))

    # Bare owner/image context: docker commands, image-related words, or registry URLs.
    for line in text.splitlines():
        low = line.lower()
        has_context = (
            re.search(r"\b(?:pull|run|image|container)\b", low)
            or low.startswith("docker ")
            or any(domain in low for domain in ("hub.docker.com/r/", "ghcr.io/", "docker.io/"))
        )
        if not has_context:
            continue
        clean = DOCKER_HUB_RE.sub(" ", line)
        clean = DOCKER_GHCR_RE.sub(" ", clean)
        clean = DOCKER_IO_RE.sub(" ", clean)
        clean = DOCKER_URI_RE.sub(" ", clean)
        for m in DOCKER_BARE_RE.finditer(clean):
            owner, image = m.group(1), m.group(2)
            if "." in owner or "_" in owner:
                continue
            if owner.lower() in COMMON_WORDS or len(owner) < 2 or len(image) < 2:
                continue
            if not _valid_docker_part(owner) or not _valid_docker_part(image):
                continue
            targets.add(f"{owner}/{image}")
    return targets


def extract_circleci(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in CIRCLECI_RE.finditer(text):
        targets.add(f"https://circleci.com/gh/{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in CIRCLECI_URI_RE.finditer(text):
        uri = m.group(0)
        m2 = re.match(r"circleci://(github|bitbucket)/([^/]+)/([^/]+)", uri, re.IGNORECASE)
        if m2:
            targets.add(f"https://circleci.com/{m2.group(1)}/{m2.group(2)}/{m2.group(3)}".rstrip("/"))
        else:
            targets.add(uri.rstrip("/"))

    # Bare owner/repo on lines that begin with "circleci".
    for line in text.splitlines():
        llow = line.lower().lstrip()
        if not (llow.startswith("circleci://") or llow.startswith("https://circleci.com/") or llow.startswith("circleci")):
            continue
        clean = CIRCLECI_RE.sub(" ", line)
        clean = CIRCLECI_URI_RE.sub(" ", clean)
        for m in OWNER_REPO_RE.finditer(clean):
            owner, repo = m.group(1), m.group(2)
            if not _valid_owner_repo(owner, repo):
                continue
            targets.add(f"https://circleci.com/gh/{owner}/{repo}".rstrip("/"))
    return targets


def extract_postman(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in POSTMAN_RE.finditer(text):
        url = m.group(0).rstrip("/")
        if url.startswith(("http://", "https://")):
            targets.add(url)
        else:
            targets.add(f"https://{url}")
    for m in POSTMAN_URI_RE.finditer(text):
        uri = m.group(0)
        if uri.startswith("postman://"):
            targets.add(f"https://postman.com/{uri[len('postman://'):]}".rstrip("/"))
        else:
            targets.add(uri.rstrip("/"))
    return targets


def extract_s3(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in S3_URI_RE.finditer(text):
        targets.add(m.group(0).rstrip("/"))
    for m in S3_WEB_RE.finditer(text):
        targets.add(m.group(0).rstrip("/"))
    return targets


def extract_gcs(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in GCS_URI_RE.finditer(text):
        targets.add(m.group(0).rstrip("/"))
    for m in GCS_WEB_RE.finditer(text):
        targets.add(m.group(0).rstrip("/"))
    return targets


def extract_jenkins(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in JENKINS_RE.finditer(text):
        targets.add(m.group(0).rstrip("/"))
    return targets


def extract_elasticsearch(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in ELASTICSEARCH_RE.finditer(text):
        targets.add(m.group(0).rstrip("/"))
    return targets


def extract_syslog(text: str) -> Set[str]:
    targets: Set[str] = set()
    for m in SYSLOG_RE.finditer(text):
        targets.add(m.group(0).rstrip("/"))
    return targets


# ---------------------------------------------------------------------------
# Crypto / API / RPC extraction (existing behavior)
# ---------------------------------------------------------------------------
def extract_crypto_material(text: str) -> List[dict]:
    """Return pseudo-trufflehog JSONL records for crypto material."""
    records = []
    seen = set()

    def add(kind: str, value: str, chain: str = ""):
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        records.append({
            "reason": kind,
            "string": value,
            "chain": chain,
            "path": "paste_box",
            "commit": "",
            "source_line": value,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    for m in BTC_ADDR_RE.finditer(text):
        add("BTC address", m.group(0), "btc")
    for m in ETH_ADDR_RE.finditer(text):
        add("ETH address", m.group(0), "eth")
    for m in LTC_ADDR_RE.finditer(text):
        add("LTC address", m.group(0), "ltc")
    for m in SOL_ADDR_RE.finditer(text):
        add("SOL address", m.group(0), "sol")
    for m in DOGE_ADDR_RE.finditer(text):
        add("DOGE address", m.group(0), "doge")
    for m in XRP_ADDR_RE.finditer(text):
        add("XRP address", m.group(0), "xrp")
    for m in TON_ADDR_RE.finditer(text):
        add("TON address", m.group(0), "ton")
    for m in AVAX_ADDR_RE.finditer(text):
        add("AVAX address", m.group(0), "avax")
    for m in WIF_RE.finditer(text):
        add("Bitcoin WIF", m.group(0), "btc")
    for m in HEX_KEY_RE.finditer(text):
        add("Hex private key", m.group(0), "eth")
    for m in SEED_RE.finditer(text):
        add("Seed phrase", m.group(0).strip(), "seed")

    return records


def extract_api_keys(text: str) -> List[dict]:
    keys = []
    seen = set()

    def add(provider: str, value: str):
        if value in seen:
            return
        seen.add(value)
        keys.append({
            "provider": provider,
            "key": value,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    for k in re.findall(r"https?://[a-z0-9-]+\.g\.alchemy\.com/v2/([a-zA-Z0-9_-]+)", text, re.IGNORECASE):
        add("alchemy", k)
    for k in re.findall(r"https?://[a-z0-9-]+\.infura\.io/v3/([a-zA-Z0-9]{32})", text, re.IGNORECASE):
        add("infura", k)
    for m in GENERIC_SECRET_RE.finditer(text):
        add("generic", m.group(1))
    for m in AWS_KEY_RE.finditer(text):
        add("aws", m.group(0))
    for m in GITHUB_PAT_RE.finditer(text):
        add("github", m.group(0))
    for m in SLACK_TOKEN_RE.finditer(text):
        add("slack", m.group(0))
    for m in STRIPE_KEY_RE.finditer(text):
        add("stripe", m.group(0))

    return keys


def extract_rpc_endpoints(text: str) -> List[dict]:
    endpoints = []
    seen = set()
    for url in RPC_RE.findall(text):
        url = url.rstrip("/")
        if url in seen:
            continue
        seen.add(url)
        endpoints.append({
            "url": url,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    return endpoints


# ---------------------------------------------------------------------------
# Provider awareness loader (no external calls)
# ---------------------------------------------------------------------------
def load_providers(path: Optional[str] = None) -> dict:
    """Read providers.yaml for awareness/logging only. No network calls."""
    path = path or os.path.join(HOME, "providers.yaml")
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if HAS_YAML:
            data = yaml.safe_load(content) or {}
        else:
            # Minimal fallback parser for simple key: value files.
            data: dict = {}
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    data[key.strip()] = value.strip()
        if not isinstance(data, dict):
            data = {}
        provider_names: List[str] = []
        if isinstance(data.get("providers"), dict):
            provider_names = list(data["providers"].keys())
        elif data:
            provider_names = list(data.keys())
        print(f"[*] providers.yaml loaded ({len(provider_names)} provider entries): {provider_names[:20]}")
        return data
    except Exception as exc:
        print(f"[!] Failed to load providers.yaml: {exc}")
        return {}


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------
def read_input(argv: List[str]) -> str:
    # Use explicit file arg if given; '-' means read stdin.
    if len(argv) > 1:
        path = argv[1]
        if path == "-":
            return sys.stdin.read()
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    # Default: read the paste box file
    if not os.path.exists(PASTE_BOX):
        open(PASTE_BOX, "w").close()
        print(f"[*] Created empty paste box: {PASTE_BOX}")
        return ""

    with open(PASTE_BOX, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def write_lines(path: str, lines: List[str]) -> None:
    """Write text lines (deduped, preserving order)."""
    seen = set()
    out = []
    for line in lines:
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
    with open(path, "w", encoding="utf-8") as f:
        for line in out:
            f.write(line + "\n")


def read_existing_lines(path: str) -> Set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {line.strip() for line in f if line.strip() and not line.strip().startswith("#")}


def write_target_file(path: str, items: Set[str]) -> None:
    """Append new target lines, deduplicating against existing file contents."""
    existing = read_existing_lines(path)
    new = [item for item in sorted(items) if item and item not in existing]
    if not new and not os.path.exists(path):
        Path(path).touch()
        return
    if new:
        with open(path, "a", encoding="utf-8") as f:
            for item in new:
                f.write(item + "\n")


def existing_jsonl_keys(path: str, key_func) -> Set:
    keys: Set = set()
    if not os.path.exists(path):
        return keys
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                keys.add(key_func(rec))
            except Exception:
                continue
    return keys


def append_jsonl(path: str, records: List[dict], key_func) -> None:
    if not records:
        return
    existing = existing_jsonl_keys(path, key_func)
    with open(path, "a", encoding="utf-8") as f:
        for rec in records:
            k = key_func(rec)
            if k in existing:
                continue
            existing.add(k)
            f.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    raw = read_input(sys.argv)
    if not raw.strip():
        print("[!] Paste box is empty. Add text to ~/paste_box.txt first.")
        return

    text = deobfuscate(raw)

    # Load providers.yaml for awareness only (no external calls).
    load_providers()

    # JSON key hints help map bare lists to platforms.
    json_targets = extract_json_targets(text)

    # Extract per-platform targets.
    github_urls, github_orgs = extract_github(text)
    # Split JSON GitHub hints into URLs vs org names so paste.txt stays useful.
    for item in json_targets["github"]:
        item = item.strip()
        if not item:
            continue
        if item.startswith("https://github.com/"):
            github_urls.add(item.rstrip("/"))
        elif "/" in item:
            github_urls.add(f"https://github.com/{item}".rstrip("/"))
        else:
            github_orgs.add(item)
    github_targets = github_urls | github_orgs

    gitlab_targets = extract_gitlab(text) | json_targets["gitlab"]
    hf_targets = extract_huggingface(text) | json_targets["hf"]
    docker_targets = extract_docker(text) | json_targets["docker"]
    circleci_targets = extract_circleci(text) | json_targets["circleci"]
    postman_targets = extract_postman(text) | json_targets["postman"]
    s3_targets = extract_s3(text) | json_targets["s3"]
    gcs_targets = extract_gcs(text) | json_targets["gcs"]
    jenkins_targets = extract_jenkins(text) | json_targets["jenkins"]
    elasticsearch_targets = extract_elasticsearch(text) | json_targets["elasticsearch"]
    syslog_targets = extract_syslog(text) | json_targets["syslog"]

    crypto_records = extract_crypto_material(text)
    api_keys = extract_api_keys(text)
    rpc_endpoints = extract_rpc_endpoints(text)

    # Ensure targets directory exists.
    os.makedirs(TARGETS_DIR, exist_ok=True)

    # Write per-platform target files (deduplicated / idempotent).
    write_target_file(TARGET_FILES["github"], github_targets)
    write_target_file(TARGET_FILES["gitlab"], gitlab_targets)
    write_target_file(TARGET_FILES["hf"], hf_targets)
    write_target_file(TARGET_FILES["docker"], docker_targets)
    write_target_file(TARGET_FILES["circleci"], circleci_targets)
    write_target_file(TARGET_FILES["postman"], postman_targets)
    write_target_file(TARGET_FILES["s3"], s3_targets)
    write_target_file(TARGET_FILES["gcs"], gcs_targets)
    write_target_file(TARGET_FILES["jenkins"], jenkins_targets)
    write_target_file(TARGET_FILES["elasticsearch"], elasticsearch_targets)
    write_target_file(TARGET_FILES["syslog"], syslog_targets)

    # Build legacy paste.txt output.
    paste_lines = [
        "# Auto-generated from ~/paste_box.txt by paste_box.py",
        "# Put messy text in paste_box.txt, then run: python3 ~/paste_box.py",
    ]
    if github_urls:
        paste_lines.append("# GitHub URLs")
        paste_lines.extend(sorted(github_urls))
    if github_orgs:
        paste_lines.append("# Bare orgs/users (resolved by mass_scan.py)")
        paste_lines.extend(sorted(github_orgs))
    if not github_urls and not github_orgs:
        paste_lines.append("# No GitHub URLs or orgs detected")

    write_lines(PASTE_OUT, paste_lines)

    # Append JSONL outputs, deduplicated against existing files.
    append_jsonl(
        CRYPTO_OUT,
        crypto_records,
        key_func=lambda r: (r.get("reason"), r.get("string")),
    )
    append_jsonl(API_KEYS_OUT, api_keys, key_func=lambda r: r.get("key"))
    append_jsonl(RPC_OUT, rpc_endpoints, key_func=lambda r: r.get("url"))

    print("[+] Paste box processed")
    print(f"    GitHub URLs:   {len(github_urls)}")
    print(f"    Orgs/users:    {len(github_orgs)}")
    print(f"    GitHub targets written: {len(github_targets)}")
    print(f"    GitLab targets:         {len(gitlab_targets)}")
    print(f"    HuggingFace targets:    {len(hf_targets)}")
    print(f"    Docker targets:         {len(docker_targets)}")
    print(f"    CircleCI targets:       {len(circleci_targets)}")
    print(f"    Postman targets:        {len(postman_targets)}")
    print(f"    S3 targets:             {len(s3_targets)}")
    print(f"    GCS targets:            {len(gcs_targets)}")
    print(f"    Jenkins targets:        {len(jenkins_targets)}")
    print(f"    Elasticsearch targets:  {len(elasticsearch_targets)}")
    print(f"    Syslog targets:         {len(syslog_targets)}")
    print(f"    Crypto items:  {len(crypto_records)}")
    print(f"    API keys:      {len(api_keys)}")
    print(f"    RPC endpoints: {len(rpc_endpoints)}")
    print("    Output files:")
    print(f"      {PASTE_OUT}")
    print(f"      {CRYPTO_OUT}")
    print(f"      {API_KEYS_OUT}")
    print(f"      {RPC_OUT}")
    print(f"      {TARGETS_DIR}/")


if __name__ == "__main__":
    main()
