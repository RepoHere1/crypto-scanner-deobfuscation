#!/usr/bin/env python3
"""
7000.py v4.0 — Multi-engine secret-surface discovery scraper
Searches GitHub, GitLab, HuggingFace, Docker Hub, Bitbucket, Postman,
and cloud storage (GCS, S3, Azure Blob, DigitalOcean Spaces)
for repos/projects/buckets likely to contain secrets, keys, credentials,
and crypto material. Outputs to paste_box.txt for downstream scanning.

v4.0 improvements:
  • Keyword yield tracking — top-25 report at end of each run
  • --boost flag — re-probes repos with funded wallets using deep file queries
  • --adaptive flag — blends high-weight adaptive queries from success atlas
  • --format targets — writes directly to targets/ directory for pipeline feeding
  • --two-pass — discovery + deep harvest against funded repos
  • Keywords rewritten from success-atlas signal (2,448 funded hits analyzed)


v5.0 upgrades (Aug 2026):
  • Atlas-First Engine Selection — rank engines by funded_hits/total_scans yield
  • Living Dedup with TTL — ffod.jsonl replaces flat ffod.txt, 14-day expiry
  • Signal-Path Surgical Targeting — atlas top_filenames/signal_paths → precise queries
  • Token Lifecycle Manager — health scoring, auto-rotation, unauthenticated fallback
  • Cloud Bucket Genome from Atlas — bucket names generated from proven signal patterns
  • Default Two-Pass Deep Harvest — discovery + deep file-level surgical strike
  • Closed-Loop Target Scoring — scan outcomes update .target_scores.json + .hot_targets.json
  • Onion/Clearnet Correlation — first-class parallel engine via Tor SOCKS proxy

Major improvements in v3.0:
  • Engines run in parallel via ThreadPoolExecutor (4-6x faster)
  • Shared global target — no rigid per-engine quotas
  • Append-mode output by default, --fresh to truncate
  • --no-dedup, --dry-run, --resume, --deep flags
  • Rate-limit detection with proper Retry-After / X-RateLimit-Reset backoff
  • CPU/RAM throttle with configurable ceilings (default 90%)
  • Only confirmed-live bucket and Bitbucket probe results written to food
  • Expanded 400+ diversified keyword list covering crypto, infra, DevOps, cloud, DBs,
    mobile, firmware, IoT, automotive, OSINT, red-team, forensics, supply-chain,
    dark-web, onion services, Tor relays, darknet markets, anonymous P2P
  • JSONL output option, pipe-escaping for the default format
  • consecutive_empty bailout raised to 15, tied to total (not net-new) results
  • Token rotator with configurable per-platform budgets and header-based resets

Usage:
    python 7000.py                             # default: 100000 targets
    python 7000.py --target 10000              # custom target count
    python 7000.py --engines github,gitlab     # only specific engines
    python 7000.py --output paste_box.txt      # custom output file
    python 7000.py --fresh                     # truncate output, start clean
    python 7000.py --no-dedup                  # ignore food file, write all
    python 7000.py --dry-run                   # preview only, no writes
    python 7000.py --deep                      # also search code/blobs/gists
    python 7000.py --max-cpu 85 --max-ram 85   # throttle ceilings
    python 7000.py --topics crypto             # only crypto tier
    python 7000.py --topics infra              # only infra/devops tier
    python 7000.py --topics darkweb            # only dark-web / onion tier
    python 7000.py --topics all                # all tiers (default)
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import random
import re
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import socket

# ── Paths ───────────────────────────────────────────────────────
HOME = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HOME, ".env")
DEFAULT_OUTPUT = os.path.join(HOME, "paste_box.txt")
DEFAULT_FOOD = os.path.join(HOME, "ffod.txt")
RESUME_TMP = os.path.join(HOME, "paste_box.tmp")

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# ── ANSI Terminal Colors ────────────────────────────────────────
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

if _USE_COLOR:
    C_RESET   = "\033[0m";      C_BOLD    = "\033[1m"
    C_DIM     = "\033[2m";      C_RED     = "\033[91m"
    C_GREEN   = "\033[92m";     C_YELLOW  = "\033[93m"
    C_BLUE    = "\033[94m";     C_MAGENTA = "\033[95m"
    C_CYAN    = "\033[96m";     C_WHITE   = "\033[97m"
    C_GRAY    = "\033[90m";     C_BGRN    = "\033[1;92m"
    C_BRED    = "\033[1;91m";   C_BYEL    = "\033[1;93m"
    C_BCYN    = "\033[1;96m";   C_BMAG    = "\033[1;95m"
else:
    C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = ""
    C_MAGENTA = C_CYAN = C_WHITE = C_GRAY = C_BGRN = C_BRED = C_BYEL = C_BCYN = C_BMAG = ""

def cprint(*args, color=None, bold=False, dim=False, **kwargs):
    pre = ""
    if bold and _USE_COLOR: pre += C_BOLD
    if dim and _USE_COLOR:   pre += C_DIM
    if color and _USE_COLOR: pre += color
    text = " ".join(str(a) for a in args)
    if pre:
        print(f"{pre}{text}{C_RESET}", **kwargs)
    else:
        print(text, **kwargs)

# =============================================================================
# CPU / RAM THROTTLE
# =============================================================================

class ResourceThrottle:
    """Monitor RAM via /proc/meminfo and CPU via concurrency heuristics.

    On Android/Termux /proc/stat is often unreadable, so CPU throttle is
    enforced indirectly through worker-caps and inter-request delays.
    Ram throttle reads /proc/meminfo directly.
    """

    def __init__(self, max_cpu_pct: float = 90.0, max_ram_pct: float = 90.0):
        self.max_cpu_pct = max_cpu_pct
        self.max_ram_pct = max_ram_pct
        self._ram_path = "/proc/meminfo"
        self._ram_available = os.path.exists(self._ram_path)

    def ram_pct(self) -> float:
        """Return current RAM usage as a percentage, or 0 if unavailable."""
        if not self._ram_available:
            return 0.0
        try:
            mem = {}
            with open(self._ram_path, "r") as f:
                for line in f:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        try:
                            mem[key] = int(val)
                        except ValueError:
                            pass
            total = mem.get("MemTotal", 1)
            avail = mem.get("MemAvailable", mem.get("MemFree", 0))
            if total > 0:
                return ((total - avail) / total) * 100.0
        except Exception:
            pass
        return 0.0

    def wait_if_hot(self):
        """Sleep until both CPU (heuristic) and RAM are below ceilings."""
        slept = False
        while True:
            ram = self.ram_pct()
            if ram >= self.max_ram_pct:
                cprint(f"[throttle] RAM {ram:.1f}% >= {self.max_ram_pct}%, sleeping 3s...",
                       color=C_YELLOW, dim=True)
                time.sleep(3)
                slept = True
            else:
                break
        return slept

    def ok(self) -> bool:
        """Non-blocking check: are we below ceilings?"""
        return self.ram_pct() < self.max_ram_pct


# =============================================================================
# COMPREHENSIVE SEARCH TOPICS  (300+ diversified low-overlap terms, tiered)
# =============================================================================
# v4.0 rewrite — keywords driven by success-atlas signal (2,448 funded hits):
#   • 97% EVM — bias Ethereum/EVM hard
#   • Test fixtures = goldmine (web3-eth-accounts/test/fixtures/ is #1 path)
#   • .env PRIVATE_KEY is the single best query (weight 1.0 in adaptive)
#   • registry / testsv2 / morpho / aave / lido dominate funded path parts
#   • JSON + TS config/fixture files, not library source code
#   • "Small orgs with .env beat megarepos"
#   • Drop generic crypto-lib terms — they return repos with NO key material
# =============================================================================

CRYPTO_TOPICS: List[str] = [
    # ── TIER 1 — Proven signal paths (success atlas) ──
    "web3-eth-accounts test fixtures",
    "eip1559txs test vector",
    "eip2930txs test fixture",
    "web3-eth test fixtures erc20",
    "web3-eth-contract test unit",
    "deploy_erc20 script",
    "morpho testsv2 config",

    # ── TIER 2 — .env / PRIVATE_KEY (weight 1.0 adaptive) ──
    "PRIVATE_KEY env example",
    "ETH_PRIVATE_KEY env",
    "MNEMONIC env wallet",
    "WALLET_PRIVATE env",
    "secrets json privateKey",
    "hardhat config PRIVATE_KEY",
    "foundry deploy private key",

    # ── TIER 3 — DeFi deploy configs (test wallets → real funds) ──
    "aave deploy script private",
    "lido deployment config",
    "uniswap deploy script",
    "chainlink deploy config",
    "safe multisig deploy config",
    "morpho blue deploy",
    "eigenlayer deploy config",
    "pendle deploy script",
    "etherfi deploy script",

    # ── TIER 4 — Fixture files that ship keys ──
    "account ts test fixtures",
    "wallet ts test fixtures",
    "eip712 typed data test json",
    "eip712 receiveWithAuthorization test",
    "token json test fixture",
    "rpc method wrappers fixtures",

    # ── TIER 5 — L2 deploy configs (chains with actual hits) ──
    "arbitrum deploy config l2",
    "optimism deploy config l2",
    "base deploy config l2",
    "polygon zkEVM deploy",

    # ── TIER 6 — Registry / keystore configs ──
    "registry config deployment json",
    "keystore json v3 wallet",
    "solana keypair json array",
    "ethereum keystore file",
    "geth keystore directory",

    # ── TIER 7 — Non-EVM with actual hits (SOL 356, BTC 108) ──
    "solana program test validator",
    "solana deploy script keypair",
    "bitcoin regtest private key",
    "bitcoin testnet wallet seed",
]

INFRA_TOPICS: List[str] = [
    # ── CI/CD env leaks ──
    "github actions secret env variable",
    "github workflow env deploy",
    "gitlab ci variables env",
    "jenkins credential env config",

    # ── Docker / K8s with exposed env ──
    "docker compose env file deploy",
    "Dockerfile env private key",
    "kubeconfig cluster user token",
    "k8s secret opaque data",
    "helm values secrets config",

    # ── IaC secrets ──
    "terraform state encryption key",
    "terraform tfvars private key",
    "pulumi secret provider config",

    # ── SSH / SSL / PKI ──
    "ssh private key pem config",
    "ssl certificate private key config",
    "wireguard private key config",

    # ── Cloud credentials ──
    "aws access key id secret config",
    "gcp service account json key",
    "azure service principal secret config",
    "cloudflare api token config",
]

GENERAL_TOPICS: List[str] = [
    # ── Mobile app configs ──
    "android keystore config",
    "expo secrets env config",

    # ── Router / firmware (backups have real creds) ──
    "router configuration backup config",
    "openwrt config shadow hash",
    "mikrotik backup config password",
    "cisco config enable secret",

    # ── OSINT API keys ──
    "shodan api key config",
    "censys api secret config",
    "virustotal api key config",

    # ── Secret scanner configs (dogfooding) ──
    "trufflehog config verified",
    "gitleaks config toml detect",
    "detect-secrets baseline config",
    "semgrep secrets rule config",

    # ── Supply chain tokens ──
    "npm package publish token config",
    "pypi publish token config",
    "dockerhub access token config",

    # ── DeFi exploit PoCs (test wallets) ──
    "defi hack poc exploit contract",
    "flash loan attack contract test",
    "reentrancy attack solidity test",
]
DARKWEB_TOPICS: List[str] = [
    # ── Onion service deployment / keys ──
    "tor hidden service private key", "onion service v3 address",
    "torrc hidden service dir", "onionbalance config instance",
    "onion-service docker compose tor",

    # ── Tor relays / anti-censorship ──
    "tor relay operator configuration", "obfs4 bridge server torrc",
]

# Combined list for default mode  (dict.fromkeys removes exact dupes)
ALL_TOPICS: List[str] = list(dict.fromkeys(
    CRYPTO_TOPICS + INFRA_TOPICS + GENERAL_TOPICS + DARKWEB_TOPICS
))

TOPIC_TIERS = {
    "crypto":  CRYPTO_TOPICS,
    "infra":   INFRA_TOPICS,
    "general": GENERAL_TOPICS,
    "darkweb": DARKWEB_TOPICS,
    "all":     ALL_TOPICS,
}

ALL_ENGINES = ["github", "gitlab", "huggingface", "docker",
               "gcs", "s3", "azure", "spaces", "bitbucket", "postman", "onion"]

KNOWN_BB_WORKSPACES = [
    # ── Crypto ──────────────────────────────────────────────────
    "bitcoin-core", "bitcoin", "ethereum", "ethereumproject",
    "ethereumjs", "solana-labs", "polkadot", "cosmos",
    "avalanche", "near", "cardano-foundation", "algorand",
    "monero-project", "monero", "zcash", "zcash-hackworks",
    "litecoin-project", "ripple", "stellar", "tronprotocol",
    "sui", "aptos-labs", "sei", "injective",
    # ── Security / Auditing ─────────────────────────────────────
    "trailofbits", "openzeppelin", "consensys",
    "quantstamp", "certik", "peckshield", "slowmist",
    "halborn", "chainsecurity", "byterocket",
    "immunefi", "hackenproof", "code4rena",
    "blocksec", "samczsun",
    # ── Wallets ─────────────────────────────────────────────────
    "metamask", "trustwallet", "myetherwallet",
    "phantom", "solflare", "electrum",
    "wasabiwallet", "sparrow-wallet", "bluewallet",
    "ledgerhq", "trezor", "safe-global",
    # ── Dev Tooling ─────────────────────────────────────────────
    "foundry", "hardhat", "trufflesuite", "dapphub",
    "web3j", "web3js", "web3py", "ethers-io",
    "vyperlang", "solidity",
    "chainlink", "aave", "uniswap", "makerdao",
    "compound-finance", "curvefi",
    # ── Cloud / Infra ───────────────────────────────────────────
    "googlecloudplatform", "google-cloud",
    "aws-samples", "azure", "heroku",
    "hashicorp", "vault", "terraform",
    "kubernetes", "docker", "helm",
    "jenkinsci", "ansible", "gitlab",
    # ── Security Research ───────────────────────────────────────
    "cobalt-io", "bugcrowd", "hackerone",
    "projectdiscovery", "swisskyrepo",
    "danielmiessler", "payloadbox",
    "carlospolop", "orange-tsai",
]

# ── Known high-signal GitHub orgs for org-probe ─────────────────
GITHUB_KNOWN_ORGS = [
    "ethereum", "bitcoin", "solana-labs", "polkadot", "cosmos",
    "near", "aptos-labs", "sui", "monero-project", "zcash",
    "openzeppelin", "foundry-rs", "web3", "web3j", "ethers-io",
    "metamask", "trustwallet", "safe-global", "ledgerhq", "trezor",
    "aave", "uniswap", "compound-finance", "makerdao", "curvefi",
    "chainlink", "lido", "1inch", "morpho-org", "pendle-finance",
    "eigenlayer", "etherfi", "renzo-protocol",
    "layerzero-labs", "wormhole-foundation",
    "offchainlabs", "ethereum-optimism", "base-org",
    "matter-labs", "scroll-tech", "starkware-libs",
    "googlecloudplatform", "aws-samples", "hashicorp",
    "trailofbits", "certik", "peckshield",
    "projectdiscovery", "trufflesecurity", "gitleaks",
]

# ── Docker Hub darknet queries ──────────────────────────────────
DOCKER_DARKNET_QUERIES = [
    "tor hidden", "onion service", "i2p router",
    "darknet", "privacy proxy", "mixnet",
]

# ── HuggingFace darknet queries ─────────────────────────────────
HF_DARKNET_QUERIES = [
    "onion", "tor hidden", "darknet", "privacy",
    "anonymous communication", "censorship resistant",
]

# ── Postman darknet queries ─────────────────────────────────────
POSTMAN_DARKNET_QUERIES = [
    "onion", "tor", "darknet", "bitcoin rpc",
    "monero wallet", "privacy",
]

# ── Bitbucket darknet workspace probes ──────────────────────────
DARKNET_ORGS = [
    "onionshare", "torproject", "privacytools",
    "darknet-market", "monero-ecosystem",
    "zcashexplorer", "wasabiwallet",
]


# =============================================================================
# TOKEN LOADING
# =============================================================================

def load_env_tokens() -> Dict[str, Any]:
    tokens: Dict[str, Any] = {
        "github": [],
        "gitlab": [],
        "huggingface": [],
        "bitbucket_user": "",
        "bitbucket_pass": "",
        "bitbucket_api_token": "",
        "docker_user": "",
        "docker_token": "",
        "postman_key": "",
    }
    if not os.path.exists(ENV_FILE):
        return tokens
    try:
        with open(ENV_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                # GitHub tokens (single or comma-separated)
                m = re.match(r'^\s*GITHUB_TOKENS?\s*=\s*(.+)$', line, re.IGNORECASE)
                if m:
                    raw = m.group(1).strip().strip('"').strip("'")
                    toks = [t.strip() for t in re.split(r'[,;\s]+', raw)
                            if t.strip() and not re.search(r'xxxx|your_|YOUR_|ghp_xxxx', t, re.IGNORECASE)]
                    tokens["github"].extend(toks)
                    continue
                # GitLab tokens
                m = re.match(r'^\s*GITLAB_TOKENS?\s*=\s*(.+)$', line, re.IGNORECASE)
                if m:
                    raw = m.group(1).strip().strip('"').strip("'")
                    toks = [t.strip() for t in re.split(r'[,;\s]+', raw)
                            if t.strip() and not re.search(r'xxxx|your_|YOUR_', t, re.IGNORECASE)
                            and t.startswith("glpat-")]
                    tokens["gitlab"].extend(toks)
                    continue
                # HuggingFace tokens
                m = re.match(r'^\s*HUGGINGFACE_TOKENS?\s*=\s*(.+)$', line, re.IGNORECASE)
                if m:
                    raw = m.group(1).strip().strip('"').strip("'")
                    toks = [t.strip() for t in re.split(r'[,;\s]+', raw)
                            if t.strip() and not re.search(r'xxxx|your_|YOUR_', t, re.IGNORECASE)]
                    tokens["huggingface"].extend(toks)
                    continue
                # Bitbucket
                m = re.match(r'^\s*BITBUCKET_USERNAME\s*=\s*([^#]+)', line)
                if m:
                    tokens["bitbucket_user"] = m.group(1).strip()
                    continue
                m = re.match(r'^\s*BITBUCKET_APP_PASSWORD\s*=\s*(.+)$', line)
                if m:
                    tokens["bitbucket_pass"] = m.group(1).strip().strip('"').strip("'")
                    continue
                # Postman
                m = re.match(r'^\s*POSTMAN_API_KEY\s*=\s*(.+)$', line)
                if m:
                    tokens["postman_key"] = m.group(1).strip().strip('"').strip("'")
                    continue
                # Docker Hub
                m = re.match(r'^\s*DOCKER_HUB_USERNAME\s*=\s*([^#]+)', line)
                if m:
                    tokens["docker_user"] = m.group(1).strip()
                    continue
                m = re.match(r'^\s*DOCKER_HUB_TOKEN\s*=\s*(.+)$', line)
                if m:
                    tok = m.group(1).strip().strip('"').strip("'")
                    tokens["docker_token"] = tok
                    continue
    except Exception:
        pass

    # Remove duplicates
    for k in ("github", "gitlab", "huggingface"):
        tokens[k] = list(dict.fromkeys(tokens[k]))
    return tokens


# =============================================================================
# HTTP HELPERS  (rate-limit aware)
# =============================================================================

def jittered_backoff(attempt: int, base_ms: int = 1000) -> float:
    """Exponential backoff with jitter, capped at 60s. Returns seconds."""
    backoff = min(base_ms * (2 ** attempt), 60000)
    jitter = random.randint(0, max(1, int(backoff * 0.3)))
    return (backoff + jitter) / 1000.0


def http_request(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    method: str = "GET",
    data: Optional[bytes] = None,
    token_rotator = None,
    throttle: Optional[ResourceThrottle] = None,
) -> Dict[str, Any]:
    """Perform an HTTP request with optional rate-limit awareness.

    Returns JSON-parsed body, or a dict with _error / _code on failure.
    Detects 403/429 and extracts Retry-After / X-RateLimit-Reset for backoff.
    """
    if throttle:
        throttle.wait_if_hot()

    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            if v:
                req.add_header(k, v)

    # Determine max retries: 4 for auth'd requests, only 2 for anonymous
    has_auth = bool(headers and any(
        v for k, v in headers.items()
        if k.lower() in ("authorization", "x-api-key", "private-token")))
    max_attempts = 4 if has_auth else 2

    for attempt in range(max_attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as resp:
                # Check rate-limit headers for informational logging
                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining is not None:
                    try:
                        rem = int(remaining)
                        if rem < 5:
                            cprint(f"   ⚠ rate-limit low: {rem} remaining", color=C_YELLOW, dim=True)
                    except ValueError:
                        pass
                body = resp.read().decode("utf-8", errors="replace")
                return json.loads(body) if body else {}

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""

            # Rate-limited -- extract backoff from headers
            if e.code in (403, 429):
                retry_after = e.headers.get("Retry-After")
                reset_epoch = e.headers.get("X-RateLimit-Reset")
                wait_s = 10.0  # default

                if retry_after:
                    try:
                        wait_s = float(retry_after) + 1
                    except ValueError:
                        pass
                elif reset_epoch:
                    try:
                        wait_s = max(1, float(reset_epoch) - time.time() + 1)
                    except (ValueError, TypeError):
                        pass
                else:
                    wait_s = jittered_backoff(attempt, base_ms=3000)

                # For anonymous 403: if wait > 120s, skip retrying entirely
                if not has_auth and e.code == 403 and wait_s > 120:
                    cprint(f"   ⚠ HTTP 403 (anonymous, wait {wait_s:.0f}s) -- giving up",
                           color=C_YELLOW)
                    return {"_error": "rate-limited (anonymous 403)", "_code": 403}

                cprint(f"   ⚠ HTTP {e.code} rate-limited -- sleeping {wait_s:.0f}s "
                       f"(attempt {attempt+1}/{max_attempts})",
                       color=C_YELLOW)
                if token_rotator and hasattr(token_rotator, 'mark_token_ratelimited'):
                    token_rotator.mark_token_ratelimited(wait_s)
                time.sleep(wait_s)
                continue  # retry

            # Non-rate-limit error
            try:
                return json.loads(body) if body else {"_error": str(e), "_code": e.code}
            except Exception:
                return {"_error": str(e), "_code": e.code}

        except Exception as e:
            if attempt < 3:
                wait_s = jittered_backoff(attempt)
                time.sleep(wait_s)
                continue
            return {"_error": str(e)}

    return {"_error": "max retries exceeded"}


def http_head(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 6,
) -> int:
    """HTTP HEAD request. Returns status code, or 0 on failure."""
    req = urllib.request.Request(url, method="HEAD")
    if headers:
        for k, v in headers.items():
            if v:
                req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


# =============================================================================
# TOKEN ROTATOR  (improved, configurable budget, header-based resets)
# =============================================================================

class TokenRotator:
    """Thread-safe token rotator with configurable per-platform budgets.

    Default: 60 calls per token per hour, rotating round-robin.
    On rate-limit detection, the offending token is marked dead until
    the X-RateLimit-Reset epoch (or a configurable cooldown).
    """

    def __init__(self, tokens: List[str], platform: str = "unknown",
                 calls_per_hour: int = 60, cooldown_secs: int = 3600):
        self._tokens = list(tokens)
        self._idx = 0
        self._lock = threading.Lock()
        self._remain: Dict[str, int] = {}
        self._reset: Dict[str, float] = {}
        self._platform = platform
        self._calls_per_hour = calls_per_hour
        self._cooldown_secs = cooldown_secs
        for t in self._tokens:
            self._remain[t] = calls_per_hour
            self._reset[t] = time.time() + cooldown_secs

    @property
    def count(self) -> int:
        return len(self._tokens)

    def next(self) -> Optional[str]:
        with self._lock:
            if not self._tokens:
                return None
            now = time.time()
            for _ in range(len(self._tokens)):
                self._idx = (self._idx + 1) % len(self._tokens)
                t = self._tokens[self._idx]
                if now > self._reset.get(t, 0):
                    self._remain[t] = self._calls_per_hour
                    self._reset[t] = now + self._cooldown_secs
                if self._remain.get(t, 0) > 0:
                    self._remain[t] -= 1
                    return t
            # All exhausted — wait for the soonest reset
            soonest = min(self._reset.values()) if self._reset else now + 60
            wait = max(1, soonest - now)
            cprint(f"[{self._platform}] all tokens exhausted, waiting {wait:.0f}s...",
                   color=C_YELLOW, dim=True)
            self._lock.release()
            try:
                time.sleep(wait)
            finally:
                self._lock.acquire()
            # Reset all
            now = time.time()
            for t in self._tokens:
                self._remain[t] = self._calls_per_hour
                self._reset[t] = now + self._cooldown_secs
            return self._tokens[0] if self._tokens else None

    def mark_token_ratelimited(self, cooldown_secs: float = 3600):
        """Mark the current token as rate-limited for cooldown_secs."""
        with self._lock:
            if self._tokens and 0 <= self._idx < len(self._tokens):
                t = self._tokens[self._idx]
                self._remain[t] = 0
                self._reset[t] = time.time() + cooldown_secs

    def mark_token_dead(self, token: str):
        with self._lock:
            if token in self._remain:
                self._remain[token] = 0
                self._reset[token] = time.time() + self._cooldown_secs


# =============================================================================
# OUTPUT WRITER  (append-mode, JSONL option, resume support, dedup stats)
# =============================================================================

class OutputWriter:
    """Thread-safe line-delimited text writer with dedup.

    v3.0 improvements:
      - Append mode by default (--fresh to truncate)
      - JSONL output option (--format jsonl)
      - Pipe-escaping for default format
      - Resume support via .tmp file
      - Dedup stats (writes, skipped)
    """

    def __init__(self, output_path: str, food_path: str,
                 fresh: bool = False, no_dedup: bool = False,
                 jsonl: bool = False, resume: bool = False, targets_fmt: bool = False,
                 skip_probes: bool = False):
        self.output_path = output_path
        self.food_path = food_path
        self.no_dedup = no_dedup
        self.jsonl = jsonl
        self.skip_probes = skip_probes
        self._lock = threading.Lock()
        self._food_seen: Set[str] = set()
        self._repo_ids_seen: Set[str] = set()  # "source:owner/repo" normalized
        # v5.0: TTL-based dedup store
        self._ttl_store: dict[str, dict] = {}
        self._ttl_seconds: int = 14 * 86400  # default 14 days (overridden by --dedup-ttl)
        self._ttl_enabled: bool = True
        self._ffod_jsonl = food_path.replace(".txt", ".jsonl") if food_path.endswith(".txt") else food_path + ".jsonl"
        self._load_ttl_store()
        self._migrate_ffod_if_needed()
        self.total_written = 0
        self.total_skipped = 0
        self.total_duplicate_repos = 0  # same repo, different keyword
        self.total_seen = 0
        self.engine_counts: Dict[str, int] = {}
        self._resume_loaded = 0
        self.keyword_yield: Dict[str, int] = {}  # keyword → repos discovered
        self._targets_fmt = targets_fmt

        # Determine open mode
        if fresh:
            mode = "w"
        elif resume and os.path.exists(RESUME_TMP):
            mode = "a"
            cprint(f"[init] Found resume file {RESUME_TMP}, loading...", color=C_CYAN)
            self._load_resume()
        elif targets_fmt:
            mode = "a"  # targets mode always appends
        else:
            # In targets mode, always append (multiple engines write to same files)
            mode = "a" if os.path.exists(output_path) else "w"

        # Open output file
        try:
            self._fh = open(self.output_path if not resume else RESUME_TMP,
                            mode, encoding="utf-8")
        except Exception as e:
            cprint(f"[!] Cannot open output file {output_path}: {e}", color=C_BRED)
            self._fh = None
            return

        # Load existing output into dedup set (for append mode)
        if mode == "a" and not fresh:
            try:
                with open(self.output_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self._food_seen.add(line)
            except Exception:
                pass

        # Load food dedup file
        if not no_dedup and os.path.exists(food_path):
            try:
                with open(food_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Optionally skip probe entries
                            if skip_probes and ("|probe:" in line or "|ws-probe:" in line):
                                continue
                            self._food_seen.add(line)
            except Exception:
                pass

    def _load_resume(self):
        """Load existing .tmp file lines into dedup set."""
        try:
            with open(RESUME_TMP, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._food_seen.add(line)
                        self._resume_loaded += 1
            cprint(f"[resume] Loaded {self._resume_loaded} lines from .tmp", color=C_CYAN)
        except Exception:
            pass

    def _mkline(self, url: str, owner: str, repo: str, topic: str, source: str) -> str:
        """Build output line with pipe-escaping or JSONL."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if self.jsonl:
            rec = {
                "url": url, "owner": owner, "repo": repo,
                "topic": topic, "source": source, "ts": ts,
            }
            return json.dumps(rec, ensure_ascii=False)
        else:
            # Escape pipes in all fields
            def esc(s: str) -> str:
                return str(s).replace("\\", "\\\\").replace("|", "\\|")
            return f"{esc(url)}|{esc(owner)}|{esc(repo)}|{esc(topic)}|{esc(source)}|{ts}"

    def write(self, url: str, owner: str, repo: str, topic: str,
              source: str, food_line: str) -> bool:
        """Write a line to output and food file. Returns True on success."""
        line = self._mkline(url, owner, repo, topic, source)
        # Normalized repo identity key: "source:owner/repo" (lowercase)
        repo_id = f"{source}:{owner.lower()}/{repo.lower()}"

        with self._lock:
            self.total_seen += 1
            # Dedup check: exact food_line or output line
            if not self.no_dedup:
                if food_line in self._food_seen or line in self._food_seen:
                    self.total_skipped += 1
                    return False

            # Dedup check: same repo from a different keyword
            if not self.no_dedup and repo_id in self._repo_ids_seen:
                self.total_duplicate_repos += 1
                return False

            # Register repo ID and food lines
            if not self.no_dedup:
                self._food_seen.add(food_line)
                self._repo_ids_seen.add(repo_id)
            self._food_seen.add(line)

            # Write output line (deferred fsync outside lock)
            write_ok = True
            try:
                if self._fh is not None:
                    self._fh.write(line + "\n")
                    self._fh.flush()
            except Exception as e:
                cprint(f"[!] Failed to write line: {e}", color=C_BRED)
                write_ok = False

            # Write food line
            if not self.no_dedup:
                try:
                    with open(self.food_path, "a", encoding="utf-8") as ff:
                        ff.write(food_line + "\n")
                except Exception:
                    pass

            # ── Keyword yield tracking ───────────────────────────
            self.keyword_yield[topic] = self.keyword_yield.get(topic, 0) + 1

            if write_ok:
                self.total_written += 1
                self.engine_counts[source] = self.engine_counts.get(source, 0) + 1

        # fsync outside the lock to avoid deadlock
        if write_ok:
            try:
                if self._fh is not None:
                    os.fsync(self._fh.fileno())
            except Exception:
                pass

        return write_ok

    def flush(self) -> int:
        written = self.total_written
        try:
            if self._fh is not None:
                self._fh.flush()
                os.fsync(self._fh.fileno())
        except Exception:
            pass
        # If using resume tmp, rename to final on completion
        if os.path.exists(RESUME_TMP) and written > 0:
            try:
                os.rename(RESUME_TMP, self.output_path)
                cprint(f"[resume] Renamed {RESUME_TMP} → {self.output_path}", color=C_GREEN)
            except Exception:
                pass
        return written

    # ── v5.0: TTL dedup methods ─────────────────────────────────────

    def _load_ttl_store(self):
        """Load TTL dedup store from ffod.jsonl."""
        if not os.path.exists(self._ffod_jsonl):
            return
        try:
            with open(self._ffod_jsonl, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        uri = rec.get("uri", "")
                        if uri:
                            self._ttl_store[uri] = rec
                            self._food_seen.add(uri)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

    def _migrate_ffod_if_needed(self):
        """Migrate old flat ffod.txt to ffod.jsonl on first v5.0 run."""
        if self._ttl_store:
            return  # Already migrated
        if not os.path.exists(self.food_path):
            return
        # Only migrate if it's the old flat format
        try:
            count = 0
            with open(self.food_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if not line.startswith("{"):
                        # Old format — needs migration
                        now = datetime.now(timezone.utc).isoformat()
                        self._ttl_store[line] = {"uri": line, "first_seen": now,
                                                  "last_seen": now, "scan_count": 1,
                                                  "last_scanned_at": now}
                        self._food_seen.add(line)
                        count += 1
            if count > 0:
                self._flush_ttl_store()
                cprint(f"[init] Migrated {count} entries from ffod.txt → ffod.jsonl (TTL enabled)", color=C_CYAN)
        except Exception:
            pass

    def _flush_ttl_store(self):
        """Write TTL store to ffod.jsonl."""
        try:
            with open(self._ffod_jsonl, "w") as f:
                for uri, rec in self._ttl_store.items():
                    f.write(json.dumps(rec) + "\n")
        except Exception:
            pass

    def is_expired(self, uri: str) -> bool:
        """Check if a URI's TTL has expired and it can be re-scanned."""
        if not self._ttl_enabled or uri not in self._ttl_store:
            return True  # Not in store = eligible
        rec = self._ttl_store[uri]
        last = rec.get("last_scanned_at", rec.get("first_seen", ""))
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - last_dt).total_seconds()
            return age > self._ttl_seconds
        except Exception:
            return True

    def touch_uri(self, uri: str):
        """Update last_seen for a URI in the TTL store."""
        now = datetime.now(timezone.utc).isoformat()
        if uri in self._ttl_store:
            self._ttl_store[uri]["last_seen"] = now
            self._ttl_store[uri]["scan_count"] = self._ttl_store[uri].get("scan_count", 0) + 1
            self._ttl_store[uri]["last_scanned_at"] = now
        else:
            self._ttl_store[uri] = {"uri": uri, "first_seen": now, "last_seen": now,
                                     "scan_count": 1, "last_scanned_at": now}

    def reap_stale(self, max_age_days: int = 90):
        """Remove entries older than max_age_days from TTL store."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        stale = [u for u, r in self._ttl_store.items()
                 if r.get("last_scanned_at", r.get("first_seen", "")) < cutoff]
        for u in stale:
            del self._ttl_store[u]
            self._food_seen.discard(u)
        if stale:
            self._flush_ttl_store()
            cprint(f"[reap] Removed {len(stale)} stale entries (> {max_age_days} days)", color=C_CYAN)

    def close(self):
        try:
            if self._fh is not None:
                self._fh.close()
        except Exception:
            pass



# =============================================================================
# v5.0: ATLAS-DRIVEN INTELLIGENCE
# =============================================================================

def load_target_scores() -> dict:
    """Load .target_scores.json, return empty dict if missing."""
    path = os.path.join(HOME, ".target_scores.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_target_scores(scores: dict) -> None:
    """Save .target_scores.json atomically."""
    path = os.path.join(HOME, ".target_scores.json")
    try:
        with open(path, "w") as f:
            json.dump(scores, f, indent=2)
    except Exception as e:
        cprint(f"[!] Failed to save target scores: {e}", color=C_RED)


def rank_engines_by_yield() -> list[tuple[str, float, int, int]]:
    """Rank engines by funded_hits / total_scans from .scan_outcomes.jsonl.

    Returns [(engine_name, yield_ratio, funded_hits, total_scans), ...] sorted by yield desc.
    """
    outcomes_path = os.path.join(HOME, ".scan_outcomes.jsonl")
    if not os.path.exists(outcomes_path):
        return []

    engine_stats: dict[str, dict[str, int]] = {}
    try:
        with open(outcomes_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                plat = rec.get("platform", "unknown")
                if plat not in engine_stats:
                    engine_stats[plat] = {"scans": 0, "funded": 0}
                engine_stats[plat]["scans"] += 1
                if rec.get("has_balance"):
                    engine_stats[plat]["funded"] += 1
    except Exception:
        return []

    ranked = []
    for eng, stats in engine_stats.items():
        ratio = stats["funded"] / max(stats["scans"], 1)
        ranked.append((eng, round(ratio, 4), stats["funded"], stats["scans"]))

    ranked.sort(key=lambda x: -x[1])
    return ranked


def generate_atlas_queries(atlas: dict, boost_count: int = 15) -> list[str]:
    """Generate precise search queries from atlas signal data.

    Uses top_filenames → GitHub filename: qualifiers, signal_paths → path: qualifiers,
    and promote_globs → code search patterns.
    """
    queries = []

    # Filename-based queries (highest precision)
    for fn in atlas.get("top_filenames", [])[:boost_count]:
        name = fn if isinstance(fn, str) else fn.get("name", str(fn))
        if name and len(name) > 1:
            queries.append(f"filename:{name}")

    # Path-based queries
    for sp in atlas.get("signal_paths", [])[:boost_count]:
        path = sp if isinstance(sp, str) else sp.get("path", str(sp))
        if path and len(path) > 2 and "/" in path:
            queries.append(f"path:{path}")

    # Promote globs
    for pg in atlas.get("promote_globs", [])[:int(boost_count/2)]:
        glob_pat = pg if isinstance(pg, str) else pg.get("glob", str(pg))
        if glob_pat and len(glob_pat) > 2:
            queries.append(glob_pat.replace("**/", "").replace("*", ""))

    return list(dict.fromkeys(queries))  # dedup preserving order


def generate_atlas_bucket_names(atlas: dict, hot_targets: list[dict], max_names: int = 5000) -> list[str]:
    """Generate cloud bucket name candidates from atlas signal patterns.

    Uses top_filenames, promote_globs, and hot target org names combined with signal suffixes.
    """
    candidates = set()
    suffixes = ["-secrets", "-secret", "-keys", "-key", "-private", "-backup", "-backups",
                "-dump", "-data", "-config", "-env", "-envs", "-credentials", "-creds",
                "-production", "-prod", "-wallet", "-crypto", "-api", "-tokens", "-storage"]

    # From top_filenames: strip extensions, use as bucket name roots
    for fn in atlas.get("top_filenames", [])[:30]:
        name = fn if isinstance(fn, str) else fn.get("name", str(fn))
        if name:
            root = name.rsplit(".", 1)[0] if "." in name else name
            root = re.sub(r"[^a-z0-9-]", "", root.lower())
            if 3 <= len(root) <= 40:
                candidates.add(root)
                for s in suffixes[:6]:
                    candidates.add(f"{root}{s}")

    # From promote_globs: extract meaningful name parts
    for pg in atlas.get("promote_globs", [])[:10]:
        pg_str = pg if isinstance(pg, str) else pg.get("glob", str(pg))
        parts = re.findall(r"[a-z0-9_-]{3,}", pg_str.lower())
        for p in parts:
            p = p.strip("_-")
            if 3 <= len(p) <= 40:
                candidates.add(p)

    # From hot target org names: combine with signal suffixes
    for ht in hot_targets[:100]:
        uri = ht.get("uri", "")
        m = re.search(r"github\.com/([A-Za-z0-9_.-]+)", uri)
        if m:
            org = m.group(1).lower().replace(".", "-")
            if 3 <= len(org) <= 40:
                for s in suffixes[:5]:
                    candidates.add(f"{org}{s}")

    return list(candidates)[:max_names]


def update_target_scores_from_outcomes() -> int:
    """Read .scan_outcomes.jsonl and update .target_scores.json + .hot_targets.json.

    Returns number of scores updated.
    """
    outcomes_path = os.path.join(HOME, ".scan_outcomes.jsonl")
    scores_path = os.path.join(HOME, ".target_scores.json")
    hot_path = os.path.join(HOME, ".hot_targets.json")

    if not os.path.exists(outcomes_path):
        return 0

    scores = load_target_scores()
    updated = 0

    try:
        with open(outcomes_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                uri = rec.get("uri", "")
                if not uri:
                    continue

                # Generate a stable key from URI
                key = hashlib.md5(uri.encode()).hexdigest()[:16]

                if key not in scores:
                    scores[key] = {"uri": uri, "platform": rec.get("platform", "?"),
                                   "score": 0.5, "key_hits": 0, "balance_hits": 0,
                                   "scans": 0, "empty_scans": 0, "demoted": False,
                                   "never_expire": False}

                entry = scores[key]
                entry["scans"] = entry.get("scans", 0) + 1
                entry["last_updated"] = datetime.now(timezone.utc).isoformat()
                entry["last_outcome"] = rec.get("ts", "")

                if rec.get("has_balance"):
                    entry["balance_hits"] = entry.get("balance_hits", 0) + 1
                    entry["score"] = min(10.0, entry.get("score", 0.5) * 2.0)
                    entry["never_expire"] = True
                elif rec.get("has_key"):
                    entry["key_hits"] = entry.get("key_hits", 0) + 1
                    entry["score"] = min(10.0, entry.get("score", 0.5) * 1.3)
                else:
                    entry["empty_scans"] = entry.get("empty_scans", 0) + 1

                # Demote if 3+ scans with zero hits
                if entry.get("scans", 0) >= 3 and entry.get("balance_hits", 0) == 0 and entry.get("key_hits", 0) == 0:
                    if not entry.get("never_expire"):
                        entry["score"] = entry.get("score", 0.5) * 0.1
                        entry["demoted"] = True

                updated += 1

    except Exception as e:
        cprint(f"[!] Target scoring error: {e}", color=C_RED)
        return updated

    save_target_scores(scores)

    # Update .hot_targets.json with top 350
    try:
        ranked = sorted(scores.values(), key=lambda x: -x.get("score", 0))
        # Filter demoted and keep top N
        hot = [r for r in ranked if not r.get("demoted")][:350]
        hot_targets = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(hot),
            "targets": [{"uri": r["uri"], "platform": r.get("platform", "?"),
                        "score": r.get("score", 0),
                        "origins": ["outcome_scoring"]} for r in hot]
        }
        with open(hot_path, "w") as f:
            json.dump(hot_targets, f, indent=2)
    except Exception:
        pass

    return updated


# =============================================================================
# v5.0: ONION/CLEARNET CORRELATION ENGINE (first-class)
# =============================================================================

def scrape_onion_clearnet(out: OutputWriter, topic: str, target_count: int,
                          onion_proxy: str = "127.0.0.1:9050",
                          throttle: Optional[ResourceThrottle] = None):
    """v5.0: First-class onion/clearnet correlation engine.

    Scans existing paste_box.txt for .onion addresses, resolves them via Tor SOCKS proxy,
    fingerprints services, and cross-references against known darknet infrastructure.
    """
    if out.total_written >= target_count:
        return

    cprint(f"   onion-engine: scanning for .onion addresses...", color=C_MAGENTA)

    onion_v3 = re.compile(r"[a-z2-7]{56}\.onion", re.I)
    paste_path = os.path.join(HOME, "paste_box.txt")
    found = 0

    if not os.path.exists(paste_path):
        cprint("   onion-engine: no paste_box.txt yet, skipping", color=C_DIM)
        return

    seen_onions: set = set()
    try:
        with open(paste_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if out.total_written >= target_count:
                    break
                matches = onion_v3.findall(line)
                for addr in matches:
                    addr_lower = addr.lower()
                    if addr_lower in seen_onions:
                        continue
                    seen_onions.add(addr_lower)

                    # Try to resolve via Tor SOCKS proxy
                    service_info = _probe_onion_service(addr, onion_proxy)
                    if service_info:
                        tags = ["onion-correlation"]
                        if service_info.get("title"):
                            tags.append(f"title:{service_info['title'][:40]}")
                        if service_info.get("server"):
                            tags.append(f"server:{service_info['server'][:30]}")
                        topic_str = ";".join(tags)
                        out.write(f"http://{addr}", "onion", addr, topic_str, "onion", f"onion:{addr_lower}")
                        found += 1
                    else:
                        # Still record the discovery even if probe fails
                        out.write(f"http://{addr}", "onion", addr, "onion-correlation:unreachable", "onion", f"onion:{addr_lower}")
                        found += 1
    except Exception as e:
        cprint(f"   onion-engine: error {e}", color=C_RED)

    if found:
        cprint(f"   onion-engine: +{found} onion services discovered", color=C_GREEN)
    else:
        cprint(f"   onion-engine: no new onion addresses found", color=C_DIM)


def _probe_onion_service(addr: str, proxy: str = "127.0.0.1:9050", timeout: int = 10) -> dict | None:
    """Attempt to connect to an .onion service via Tor SOCKS proxy and fingerprint it."""
    try:
        import socks
        host, port = proxy.split(":")
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, host, int(port))
        s.settimeout(timeout)

        onion_host = addr.rstrip("/")
        if "://" in onion_host:
            onion_host = onion_host.split("://")[1]
        onion_host = onion_host.split("/")[0]

        s.connect((onion_host, 80))
        s.sendall(f"GET / HTTP/1.0\r\nHost: {onion_host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        s.close()

        info = {}
        for line in resp.split("\r\n"):
            if line.lower().startswith("server:"):
                info["server"] = line.split(":", 1)[1].strip()[:50]
            if line.lower().startswith("content-type:"):
                info["content_type"] = line.split(":", 1)[1].strip()[:50]
        # Extract title
        tm = re.search(r"<title>([^<]+)</title>", resp, re.I)
        if tm:
            info["title"] = tm.group(1).strip()[:60]
        return info if info else {"fingerprint": "connected"}
    except ImportError:
        # PySocks not installed — skip probing but don't crash
        return None
    except Exception:
        return None


# =============================================================================
# ENGINE: GITHUB
# =============================================================================

def scrape_github(out: OutputWriter, token_rotator: TokenRotator,
                  topic: str, target_count: int, deep: bool = False,
                  throttle: Optional[ResourceThrottle] = None):
    max_pages = 5
    for page in range(1, max_pages + 1):
        if out.total_written >= target_count:
            break
        token = token_rotator.next()
        q = urllib.parse.quote(f"{topic} in:name,description,readme")
        url = f"https://api.github.com/search/repositories?q={q}&sort=stars&order=desc&per_page=100&page={page}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Mozilla/5.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        resp = http_request(url, headers=headers, timeout=45,
                            token_rotator=token_rotator, throttle=throttle)
        if not resp or resp.get("_error"):
            err = resp.get("_error", "unknown") if resp else "no response"
            code = resp.get("_code", "") if resp else ""
            cprint(f"   github API error ({code}): {err}", color=C_RED)
            if code == 403 or code == 429:
                continue  # retry with next token
            break
        if not resp.get("items"):
            break

        written_before = out.total_written
        for item in resp.get("items", []):
            if out.total_written >= target_count:
                break
            html_url = item.get("html_url", "")
            owner_login = item.get("owner", {}).get("login", "")
            repo_name = item.get("name", "")
            food = f"https://github.com/{owner_login}/{repo_name}.git"
            out.write(html_url, owner_login, repo_name, topic, "github", food)

        new_written = out.total_written - written_before
        cprint(f"   github page {page}: +{new_written} | Total: {out.total_written}/{target_count}", color=C_GREEN)
        time.sleep(1.5 + random.uniform(0, 1.0))

    # --deep: also search code
    if deep and out.total_written < target_count:
        cprint(f"   github deep: searching code for '{topic}'...", color=C_BLUE, dim=True)
        for page in range(1, 3):
            if out.total_written >= target_count:
                break
            token = token_rotator.next()
            q = urllib.parse.quote(f"{topic} in:file")
            url = f"https://api.github.com/search/code?q={q}&sort=indexed&order=desc&per_page=100&page={page}"
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Mozilla/5.0",
            }
            if token:
                headers["Authorization"] = f"Bearer {token}"

            resp = http_request(url, headers=headers, timeout=45,
                                token_rotator=token_rotator, throttle=throttle)
            if not resp or resp.get("_error") or not resp.get("items"):
                break
            for item in resp.get("items", []):
                if out.total_written >= target_count:
                    break
                repo_info = item.get("repository", {})
                html_url = repo_info.get("html_url", "")
                owner_login = repo_info.get("owner", {}).get("login", "")
                repo_name = repo_info.get("name", "")
                if html_url and owner_login and repo_name:
                    food = f"https://github.com/{owner_login}/{repo_name}.git"
                    out.write(html_url, owner_login, repo_name, f"code:{topic}", "github", food)
            time.sleep(2.0 + random.uniform(0, 1.0))


# =============================================================================
# ENGINE: GITLAB
# =============================================================================

def scrape_gitlab(out: OutputWriter, token_rotator: TokenRotator,
                  topic: str, target_count: int, deep: bool = False,
                  throttle: Optional[ResourceThrottle] = None):
    pages = 3 if token_rotator.count == 0 else 5
    pp = 100
    for page in range(1, pages + 1):
        if out.total_written >= target_count:
            break
        token = token_rotator.next()
        q = urllib.parse.quote(topic)
        url = f"https://gitlab.com/api/v4/projects?search={q}&per_page={pp}&page={page}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        if token:
            headers["PRIVATE-TOKEN"] = token

        items = http_request(url, headers=headers, timeout=30,
                             token_rotator=token_rotator, throttle=throttle)
        # Empty list = no results for this query (not an error)
        if isinstance(items, list) and len(items) == 0:
            break
        # Dict with _error = real API or connection error
        if isinstance(items, dict) and items.get("_error"):
            err = items.get("_error", "unknown")
            code = items.get("_code", "")
            cprint(f"   gitlab API error ({code}): {err}", color=C_RED)
            break
        if not isinstance(items, list):
            cprint(f"   gitlab unexpected response type: {type(items).__name__}", color=C_RED)
            break

        written_before = out.total_written
        for item in items:
            if out.total_written >= target_count:
                break
            ns = item.get("path_with_namespace", "")
            if not ns or "/" not in ns:
                continue
            parts = ns.split("/")
            owner = parts[0]
            repo_name = parts[-1]
            web_url = f"https://gitlab.com/{ns}"
            food = f"https://gitlab.com/{ns}.git"
            out.write(web_url, owner, repo_name, topic, "gitlab", food)

        new_written = out.total_written - written_before
        cprint(f"   gitlab page {page}: +{new_written} | Total: {out.total_written}/{target_count}", color=C_GREEN)
        time.sleep(1.5 + random.uniform(0, 1.0))


# =============================================================================
# ENGINE: HUGGINGFACE
# =============================================================================

def scrape_huggingface(out: OutputWriter, token_rotator: TokenRotator,
                       topic: str, target_count: int,
                       throttle: Optional[ResourceThrottle] = None):
    token = token_rotator.next() if token_rotator.count > 0 else None
    search_queries = [topic]
    if " " in topic:
        first_word = topic.split()[0]
        if first_word != topic:
            search_queries.append(first_word)

    for q in search_queries:
        if out.total_written >= target_count:
            break
        q_enc = urllib.parse.quote(q)
        for kind in ("models", "datasets", "spaces"):
            if out.total_written >= target_count:
                break
            url = f"https://huggingface.co/api/{kind}?search={q_enc}&limit=100"
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            }
            if token:
                headers["Authorization"] = f"Bearer {token}"

            items = http_request(url, headers=headers, timeout=30, throttle=throttle)
            if not items or not isinstance(items, list):
                continue

            written_before = out.total_written
            for item in items:
                if out.total_written >= target_count:
                    break
                item_id = item.get("id", "")
                if not item_id or "/" not in item_id:
                    continue
                parts = item_id.split("/")
                owner = parts[0]
                repo_name = parts[-1]
                hf_url = f"https://huggingface.co/{item_id}"
                out.write(hf_url, owner, repo_name, topic, "huggingface", f"hf:{item_id}")

            new_written = out.total_written - written_before
            if new_written > 0:
                cprint(f"   huggingface '{q}' {kind}: +{new_written} | Total: {out.total_written}/{target_count}", color=C_GREEN)
            time.sleep(0.8)


# =============================================================================
# ENGINE: DOCKER HUB
# =============================================================================

def scrape_docker(out: OutputWriter, topic: str, target_count: int,
                  throttle: Optional[ResourceThrottle] = None,
                  docker_user: str = "", docker_token: str = ""):
    # Build auth header if credentials are available
    auth_headers = {}
    if docker_user and docker_token and not re.search(
            r'your_|xxxx|YOUR_', docker_user + docker_token, re.IGNORECASE):
        cred_bytes = f"{docker_user}:{docker_token}".encode("utf-8")
        import base64 as _b64
        auth_headers["Authorization"] = "Basic " + _b64.b64encode(cred_bytes).decode("ascii")

    max_pages = 5
    for page in range(1, max_pages + 1):
        if out.total_written >= target_count:
            break
        q = urllib.parse.quote(topic)
        url = f"https://hub.docker.com/v2/search/repositories/?query={q}&page_size=100&page={page}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
            **auth_headers,
        }

        resp = http_request(url, headers=headers, timeout=30, throttle=throttle)
        if not resp or not resp.get("results"):
            break

        written_before = out.total_written
        for r in resp.get("results", []):
            if out.total_written >= target_count:
                break
            name = r.get("repo_name", "")
            if not name:
                continue
            if "/" in name:
                parts = name.split("/")
                owner = parts[0]
                repo_name = parts[-1]
            else:
                owner = "library"
                repo_name = name
            docker_url = f"https://hub.docker.com/r/{name}"
            out.write(docker_url, owner, repo_name, topic, "docker", f"docker:{name}:latest")

        new_written = out.total_written - written_before
        cprint(f"   docker page {page}: +{new_written} | Total: {out.total_written}/{target_count}", color=C_GREEN)
        time.sleep(1.5 + random.uniform(0, 1.0))


# =============================================================================
# ENGINE: BITBUCKET  (improved — only write confirmed-live probes)
# =============================================================================

def scrape_bitbucket(out: OutputWriter, topic: str, target_count: int,
                     bb_user: str, bb_pass: str, bb_api_token: str,
                     throttle: Optional[ResourceThrottle] = None):
    cred = ""
    has_creds = False
    auth_type = "Basic"

    if bb_api_token and not re.search(r"your_|xxxx|YOUR_", bb_api_token, re.IGNORECASE):
        cred = bb_api_token
        has_creds = True
        auth_type = "Bearer"
    elif bb_user and bb_pass and "your_" not in bb_user.lower() and "your_" not in bb_pass.lower():
        cred_bytes = f"{bb_user}:{bb_pass}".encode("utf-8")
        cred = base64.b64encode(cred_bytes).decode("ascii")
        has_creds = True
        auth_type = "Basic"

    if has_creds:
        max_pages = 5
        pp = 100
        for page in range(1, max_pages + 1):
            if out.total_written >= target_count:
                break
            q = urllib.parse.quote(f'name~"{topic}" OR description~"{topic}"')
            url = f"https://api.bitbucket.org/2.0/repositories?q={q}&sort=-updated_on&pagelen={pp}&page={page}"
            headers = {
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0",
            }
            if auth_type == "Bearer":
                headers["Authorization"] = f"Bearer {cred}"
            else:
                headers["Authorization"] = f"Basic {cred}"

            resp = http_request(url, headers=headers, timeout=30, throttle=throttle)
            if not resp or not resp.get("values"):
                break

            written_before = out.total_written
            for item in resp.get("values", []):
                if out.total_written >= target_count:
                    break
                full_name = item.get("full_name", "")
                if not full_name or "/" not in full_name:
                    continue
                parts = full_name.split("/")
                owner = parts[0]
                repo_name = parts[-1]
                try:
                    html_url = item["links"]["html"]["href"]
                except (KeyError, TypeError):
                    html_url = f"https://bitbucket.org/{full_name}"
                food = f"https://bitbucket.org/{full_name}.git"
                out.write(html_url, owner, repo_name, topic, "bitbucket", food)

            new_written = out.total_written - written_before
            cprint(f"   bitbucket API page {page}: +{new_written} | Total: {out.total_written}/{target_count}", color=C_GREEN)
            time.sleep(1.5 + random.uniform(0, 1.0))

    # Workspace probe (only write confirmed-live repos)
    if out.total_written < target_count:
        cprint("   bitbucket: probing known workspaces...", color=C_YELLOW)
        probed = 0
        for ws in KNOWN_BB_WORKSPACES:
            if probed >= 20:
                break
            probed += 1
            ws_url = f"https://bitbucket.org/{ws}/"
            headers_h = {"User-Agent": "Mozilla/5.0"}
            if has_creds:
                if auth_type == "Bearer":
                    headers_h["Authorization"] = f"Bearer {cred}"
                else:
                    headers_h["Authorization"] = f"Basic {cred}"
            status = http_head(ws_url, headers=headers_h)
            if status == 200:
                cprint(f"   bitbucket workspace LIVE: {ws}", color=C_GREEN)
                # Confirm a few sample repos exist before writing
                words = [w for w in re.split(r'[^a-z0-9]+', topic.lower())
                        if len(w) >= 3 and not w.isdigit()][:3]
                for w in words:
                    if out.total_written >= target_count:
                        break
                    candidate_url = f"https://bitbucket.org/{ws}/{w}"
                    st = http_head(candidate_url, headers=headers_h)
                    if st == 200:
                        out.write(candidate_url, ws, w, f"ws-probe:{topic}", "bitbucket",
                                  f"https://bitbucket.org/{ws}/{w}.git")
                        cprint(f"     → confirmed: {candidate_url}", color=C_GREEN)
            time.sleep(0.3)

    # Git URL probe (only write confirmed-live)
    if out.total_written < target_count:
        cprint("   bitbucket: probing git URLs from topic keywords...", color=C_YELLOW)
        probe_words = [w for w in re.split(r'[^a-z0-9]+', topic.lower())
                       if len(w) >= 4 and not w.isdigit()][:8]
        probe_count = 0
        headers_h = {"User-Agent": "Mozilla/5.0"}
        for pw in probe_words:
            if out.total_written >= target_count or probe_count >= 5:
                break
            probe_count += 1
            candidates = [
                pw, f"{pw}-tool", f"{pw}-tools", f"{pw}-scanner",
                f"{pw}-key", f"{pw}-keys", f"{pw}-secret", f"{pw}-secrets",
                f"{pw}-wallet", f"{pw}-crypto", f"{pw}-leak", f"{pw}-leaks",
            ]
            for cand in candidates[:5]:
                if out.total_written >= target_count:
                    break
                candidate_url = f"https://bitbucket.org/bitbucket/{cand}"
                st = http_head(candidate_url, headers=headers_h)
                if st == 200:
                    out.write(candidate_url, "bitbucket", cand, f"probe:{topic}", "bitbucket",
                              f"https://bitbucket.org/bitbucket/{cand}.git")
                    cprint(f"     → confirmed: {candidate_url}", color=C_GREEN)

    if out.engine_counts.get("bitbucket", 0) == 0:
        if has_creds:
            cprint(f"   bitbucket: no results for '{topic}'", color=C_GRAY)
        else:
            cprint("   bitbucket: no valid creds — probe-only mode", color=C_GRAY)


# =============================================================================
# ENGINE: POSTMAN
# =============================================================================

def scrape_postman(out: OutputWriter, topic: str, target_count: int,
                   pm_key: str, throttle: Optional[ResourceThrottle] = None):
    max_pages = 3
    pp = 50
    for page in range(max_pages):
        if out.total_written >= target_count:
            break
        q = urllib.parse.quote(topic)
        url = f"https://api.getpostman.com/collections?search={q}&limit={pp}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        if pm_key and not re.search(r'your_|xxxx|YOUR_', pm_key, re.IGNORECASE):
            headers["X-Api-Key"] = pm_key

        resp = http_request(url, headers=headers, timeout=30, throttle=throttle)
        if not resp or not resp.get("collections"):
            break

        written_before = out.total_written
        for col in resp.get("collections", []):
            if out.total_written >= target_count:
                break
            uid = str(col.get("uid", ""))
            col_name = str(col.get("name", ""))
            if not uid:
                continue
            col_url = f"https://www.postman.com/collections/{uid}"
            out.write(col_url, "postman", col_name, topic, "postman", f"postman:{uid}")

        new_written = out.total_written - written_before
        cprint(f"   postman page {page}: +{new_written} | Total: {out.total_written}/{target_count}", color=C_GREEN)
        time.sleep(1.5 + random.uniform(0, 1.0))


# =============================================================================
# CLOUD BUCKET PROBING — multi-provider, multi-region, content-aware
# =============================================================================

# Provider configurations: label, endpoints, listing path, food prefix
CLOUD_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "s3": {
        "label": "AWS S3",
        "endpoints": [
            "https://{name}.s3.amazonaws.com",
            "https://{name}.s3.us-east-1.amazonaws.com",
            "https://{name}.s3.us-east-2.amazonaws.com",
            "https://{name}.s3.us-west-1.amazonaws.com",
            "https://{name}.s3.us-west-2.amazonaws.com",
            "https://{name}.s3.eu-west-1.amazonaws.com",
            "https://{name}.s3.eu-west-2.amazonaws.com",
            "https://{name}.s3.eu-central-1.amazonaws.com",
            "https://{name}.s3.ap-southeast-1.amazonaws.com",
            "https://{name}.s3.ap-southeast-2.amazonaws.com",
            "https://{name}.s3.ap-northeast-1.amazonaws.com",
            "https://{name}.s3.ap-south-1.amazonaws.com",
            "https://{name}.s3.sa-east-1.amazonaws.com",
        ],
        "listing_path": "?prefix=&max-keys=1000",
        "listing_namespace": "http://s3.amazonaws.com/doc/2006-03-01/",
        "food_prefix": "s3://",
    },
    "gcs": {
        "label": "Google Cloud Storage",
        "endpoints": [
            "https://storage.googleapis.com/{name}",
            "https://{name}.storage.googleapis.com",
        ],
        "listing_path": "?max-results=1000",
        "listing_namespace": "http://doc.s3.amazonaws.com/2006-03-01",
        "food_prefix": "gs://",
    },
    "azure": {
        "label": "Azure Blob Storage",
        "endpoints": [
            "https://{name}.blob.core.windows.net",
        ],
        "listing_path": "?restype=container&comp=list&maxresults=1000",
        "listing_namespace": "",
        "food_prefix": "azure://",
    },
    "spaces": {
        "label": "DigitalOcean Spaces",
        "endpoints": [
            "https://{name}.nyc3.digitaloceanspaces.com",
            "https://{name}.sfo2.digitaloceanspaces.com",
            "https://{name}.sfo3.digitaloceanspaces.com",
            "https://{name}.ams3.digitaloceanspaces.com",
            "https://{name}.sgp1.digitaloceanspaces.com",
            "https://{name}.fra1.digitaloceanspaces.com",
        ],
        "listing_path": "?prefix=&max-keys=1000",
        "listing_namespace": "http://s3.amazonaws.com/doc/2006-03-01/",
        "food_prefix": "do://",
    },
}

# ── Smart bucket name seed list ──────────────────────────────────
# These are common bucket-name patterns observed in real-world leaks:
# terraform state, cloudformation, elasticbeanstalk, backups, CI artifacts, etc.
BUCKET_SEEDS: List[str] = [
    # ── Infrastructure-as-Code state ─────────────────────────────
    "terraform-state", "terraform-tfstate", "tfstate", "tfstate-backend",
    "terraform-backend", "terraform", "tfvars",
    "cloudformation-templates", "cf-templates", "cfn-templates",
    "cdk-bootstrap", "cdk-assets", "cdktoolkit",
    "pulumi-state", "pulumi-backend",
    # ── AWS service buckets ──────────────────────────────────────
    "elasticbeanstalk", "beanstalk", "eb-deploy", "eb-app",
    "cloudtrail", "cloudtrail-logs", "aws-logs", "aws-log",
    "cloudfront-logs", "cloudfront", "cf-logs",
    "serverless-deploy", "serverless-state", "sls-deploy", "sls-state",
    "codepipeline", "codebuild", "codedeploy",
    "s3-access-logs", "elb-access-logs", "alb-access-logs",
    "aws-config", "config-bucket", "aws-inventory",
    "guardduty", "macie", "securityhub",
    # ── Backup / Archive ─────────────────────────────────────────
    "backup", "backups", "db-backup", "database-backup",
    "sql-backup", "sql-dump", "mongodb-backup", "postgres-backup",
    "mysql-backup", "redis-backup", "elasticsearch-backup",
    "snapshots", "snapshot", "ebs-snapshots", "rds-snapshots",
    "archive", "archives", "old-data", "cold-storage",
    "disaster-recovery", "dr-backup", "dr-replica",
    # ── Storage / Assets ─────────────────────────────────────────
    "assets", "media", "uploads", "downloads",
    "static", "static-assets", "static-files", "static-media",
    "cdn", "cdn-assets", "cdn-static", "cdn-media",
    "public", "public-assets", "public-files",
    "user-uploads", "user-files", "user-data",
    "app-data", "app-storage", "app-assets",
    "content", "content-store", "content-delivery",
    # ── Config / Secrets ─────────────────────────────────────────
    "config", "configs", "configuration", "app-config",
    "env-config", "env-files", "dotenv", "env-vars",
    "credentials", "creds", "secrets", "secret-config",
    "vault", "vault-data", "vault-backend", "vault-storage",
    "key-store", "keystore", "cert-store", "certs",
    "ssl-certs", "tls-certs", "certificates",
    "service-accounts", "sa-keys", "iam-keys",
    # ── CI/CD Artifacts ──────────────────────────────────────────
    "jenkins", "jenkins-artifacts", "jenkins-data",
    "gitlab-artifacts", "gitlab-ci", "gitlab-registry",
    "github-artifacts", "github-actions",
    "circleci", "circleci-artifacts", "circleci-cache",
    "travis-ci", "travis-artifacts",
    "build-artifacts", "build-output", "build-cache",
    "docker-registry", "docker-images", "container-registry",
    "helm-charts", "helm-repo", "chartmuseum",
    "packages", "releases", "artifacts", "dist",
    # ── Logs / Monitoring ────────────────────────────────────────
    "logs", "app-logs", "access-logs", "error-logs",
    "syslog", "event-logs", "audit-logs",
    "analytics", "metrics", "monitoring",
    "elasticsearch", "kibana", "grafana", "prometheus",
    "splunk", "datadog", "newrelic",
    # ── Databases ────────────────────────────────────────────────
    "database", "db-store", "data-store", "datastore",
    "db-snapshots", "db-dumps", "db-exports",
    "data-lake", "data-warehouse", "datalake",
    "athena-results", "athena-query", "redshift", "redshift-spectrum",
    "glue", "glue-scripts", "glue-data",
    "emr", "emr-logs", "emr-data",
    # ── Development / Staging ────────────────────────────────────
    "dev", "development", "staging", "test", "testing",
    "qa", "uat", "sandbox", "demo",
    "dev-assets", "dev-data", "dev-config",
    "staging-assets", "staging-data",
    "test-data", "test-fixtures", "test-assets",
    # ── Corporate / Enterprise ───────────────────────────────────
    "internal", "internal-assets", "internal-data",
    "corp", "corporate", "enterprise",
    "hr", "hr-data", "employee-data",
    "finance", "financial", "billing", "invoices",
    "payroll", "accounting", "tax",
    "legal", "contracts", "documents",
    "customer-data", "client-data", "partner-data",
    "onboarding", "offboarding",
    # ── Source Code ──────────────────────────────────────────────
    "source-code", "code-repo", "git-repo", "repo-mirror",
    "releases", "software-releases", "binaries",
    "mobile-app", "app-builds", "ipa", "apk",
    "website", "webapp", "frontend", "backend",
]

# ── Files to probe on publicly listable buckets ──────────────────
SECRET_FILES: List[str] = [
    ".env", ".env.production", ".env.staging", ".env.local",
    ".env.development", ".env.backup", ".env.example",
    "credentials.json", "credentials.yml", "credentials.yaml",
    "config.json", "config.yml", "config.yaml", "config.toml",
    "settings.json", "settings.yml", "settings.py",
    "terraform.tfstate", "terraform.tfstate.backup",
    "terraform.tfvars", "terraform.tfvars.json",
    "secrets.yml", "secrets.yaml", "secrets.json",
    "service-account.json", "service-account-key.json",
    "gcp-credentials.json", "google-credentials.json",
    "aws-credentials", "aws-config", "credentials.csv",
    "kubeconfig", "kube-config", "admin.conf",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "ssh-private-key", "ssh-key", "authorized_keys",
    "docker-compose.yml", "docker-compose.yaml",
    "docker-config.json", "config.json",
    "backup.sql", "dump.sql", "database.sql",
    "wp-config.php", "wp-config.bak", "wp-config-sample.php",
    ".htpasswd", ".htaccess",
    ".npmrc", ".pypirc", ".git-credentials", ".gitconfig",
    "jenkins-credentials.xml",
    "ansible-vault.yml", "ansible-vault.yaml",
    "vault-token", "vault-secret",
    ".bash_history", ".zsh_history", ".mysql_history",
    "private.key", "private.pem", "key.pem",
    "cert.pem", "certificate.pem", "fullchain.pem",
    "server.key", "server.crt",
    ".s3cfg", ".aws/credentials", ".boto",
    "packer-vars.json", "packer.json",
    "Makefile.env", ".makerc",
    "gradle.properties", "local.properties",
]


def _generate_bucket_candidates(bucket_probe_cap: int) -> List[str]:
    """Generate candidate bucket names from topics, seeds, and patterns.

    Combines three strategies:
    1. Topic keywords × suffix patterns (e.g. wallet-backup, wallet-secrets)
    2. Built-in seed list combined with topic keywords (e.g. terraform-state-wallet)
    3. Standalone built-in seeds that are likely targets on their own
    """
    candidates: Set[str] = set()

    suffix_patterns = [
        "{0}", "{0}-secrets", "{0}-secret", "{0}-keys", "{0}-key",
        "{0}-private", "{0}-backup", "{0}-backups", "{0}-dump",
        "{0}-dumps", "{0}-data", "{0}-config", "{0}-env", "{0}-envs",
        "{0}-credentials", "{0}-creds", "{0}-leaks", "{0}-leak",
        "{0}-production", "{0}-prod", "{0}-staging", "{0}-database",
        "{0}-db", "{0}-wallet", "{0}-crypto", "{0}-api",
        "{0}-tokens", "{0}-token", "{0}-storage", "{0}-store",
        "{0}-files", "{0}-assets", "{0}-logs",
        "secrets-{0}", "keys-{0}", "private-{0}",
        "backup-{0}", "leaked-{0}", "dump-{0}", "creds-{0}",
        "dev-{0}", "prod-{0}", "staging-{0}", "test-{0}",
    ]

    # Pre-extract short keywords (3+ chars, not digits-only)
    short_words: List[str] = []
    for topic in ALL_TOPICS:
        for w in re.split(r'[^a-z0-9]+', topic.lower()):
            w = w.strip("-.")
            if len(w) >= 3 and not w.isdigit() and w not in short_words:
                short_words.append(w)

    # Also pull words from known Bitbucket workspaces (real org names)
    for ws in KNOWN_BB_WORKSPACES:
        w = ws.lower().strip("-.")
        if len(w) >= 3 and w not in short_words:
            short_words.append(w)

    # Strategy 1: topic keywords × patterns
    for w in short_words:
        if len(candidates) >= bucket_probe_cap:
            break
        for p in suffix_patterns:
            if len(candidates) >= bucket_probe_cap:
                break
            n = p.format(w)
            if 3 <= len(n) <= 63:  # S3/GCS bucket name length limits
                candidates.add(n)

    # Strategy 2: seed × keyword combinations
    for seed in BUCKET_SEEDS:
        if len(candidates) >= bucket_probe_cap:
            break
        for w in short_words[:40]:  # cap keyword cross-product
            if len(candidates) >= bucket_probe_cap:
                break
            for combo in (f"{seed}-{w}", f"{w}-{seed}"):
                if 3 <= len(combo) <= 63:
                    candidates.add(combo)

    # Strategy 3: standalone seeds with common suffixes
    for seed in BUCKET_SEEDS:
        if len(candidates) >= bucket_probe_cap:
            break
        candidates.add(seed)
        for suffix in ("-dev", "-staging", "-prod", "-test", "-qa",
                       "-us", "-eu", "-ap", "-01", "-1", "-backup", "-old"):
            combo = f"{seed}{suffix}"
            if len(combo) <= 63:
                candidates.add(combo)

    return list(candidates)[:bucket_probe_cap]


def _try_list_bucket(url: str, provider_cfg: Dict[str, Any],
                     timeout: int = 15) -> List[str]:
    """Attempt to list objects in a public bucket. Returns list of object keys."""
    list_url = url.rstrip("/") + provider_cfg["listing_path"]
    try:
        req = urllib.request.Request(list_url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            # Parse XML for S3-compatible and Azure listing formats
            keys: List[str] = []
            # S3/GCS/DO format: <Key>...</Key> or <Contents><Key>...</Key></Contents>
            for m in re.finditer(r'<Key>([^<]+)</Key>', body):
                keys.append(m.group(1))
            # Azure format: <Name>...</Name> inside <Blob>
            for m in re.finditer(r'<Name>([^<]+)</Name>', body):
                k = m.group(1)
                if k not in keys:
                    keys.append(k)
            return keys
    except Exception:
        return []


def _probe_secret_files(base_url: str, keys: List[str],
                        timeout: int = 8) -> List[str]:
    """Among listing results, identify secret-bearing file paths.

    Matches against SECRET_FILES patterns (exact filename, partial path match).
    Also heuristically identifies .env, credentials, backup, config, and key files.
    """
    found: List[str] = []
    key_set = set(keys)

    # Direct matches against known secret filenames
    for sf in SECRET_FILES:
        if sf in key_set:
            found.append(sf)
        # Also try with leading path components
        for k in keys:
            if k.endswith("/" + sf) or k == sf:
                if sf not in found:
                    found.append(sf)

    # Heuristic pattern matches on full key listing
    secret_patterns = [
        (r'(?:^|/)\.env', '.env file'),
        (r'(?:^|/)credentials', 'credentials file'),
        (r'(?:^|/)backup.*\.sql', 'SQL backup'),
        (r'(?:^|/)id_rsa', 'SSH private key'),
        (r'(?:^|/)id_ed25519', 'SSH private key'),
        (r'(?:^|/)terraform\.tfstate', 'Terraform state'),
        (r'(?:^|/)kubeconfig', 'Kubernetes config'),
        (r'(?:^|/)\.docker/config\.json', 'Docker registry auth'),
        (r'(?:^|/)\.npmrc', 'NPM config'),
        (r'(?:^|/)\.pypirc', 'PyPI config'),
        (r'(?:^|/)\.git-credentials', 'Git credentials'),
        (r'(?:^|/)wp-config\.php', 'WordPress config'),
        (r'(?:^|/)private\.(?:key|pem)', 'Private key'),
        (r'(?:^|/)server\.(?:key|crt)', 'Server cert/key'),
        (r'\.pem$', 'PEM file'),
        (r'\.pfx$', 'PKCS#12 cert'),
        (r'\.p12$', 'PKCS#12 cert'),
        (r'\.jks$', 'Java keystore'),
        (r'\.kdbx?$', 'KeePass database'),
    ]
    for pattern, label in secret_patterns:
        for k in keys:
            if re.search(pattern, k, re.IGNORECASE):
                found.append(f"{k} ({label})")
                break

    return list(dict.fromkeys(found))  # dedup preserving order


def probe_cloud_buckets(out: OutputWriter, provider: str, target_count: int,
                        bucket_probe_cap: int,
                        throttle: Optional[ResourceThrottle] = None):
    """Multi-provider, multi-region, content-aware cloud bucket probing.

    For each provider (s3/gcs/azure/spaces):
      1. Generates smart candidate names from topics + built-in wordlist
      2. Probes multiple regional endpoints per name
      3. On HTTP 200: tries to list bucket contents
      4. On listable buckets: scans for secret-bearing files
      5. Reports live buckets (200), private buckets (403), and discovered secrets
    """

    provider_cfg = CLOUD_PROVIDERS.get(provider)
    if not provider_cfg:
        cprint(f"[{provider}] unknown cloud provider, skipping", color=C_RED)
        return

    label = provider_cfg["label"]
    endpoints = provider_cfg["endpoints"]
    food_prefix = provider_cfg["food_prefix"]

    # ── v5.0: Generate candidates (atlas-boosted if data available) ────
    atlas_bucket = {}
    try:
        atlas_bucket = load_success_atlas()
    except Exception:
        pass
    if atlas_bucket:
        hot_path_local = os.path.join(HOME, ".hot_targets.json")
        hot_data = []
        try:
            with open(hot_path_local, "r") as f:
                hot_data = json.load(f).get("targets", [])
        except Exception:
            pass
        atlas_names = generate_atlas_bucket_names(atlas_bucket, hot_data, max_names=bucket_probe_cap * 3)
        candidates = _generate_bucket_candidates(bucket_probe_cap)
        # Merge: atlas names first, then conventional candidates
        seen = set(candidates)
        for an in atlas_names:
            if an not in seen and len(seen) < bucket_probe_cap * 3:
                candidates.append(an)
                seen.add(an)
        candidates = candidates[:bucket_probe_cap * 3]
        cprint(f"[{label}] atlas-boosted: {len(atlas_names)} atlas-generated names added ({len(candidates)} total)", color=C_CYAN)
    else:
        candidates = _generate_bucket_candidates(bucket_probe_cap)
    cprint(f"\n[{label}] generated {len(candidates)} candidate names", color=C_YELLOW)
    cprint(f"[{label}] probing across {len(endpoints)} regional endpoint(s)...", color=C_YELLOW)

    # ── Probe all names × all endpoints ──────────────────────────
    # Track: name -> best endpoint URL, name -> list of file findings
    live_buckets: Dict[str, str] = {}      # name -> best URL
    private_buckets: Dict[str, int] = {}   # name -> first 403 count
    bucket_secrets: Dict[str, List[str]] = {}  # name -> discovered secret files
    probed_count = 0
    found_200 = 0
    found_403 = 0

    def _check_single(name: str) -> Tuple[str, Optional[str], int, Optional[List[str]]]:
        """Check one name across all endpoints. Returns (name, url_or_None, best_status, secrets_or_None)."""
        nonlocal probed_count
        probed_count += 1
        if throttle:
            throttle.wait_if_hot()

        best_url = None
        best_status = 0

        for ep_template in endpoints:
            url = ep_template.format(name=name)
            status = http_head(url, headers={"User-Agent": "Mozilla/5.0"})

            if status == 200:
                best_url = url
                best_status = 200
                break  # Found it, no need to check other regions
            elif status == 403:
                if best_status == 0:
                    best_status = 403
            elif status in (301, 302, 307):
                # Redirect — bucket exists but in a different region
                if best_status == 0:
                    best_status = status

            # Small delay between region probes to avoid rate limiting
            time.sleep(0.05)

        if best_status == 200 and best_url:
            # Try to list contents
            keys = _try_list_bucket(best_url, provider_cfg)
            secrets = None
            if keys:
                secrets = _probe_secret_files(best_url, keys)
                if secrets:
                    cprint(f"   🔓 {name}: listable ({len(keys)} objects, {len(secrets)} secret indicators)",
                           color=C_BGRN)
                else:
                    cprint(f"   📂 {name}: listable ({len(keys)} objects, no secrets found)",
                           color=C_GREEN)
            return name, best_url, best_status, secrets
        else:
            return name, None, best_status, None  # 403, redirect, or not found

    # Use a moderate worker count to avoid overwhelming endpoints
    max_w = min(30, max(8, bucket_probe_cap // 50))
    total_checks = len(candidates) * len(endpoints)

    with ThreadPoolExecutor(max_workers=max_w) as executor:
        futures = {executor.submit(_check_single, c): c for c in candidates}
        for future in as_completed(futures):
            name, url, status, secrets = future.result()
            if status == 200 and url:
                live_buckets[name] = url
                found_200 += 1
                if secrets:
                    bucket_secrets[name] = secrets
            elif status == 403:
                found_403 += 1
                private_buckets[name] = 403
            elif status in (301, 302, 307):
                found_403 += 1  # redirect = exists but inaccessible
                private_buckets[name] = status

    # ── Summary ──────────────────────────────────────────────────
    cprint(f"\n[{label}] RESULTS:", color=C_BGRN, bold=True)
    cprint(f"  Live (200):      {len(live_buckets)}", color=C_GREEN)
    cprint(f"  Private (403):   {found_403}", color=C_YELLOW)
    cprint(f"  Listable:        {len(bucket_secrets)}", color=C_BGRN)
    secret_file_count = sum(len(v) for v in bucket_secrets.values())
    if secret_file_count:
        cprint(f"  Secret indicators: {secret_file_count}", color=C_BRED, bold=True)

    # ── Write results ────────────────────────────────────────────
    written = 0
    for name, url in live_buckets.items():
        if out.total_written >= target_count:
            break

        # Build rich topic tag
        tags = ["bucket-probe"]
        if name in bucket_secrets:
            for sf in bucket_secrets[name][:3]:  # top 3 indicators
                # Sanitize: remove path, keep filename + label
                short = sf.split("/")[-1] if "/" in sf else sf
                short = short[:40]
                tags.append(f"has:{short}")
        topic = ";".join(tags)

        out.write(url, "", name, topic, provider, f"{food_prefix}{name}")
        written += 1

    cprint(f"[{label}] wrote {written} entries to output", color=C_GREEN)


# =============================================================================
# DARKNET DEEP-SEARCH HELPERS  (onion code search, org probes, workspace probes)
# =============================================================================

def _github_onion_deep_search(out: OutputWriter, token_rotator: TokenRotator,
                               target_count: int,
                               throttle: Optional[ResourceThrottle] = None):
    """Search GitHub code for .onion addresses and hidden service private keys."""
    onion_patterns = [
        (ONION_V3_REGEX, "onion-v3-address"),
        (ONION_KEY_REGEX, "hs-ed25519-secret"),
        (ONION_TORRC_REGEX, "torrc-hidden-service"),
        (r'BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY', "private-key-pem"),
        (r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "bitcoin-address"),
        (r'0x[a-fA-F0-9]{64}', "ethereum-private-key"),
        (r'L[1-9A-HJ-NP-Za-km-z]{51,52}', "litecoin-wif"),
    ]
    for pattern, label in onion_patterns:
        if out.total_written >= target_count:
            break
        cprint(f"   github onion-deep: searching code for {label}...", color=C_BLUE, dim=True)
        try:
            q = urllib.parse.quote(pattern)
            url = (f"https://api.github.com/search/code?q={q}"
                   f"&sort=indexed&order=desc&per_page=30")
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Mozilla/5.0",
            }
            token = token_rotator.get()
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = http_request(url, headers=headers, timeout=45, throttle=throttle)
            if not resp or resp.get("_error") or not resp.get("items"):
                continue
            for item in resp.get("items", []):
                if out.total_written >= target_count:
                    break
                repo_info = item.get("repository", {})
                html_url = repo_info.get("html_url", "")
                owner_login = repo_info.get("owner", {}).get("login", "")
                repo_name = repo_info.get("name", "")
                if html_url and owner_login and repo_name:
                    food = f"https://github.com/{owner_login}/{repo_name}.git"
                    out.write(html_url, owner_login, repo_name,
                              f"onion-deep:{label}", "github", food)
            time.sleep(1.5)
        except Exception:
            continue


def _gitlab_onion_deep_search(out: OutputWriter, token_rotator: TokenRotator,
                               target_count: int,
                               throttle: Optional[ResourceThrottle] = None):
    """Search GitLab for .onion patterns in blobs."""
    if out.total_written >= target_count:
        return
    cprint("   gitlab onion-deep: searching blobs for .onion...", color=C_BLUE, dim=True)
    try:
        q = urllib.parse.quote(".onion")
        url = f"https://gitlab.com/api/v4/search?scope=blobs&search={q}&per_page=30"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        token = token_rotator.get()
        if token:
            headers["PRIVATE-TOKEN"] = token
        resp = http_request(url, headers=headers, timeout=30, throttle=throttle)
        if not resp or not isinstance(resp, list):
            return
        for item in resp:
            if out.total_written >= target_count:
                break
            proj = item.get("project", {})
            path = proj.get("path_with_namespace", "")
            if not path or "/" not in path:
                continue
            parts = path.split("/")
            web_url = f"https://gitlab.com/{path}"
            out.write(web_url, parts[0], parts[-1],
                      "onion-deep:onion-blob", "gitlab", f"https://gitlab.com/{path}.git")
    except Exception:
        pass


def _probe_github_orgs(out: OutputWriter, token_rotator: TokenRotator,
                       target_count: int,
                       throttle: Optional[ResourceThrottle] = None):
    """Fetch repo listings for known high-signal GitHub orgs."""
    cprint("   github org-probe: scanning known orgs...", color=C_BLUE, dim=True)
    for org in GITHUB_KNOWN_ORGS:
        if out.total_written >= target_count:
            break
        try:
            url = (f"https://api.github.com/orgs/{org}/repos"
                   f"?sort=updated&direction=desc&per_page=30&type=sources")
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Mozilla/5.0",
            }
            token = token_rotator.get()
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = http_request(url, headers=headers, timeout=30, throttle=throttle)
            if not resp or resp.get("_error") or not isinstance(resp, list):
                continue
            for repo in resp:
                if out.total_written >= target_count:
                    break
                html_url = repo.get("html_url", "")
                owner_login = repo.get("owner", {}).get("login", "")
                repo_name = repo.get("name", "")
                if html_url and owner_login and repo_name:
                    food = f"https://github.com/{owner_login}/{repo_name}.git"
                    out.write(html_url, owner_login, repo_name,
                              f"org-probe:{org}", "github", food)
            time.sleep(0.5)
        except Exception:
            continue


def _probe_bitbucket_workspace(out: OutputWriter, workspace: str,
                               target_count: int,
                               bb_user: str, bb_pass: str,
                               bb_api_token: str,
                               throttle: Optional[ResourceThrottle] = None):
    """Fetch repos for a specific Bitbucket workspace."""
    if out.total_written >= target_count:
        return
    # Build auth
    auth_type = "none"
    cred = ""
    if bb_api_token and not re.search(r'your_|xxxx|YOUR_', bb_api_token, re.IGNORECASE):
        cred = bb_api_token
        auth_type = "Bearer"
    elif bb_user and bb_pass and "your_" not in bb_user.lower() and "your_" not in bb_pass.lower():
        cred_bytes = f"{bb_user}:{bb_pass}".encode("utf-8")
        cred = base64.b64encode(cred_bytes).decode("ascii")
        auth_type = "Basic"
    if auth_type == "none":
        return
    try:
        url = f"https://api.bitbucket.org/2.0/repositories/{workspace}?pagelen=30"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        if auth_type == "Bearer":
            headers["Authorization"] = f"Bearer {cred}"
        else:
            headers["Authorization"] = f"Basic {cred}"
        resp = http_request(url, headers=headers, timeout=30, throttle=throttle)
        if not resp or not resp.get("values"):
            return
        for item in resp.get("values", []):
            if out.total_written >= target_count:
                break
            full_name = item.get("full_name", "")
            if not full_name or "/" not in full_name:
                continue
            parts = full_name.split("/")
            owner = parts[0]
            repo_name = parts[-1]
            html_url = item.get("links", {}).get("html", {}).get("href", "")
            if html_url:
                out.write(html_url, owner, repo_name,
                          f"ws-probe:{workspace}", "bitbucket", f"bb:{full_name}")
    except Exception:
        pass


# =============================================================================
# ONION → CLEARNET CORRELATION  (find onion addresses leaked in clearnet repos)
# =============================================================================

def correlate_onion_clearnet(output_file: str = "paste_box.txt",
                              correlation_file: str = "onion_correlations.jsonl"):
    """Post-process 7000.py output: find repos where .onion addresses appear
    alongside clearnet infrastructure, indicating a leak path.

    Outputs walletx-compatible JSONL with:
      - onion address (if found in repo metadata/content)
      - clearnet repo URL where it was found
      - source engine
      - correlation confidence (high/medium/low)
    """
    if not os.path.exists(output_file):
        cprint(f"[correlate] No output file: {output_file}", color=C_RED)
        return []

    onion_pattern = re.compile(ONION_V3_REGEX)
    correlations = []
    seen_onions: Set[str] = set()

    cprint(f"[correlate] Scanning {output_file} for onion→clearnet leaks...", color=C_BCYN)

    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                # Parse pipe-delimited format: url|owner|repo|topic|source|ts
                parts = line.split("|")
                if len(parts) < 5:
                    # Try JSONL
                    try:
                        rec = json.loads(line)
                        url = rec.get("url", "")
                        owner = rec.get("owner", "")
                        repo = rec.get("repo", "")
                        topic = rec.get("topic", "")
                        source = rec.get("source", "")
                    except json.JSONDecodeError:
                        continue
                else:
                    # Unescape pipes
                    def _unescape(s: str) -> str:
                        return s.replace("\\|", "|").replace("\\\\", "\\")
                    url = _unescape(parts[0])
                    owner = _unescape(parts[1])
                    repo = _unescape(parts[2])
                    topic = _unescape(parts[3])
                    source = _unescape(parts[4])

                # Check topic field for onion indicators
                onion_match = onion_pattern.search(topic)
                if not onion_match:
                    onion_match = onion_pattern.search(repo)
                if not onion_match:
                    onion_match = onion_pattern.search(owner)

                if onion_match:
                    onion_addr = onion_match.group(0)
                    # Determine confidence
                    confidence = "low"
                    if "onion" in topic.lower() or "hidden-service" in topic.lower():
                        confidence = "high"
                    elif "darknet" in topic.lower() or "tor" in topic.lower():
                        confidence = "medium"
                    elif source in ("github", "gitlab"):
                        confidence = "medium"

                    corr = {
                        "onion": onion_addr,
                        "clearnet_repo": url,
                        "owner": owner,
                        "repo": repo,
                        "source": source,
                        "topic": topic,
                        "confidence": confidence,
                        "discovered_at": datetime.now(timezone.utc).isoformat(),
                    }
                    correlations.append(corr)
                    seen_onions.add(onion_addr)

        # Write correlation file (walletx-compatible JSONL)
        with open(correlation_file, "w", encoding="utf-8") as out_f:
            for corr in correlations:
                out_f.write(json.dumps(corr, ensure_ascii=False) + "\n")

        cprint(f"[correlate] Found {len(correlations)} onion→clearnet leak paths "
               f"({len(seen_onions)} unique .onion addresses)", color=C_BGRN)
        cprint(f"[correlate] Output: {correlation_file} (walletx-compatible JSONL)", color=C_GREEN)

        # High-confidence summary
        high_conf = [c for c in correlations if c["confidence"] == "high"]
        if high_conf:
            cprint(f"[correlate] ⚠ {len(high_conf)} HIGH-confidence leaks:", color=C_BRED, bold=True)
            for hc in high_conf[:10]:
                cprint(f"   {hc['onion']} → {hc['clearnet_repo']}", color=C_BRED)

    except Exception as e:
        cprint(f"[correlate] Error: {e}", color=C_RED)

    return correlations


# =============================================================================
# BOOST / ADAPTIVE / TWO-PASS / TARGETS helpers  (v4.0)
# =============================================================================

SUCCESS_ATLAS = os.path.join(HOME, ".success_atlas.json")
BALANCES_HIT = os.path.join(HOME, "balances_hit.jsonl")
TARGETS_DIR = os.path.join(HOME, "targets")


def load_success_atlas() -> Dict[str, Any]:
    """Load success atlas, return empty dict if missing or corrupt."""
    if not os.path.exists(SUCCESS_ATLAS):
        return {}
    try:
        with open(SUCCESS_ATLAS, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_funded_repos() -> Set[str]:
    """Extract unique github repo URLs from balances_hit.jsonl (funded wallets)."""
    repos: Set[str] = set()
    if not os.path.exists(BALANCES_HIT):
        return repos
    try:
        with open(BALANCES_HIT, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                src = rec.get("source_file", "") or rec.get("source_url", "") or rec.get("repo", "")
                if not src:
                    continue
                m = re.search(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", src)
                if m:
                    repos.add(m.group(1))
    except Exception:
        pass
    return repos


def boost_pass(out: OutputWriter, token_rotator: TokenRotator,
               target_count: int, throttle=None):
    """Re-probe repos that previously produced funded wallets.

    Reads success_atlas + balances_hit to find winning repos, then runs
    targeted GitHub code searches (filename:.env, path:test/fixtures, etc.)
    against each repo to find sibling files with keys.
    """
    atlas = load_success_atlas()
    funded = load_funded_repos()

    boost_repos: Set[str] = set()
    for repo_key in atlas.get("top_github_repos", {}):
        boost_repos.add(repo_key)
    for r in atlas.get("boost_repos", []):
        boost_repos.add(r)
    boost_repos |= funded

    if not boost_repos:
        cprint("[boost] No funded repos found — skipping boost pass", color=C_YELLOW)
        return

    cprint(f"\n[boost]  Boosting: re-probing {len(boost_repos)} funded repos...",
           color=C_BGRN, bold=True)

    boost_queries = [
        "filename:.env",
        "filename:.env.local",
        "filename:secrets.json",
        "filename:wallet.json",
        "filename:hardhat.config",
        "path:test/fixtures extension:json",
        "path:deployments",
        "path:scripts filename:.env",
        "filename:keystore",
    ]

    repo_list = list(boost_repos)
    probed = 0
    for repo_key in repo_list:
        if out.total_written >= target_count:
            break
        for bq in boost_queries:
            if out.total_written >= target_count:
                break
            q = urllib.parse.quote(f"repo:{repo_key} {bq}")
            url = f"https://api.github.com/search/code?q={q}&per_page=30"
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "Mozilla/5.0",
            }
            token = token_rotator.current()
            if token:
                headers["Authorization"] = f"Bearer {token}"
            resp = http_request(url, headers=headers, timeout=30,
                                token_rotator=token_rotator, throttle=throttle)
            if not resp or resp.get("_error") or not resp.get("items"):
                continue
            for item in resp.get("items", []):
                if out.total_written >= target_count:
                    break
                repo_info = item.get("repository", {})
                html_url = repo_info.get("html_url", "")
                owner_login = repo_info.get("owner", {}).get("login", "")
                repo_name = repo_info.get("name", "")
                if html_url and owner_login and repo_name:
                    food = f"https://github.com/{owner_login}/{repo_name}.git"
                    out.write(html_url, owner_login, repo_name,
                              f"boost:{bq}", "github", food)
            time.sleep(2.0 + random.uniform(0, 1.5))
        probed += 1
        if probed % 10 == 0:
            cprint(f"   boost probed {probed}/{len(repo_list)} repos | written: {out.total_written}",
                   color=C_GREEN)
    cprint(f"[boost]  Boost pass complete — probed {probed} repos", color=C_BGRN)


def write_targets_format(out: OutputWriter):
    """Write results to targets/ directory by engine."""
    os.makedirs(TARGETS_DIR, exist_ok=True)
    suffix_map = {
        "github": "github", "gitlab": "gitlab", "huggingface": "hf",
        "docker": "docker", "bitbucket": "bitbucket", "postman": "postman",
        "gcs": "gcs", "s3": "s3", "azure": "azure", "spaces": "spaces",
    }
    engine_urls: Dict[str, List[str]] = {e: [] for e in ALL_ENGINES}

    if not os.path.exists(out.output_path):
        cprint("[targets] No output file to convert", color=C_YELLOW)
        return

    try:
        with open(out.output_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if out.jsonl:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    source = rec.get("source", "")
                    owner = rec.get("owner", "")
                    repo = rec.get("repo", "")
                else:
                    parts = line.split("|")
                    if len(parts) < 5:
                        continue
                    source = parts[4]
                    owner = parts[1]
                    repo = parts[2]

                if source not in engine_urls:
                    continue
                if source == "github":
                    clone = f"https://github.com/{owner}/{repo}.git"
                elif source == "gitlab":
                    clone = f"https://gitlab.com/{owner}/{repo}.git"
                elif source == "huggingface":
                    clone = f"huggingface://{owner}/{repo}"
                elif source == "docker":
                    clone = f"docker://{owner}/{repo}"
                else:
                    clone = line.split("|")[0] if not out.jsonl else rec.get("url", "")
                engine_urls[source].append(clone)
    except Exception as e:
        cprint(f"[targets] Error reading output: {e}", color=C_RED)
        return

    total = 0
    for engine, urls in engine_urls.items():
        if not urls:
            continue
        tf = os.path.join(TARGETS_DIR, f"targets_{suffix_map.get(engine, engine)}.txt")
        try:
            with open(tf, "a", encoding="utf-8") as fh:
                for u in urls:
                    fh.write(u + "\n")
            total += len(urls)
            cprint(f"[targets] {tf}: +{len(urls)} URLs", color=C_GREEN)
        except Exception as e:
            cprint(f"[targets] Error writing {tf}: {e}", color=C_RED)
    cprint(f"[targets]  Wrote {total} URLs to {TARGETS_DIR}/", color=C_BGRN)


def get_adaptive_queries() -> List[str]:
    """Extract high-weight adaptive queries from success atlas."""
    atlas = load_success_atlas()
    queries = []
    for aq in atlas.get("adaptive_queries", []):
        if aq.get("weight", 0) >= 0.7:
            queries.append(aq["q"])
    return queries


# =============================================================================
# MAIN ORCHESTRATOR  (parallel engines, global target, resume, dry-run)
# =============================================================================

def run(args) -> None:
    start_time = time.time()

    # ── Load tokens ──────────────────────────────────────────────
    tokens = load_env_tokens()
    cprint(f"[init] GitHub tokens: {len(tokens['github'])}", color=C_GREEN)
    cprint(f"[init] GitLab tokens: {len(tokens['gitlab'])}", color=C_GREEN)
    cprint(f"[init] HuggingFace tokens: {len(tokens['huggingface'])}", color=C_GREEN)
    cprint(f"[init] Bitbucket creds: {'yes' if tokens['bitbucket_user'] else 'no'}", color=C_GREEN)
    cprint(f"[init] Postman API key: {'yes' if tokens['postman_key'] else 'no'}", color=C_GREEN)

    # ── Resolve engines ─────────────────────────────────────────
    if args.engines:
        active_engines = [e.strip() for e in args.engines.split(",") if e.strip() in ALL_ENGINES]
    else:
        active_engines = list(ALL_ENGINES)
    if not active_engines:
        active_engines = list(ALL_ENGINES)
    # v5.0: respect --skip-onion
    if getattr(args, "skip_onion", False) and "onion" in active_engines:
        active_engines.remove("onion")

    # ── Resolve topics ──────────────────────────────────────────
    tier = args.topics if args.topics in TOPIC_TIERS else "all"
    topics_list = TOPIC_TIERS[tier]
    # --two-pass implies --boost and --adaptive
    if getattr(args, "two_pass", False):
        args.boost = True
        args.adaptive = True
    # Blend adaptive queries from success atlas if --adaptive or --boost
    if getattr(args, "adaptive", False) or getattr(args, "boost", False):
        adaptive_qs = get_adaptive_queries()
        if adaptive_qs:
            cprint(f"[init] Blending {len(adaptive_qs)} adaptive queries (weight>=0.7)", color=C_CYAN)
            topics_list = list(dict.fromkeys(topics_list + adaptive_qs))
    unique_topics = list(dict.fromkeys(topics_list))

    # ── Paths ───────────────────────────────────────────────────
    output_file = args.output or DEFAULT_OUTPUT
    food_file = args.food or DEFAULT_FOOD

    # ── Resource throttle ───────────────────────────────────────
    throttle = ResourceThrottle(
        max_cpu_pct=float(args.max_cpu),
        max_ram_pct=float(args.max_ram),
    )

    # ── Header ──────────────────────────────────────────────────
    cprint("=" * 60, color=C_BCYN, bold=True)
    cprint(" 7000.py v4.0 — Multi-engine secret-surface scraper", color=C_BMAG, bold=True)
    cprint(f" Start : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", color=C_CYAN)
    cprint(f" Target: {args.target} repos/projects", color=C_BOLD)
    cprint(f" Topics: {len(unique_topics)} search terms (tier: {tier})", color=C_BOLD)
    cprint(f" Engines: {', '.join(active_engines)}", color=C_MAGENTA)
    cprint(f" Output: {output_file}", color=C_CYAN)
    cprint(f" Feed  : {food_file}", color=C_CYAN)
    cprint(f" Deep  : {'yes' if args.deep else 'no'}", color=C_CYAN)
    cprint(f" Dry-run: {'yes' if args.dry_run else 'no'}", color=C_YELLOW if args.dry_run else C_CYAN)
    cprint(f" Throttle: CPU≤{args.max_cpu}% RAM≤{args.max_ram}%", color=C_CYAN)
    cprint(f" No-dedup: {'yes' if args.no_dedup else 'no'}", color=C_CYAN)
    cprint("=" * 60, color=C_BCYN, bold=True)
    print()

    # ── Output writer ───────────────────────────────────────────
    out = OutputWriter(
        output_file, food_file,
        fresh=args.fresh,
        no_dedup=args.no_dedup,
        jsonl=args.format == "jsonl",
        resume=args.resume,
        skip_probes=args.skip_probes,
    )
    cprint(f"[init] Food: {len(out._food_seen)} existing dedup entries", color=C_CYAN)

    # ── Dry run: just preview ───────────────────────────────────
    if args.dry_run:
        cprint("\n[dry-run] Would search with these settings. No writes will occur.", color=C_BYEL, bold=True)
        cprint(f"[dry-run] Engines: {active_engines}", color=C_CYAN)
        cprint(f"[dry-run] Topics: {len(unique_topics)}", color=C_CYAN)
        for i, t in enumerate(unique_topics[:20]):
            cprint(f"  {i+1}. {t}", color=C_DIM)
        if len(unique_topics) > 20:
            cprint(f"  ... and {len(unique_topics)-20} more", color=C_DIM)
        return

    # ── Token rotators ──────────────────────────────────────────
    # v5.0: TokenManager replaces TokenRotator (already created above)

    # ── Engine dispatch (parallel) ──────────────────────────────
    # ── v5.0: Atlas-first engine selection & budget allocation ────
    engine_ranking = rank_engines_by_yield()
    if engine_ranking and not getattr(args, "skip_dead_engines", False):
        cprint(f"\n[init] Engine yield ranking (funded/scans):", color=C_CYAN)
        for eng, ratio, funded, scans in engine_ranking[:8]:
            cprint(f"  {eng:15s} {ratio:.4f}  ({funded} funded / {scans} scans)", color=C_GREEN if ratio > 0.001 else C_DIM)

    # Allocate budget: top 3 get 70%, middle 3 get 20%, bottom get 10%
    engine_budget = {}
    if engine_ranking and active_engines:
        ranked_names = [e[0] for e in engine_ranking if e[0] in active_engines]
        for i, name in enumerate(ranked_names):
            if i < 3:
                engine_budget[name] = int(target * 0.70 / 3)
            elif i < 6:
                engine_budget[name] = int(target * 0.20 / max(1, len(ranked_names) - 3))
            else:
                remaining = len(ranked_names) - 6
                engine_budget[name] = int(target * 0.10 / max(1, remaining)) if remaining > 0 else int(target * 0.02)

    # ── v5.0: Atlas-generated surgical queries ─────────────────────
    atlas = load_success_atlas()
    atlas_boost = getattr(args, "atlas_boost", 0)
    atlas_queries = []
    if atlas_boost > 0 and atlas:
        atlas_queries = generate_atlas_queries(atlas, boost_count=atlas_boost)
        if atlas_queries:
            cprint(f"[init] Atlas queries: {len(atlas_queries)} surgical targets from signal data", color=C_BCYN)

    # ── v5.0: Token lifecycle managers ─────────────────────────────
    token_fallback = getattr(args, "token_fallback", True)
    gh_manager = TokenManager(tokens["github"], "github", calls_per_hour=80, allow_fallback=token_fallback)
    gl_manager = TokenManager(tokens["gitlab"], "gitlab", calls_per_hour=80, allow_fallback=token_fallback)
    hf_manager = TokenManager(tokens["huggingface"], "huggingface", calls_per_hour=80, allow_fallback=token_fallback)
    cprint(f"[init] Token health — {gh_manager.health_report()}", color=C_CYAN)
    cprint(f"[init] Token health — {gl_manager.health_report()}", color=C_CYAN)

    # Cloud engines handled separately (already parallel internally)
    cloud_engines = {"gcs", "s3", "azure", "spaces"}
    api_engines = [e for e in active_engines if e not in cloud_engines]

    # Shared global target — any engine can fill it
    target = args.target

    def _run_engine(engine: str):
        """Run a single engine, iterating through topics until global target met."""
        consecutive_empty = 0
        topic_index = 0
        prev_engine_count = out.engine_counts.get(engine, 0)

        while (out.total_written < target
               and topic_index < len(unique_topics)
               and consecutive_empty < 15):
            # v5.0: Run atlas surgical queries first (higher priority)
            if atlas_queries and engine in ("github", "gitlab"):
                for aq in atlas_queries:
                    if out.total_written >= target:
                        break
                    prev_atlas = out.total_seen
                    if engine == "github":
                        scrape_github(out, gh_manager, aq, target, deep=args.deep, throttle=throttle)
                    elif engine == "gitlab":
                        scrape_gitlab(out, gl_manager, aq, target, deep=args.deep, throttle=throttle)
                    if out.total_seen > prev_atlas:
                        cprint(f"   atlas-query '{aq[:50]}': +{out.total_seen - prev_atlas}", color=C_MAGENTA)
                    time.sleep(0.2)

            topic = unique_topics[topic_index]
            topic_index += 1
            prev_seen = out.total_seen

            if engine == "github":
                scrape_github(out, gh_manager, topic, target, deep=args.deep, throttle=throttle)
                # --deep: also search for .onion patterns and keys in code
                if args.deep and out.total_written < target:
                    _github_onion_deep_search(out, gh_manager, target, throttle=throttle)
                # Pre-seed known org repos (once only when darkweb tier active)
                if not getattr(_run_engine, "_github_orgs_probed", False):
                    _run_engine._github_orgs_probed = True
                    if tier in ("all", "darkweb") and out.total_written < target:
                        _probe_github_orgs(out, gh_manager, target, throttle=throttle)
            elif engine == "gitlab":
                scrape_gitlab(out, gl_manager, topic, target, deep=args.deep, throttle=throttle)
                # GitLab onion deep search
                if args.deep and out.total_written < target:
                    _gitlab_onion_deep_search(out, gl_manager, target, throttle=throttle)
            elif engine == "huggingface":
                scrape_huggingface(out, hf_manager, topic, target, throttle=throttle)
            elif engine == "docker":
                scrape_docker(out, topic, target, throttle=throttle,
                              docker_user=tokens["docker_user"],
                              docker_token=tokens["docker_token"])
            elif engine == "bitbucket":
                scrape_bitbucket(out, topic, target,
                                 tokens["bitbucket_user"],
                                 tokens["bitbucket_pass"],
                                 tokens["bitbucket_api_token"],
                                 throttle=throttle)
            elif engine == "postman":
                scrape_postman(out, topic, target, tokens["postman_key"], throttle=None)
            elif engine == "onion":
                onion_proxy = getattr(args, "onion_proxy", "127.0.0.1:9050")
                scrape_onion_clearnet(out, topic, target, onion_proxy=onion_proxy, throttle=throttle)

            topic_empty = (out.total_seen == prev_seen)
            if not topic_empty:
                consecutive_empty = 0
            else:
                consecutive_empty += 1

            # Short pause between topics
            time.sleep(0.3 + random.uniform(0, 0.3))

        # ── Engine-specific darknet pre-seeds (run once per engine after topic loop) ─
        if out.total_written < target:
            if engine == "docker" and tier in ("all", "darkweb"):
                for dq in DOCKER_DARKNET_QUERIES:
                    if out.total_written >= target:
                        break
                    scrape_docker(out, dq, target, throttle=throttle,
                                  docker_user=tokens["docker_user"],
                                  docker_token=tokens["docker_token"])
            elif engine == "huggingface" and tier in ("all", "darkweb"):
                for hq in HF_DARKNET_QUERIES:
                    if out.total_written >= target:
                        break
                    scrape_huggingface(out, hf_manager, hq, target, throttle=throttle)
            elif engine == "postman" and tier in ("all", "darkweb"):
                for pq in POSTMAN_DARKNET_QUERIES:
                    if out.total_written >= target:
                        break
                    scrape_postman(out, pq, target, tokens["postman_key"], throttle=throttle)
            elif engine == "bitbucket" and tier in ("all", "darkweb"):
                for ws in DARKNET_ORGS[:20]:  # cap at 20 workspace probes
                    if out.total_written >= target:
                        break
                    _probe_bitbucket_workspace(out, ws, target,
                                               tokens["bitbucket_user"],
                                               tokens["bitbucket_pass"],
                                               tokens["bitbucket_api_token"],
                                               throttle=throttle)

        eng_done = out.engine_counts.get(engine, 0) - prev_engine_count
        cprint(f"[{engine}] done: +{eng_done} new (seen: {out.total_seen}, written: {out.total_written}/{target})", color=C_GREEN)

    # ── Launch API engines in parallel ──────────────────────────
    if api_engines:
        with ThreadPoolExecutor(max_workers=min(len(api_engines), 6)) as executor:
            futures = {executor.submit(_run_engine, e): e for e in api_engines}
            for future in as_completed(futures):
                engine = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    cprint(f"[{engine}] error: {exc}", color=C_BRED)

    # ── Run cloud engines sequentially after API engines ────────
    for engine in active_engines:
        if engine not in cloud_engines:
            continue
        if out.total_written >= target:
            cprint(f"[{engine}] target already reached, skipping", color=C_GRAY, dim=True)
            continue
        cprint(f"\n=== Engine: {engine} ===", color=C_BCYN, bold=True)
        probe_cloud_buckets(out, engine, target, args.bucket_probe_cap, throttle=throttle)

    # ── Boost pass: re-probe funded repos (--boost) ─────────────
    if getattr(args, "boost", False) and out.total_written < target:
        boost_pass(out, gh_manager, target, throttle=throttle)

    # ── Finalize ────────────────────────────────────────────────
    total_rows = out.flush()
    out.close()

    # Clean up resume tmp
    if os.path.exists(RESUME_TMP) and total_rows > 0:
        try:
            os.rename(RESUME_TMP, output_file)
        except Exception:
            pass

    elapsed = round((time.time() - start_time) / 60, 1)
    food_lines = len(out._food_seen)

    print()
    cprint("=" * 60, color=C_BCYN, bold=True)
    cprint(f" DONE — Elapsed: {elapsed}min", color=C_BGRN, bold=True)
    cprint("=" * 60, color=C_BCYN, bold=True)
    cprint(f"Total targets discovered: {out.total_written} / {target}", color=C_BGRN, bold=True)
    cprint(f"Total duplicates skipped: {out.total_skipped}", color=C_YELLOW)
    cprint(f"  (same-repo cross-keyword: {out.total_duplicate_repos})", color=C_YELLOW, dim=True)
    for k in active_engines:
        cnt = out.engine_counts.get(k, 0)
        cprint(f"  {k} : {cnt}", color=C_CYAN)
    cprint(f"Output: {os.path.abspath(output_file)}", color=C_CYAN)
    cprint(f"Feed  : {food_lines} dedup entries => {os.path.abspath(food_file)}", color=C_CYAN)

    # ── Keyword yield report ───────────────────────────────────
    if out.keyword_yield:
        print()
        cprint("─" * 40, color=C_DIM)
        cprint(" Top keywords by repos discovered", color=C_BCYN, bold=True)
        cprint("─" * 40, color=C_DIM)
        ranked = sorted(out.keyword_yield.items(), key=lambda x: -x[1])[:25]
        for i, (kw, n) in enumerate(ranked, 1):
            bar = "█" * min(30, n) if n > 0 else ""
            cprint(f"  {i:2d}. {kw[:55]:55s} {n:5d} {bar}", color=C_GREEN if n >= 5 else C_DIM)
        if len(out.keyword_yield) > 25:
            cprint(f"  ... and {len(out.keyword_yield)-25} more", color=C_DIM)

    # ── Targets format output (--format targets) ───────────────
    if getattr(args, "format", "pipe") == "targets":
        cprint("\n[targets] Writing targets/ directory format...", color=C_CYAN)
        write_targets_format(out)


# =============================================================================
# CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="7000.py v4.0 — Multi-engine secret-surface discovery scraper"
    )
    ap.add_argument("--target", "-t", type=int, default=100000,
                    help="Target number of repos/projects to discover (default: 100000)")
    ap.add_argument("--output", "-o", type=str, default="",
                    help="Output file (default: paste_box.txt)")
    ap.add_argument("--food", "-f", type=str, default="",
                    help="Food/dedup file (default: ffod.txt)")
    ap.add_argument("--engines", "-e", type=str, default="",
                    help="Comma-separated engine list (default: all)")
    ap.add_argument("--topics", type=str, default="all",
                    choices=["crypto", "infra", "general", "darkweb", "all"],
                    help="Topic tier (default: all)")
    ap.add_argument("--bucket-probe-cap", type=int, default=3000,
                    help="Max GCS/S3 bucket name candidates to probe (default: 3000)")
    ap.add_argument("--fresh", action="store_true",
                    help="Truncate output file, start clean (default: append)")
    ap.add_argument("--no-dedup", action="store_true",
                    help="Ignore food file, write all results")
    ap.add_argument("--skip-probes", action="store_true",
                    help="Skip previously-written Bitbucket probe entries in dedup")
    ap.add_argument("--deep", action="store_true",
                    help="Also search code/blobs (slower, higher signal)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Preview only — no writes to output or food files")
    ap.add_argument("--resume", action="store_true",
                    help="Resume from paste_box.tmp if found")
    ap.add_argument("--format", type=str, default="pipe",
                    choices=["pipe", "jsonl", "targets"],
                    help="Output format: pipe (default), jsonl, or targets (targets/ dir)")
    ap.add_argument("--boost", action="store_true",
                    help="After discovery, re-probe repos with funded wallets (deep file search)")
    ap.add_argument("--adaptive", action="store_true",
                    help="Blend high-weight adaptive queries from success atlas into topics")
    ap.add_argument("--two-pass", action="store_true",
                    help="Two-pass: discovery + deep harvest against funded repos (implies --boost)")
    ap.add_argument("--max-cpu", type=int, default=90,
                    help="CPU throttle ceiling %% (default: 90)")
    ap.add_argument("--max-ram", type=int, default=90,
                    help="RAM throttle ceiling %% (default: 90)")
    # ── v5.0 flags ─────────────────────────────────────────
    ap.add_argument("--skip-dead-engines", action="store_true", default=True,
                    help="Auto-skip engines with zero yield and exhausted tokens")
    ap.add_argument("--dedup-ttl", type=int, default=14, metavar="DAYS",
                    help="TTL for dedup entries before re-scan eligibility (default: 14)")
    ap.add_argument("--reap-stale", type=int, default=0, metavar="DAYS",
                    help="Remove dedup entries older than DAYS days (0=disabled)")
    ap.add_argument("--atlas-boost", type=int, default=15, metavar="N",
                    help="Number of atlas-generated surgical queries to blend (default: 15)")
    ap.add_argument("--token-fallback", action="store_true", default=True,
                    help="Fall back to unauthenticated API when all tokens exhausted")
    ap.add_argument("--no-deep-harvest", action="store_true",
                    help="Skip the default two-pass deep harvest (faster)")
    ap.add_argument("--deep-harvest-count", type=int, default=100, metavar="N",
                    help="Number of repos to deep-harvest in pass 2 (default: 100)")
    ap.add_argument("--rescore", action="store_true", default=True,
                    help="Update target scores from scan outcomes at startup (default: true)")
    ap.add_argument("--hot-count", type=int, default=350, metavar="N",
                    help="Number of hot targets to maintain (default: 350)")
    ap.add_argument("--onion-proxy", type=str, default="127.0.0.1:9050",
                    help="Tor SOCKS proxy for onion engine (default: 127.0.0.1:9050)")
    ap.add_argument("--skip-onion", action="store_true",
                    help="Skip the onion/clearnet correlation engine")
    args = ap.parse_args()

    # Validate
    if args.max_cpu < 10 or args.max_cpu > 100:
        cprint("[!] --max-cpu must be 10-100", color=C_BRED)
        sys.exit(1)
    if args.max_ram < 10 or args.max_ram > 100:
        cprint("[!] --max-ram must be 10-100", color=C_BRED)
        sys.exit(1)

    try:
        run(args)
    except KeyboardInterrupt:
        cprint("\n[!] Interrupted by user. Partial results preserved.", color=C_BYEL)
        sys.exit(1)
    except Exception as exc:
        cprint(f"[!] Fatal error: {exc}", color=C_BRED, bold=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
