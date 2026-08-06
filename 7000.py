#!/usr/bin/env python3
"""
7000.py v3.0 — Multi-engine secret-surface discovery scraper
Searches GitHub, GitLab, HuggingFace, Docker Hub, Bitbucket, Postman,
and cloud storage (GCS, S3, Azure Blob, DigitalOcean Spaces)
for repos/projects/buckets likely to contain secrets, keys, credentials,
and crypto material. Outputs to paste_box.txt for downstream scanning.

Major improvements in v3.0:
  • Engines run in parallel via ThreadPoolExecutor (4-6x faster)
  • Shared global target — no rigid per-engine quotas
  • Append-mode output by default, --fresh to truncate
  • --no-dedup, --dry-run, --resume, --deep flags
  • Rate-limit detection with proper Retry-After / X-RateLimit-Reset backoff
  • CPU/RAM throttle with configurable ceilings (default 90%)
  • Only confirmed-live bucket and Bitbucket probe results written to food
  • Expanded 250+ keyword list covering crypto, infra, DevOps, cloud, DBs
  • JSONL output option, pipe-escaping for the default format
  • consecutive_empty bailout raised to 15, tied to total (not net-new) results
  • Token rotator with configurable per-platform budgets and header-based resets

Usage:
    python 7000.py                             # default: 50000 targets
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
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any, Tuple

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
# COMPREHENSIVE SEARCH TOPICS  (250+ high-signal terms, tiered)
# =============================================================================

CRYPTO_TOPICS: List[str] = [
    # ── Wallet / Key Material ───────────────────────────────────
    "wallet.dat", "wallet-backup", "keystore-file", "keystore-json",
    "seed-phrase", "seed-words", "mnemonic-phrase", "mnemonic-code",
    "recovery-phrase", "restore-wallet", "import-wallet",
    "hd-wallet", "bip32", "bip39", "bip44", "bip84", "bip141",
    "xprv", "xpub", "ypub", "zpub", "tpub",
    "extended-private-key", "extended-public-key",
    "private-key", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "ethereum-private-key", "bitcoin-private-key", "solana-keypair",
    "secret-key", "secret-keys",

    # ── Crypto Libraries & Frameworks ───────────────────────────
    "secp256k1", "ed25519", "curve25519", "p256", "nistp256",
    "libsodium", "nacl", "openssl", "boringssl",
    "pycryptodome", "cryptography-io", "pycoin",
    "bitcoinlib", "web3py", "web3js", "ethers-js",
    "solana-web3", "anchor-framework",
    "openzeppelin", "openzeppelin-contracts",
    "forge-std", "foundry-test", "hardhat-deploy",
    "eth-account", "eth-keys", "eth-hash",
    "coincurve", "ecdsa", "eddsa", "schnorr",
    "musig2", "frost-signature", "threshold-signature",

    # ── Encoding / Hashing ──────────────────────────────────────
    "base58", "base58check", "base64", "base64url", "bech32",
    "rlp-encoding", "rlp-decode", "abi-encode", "abi-decode",
    "protobuf-encode", "der-encoding", "pem-encoding",
    "keccak256", "sha3-256", "blake2b", "ripemd160",
    "hash160", "scrypt", "argon2",
    "eth-abi", "solidity-encode", "solidity-decode",

    # ── Crypto Storage / Cloud ──────────────────────────────────
    "gcs-bucket", "gcs-secret", "gcs-credentials",
    "s3-bucket", "s3-leak", "aws-bucket",
    "cloud-secrets", "cloud-kms", "gcp-kms",
    "hashicorp-vault", "vault-secret", "vault-token",
    "secrets-manager", "aws-secrets-manager", "gcp-secret-manager",
    "azure-keyvault", "doppler-secrets", "infisical",

    # ── DeFi / Smart Contracts ──────────────────────────────────
    "reentrancy", "flash-loan-attack", "frontrun",
    "mev-exploit", "sandwich-attack", "oracle-manipulation",
    "rugpull", "honeypot", "drainer", "wallet-drainer",
    "ice-phishing", "approval-phishing", "permit-phish",
    "uniswap", "aave", "compound-finance", "curvefi",
    "chainlink", "makerdao", "liquity", "sushi",
    "pancakeswap", "balancer", "yearn",

    # ── Crypto Tooling / Explorers ──────────────────────────────
    "etherscan-api", "bscscan-api", "polygonscan-api",
    "block-explorer", "tx-hash", "block-hash",
    "raw-transaction", "signed-tx", "unsigned-tx",
    "metamask", "trustwallet", "phantom-wallet", "electrum",
    "ledger", "trezor", "coldcard",
    "gnosis-safe", "safe-wallet", "multisig-wallet",

    # ── General Crypto ──────────────────────────────────────────
    "bitcoin", "ethereum", "solana", "polkadot", "cosmos",
    "avalanche", "polygon", "arbitrum", "optimism",
    "monero", "zcash", "litecoin", "ripple", "stellar",
    "cardano", "algorand", "tezos", "near",
    "defi", "nft", "web3", "dapp", "smart-contract",
    "solidity", "vyper", "rust-bitcoin",
]

INFRA_TOPICS: List[str] = [
    # ── Environment / Config Files ──────────────────────────────
    ".env", ".env.example", ".env.production", ".env.local",
    ".env.development", ".env.staging",
    "dotenv", "env-vars", "environment-variables",
    "config-yaml", "config-json", "config-toml",
    "credentials.json", "credentials-file",
    "service-account-json", "service-account-key",
    "google-credentials", "gcp-credentials",
    "aws-credentials", "aws-config",

    # ── API Keys / Tokens ───────────────────────────────────────
    "api-key", "api-secret", "api-token",
    "aws-access-key", "aws-secret-key", "aws-session-token",
    "infura-key", "alchemy-key", "quicknode-key",
    "chainstack", "moralis-api", "blocknative",
    "stripe-secret-key", "stripe-api-key",
    "twilio-auth-token", "sendgrid-api-key",
    "github-token", "gitlab-token", "bitbucket-app-password",
    "slack-webhook", "discord-webhook", "telegram-bot-token",
    "openai-api-key", "anthropic-api-key", "cohere-api-key",
    "huggingface-token",

    # ── Terraform / IaC ─────────────────────────────────────────
    "terraform.tfstate", "terraform.tfvars",
    "terraform-backend", "terraform-variables",
    "pulumi-state", "pulumi-config",
    "cloudformation-template", "arm-template",
    "cdk-output", "cdk-context",

    # ── Kubernetes ──────────────────────────────────────────────
    "kubeconfig", "kube-config", "kubectl-config",
    "k8s-secret", "kubernetes-secret",
    "configmap", "helm-values", "helm-secrets",
    "kustomize", "kustomization",

    # ── Docker ──────────────────────────────────────────────────
    "docker-compose", "docker-secret", "docker-swarm-secret",
    "docker-config", "docker-credentials",
    "Dockerfile", "docker-build",

    # ── CI / CD ─────────────────────────────────────────────────
    "Jenkinsfile", "jenkins-credentials",
    "github-actions", "github-workflow",
    "gitlab-ci", "gitlab-ci-yml",
    "circleci-config", "travis-yml",
    "argocd", "fluxcd",
    "bitbucket-pipelines",

    # ── Ansible / Configuration Management ──────────────────────
    "ansible-vault", "ansible-secrets",
    "group_vars", "host_vars",
    "chef-secret", "puppet-eyaml",
    "salt-pillar",

    # ── Database ────────────────────────────────────────────────
    "connection-string", "mongodb-uri", "mongo-url",
    "redis-password", "redis-url",
    "postgresql-password", "postgres-url",
    "mysql-password", "mysql-credentials",
    "database-url", "database-password", "database-credentials",
    "pgpass", "my-cnf",

    # ── SSH / SSL / Certs ───────────────────────────────────────
    "id_rsa", "id_ed25519", "id_ecdsa",
    "ssh-private-key", "ssh-config",
    "authorized_keys", "known_hosts",
    "ssl-certificate", "ssl-private-key", "ssl-key",
    "openvpn-config", "wireguard-config",
    "gpg-private-key", "pgp-private-key",

    # ── Password / Secret Managers ──────────────────────────────
    "password-store", "bitwarden", "lastpass",
    "1password", "keepass",
    "aws-secrets-manager", "gcp-secret-manager",

    # ── Cloud Provider ──────────────────────────────────────────
    "google-cloud", "google-cloud-platform",
    "aws", "azure", "heroku", "digitalocean",
    "linode", "vultr",

    # ── General Infra ───────────────────────────────────────────
    "nginx-conf", "apache-conf", "haproxy-cfg",
    "systemd-service", "cron-job",
    "logrotate-conf", "rsyslog-conf",
]

GENERAL_TOPICS: List[str] = [
    "secret", "secrets", "credential", "credentials",
    "token", "tokens", "password", "passwords",
    "private", "confidential", "sensitive",
    "keystore", "keychain", "keyring",
    "jwt-secret", "jwt-token", "oauth2",
    "webhook-secret", "webhook-url",
    "auth", "authentication", "authorization",
    "backup", "backups", "dump", "dumps",
    "database-dump", "sql-dump", "mongodump",
    "leak", "leaks", "exposed", "exposure",
    "pentest", "penetration-test", "vulnerability-assessment",
    "exploit", "exploit-development", "cve",
    "bug-bounty", "responsible-disclosure",
    "forensic", "forensics", "incident-response",
    "malware-analysis", "reverse-engineering",
    "security-audit", "security-scan", "sast", "dast",
    "code-review", "static-analysis",
    "supply-chain", "dependency-confusion",
    "misconfiguration", "hardcoded",
]

# Combined list for default mode
ALL_TOPICS: List[str] = list(dict.fromkeys(
    CRYPTO_TOPICS + INFRA_TOPICS + GENERAL_TOPICS
))

TOPIC_TIERS = {
    "crypto":  CRYPTO_TOPICS,
    "infra":   INFRA_TOPICS,
    "general": GENERAL_TOPICS,
    "all":     ALL_TOPICS,
}

ALL_ENGINES = ["github", "gitlab", "huggingface", "docker",
               "gcs", "s3", "azure", "spaces", "bitbucket", "postman"]

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

    for attempt in range(4):
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

            # Rate-limited — extract backoff from headers
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

                cprint(f"   ⚠ HTTP {e.code} rate-limited — sleeping {wait_s:.0f}s (attempt {attempt+1}/4)",
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
            time.sleep(wait)
            # Reset all
            for t in self._tokens:
                self._remain[t] = self._calls_per_hour
                self._reset[t] = time.time() + self._cooldown_secs
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
                 jsonl: bool = False, resume: bool = False,
                 skip_probes: bool = False):
        self.output_path = output_path
        self.food_path = food_path
        self.no_dedup = no_dedup
        self.jsonl = jsonl
        self.skip_probes = skip_probes
        self._lock = threading.Lock()
        self._food_seen: Set[str] = set()
        self.total_written = 0
        self.total_skipped = 0
        self.engine_counts: Dict[str, int] = {}
        self._resume_loaded = 0

        # Determine open mode
        if fresh:
            mode = "w"
        elif resume and os.path.exists(RESUME_TMP):
            mode = "a"
            cprint(f"[init] Found resume file {RESUME_TMP}, loading...", color=C_CYAN)
            self._load_resume()
        else:
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

        with self._lock:
            # Dedup check
            if not self.no_dedup:
                if food_line in self._food_seen or line in self._food_seen:
                    self.total_skipped += 1
                    return False

            # Dedup: also check by food_line (git URL) to avoid duplicates
            if not self.no_dedup:
                self._food_seen.add(food_line)
            self._food_seen.add(line)

            # Write output line
            try:
                if self._fh is not None:
                    self._fh.write(line + "\n")
                    self._fh.flush()
            except Exception as e:
                cprint(f"[!] Failed to write line: {e}", color=C_BRED)
                return False

            # Write food line
            if not self.no_dedup:
                try:
                    with open(self.food_path, "a", encoding="utf-8") as ff:
                        ff.write(food_line + "\n")
                except Exception:
                    pass

            self.total_written += 1
            self.engine_counts[source] = self.engine_counts.get(source, 0) + 1

        return True

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

    def close(self):
        try:
            if self._fh is not None:
                self._fh.close()
        except Exception:
            pass


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

        for item in resp.get("items", []):
            if out.total_written >= target_count:
                break
            html_url = item.get("html_url", "")
            owner_login = item.get("owner", {}).get("login", "")
            repo_name = item.get("name", "")
            food = f"https://github.com/{owner_login}/{repo_name}.git"
            out.write(html_url, owner_login, repo_name, topic, "github", food)

        count = len(resp.get("items", []))
        cprint(f"   github page {page}: +{count} | Total: {out.total_written}/{target_count}", color=C_GREEN)
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
        if not items or (isinstance(items, dict) and items.get("_error")):
            err = items.get("_error", "unknown") if isinstance(items, dict) else "no response"
            cprint(f"   gitlab API error: {err}", color=C_RED)
            break
        if not isinstance(items, list) or len(items) == 0:
            break

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

        cprint(f"   gitlab page {page}: +{len(items)} | Total: {out.total_written}/{target_count}", color=C_GREEN)
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

            found = 0
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
                found += 1

            if found > 0:
                cprint(f"   huggingface '{q}' {kind}: +{found} | Total: {out.total_written}/{target_count}", color=C_GREEN)
            time.sleep(0.8)


# =============================================================================
# ENGINE: DOCKER HUB
# =============================================================================

def scrape_docker(out: OutputWriter, topic: str, target_count: int,
                  throttle: Optional[ResourceThrottle] = None):
    max_pages = 5
    for page in range(1, max_pages + 1):
        if out.total_written >= target_count:
            break
        q = urllib.parse.quote(topic)
        url = f"https://hub.docker.com/v2/search/repositories/?query={q}&page_size=100&page={page}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }

        resp = http_request(url, headers=headers, timeout=30, throttle=throttle)
        if not resp or not resp.get("results"):
            break

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

        count = len(resp.get("results", []))
        cprint(f"   docker page {page}: +{count} | Total: {out.total_written}/{target_count}", color=C_GREEN)
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

            count = len(resp.get("values", []))
            cprint(f"   bitbucket API page {page}: +{count} | Total: {out.total_written}/{target_count}", color=C_GREEN)
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

        for col in resp.get("collections", []):
            if out.total_written >= target_count:
                break
            uid = str(col.get("uid", ""))
            col_name = str(col.get("name", ""))
            if not uid:
                continue
            col_url = f"https://www.postman.com/collections/{uid}"
            out.write(col_url, "postman", col_name, topic, "postman", f"postman:{uid}")

        count = len(resp.get("collections", []))
        cprint(f"   postman page {page}: +{count} | Total: {out.total_written}/{target_count}", color=C_GREEN)
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

    # ── Generate candidates ──────────────────────────────────────
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

    # ── Resolve topics ──────────────────────────────────────────
    tier = args.topics if args.topics in TOPIC_TIERS else "all"
    topics_list = TOPIC_TIERS[tier]
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
    cprint(" 7000.py v3.0 — Multi-engine secret-surface scraper", color=C_BMAG, bold=True)
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
    gh_rotator = TokenRotator(tokens["github"], "github", calls_per_hour=80)
    gl_rotator = TokenRotator(tokens["gitlab"], "gitlab", calls_per_hour=80)
    hf_rotator = TokenRotator(tokens["huggingface"], "huggingface", calls_per_hour=80)

    # ── Engine dispatch (parallel) ──────────────────────────────
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
            topic = unique_topics[topic_index]
            topic_index += 1
            prev_count = out.total_written

            if engine == "github":
                scrape_github(out, gh_rotator, topic, target, deep=args.deep, throttle=throttle)
            elif engine == "gitlab":
                scrape_gitlab(out, gl_rotator, topic, target, deep=args.deep, throttle=throttle)
            elif engine == "huggingface":
                scrape_huggingface(out, hf_rotator, topic, target, throttle=throttle)
            elif engine == "docker":
                scrape_docker(out, topic, target, throttle=throttle)
            elif engine == "bitbucket":
                scrape_bitbucket(out, topic, target,
                                 tokens["bitbucket_user"],
                                 tokens["bitbucket_pass"],
                                 tokens["bitbucket_api_token"],
                                 throttle=throttle)
            elif engine == "postman":
                scrape_postman(out, topic, target, tokens["postman_key"], throttle=throttle)

            topic_empty = (out.total_written == prev_count)
            if not topic_empty:
                consecutive_empty = 0
            else:
                consecutive_empty += 1

            # Short pause between topics
            time.sleep(0.3 + random.uniform(0, 0.3))

        eng_done = out.engine_counts.get(engine, 0) - prev_engine_count
        cprint(f"[{engine}] done: +{eng_done} new targets (total: {out.total_written}/{target})", color=C_GREEN)

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
    for k in active_engines:
        cnt = out.engine_counts.get(k, 0)
        cprint(f"  {k} : {cnt}", color=C_CYAN)
    cprint(f"Output: {os.path.abspath(output_file)}", color=C_CYAN)
    cprint(f"Feed  : {food_lines} dedup entries => {os.path.abspath(food_file)}", color=C_CYAN)


# =============================================================================
# CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="7000.py v3.0 — Multi-engine secret-surface discovery scraper"
    )
    ap.add_argument("--target", "-t", type=int, default=50000,
                    help="Target number of repos/projects to discover (default: 50000)")
    ap.add_argument("--output", "-o", type=str, default="",
                    help="Output file (default: paste_box.txt)")
    ap.add_argument("--food", "-f", type=str, default="",
                    help="Food/dedup file (default: ffod.txt)")
    ap.add_argument("--engines", "-e", type=str, default="",
                    help="Comma-separated engine list (default: all)")
    ap.add_argument("--topics", type=str, default="all",
                    choices=["crypto", "infra", "general", "all"],
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
                    choices=["pipe", "jsonl"],
                    help="Output format (default: pipe-delimited)")
    ap.add_argument("--max-cpu", type=int, default=90,
                    help="CPU throttle ceiling %% (default: 90)")
    ap.add_argument("--max-ram", type=int, default=90,
                    help="RAM throttle ceiling %% (default: 90)")
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
