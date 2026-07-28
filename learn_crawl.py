#!/usr/bin/env python3
"""
learn_crawl.py - Continuous target discovery and feed helper.

Continuously parses all local data sources and feeds newly discovered
targets (GitHub URLs/orgs, GCS buckets, IPs, RPC endpoints, platform
hints) back into ~/paste_box.txt so the next pipeline run scans them.
"""
from __future__ import annotations
import json, os, re, sys
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
PASTE_BOX = HOME / "paste_box.txt"
PASTE_TXT = HOME / "paste.txt"
LEARN_FILE = HOME / "learn_findings.jsonl"
TRUFFLEHOG_RESULTS = HOME / ".trufflehog_results.jsonl"
TRUFFLEHOG_MASS = HOME / ".trufflehog_mass_results.jsonl"
HIGH_CONFIDENCE = HOME / "high_confidence_hits.jsonl"
BALANCES_HIT = HOME / "balances_hit.jsonl"
RPC_ENDPOINTS = HOME / "rpc_endpoints.jsonl"
CRYPTO_FINDINGS = HOME / "crypto_findings.jsonl"
PIPELINE_LOG = HOME / "pipeline.log"
TARGETS_DIR = HOME / "targets"

GITHUB_URL_RE = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?[/?#]?")
GITHUB_ORG_RE = re.compile(r"\bgit@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
GITHUB_BARE_ORG = re.compile(r"\b([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\s")
GITHUB_URL_SHORT = re.compile(r"\bgh://([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
GCS_URL_RE = re.compile(r"gs://([A-Za-z0-9_.-]+)")
GCS_HTTP_RE = re.compile(r"https?://storage\.googleapis\.com/([A-Za-z0-9_.-]+)")
POSTMAN_RE = re.compile(r"postman://(collection|workspace)/[A-Za-z0-9_.-]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
RPC_RE = re.compile(r"https?://(?:[\w.-]+)(?::\d+)?(?:/[^\s?#]*)?")
SKIP_DOMAINS = {"github.com", "google.com", "amazonaws.com", "gitlab.com",
                "docker.io", "postman.com", "elastic.co", "example.com",
                "wikipedia.org", "cloudflare.com", "iana.org", "iana-servers.net"}

PLATFORM_HINTS = {
    "github": re.compile(r"\bgithub\.com\b|\bgithub://|\bgh://", re.IGNORECASE),
    "gitlab": re.compile(r"\bgitlab\.com\b|\bgitlab://", re.IGNORECASE),
    "huggingface": re.compile(r"\bhuggingface\.co\b|\bhf\.co\b", re.IGNORECASE),
    "docker": re.compile(r"\bdocker\.io\b|\bdockerhub\b|\bdocker\.com\b", re.IGNORECASE),
    "circleci": re.compile(r"\bcircleci\.com\b", re.IGNORECASE),
    "postman": re.compile(r"\bpostman\.com\b|\bpostman\.co\b", re.IGNORECASE),
    "aws_s3": re.compile(r"\bs3\.amazonaws\.com\b|\baws\.amazon\.com\b", re.IGNORECASE),
    "gcs": re.compile(r"\bstorage\.googleapis\.com\b|\bgs://", re.IGNORECASE),
    "jenkins": re.compile(r"\bjenkins\b", re.IGNORECASE),
    "elasticsearch": re.compile(r"\belasticsearch\b", re.IGNORECASE),
    "syslog": re.compile(r"\bsyslog\b", re.IGNORECASE),
}

BEGIN_GEN_MARKER = "# === BEGIN GENERATED TARGETS ==="
END_GEN_MARKER = "# === END GENERATED TARGETS ==="
BEGIN_LEARN_MARKER = "# === BEGIN LEARNED TARGETS ==="
END_LEARN_MARKER = "# === END LEARNED TARGETS ==="

stats = {"sources": 0, "new_urls": 0, "new_orgs": 0, "new_buckets": 0,
         "new_ips": 0, "new_postman": 0, "new_rpc": 0, "new_hints": {}}
LEARNED = set()

def _load_seen():
    if PASTE_BOX.exists():
        with PASTE_BOX.open("r", encoding="utf-8", errors="ignore") as fh:
            txt = fh.read()
        for m in GITHUB_URL_RE.finditer(txt):
            LEARNED.add(f"github:{m.group(1)}/{m.group(2)}")
        for m in GITHUB_ORG_RE.finditer(txt):
            LEARNED.add(f"github:{m.group(1)}/{m.group(2)}")
        for m in GITHUB_URL_SHORT.finditer(txt):
            LEARNED.add(f"github:{m.group(1)}/{m.group(2)}")
        for m in GCS_URL_RE.finditer(txt):
            LEARNED.add(f"gcs:{m.group(1)}")
        for m in IP_RE.finditer(txt):
            LEARNED.add(f"ip:{m.group(0)}")

LEARNED_LINES = set()

def _seen(source, line):
    k = f"{source}:{line.strip()[:100]}"
    return k in LEARNED_LINES

def _mark(source, line):
    LEARNED_LINES.add(f"{source}:{line.strip()[:100]}")

def _extract_urls(text, source):
    new = []
    for m in GITHUB_URL_RE.finditer(text):
        url = f"https://github.com/{m.group(1)}/{m.group(2)}"
        k = f"github:{m.group(1)}/{m.group(2)}"
        if k not in LEARNED:
            LEARNED.add(k); new.append(url); _mark(source, url); stats["new_urls"] += 1
    for m in GITHUB_ORG_RE.finditer(text):
        org = f"{m.group(1)}/{m.group(2)}"
        k = f"github:{m.group(1)}/{m.group(2)}"
        if k not in LEARNED:
            LEARNED.add(k); new.append(org); _mark(source, org); stats["new_orgs"] += 1
    for m in GITHUB_BARE_ORG_RE.finditer(text):
        org = f"{m.group(1)}/{m.group(2)}"
        if org.lower() in {"git","root","admin","user","test","src","lib","bin"}:
            continue
        k = f"github:{org}"
        if k not in LEARNED:
            LEARNED.add(k); new.append(org); _mark(source, org); stats["new_orgs"] += 1
    for m in GITHUB_URL_SHORT.finditer(text):
        url = f"https://github.com/{m.group(1)}/{m.group(2)}"
        k = f"github:{m.group(1)}/{m.group(2)}"
        if k not in LEARNED:
            LEARNED.add(k); new.append(url); _mark(source, url); stats["new_urls"] += 1
    return new

def _extract_gcs(text, source):
    new = []
    for m in GCS_URL_RE.finditer(text):
        k = f"gcs:{m.group(1)}"
        if k not in LEARNED:
            LEARNED.add(k); new.append(f"gs://{m.group(1)}"); _mark(source, m.group(1)); stats["new_buckets"] += 1
    for m in GCS_HTTP_RE.finditer(text):
        k = f"gcs:{m.group(1)}"
        if k not in LEARNED:
            LEARNED.add(k); new.append(f"https://storage.googleapis.com/{m.group(1)}"); _mark(source, m.group(1)); stats["new_buckets"] += 1
    return new

def _extract_ips(text, source):
    new = []
    for m in IP_RE.finditer(text):
        k = f"ip:{m.group(0)}"
        if k not in LEARNED:
            LEARNED.add(k); new.append(m.group(0)); _mark(source, m.group(0)); stats["new_ips"] += 1
    return new

def _extract_rpc(text, source):
    new = []
    for m in RPC_RE.finditer(text):
        url = m.group(0)
        dom = url.split("/")[2].split(":")[0].lower() if "://" in url else ""
        if dom in SKIP_DOMAINS or dom.endswith((".gov", ".edu", ".org")):
            continue
        if url not in LEARNED:
            LEARNED.add(url); new.append(url); _mark(source, url); stats["new_rpc"] += 1
    return new

def _extract_postman(text, source):
    new = []
    for m in POSTMAN_RE.finditer(text):
        url = f"postman://{m.group(1)}"
        if url not in LEARNED:
            LEARNED.add(url); new.append(url); _mark(source, url); stats["new_postman"] += 1
    return new

def _hints(text):
    h = {}
    for p, pat in PLATFORM_HINTS.items():
        c = len(pat.findall(text))
        if c: h[p] = h.get(p, 0) + c
    return h

def _process_file(path, source):
    r = {"github_urls": [], "github_orgs": [], "gcs_buckets": [], "ips": [], "postman": [], "rpc_endpoints": [], "hints": {}}
    if not path.exists(): return r
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or _seen(source, line): continue
            _mark(source, line)
            r["github_urls"].extend(_extract_urls(line, source))
            r["github_orgs"].extend(_extract_urls(line, source))
            r["gcs_buckets"].extend(_extract_gcs(line, source))
            r["ips"].extend(_extract_ips(line, source))
            r["rpc_endpoints"].extend(_extract_rpc(line, source))
            r["postman"].extend(_extract_postman(line, source))
            for p, c in _hints(line).items():
                r["hints"][p] = r["hints"].get(p, 0) + c
    stats["sources"] += 1
    return r

def _process_text(text, source):
    r = {"github_urls": [], "github_orgs": [], "gcs_buckets": [], "ips": [], "postman": [], "rpc_endpoints": [], "hints": {}}
    for line in text.splitlines():
        line = line.strip()
        if not line or _seen(source, line): continue
        _mark(source, line)
        r["github_urls"].extend(_extract_urls(line, source))
        r["gcs_buckets"].extend(_extract_gcs(line, source))
        r["ips"].extend(_extract_ips(line, source))
        r["rpc_endpoints"].extend(_extract_rpc(line, source))
        for p, c in _hints(line).items():
            r["hints"][p] = r["hints"].get(p, 0) + c
    stats["sources"] += 1
    return r

def process_all():
    all_f = {"github_urls": set(), "github_orgs": set(), "gcs_buckets": set(),
             "ips": set(), "postman": set(), "rpc_endpoints": set(), "hints": {}}

    print("  [learn] Processing trufflehog results...")
    r = _process_file(TRUFFLEHOG_RESULTS, "trufflehog")
    for k in ("github_urls","github_orgs","gcs_buckets","ips","postman","rpc_endpoints"):
        all_f[k].update(r.get(k,[]))
    for p,c in r.get("hints",{}).items(): all_f["hints"][p]=all_f["hints"].get(p,0)+c

    print("  [learn] Processing high-confidence hits...")
    r = _process_file(HIGH_CONFIDENCE, "highconf")
    for k in ("github_urls","ips","rpc_endpoints"):
        all_f[k].update(r.get(k,[]))
    for p,c in r.get("hints",{}).items(): all_f["hints"][p]=all_f["hints"].get(p,0)+c

    print("  [learn] Processing pipeline log...")
    r = _process_file(PIPELINE_LOG, "pipeline")
    for k in ("github_urls","github_orgs","ips","rpc_endpoints"):
        all_f[k].update(r.get(k,[]))
    for p,c in r.get("hints",{}).items(): all_f["hints"][p]=all_f["hints"].get(p,0)+c

    print("  [learn] Processing balance hits...")
    r = _process_file(BALANCES_HIT, "balances")
    for k in ("ips","rpc_endpoints"):
        all_f[k].update(r.get(k,[]))
    for p,c in r.get("hints",{}).items(): all_f["hints"][p]=all_f["hints"].get(p,0)+c

    print("  [learn] Processing RPC endpoints...")
    r = _process_file(RPC_ENDPOINTS, "rpc")
    for k in ("rpc_endpoints","ips"):
        all_f[k].update(r.get(k,[]))
    for p,c in r.get("hints",{}).items(): all_f["hints"][p]=all_f["hints"].get(p,0)+c

    print("  [learn] Processing targets directory...")
    if TARGETS_DIR.exists():
        for tf in sorted(TARGETS_DIR.iterdir()):
            if tf.is_file():
                r = _process_file(tf, f"targets/{tf.name}")
                for k in ("github_urls","github_orgs","gcs_buckets","ips"):
                    all_f[k].update(r.get(k,[]))
                for p,c in r.get("hints",{}).items(): all_f["hints"][p]=all_f["hints"].get(p,0)+c

    if PASTE_TXT.exists():
        with PASTE_TXT.open("r", encoding="utf-8", errors="ignore") as fh:
            r = _process_text(fh.read(), "paste_txt")
        all_f["github_urls"].update(r.get("github_urls",set()))
        all_f["github_orgs"].update(r.get("github_orgs",set()))

    return all_f

def append_to_paste(new_items):
    if not new_items: return 0
    paste = ""
    if PASTE_BOX.exists():
        with PASTE_BOX.open("r", encoding="utf-8", errors="ignore") as fh:
            paste = fh.read()

    # Find insert point: after END_GENERATED or END_LEARNED marker
    pos = len(paste)
    for marker in [END_GEN_MARKER, END_LEARN_MARKER]:
        if marker in paste:
            p = paste.index(marker) + len(marker)
            while p < len(paste) and paste[p] in ("\n","\r"): p += 1
            pos = min(pos, p)

    # Read existing content after insert point
    after = paste[pos:] if pos < len(paste) else ""
    existing = set(after.splitlines())

    # Deduplicate against content after markers
    filtered = [i for i in new_items if i.strip() and i.strip() not in existing]

    if not filtered: return 0

    block = [f"# Learn crawl: {datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}"]
    for item in filtered:
        block.append(item)
    block.append(f"# --- end learn batch ({len(filtered)} items) ---")
    block.append(END_LEARN_MARKER)

    # Build new text: before pos + new block + existing after content
    new_text = paste[:pos] + "\n".join(block) + "\n" + after

    with PASTE_BOX.open("w", encoding="utf-8") as fh:
        fh.write(new_text)
    return len(filtered)

def append_record(findings):
    record = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
        "new_github_urls": len(findings.get("github_urls",[])),
        "new_github_orgs": len(findings.get("github_orgs",[])),
        "new_gcs_buckets": len(findings.get("gcs_buckets",[])),
        "new_ips": len(findings.get("ips",[])),
        "new_postman": len(findings.get("postman",[])),
        "new_rpc": len(findings.get("rpc_endpoints",[])),
        "hints": findings.get("hints",{}),
    }
    with LEARN_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

def main():
    print("[+] Learn crawl: continuous target discovery...")
    _load_seen()
    all_f = process_all()

    new_items = []
    new_items.extend(sorted(all_f.get("github_urls",set())))
    new_items.extend(sorted(all_f.get("github_orgs",set())))
    new_items.extend(sorted(all_f.get("gcs_buckets",set())))
    new_items.extend(sorted(all_f.get("ips",set())))
    new_items.extend(sorted(all_f.get("postman",set())))
    new_items.extend(sorted(all_f.get("rpc_endpoints",set())))

    appended = append_to_paste(new_items)

    print(f"\n[+] Learn crawl complete")
    print(f"    Sources parsed:    {stats['sources']}")
    print(f"    New GitHub URLs:   {stats['new_urls']}")
    print(f"    New GitHub orgs:   {stats['new_orgs']}")
    print(f"    New GCS buckets:   {stats['new_buckets']}")
    print(f"    New IPs:           {stats['new_ips']}")
    print(f"    New RPC endpoints: {stats['new_rpc']}")
    print(f"    New Postman:       {stats['new_postman']}")
    print(f"    Targets appended:  {appended}")
    print(f"    Output:            {LEARN_FILE}")

    append_record(all_f)
    return 0

if __name__ == "__main__":
    sys.exit(main())
