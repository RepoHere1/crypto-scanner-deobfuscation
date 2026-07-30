#!/usr/bin/env python3
"""feed_smooth.py — reliable URL feeder for mass_scan.

Problems this fixes:
  * paste_box.txt bloated with garbage / obfuscated sludge (100MB+)
  * duplicate paste_box.py runs pegging CPU and never finishing
  * paste.txt going stale while mass_scan keeps the old list open
  * no prioritization from real success / IQ outcomes

What it does:
  1. Single-flight lock (flock) — never two feeders at once
  2. Timestamped backups of paste.txt + paste_box.txt
  3. Stream-extract CLEAN GitHub URLs only (no full-file deobfuscate)
  4. Merge inbox/* drops, optional CLI args / stdin
  5. Rank by success IQ: hot_targets, target_scores (key/balance hits),
     success_atlas orgs, learn_boost, crypto-path keywords
  6. Write ranked ~/paste.txt + slim clean ~/paste_box.txt
  7. Optionally restart mass_scan so adaptive_throttler reloads the file

Usage:
    python3 ~/feed_smooth.py              # process box + inbox, rewrite paste.txt
    python3 ~/feed_smooth.py --restart    # same + bounce mass_scan
    python3 ~/feed_smooth.py url1 url2    # also ingest these URLs
    python3 ~/feed_smooth.py urls.txt     # also ingest file(s)
    cat list.txt | python3 ~/feed_smooth.py --restart
    python3 ~/feed_smooth.py --status     # show feed health only
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

HOME = Path.home()
PASTE_TXT = HOME / "paste.txt"
PASTE_BOX = HOME / "paste_box.txt"
INBOX_DIR = HOME / "inbox"
BACKUP_DIR = HOME / "backups" / "paste"
LOCK_FILE = HOME / ".feed_smooth.lock"
LOG_FILE = HOME / "feed_smooth.log"
HOT_FILE = HOME / ".hot_targets.json"
SCORES_FILE = HOME / ".target_scores.json"
ATLAS_FILE = HOME / ".success_atlas.json"
LEARN_BOOST = HOME / ".learn_boost_targets.txt"
TARGETS_GITHUB = HOME / "targets" / "targets_github.txt"

MAX_PASTE_URLS = int(os.environ.get("FEED_MAX_URLS", "25000"))
MAX_BOX_KEEP_URLS = int(os.environ.get("FEED_BOX_KEEP", "8000"))
MAX_BACKUP_BYTES = 80 * 1024 * 1024
MAX_LINE_SCAN = 2_000_000

GITHUB_RE = re.compile(
    r"(?:https?://(?:www\.)?github\.com/|git@github\.com:)"
    r"([A-Za-z0-9][A-Za-z0-9_.-]*)/([A-Za-z0-9][A-Za-z0-9_.-]*?)"
    r"(?:\.git)?(?:[/?#\s,\"'<>\]\)]|$)",
    re.I,
)
CSV_URL_RE = re.compile(
    r"^(https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)",
    re.I,
)
OWNER_REPO_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]{0,38})/([A-Za-z0-9][A-Za-z0-9_.-]{0,99})$"
)
GIST_RE = re.compile(
    r"https?://gist\.github\.com/([A-Za-z0-9_.-]+)/([a-f0-9]{6,})",
    re.I,
)
FAKE_RE = re.compile(
    r"placeholder|example\.com|myuser|my-bucket|your[-_]|xxx|dummy|changeme|"
    r"localhost|127\.0\.0\.1|todo|fixme|acme/wallet-app",
    re.I,
)
BAD_REPO_RE = re.compile(
    r"^(settings|marketplace|topics|collections|orgs|search|about|pricing|"
    r"features|enterprise|login|signup|notifications|explore|pulls|issues|"
    r"codespaces|copilot|sponsors|customer-stories|readme|site|apps)$",
    re.I,
)
SIGNAL_KW = (
    "wallet", "keystore", "mnemonic", "secret", ".env", "private",
    "deploy", "hardhat", "foundry", "bridge", "peggy", "ethbridge",
    "crypto", "bitcoin", "ethereum", "secp256k1", "bip39", "vault",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def acquire_lock():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        raise SystemExit("[!] feed_smooth already running (lock busy). Abort.")
    fh.write(str(os.getpid()))
    fh.flush()
    return fh

def normalize_github(owner: str, repo: str) -> Optional[str]:
    owner = (owner or "").strip().strip("/")
    repo = (repo or "").strip().strip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    if len(owner) > 39 or len(repo) > 100:
        return None
    if BAD_REPO_RE.match(owner) or BAD_REPO_RE.match(repo):
        return None
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", owner):
        return None
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", repo):
        return None
    sample = (owner + repo).lower()
    if sum(c.isdigit() for c in sample) > max(6, len(sample) * 0.45):
        return None
    url = f"https://github.com/{owner}/{repo}"
    if FAKE_RE.search(url):
        return None
    return url


def extract_urls_from_text(text: str) -> Set[str]:
    found: Set[str] = set()
    for m in GITHUB_RE.finditer(text):
        u = normalize_github(m.group(1), m.group(2))
        if u:
            found.add(u)
    for m in GIST_RE.finditer(text):
        g = f"https://gist.github.com/{m.group(1)}/{m.group(2)}"
        if not FAKE_RE.search(g):
            found.add(g)
    for raw in text.splitlines():
        s = raw.strip().strip(",").strip('"').strip("'")
        if not s or s.startswith("#"):
            continue
        cm = CSV_URL_RE.match(s)
        if cm:
            m = GITHUB_RE.search(cm.group(1))
            if m:
                u = normalize_github(m.group(1), m.group(2))
                if u:
                    found.add(u)
            continue
        if s.startswith("http") and "github.com" in s:
            continue
        parts = s.split()
        token = parts[0] if parts else s
        om = OWNER_REPO_RE.match(token)
        if om:
            u = normalize_github(om.group(1), om.group(2))
            if u:
                found.add(u)
    return found


def stream_extract_file(path: Path) -> Set[str]:
    found: Set[str] = set()
    if not path.exists():
        return found
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= MAX_LINE_SCAN:
                    log(f"  scan cap hit at {MAX_LINE_SCAN} lines in {path.name}")
                    break
                if len(line) > 8000:
                    found |= extract_urls_from_text(line[:4000])
                    continue
                low = line.lower()
                if "github" not in low and "/" not in line:
                    continue
                found |= extract_urls_from_text(line)
    except OSError as exc:
        log(f"  read error {path}: {exc}")
    return found


def backup_file(path: Path, tag: str) -> Optional[Path]:
    if not path.exists():
        return None
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = utc_now()
    size = path.stat().st_size
    try:
        if size <= MAX_BACKUP_BYTES:
            dest = BACKUP_DIR / f"{path.name}.{tag}.{ts}"
            shutil.copy2(path, dest)
            log(f"  backup {path.name} -> {dest.name} ({size} bytes)")
        else:
            dest = BACKUP_DIR / f"{path.name}.{tag}.{ts}.head"
            with path.open("rb") as src, dest.open("wb") as dst:
                dst.write(src.read(8 * 1024 * 1024))
            log(f"  backup HEAD-only {path.name} -> {dest.name} (src {size} bytes)")
        return dest
    except OSError as exc:
        log(f"  backup failed {path}: {exc}")
        return None

def load_iq_scores():
    scores: Dict[str, float] = {}
    hot_ordered: List[str] = []
    boost_orgs: Set[str] = set()

    if HOT_FILE.exists():
        try:
            hot = json.loads(HOT_FILE.read_text(encoding="utf-8", errors="ignore"))
            for t in hot.get("targets") or []:
                uri = (t.get("uri") or "").rstrip("/")
                if not uri.startswith("https://github.com/"):
                    continue
                m = GITHUB_RE.search(uri)
                if not m:
                    continue
                u = normalize_github(m.group(1), m.group(2))
                if not u:
                    continue
                sc = float(t.get("score") or 0.0) + 5.0
                scores[u] = max(scores.get(u, 0.0), sc)
                hot_ordered.append(u)
        except Exception as exc:
            log(f"  hot_targets load err: {exc}")

    if SCORES_FILE.exists():
        try:
            data = json.loads(SCORES_FILE.read_text(encoding="utf-8", errors="ignore"))
            for row in data.values():
                if not isinstance(row, dict):
                    continue
                uri = str(row.get("uri") or "")
                m = GITHUB_RE.search(uri)
                if not m:
                    m2 = re.search(
                        r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", uri
                    )
                    if not m2:
                        continue
                    m = m2
                u = normalize_github(m.group(1), m.group(2))
                if not u:
                    continue
                base = float(row.get("score") or 0.0)
                keys = int(row.get("key_hits") or 0)
                bals = int(row.get("balance_hits") or 0)
                sc = base + 3.0 * bals + 1.2 * min(keys, 20)
                if bals or keys:
                    sc += 2.0
                scores[u] = max(scores.get(u, 0.0), sc)
                if bals or keys:
                    boost_orgs.add(m.group(1).lower())
        except Exception as exc:
            log(f"  target_scores load err: {exc}")

    if ATLAS_FILE.exists():
        try:
            atlas = json.loads(ATLAS_FILE.read_text(encoding="utf-8", errors="ignore"))
            for item in atlas.get("top_github_repos") or []:
                if isinstance(item, (list, tuple)) and item:
                    repo_u = str(item[0])
                    w = float(item[1]) if len(item) > 1 else 1.0
                elif isinstance(item, str):
                    repo_u, w = item, 1.0
                else:
                    continue
                m = GITHUB_RE.search(repo_u)
                if not m:
                    om = OWNER_REPO_RE.match(repo_u)
                    if not om:
                        continue
                    m = om
                u = normalize_github(m.group(1), m.group(2))
                if u:
                    scores[u] = max(scores.get(u, 0.0), 4.0 + w)
                    boost_orgs.add(m.group(1).lower())
            for item in atlas.get("top_orgs") or []:
                if isinstance(item, (list, tuple)) and item:
                    boost_orgs.add(str(item[0]).lower())
                elif isinstance(item, str):
                    boost_orgs.add(item.lower())
        except Exception as exc:
            log(f"  atlas load err: {exc}")

    if LEARN_BOOST.exists():
        try:
            for ln in LEARN_BOOST.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                for u in extract_urls_from_text(s):
                    scores[u] = max(scores.get(u, 0.0), 3.5)
                    m = GITHUB_RE.search(u)
                    if m:
                        boost_orgs.add(m.group(1).lower())
        except Exception:
            pass

    return scores, hot_ordered, boost_orgs


def keyword_bonus(url: str) -> float:
    low = url.lower()
    return sum(0.08 for kw in SIGNAL_KW if kw in low)


def org_bonus(url: str, boost_orgs: Set[str]) -> float:
    m = GITHUB_RE.search(url)
    if not m:
        return 0.0
    return 1.5 if m.group(1).lower() in boost_orgs else 0.0

def rank_urls(urls, scores, hot_ordered, boost_orgs):
    hot_set = set(hot_ordered)
    all_urls = set(urls) | hot_set | set(scores.keys())
    clean: Set[str] = set()
    for u in all_urls:
        if "gist.github.com" in u:
            clean.add(u.rstrip("/"))
            continue
        mm = re.match(
            r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+)", u.rstrip("/")
        )
        if not mm:
            continue
        nu = normalize_github(mm.group(1), mm.group(2))
        if nu:
            clean.add(nu)

    def sort_key(u: str):
        sc = scores.get(u, 0.0) + keyword_bonus(u) + org_bonus(u, boost_orgs)
        return (-sc, u.lower())

    ranked = sorted(clean, key=sort_key)
    out: List[str] = []
    seen: Set[str] = set()
    for u in hot_ordered:
        nu = u
        m = re.match(
            r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+)", u.rstrip("/")
        )
        if m:
            nu2 = normalize_github(m.group(1), m.group(2))
            if nu2:
                nu = nu2
        if nu in clean and nu not in seen:
            out.append(nu)
            seen.add(nu)
    for u in ranked:
        if u not in seen:
            out.append(u)
            seen.add(u)
        if len(out) >= MAX_PASTE_URLS:
            break
    return out


def kill_stuck_paste_box() -> int:
    killed = 0
    try:
        out = subprocess.check_output(
            ["pgrep", "-af", "paste_box.py"], text=True, errors="ignore"
        )
    except subprocess.CalledProcessError:
        return 0
    my_pid = os.getpid()
    for line in out.splitlines():
        line = line.strip()
        if not line or "feed_smooth" in line:
            continue
        parts = line.split(None, 1)
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid == my_pid:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            killed += 1
            log(f"  SIGTERM paste_box pid={pid}")
        except ProcessLookupError:
            pass
    if killed:
        time.sleep(1.5)
        try:
            out2 = subprocess.check_output(
                ["pgrep", "-af", "paste_box.py"], text=True, errors="ignore"
            )
            for line in out2.splitlines():
                if "feed_smooth" in line:
                    continue
                try:
                    pid = int(line.split(None, 1)[0])
                    os.kill(pid, signal.SIGKILL)
                    log(f"  SIGKILL paste_box pid={pid}")
                except (ValueError, ProcessLookupError):
                    pass
        except subprocess.CalledProcessError:
            pass
    return killed


def restart_mass_scan() -> None:
    log("restarting mass_scan to reload paste.txt ...")
    try:
        subprocess.run(
            ["pkill", "-f", "trufflehog-tools/mass_scan.py"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        log(f"  pkill mass_scan err: {exc}")
    time.sleep(2)
    alive = False
    try:
        subprocess.check_call(
            ["pgrep", "-f", "adaptive_throttler.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        alive = True
    except subprocess.CalledProcessError:
        alive = False
    if not alive:
        log("  adaptive_throttler not running — starting it")
        logf = open(HOME / "adaptive_scan.log", "a", encoding="utf-8")
        subprocess.Popen(
            [sys.executable, str(HOME / "adaptive_throttler.py")],
            cwd=str(HOME),
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    for _ in range(20):
        time.sleep(1)
        try:
            subprocess.check_call(
                ["pgrep", "-f", "trufflehog-tools/mass_scan.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            log("  mass_scan is back")
            return
        except subprocess.CalledProcessError:
            continue
    log("  note: mass_scan not seen yet — watchdog/adaptive should pick it up")

def write_paste(ranked: List[str]) -> None:
    header = [
        "# Auto-generated by feed_smooth.py (clean URLs, IQ-ranked)",
        f"# generated_at={datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}",
        f"# count={len(ranked)}",
        "# GitHub URLs",
    ]
    tmp = PASTE_TXT.with_suffix(".txt.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(header) + "\n")
        for u in ranked:
            fh.write(u + "\n")
    tmp.replace(PASTE_TXT)
    TARGETS_GITHUB.parent.mkdir(parents=True, exist_ok=True)
    with TARGETS_GITHUB.open("w", encoding="utf-8") as fh:
        for u in ranked:
            fh.write(u + "\n")


def write_clean_box(ranked: List[str]) -> None:
    keep = ranked[:MAX_BOX_KEEP_URLS]
    tmp = PASTE_BOX.with_suffix(".txt.tmp")
    lines = [
        "# Cleaned by feed_smooth.py — drop new messy text below OR use ~/inbox/",
        "# Run: python3 ~/feed_smooth.py --restart",
        f"# cleaned_at={datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}",
        f"# kept={len(keep)} (IQ-ranked)",
        "# === BEGIN GENERATED TARGETS ===",
        f"# LIVE prioritized clean feed @ {utc_now()}",
        "# --- github: targets ---",
    ]
    lines.extend(keep)
    lines.append("# === END GENERATED TARGETS ===")
    lines.append("")
    lines.append("# --- manual drops (appended by you / inbox) ---")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    tmp.replace(PASTE_BOX)


def ingest_inbox() -> Set[str]:
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    found: Set[str] = set()
    processed_dir = INBOX_DIR / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(
        p for p in INBOX_DIR.iterdir()
        if p.is_file() and not p.name.startswith(".")
    )
    for p in files:
        log(f"  inbox ingest {p.name}")
        found |= stream_extract_file(p)
        ts = utc_now()
        dest = processed_dir / f"{p.name}.{ts}"
        try:
            shutil.move(str(p), str(dest))
        except OSError:
            try:
                p.unlink()
            except OSError:
                pass
    return found


def ingest_cli_sources(args: List[str]) -> Set[str]:
    found: Set[str] = set()
    for a in args:
        if a.startswith("-"):
            continue
        p = Path(os.path.expanduser(a))
        if p.is_file():
            log(f"  file ingest {p}")
            found |= stream_extract_file(p)
        else:
            found |= extract_urls_from_text(a)
    if not sys.stdin.isatty():
        try:
            data = sys.stdin.read()
            if data.strip():
                log(f"  stdin ingest ({len(data)} bytes)")
                found |= extract_urls_from_text(data)
        except Exception:
            pass
    return found


def show_status() -> int:
    def sz(p: Path) -> str:
        if not p.exists():
            return "MISSING"
        st = p.stat()
        mt = datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
        return f"{st.st_size} bytes  mtime={mt}"

    print("=== feed status ===")
    print(f"paste.txt     : {sz(PASTE_TXT)}")
    print(f"paste_box.txt : {sz(PASTE_BOX)}")
    if PASTE_TXT.exists():
        n = sum(
            1
            for ln in PASTE_TXT.read_text(errors="ignore").splitlines()
            if ln.startswith("https://github.com/")
        )
        print(f"paste github  : {n} urls")
    for pat, label in [
        ("trufflehog-tools/mass_scan.py", "mass_scan"),
        ("adaptive_throttler.py", "adaptive"),
        ("paste_box.py", "paste_box"),
        ("feed_smooth.py", "feed_smooth"),
    ]:
        try:
            out = subprocess.check_output(["pgrep", "-af", pat], text=True, errors="ignore")
            lines = [l for l in out.splitlines() if l.strip()]
            print(f"{label:12}: {len(lines)} proc")
            for l in lines[:3]:
                print(f"    {l[:140]}")
        except subprocess.CalledProcessError:
            print(f"{label:12}: not running")
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "trufflehog-tools/mass_scan.py"], text=True
        )
        pid = out.strip().splitlines()[0]
        targets = []
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                t = os.readlink(fd)
                if "paste" in t:
                    targets.append(t)
            except OSError:
                pass
        print(f"mass open     : {targets or 'no paste fd (still starting?)'}")
    except Exception:
        pass
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description="Clean IQ-ranked feeder for paste.txt")
    ap.add_argument("sources", nargs="*", help="extra URLs or files")
    ap.add_argument("--restart", action="store_true", help="bounce mass_scan after write")
    ap.add_argument("--status", action="store_true", help="status only")
    ap.add_argument("--no-box-clean", action="store_true", help="do not rewrite paste_box.txt")
    ap.add_argument("--keep-box", action="store_true", help="alias of --no-box-clean")
    ap.add_argument("--no-kill", action="store_true", help="do not kill stuck paste_box.py")
    args = ap.parse_args()

    if args.status:
        return show_status()

    lock_fh = acquire_lock()
    try:
        log("=== feed_smooth start ===")
        if not args.no_kill:
            n = kill_stuck_paste_box()
            log(f"killed stuck paste_box: {n}")

        log("backing up ...")
        backup_file(PASTE_TXT, "pre")
        backup_file(PASTE_BOX, "pre")

        log("loading success IQ ...")
        scores, hot_ordered, boost_orgs = load_iq_scores()
        log(
            f"  scored_urls={len(scores)} hot={len(hot_ordered)} "
            f"boost_orgs={len(boost_orgs)}"
        )

        log("extracting clean URLs ...")
        urls: Set[str] = set()
        urls |= stream_extract_file(PASTE_TXT)
        log(f"  from paste.txt: {len(urls)}")
        before = len(urls)
        urls |= stream_extract_file(PASTE_BOX)
        log(f"  + paste_box.txt => {len(urls)} (+{len(urls) - before})")
        before = len(urls)
        urls |= ingest_inbox()
        log(f"  + inbox => {len(urls)} (+{len(urls) - before})")
        before = len(urls)
        urls |= ingest_cli_sources(args.sources)
        log(f"  + cli/stdin => {len(urls)} (+{len(urls) - before})")

        if not urls and not scores and not hot_ordered:
            log("[!] no URLs found — abort without clobbering")
            return 2

        log("ranking by success IQ ...")
        ranked = rank_urls(urls, scores, hot_ordered, boost_orgs)
        log(f"  ranked={len(ranked)}")
        if ranked:
            log("  top 12:")
            for u in ranked[:12]:
                sc = scores.get(u, 0.0) + keyword_bonus(u) + org_bonus(u, boost_orgs)
                log(f"    {sc:7.3f}  {u}")

        log(f"writing {PASTE_TXT} ...")
        write_paste(ranked)

        if not args.no_box_clean and not args.keep_box:
            log(f"writing clean {PASTE_BOX} (slim IQ list) ...")
            write_clean_box(ranked)
        else:
            log("keeping existing paste_box.txt (--no-box-clean)")

        try:
            baks = sorted(
                BACKUP_DIR.glob("*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in baks[8:]:
                old.unlink(missing_ok=True)
        except OSError:
            pass

        log(f"DONE paste.txt urls={len(ranked)} size={PASTE_TXT.stat().st_size}")
        if args.restart:
            restart_mass_scan()
        else:
            log("tip: re-run with --restart to bounce mass_scan onto the new list")
        log("=== feed_smooth done ===")
        return 0
    finally:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            lock_fh.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
