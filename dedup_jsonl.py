#!/usr/bin/env python3
"""
Deduplicate JSONL files in-place while preserving order.

Usage:
    python3 ~/dedup_jsonl.py                          # dedup memory/hits/cache
    python3 ~/dedup_jsonl.py file1.jsonl file2.jsonl  # dedup specific files
"""
import hashlib
import json
import os
import sys
import threading
import time
import itertools

HOME = os.path.expanduser("~")
DEFAULT_FILES = [
    os.path.join(HOME, "crypto_scanner_memory.jsonl"),
    os.path.join(HOME, "high_confidence_hits.jsonl"),
    os.path.join(HOME, "balance_cache.jsonl"),
    os.path.join(HOME, "balances_hit.jsonl"),
]


class Spinner:
    """Simple terminal spinner to show a background task is alive."""

    def __init__(self, message: str):
        self.message = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for char in itertools.cycle(["|", "/", "-", "\\"]):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r{self.message} {char}")
            sys.stdout.flush()
            time.sleep(0.12)
        sys.stdout.write(f"\r{self.message} done\n")
        sys.stdout.flush()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._stop.set()
        self._thread.join()


def _normalize(line: str) -> str:
    """Normalize JSON before hashing so equivalent records dedupe."""
    try:
        obj = json.loads(line)
        return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return line.strip()


def dedup_file(path: str) -> tuple:
    """Remove duplicate lines from a JSONL file. Returns (before, after)."""
    if not os.path.exists(path):
        return 0, 0

    tmp_path = path + ".dedup.tmp"
    seen: set = set()
    before = 0
    after = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as src, \
         open(tmp_path, "w", encoding="utf-8") as dst:
        for line in src:
            before += 1
            stripped = line.strip()
            if not stripped:
                continue
            key = hashlib.md5(_normalize(stripped).encode("utf-8")).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            dst.write(stripped + "\n")
            after += 1

    os.replace(tmp_path, path)
    return before, after


def main():
    files = sys.argv[1:] or DEFAULT_FILES
    files = [f for f in files if os.path.exists(f)]

    if not files:
        print("[*] No files to dedup.")
        return

    print(f"[*] Deduplicating {len(files)} file(s)...")
    for path in files:
        with Spinner(f"  {os.path.basename(path)}"):
            before, after = dedup_file(path)
        removed = before - after
        print(f"  {os.path.basename(path)}: {before} -> {after} ({removed} removed)")
    print("[*] Done.")


if __name__ == "__main__":
    main()
