#!/usr/bin/env python3
"""paste_box_watcher — monitors ~/paste_box.txt for changes and feeds pipeline."""
import os, sys, time, subprocess
from pathlib import Path

HOME = Path(os.path.expanduser("~"))
PASTE_BOX = HOME / "paste_box.txt"
PASTE_CSV = HOME / "paste_box.csv"
POLL_SEC = 10

last_size = None; last_mtime = None
csv_size = None; csv_mtime = None

print(f"[paste_watch] Watching {PASTE_BOX} + {PASTE_CSV} (poll every {POLL_SEC}s)")
print("[paste_watch] Drop text → paste_box.txt | org names → paste_box.csv")

def process_paste_box():
    print(f"[paste_watch] paste_box.txt changed — processing with paste_box.py...")
    subprocess.run(["python3", str(HOME / "paste_box.py"), str(PASTE_BOX)],
                   capture_output=True, timeout=60)
    print("[paste_watch] paste_box.py done")

def process_paste_csv():
    print(f"[paste_watch] paste_box.csv changed — running github scraper...")
    subprocess.run(["python3", str(HOME / "github_repo_scraper.py")],
                   capture_output=True, timeout=600)
    print("[paste_watch] github scraper done")

while True:
    try:
        if PASTE_BOX.exists():
            st = PASTE_BOX.stat(); sz, mt = st.st_size, st.st_mtime
            if sz > 0 and (last_size != sz or last_mtime != mt):
                process_paste_box(); last_size, last_mtime = sz, mt
        if PASTE_CSV.exists():
            st = PASTE_CSV.stat(); sz, mt = st.st_size, st.st_mtime
            if sz > 0 and (csv_size != sz or csv_mtime != mt):
                process_paste_csv(); csv_size, csv_mtime = sz, mt
        time.sleep(POLL_SEC)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"[paste_watch] Error: {e}")
        time.sleep(POLL_SEC)
