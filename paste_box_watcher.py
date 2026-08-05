#!/usr/bin/env python3
"""paste_box_watcher — monitors ~/paste_box.txt for changes and feeds pipeline."""
import os, sys, time, subprocess
from pathlib import Path

HOME = Path(os.path.expanduser("~"))
PASTE_BOX = HOME / "paste_box.txt"
POLL_SEC = 10

last_size = None
last_mtime = None

print(f"[paste_watch] Watching {PASTE_BOX} (poll every {POLL_SEC}s)")
print("[paste_watch] Drop anything in paste_box.txt → auto-processed into pipeline")

while True:
    try:
        if PASTE_BOX.exists():
            st = PASTE_BOX.stat()
            sz, mt = st.st_size, st.st_mtime
            if sz > 0 and (last_size != sz or last_mtime != mt):
                print(f"[paste_watch] Change detected ({sz} bytes) — processing...")
                subprocess.run(
                    ["python3", str(HOME / "paste_box.py"), str(PASTE_BOX)],
                    capture_output=True, timeout=60,
                )
                print("[paste_watch] Done — fed to pipeline")
                last_size, last_mtime = sz, mt
        time.sleep(POLL_SEC)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"[paste_watch] Error: {e}")
        time.sleep(POLL_SEC)
