#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
# Install Termux:Widget from F-Droid repo
curl -fL "https://f-droid.org/repo/com.termux.widget_15.apk" -o "$HOME/termux-widget_fdroid.apk"
termux-open "$HOME/termux-widget_fdroid.apk"
echo "[*] Apk opened. Tap Install."
