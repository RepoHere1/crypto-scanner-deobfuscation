#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
APK_NAME="termux-widget-app_v0.15.0+github.debug.apk"
URL="https://github.com/termux/termux-widget/releases/download/v0.15.0/${APK_NAME}"
DEST="$HOME/${APK_NAME}"
if [ -f "$DEST" ]; then
    echo "[*] APK already exists: $DEST"
else
    echo "[*] Downloading Termux:Widget v0.15.0..."
    curl -fL "$URL" -o "$DEST"
fi
 echo "[*] Install with:"
 echo "    pm install -r $DEST"
 echo "[*] Or open it with your file manager and tap Install."
