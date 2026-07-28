#!/data/data/com.termux/files/usr/bin/bash
# Finish adding home-screen icons after Termux:Widget is installed.
# Run this after tapping Install on the Termux:Widget APK.

set -euo pipefail
HOME_DIR="$HOME"
SHORTCUT_DIR="$HOME_DIR/.shortcuts"
LOG="$HOME_DIR/icon_finish.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"
}

: > "$LOG"

# ---------------------------------------------------------------------------
# 1. Wait for Termux:Widget
# ---------------------------------------------------------------------------
log "[*] Checking for Termux:Widget..."
for i in {1..30}; do
    if pm list packages | grep -q 'com.termux.widget'; then
        log "[+] Termux:Widget is installed"
        break
    fi
    sleep 1
done

if ! pm list packages | grep -q 'com.termux.widget'; then
    log "[!] Termux:Widget is NOT installed. Open the installer and tap Install first."
    log "    Run: termux-open \$HOME/termux-widget_fdroid.apk"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Refresh shortcut scripts
# ---------------------------------------------------------------------------
log "[*] Installing shortcut scripts..."
bash "$HOME_DIR/install_home_shortcuts.sh" >> "$LOG" 2>&1

# ---------------------------------------------------------------------------
# 3. Try to auto-pin shortcuts (best-effort, Android security may block)
# ---------------------------------------------------------------------------
log "[*] Attempting to pin shortcuts to home screen..."

# Method A: launcher broadcast (deprecated but still works on some launchers)
for name in LaunchAll CryptoScanner StopAll ScannerStatus; do
    script="$SHORTCUT_DIR/$name"
    [ -f "$script" ] || continue
    am broadcast -a com.android.launcher.action.INSTALL_SHORTCUT \
        --es android.intent.extra.shortcut.NAME "$name" \
        --es android.intent.extra.shortcut.INTENT "file://$script" \
        2>/dev/null || true
done

# Method B: try to open Termux:Widget so user can long-press shortcuts there
log "[*] Opening Termux:Widget shortcuts list..."
am start -n com.termux.widget/com.termux.widget.activities.TermuxWidgetMainActivity 2>/dev/null || true
sleep 1

# Method C: launcher broadcast (deprecated but still works on some launchers)
log "[*] Attempting launcher broadcast pin..."
for name in LaunchAll CryptoScanner StopAll ScannerStatus PasteBox; do
    script="$SHORTCUT_DIR/$name"
    [ -f "$script" ] || continue
    am broadcast -a com.android.launcher.action.INSTALL_SHORTCUT \
        --es android.intent.extra.shortcut.NAME "$name" \
        --es android.intent.extra.shortcut.INTENT "file://$script" \
        2>/dev/null || true
done

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
log "[+] Done."
log "[*] Shortcuts installed in both locations:"
log "    $SHORTCUT_DIR"
log "    $HOME_DIR/.termux/widget/dynamic_shortcuts"
ls -1 "$SHORTCUT_DIR" >> "$LOG" 2>&1 || true

if pm list packages | grep -q 'com.termux.widget'; then
    log "[+] Termux:Widget is installed"
else
    log "[!] Termux:Widget is NOT installed"
fi

echo ""
echo "========================================"
echo "Termux:Widget installed: $(pm list packages | grep -q 'com.termux.widget' && echo YES || echo NO)"
echo "Shortcuts ready. Open Termux:Widget and drag them to your home screen."
echo "========================================"
