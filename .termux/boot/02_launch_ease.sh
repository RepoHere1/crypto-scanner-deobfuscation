#!/data/data/com.termux/files/usr/bin/bash
# Boot bring-up for THE-EASE strategy daemon.
# Runs on device boot via Termux:Boot.
# Launches keep-alive daemon first, then ease_watcher.
sleep 10

# ── runit supervision tree (starts keepalive service + all others) ──────
if ! pgrep -f "runsvdir /data/data/com.termux/files/usr/var/service" >/dev/null 2>&1; then
    nohup runsvdir /data/data/com.termux/files/usr/var/service > /dev/null 2>&1 &
    disown
    echo "[boot] runsvdir launched (keepalive + all services supervised)"
fi

sleep 5
termux-wake-lock 2>/dev/null || true
cd "$HOME" || exit 1
nohup setsid bash "$HOME/ease_watcher.sh" > "$HOME/ease_boot.log" 2>&1 </dev/null &
disown