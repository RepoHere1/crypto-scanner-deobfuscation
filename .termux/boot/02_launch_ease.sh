#!/data/data/com.termux/files/usr/bin/bash
# Boot bring-up for THE-EASE strategy daemon.
# Runs on device boot via Termux:Boot.
# Launches ease_watcher.sh in background with wake lock.
sleep 15
termux-wake-lock 2>/dev/null || true
cd "$HOME" || exit 1
nohup setsid bash "$HOME/ease_watcher.sh" > "$HOME/ease_boot.log" 2>&1 </dev/null &
disown
