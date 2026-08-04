# Source from ~/.bashrc:  [ -f "$HOME/shell_aliases.sh" ] && . "$HOME/shell_aliases.sh"
# No secrets in this file.

alias go='bash "$HOME/launch_all.sh"'
alias godir='cd "$HOME" && bash launch_all.sh'
alias scandir='cd "$HOME" && bash start_crypto_scanner.sh'
alias scan='python3 "$HOME/crypto_scanner.py" "$HOME/.trufflehog_results.jsonl"'
alias scanstop='pkill -f "crypto_scanner.py" || true'
alias scanstatus='python3 "$HOME/scanstatus.py"'
alias scanpipeline='python3 "$HOME/pipeline.py"'
alias scanstopall='python3 "$HOME/pipeline.py" --stop'

alias pastebox='$EDITOR "$HOME/paste_box.txt"'
alias pastep='python3 "$HOME/paste_box.py" && cat "$HOME/paste.txt"'

alias dash='python3 "$HOME/dashboard.py"'
alias dashw='python3 "$HOME/dashboard.py" --watch'
# Multi-window safe: if stack up, only open dashboard
alias dashgo='bash "$HOME/dashgo.sh"'
alias dashall='bash "$HOME/dashgo.sh"'

alias walletview='python3 "$HOME/wallet_view.py" --watch --page-size 8 --page-sec 8'
alias walletall='python3 "$HOME/wallet_view.py" --once --all --cached'
alias walletpage='python3 "$HOME/wallet_view.py" --once --cached --page'

alias watch2='python3 "$HOME/watch2.py"'
alias w2='python3 "$HOME/watch2.py"'
alias stackon='bash "$HOME/stack_on.sh"'
alias stackwatch='python3 "$HOME/watch2.py" -i 5'

alias keepgo='python3 "$HOME/keepalive.py" --daemon'
alias keepstatus='python3 "$HOME/keepalive.py" --status'
alias keepstop='python3 "$HOME/keepalive.py" --stop'

# Forensic static examiner (does NOT replace walletview rotator)
alias walletforensic='python3 "$HOME/wallet_forensic.py" --idle-sec 120 --tick-sec 0.35 --batch 24'
alias wforensic='python3 "$HOME/wallet_forensic.py" --idle-sec 120 --tick-sec 0.35 --batch 24'
# ── WalletX TUI Dashboard (NEW — orange/black/white theme, buttons, animations) ──
alias walletx='python3 "$HOME/walletx_tui.py" --funded-only --batch 24'
alias walletxall='python3 "$HOME/walletx_tui.py" --batch 24'
alias walletxlegacy='python3 "$HOME/wallet_forensic.py" --funded-only --idle-sec 120 --tick-sec 0.35 --batch 24'
# Android device wallet scanner
alias walletscan='python3 "$HOME/android_wallet_scanner.py"'
alias walletscan_email='python3 "$HOME/android_wallet_scanner.py" --email'
alias wforensic1='python3 "$HOME/wallet_forensic.py" --once --cached --funded-only'
alias walletxdump='python3 "$HOME/wallet_forensic.py" --once --cached --funded-only'
alias walletxexport='ls -lt "$HOME/forensic_exports" 2>/dev/null | head -20'

# Smooth URL feed (backup + clean + IQ-rank + reload mass_scan)
alias feed='python3 "$HOME/feed_smooth.py" --restart'
alias feedstatus='python3 "$HOME/feed_smooth.py" --status'
alias feedurls='bash "$HOME/feed_urls.sh"'
alias inbox='mkdir -p "$HOME/inbox" && echo "drop files in $HOME/inbox then: feed"'
