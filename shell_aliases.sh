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
alias dashgo='if python3 "$HOME/keepalive.py" --status 2>/dev/null | grep -q "keepalive:  RUNNING" && pgrep -f "mass_scan.py" >/dev/null 2>&1 && pgrep -f "crypto_scanner.py" >/dev/null 2>&1; then echo "[dashgo] stack already up — dashboard only"; python3 "$HOME/dashboard.py" --watch; else bash "$HOME/stack_on.sh" && python3 "$HOME/keepalive.py" --daemon && python3 "$HOME/dashboard.py" --watch; fi'
alias dashall='dashgo'

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
