# 🚀 LAUNCHER - Single Command Startup

## Installation Complete!

### What You Got

1. **Master Launcher Script**: `launch_all.sh` - runs all scans in background
2. **Home Screen Widget**: `~/.shortcuts/LaunchAll` - tap icon to launch
3. **Terminal Alias**: `go` or `all` - type this to start everything

---

## How to Use

### Option 1: Home Screen Icon (Easiest - One Tap!)

**To add to your Android home screen:**

1. **Install Termux:Widget app** (if you haven't):
   ```bash
   # In Termux:
   pkg install termux-api
   ```
   Then install the "Termux:Widget" app from Play Store or GitHub.

2. **Add the widget to your home screen:**
   - Long press on your home screen → Widgets
   - Find "Termux:Widget" or "Termux"
   - Drag it to your home screen
   - It should detect the `LaunchAll` shortcut automatically

3. **Tap the icon** → All services start!

---

### Option 2: Single Terminal Command (No Widget)

**Just type this in your terminal:**
```bash
go
```

Or for a more advanced tmux-based launcher:
```bash
all
```

**Or the full path if you prefer:**
```bash
bash "$HOME/launch_all.sh"
```

---

### Option 3: Alias (Already Set Up!)

I added these aliases to your `~/.bashrc`:

| Command | What It Does |
|---------|--------------|
| `go` | Launch all services (simple) |
| `godir` | CD to home + launch |
| `all` | Launch in tmux session (advanced) |

**Reload your bashrc:**
```bash
source ~/.bashrc
```

---

## What the Launcher Does

```
master_launch.sh
    ├── Starts run_throttled.py (trufflehog mass scan with 2 jobs, low priority)
    ├── Logs everything to ~/launch_all.log
    ├── Shows running background jobs
    └── Displays helpful commands
```

**Background Services:**
- TruffleHog mass scan (files from paste.txt)
- CPU-throttled to be nice to your system (nice level 19)
- Continuous running until you stop it

---

## Managing Services

### Check Status
```bash
tail -f ~/launch_all.log        # Live log output
jobs -l                          # List background jobs
ps aux | grep python3            # All python processes
```

### Stop Services
```bash
kill %1                          # Stop job number 1 (or %2, %3, etc.)
pkill -f run_throttled.py        # Stop the scan specifically
killall python3                  # Stop all Python processes (careful!)
```

### Restart
```bash
go                            # Just run the launcher again
```

---

## File Locations

| File | Purpose |
|------|---------|
| `~/launch_all.sh` | Master launcher script |
| `~/.shortcuts/LaunchAll` | Home screen widget shortcut |
| `~/run_throttled.py` | Throttled scan runner |
| `~/launch_all.log` | Combined log file |
| `~/.bashrc` | Aliases added here |

---

## Troubleshooting

### Widget doesn't appear:
```bash
# Make sure Termux:Widget is installed:
pkg install termux-api

# Then install Termux:Widget app from:
# https://github.com/termux/termux-widget/releases
```

### Services don't start:
```bash
# Check the log:
cat ~/launch_all.log

# Test run manually:
bash ~/launch_all.sh
```

### Can't find the alias:
```bash
# Reload bashrc:
source ~/.bashrc

# Then try:
go
```

---

## Pro Tips

1. **Auto-start on boot** - Add to Android autostart or use Termux:Boot
2. **Multiple scans** - Edit `launch_all.sh` to add more services
3. **Monitor easily** - Use `tmux` or `screen` to detach/reattach
4. **Customize** - Edit `run_throttled.py` to change scan parameters (jobs, files, etc.)

---

## Single Line Command Reference

**The main one-liner you asked for:**
```bash
bash "$HOME/launch_all.sh"
```

**Even shorter (if alias loaded):**
```bash
go
```

**With tmux (detached):**
```bash
tmux new-session -d -s scans 'bash launch_all.sh'
```

---

Need more help? Check out `SCAN_STATUS.md` for full scan status.