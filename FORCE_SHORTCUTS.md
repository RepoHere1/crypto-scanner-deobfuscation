# Force Install Home Screen Icons

## Why This Isn't Working

Android blocks apps from directly writing home-screen shortcuts without either:
- Termux:Widget app installed
- Root access
- ADB connection
- Launcher-specific support

Your `~/.shortcuts/CryptoScanner` and `~/.shortcuts/LaunchAll` ARE correct.
They just need Termux:Widget to expose them as home-screen icons.

## Direct Install of Termux:Widget APK

Since Play Store doesn't have it, install from GitHub:

```bash
# Option A: Auto-download + install
bash install_termux_widget.sh
pm install -r ~/termux-widget_v0.13.0.apk

# Option B: Manual download
# Open this URL on your phone:
# https://github.com/termux/termux-widget/releases/download/v0.13.0/termux-widget_v0.13.0.apk
# Then tap it to install
```

## Add Icons to Home Screen

After installing Termux:Widget:

1. Long-press your home screen
2. Select "Widgets"
3. Scroll to "Termux" or "Termux:Widget"
4. Find and drag **CryptoScanner** to your home screen
5. Find and drag **LaunchAll** to your home screen

## Alternative: Launcher Activities

If your launcher supports it:
1. Long-press home → Widgets → Activities
2. Find `com.termux` → `.TermuxActivity`
3. Create shortcut named CryptoScanner
4. Repeat for LaunchAll

Then to make them run scripts, you'd need to edit the shortcut target, which varies by launcher.

## Alternative: Use Aliases (Already Set Up)

Since home-screen icons are difficult without Termux:Widget, use these aliases:

```bash
scandir    # starts crypto scanner
go         # starts truffle scan + crypto scanner
scanmem    # view latest findings
scanstatus # view status
```

## Summary

- The shortcuts in `~/.shortcuts/` ARE correct
- Termux:Widget is REQUIRED for home screen icons
- Direct writing from Termux is blocked by Android security
- Install Termux:Widget APK from GitHub to get your icons
