# VHS tape for the README demo GIF.
# Render with: vhs docs/demo.tape   (requires vhs, ttyd, ffmpeg)
#
# The app is launched with --demo so every identifying value (IPs, account
# IDs, ARNs, hostnames, server names, bucket and log-group names) is
# replaced with deterministic fake equivalents — see docs/demo-mode.md.
# Safe to record against a real environment.
#
# Note: ttyd/xterm.js cannot deliver ctrl+shift chords or F-keys, hence
# the ctrl+g chat binding (fallback for F2) used below.

Output "docs/screenshots/demo.gif"

Set FontSize 15
Set Width 1400
Set Height 820
Set Padding 12
Set TypingSpeed 60ms

# Run from the working tree so the recording always matches current code.
Hide
Type "alias servonaut='PYTHONPATH=src python3 -m servonaut.main'"
Enter
Type "clear"
Enter
Show

Type "servonaut --demo"
Sleep 800ms
Enter

# App start + cached multi-provider fleet render
Sleep 9s

# Search-as-you-type filter ("/" focuses the search box first)
Type "/"
Sleep 400ms
Type "backup"
Sleep 2.5s

# Tab out of the search box into the filtered results, open server actions
Tab
Sleep 400ms
Down
Sleep 800ms
Enter
Sleep 5s

# Open the AI assistant and ask it something
Ctrl+g
Sleep 3s
Type "What can you help me with?"
Sleep 600ms
Enter

# Streamed answer from the AI assistant
Sleep 20s
Sleep 4s

# Close chat, back to the fleet, quit
Ctrl+g
Sleep 1s
Escape
Sleep 2s
Type "q"
Sleep 1.5s
