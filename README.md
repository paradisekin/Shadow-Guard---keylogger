# ShadowGuard

**ShadowGuard** is a Python-based keylogger with a live GUI dashboard, designed **strictly for educational and research purposes** in controlled sandbox environments. It demonstrates advanced cybersecurity concepts including real-time input monitoring, secure encrypted logging, thread-safe data handling, and cross-platform visualization.

> **⚠️ Important Disclaimer**  
> This tool is for **ethical, educational use only** — such as learning about keystroke logging, encryption, or defensive security techniques. Unauthorized use of keyloggers violates privacy laws (e.g., IT Act in India, GDPR globally) and is illegal without explicit consent. Always test in isolated sandboxes with permission. The author is not responsible for misuse.

## Features

- **Keystroke Capture** — Cross-platform keyboard listening using `pynput` (macOS, Linux, Windows)
- **Context Awareness** — Captures timestamps, active application, and current user
- **Live GUI Dashboard** — Tkinter-based real-time viewer (800×600) with 200ms auto-refresh, auto-scroll, and controls (Refresh / Stop / Export)
- **Encrypted & Obfuscated Storage** — Logs saved to hidden file using ChaCha20-Poly1305 + PBKDF2 + XOR + fake JPEG header
- **Thread-Safe Design** — Queue-based architecture + background threads for non-blocking capture, app detection (every 1s), flushing, and optional exfil
- **Export** — Decrypts and saves captured logs to plain text with auto-open support
- **Debug Mode** — Console prints to verify key events are captured
- **macOS Persistence** (demo only) — LaunchAgents setup for auto-start

## Requirements

- Python 3.8+
- Required packages:
1. pynput
Used for: real-time keyboard event listening and capturing keystrokes.
Install: pip install pynput
2. cryptography
Used for: secure encryption (ChaCha20Poly1305), key derivation (PBKDF2HMAC), and secure random generation.
Install: pip install cryptography
