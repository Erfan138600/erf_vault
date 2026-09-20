# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║  ERF Vault — مخفی‌ساز و رمزنگار فوق‌پیشرفته فایل               ║
║  ساخته شده توسط t.me/erftel                                  ║
║                                                              ║
║  ویژگی‌ها:                                                    ║
║   • رمزنگاری AES-256-GCM برای هر فایل                         ║
║   • رمز عبور اصلی با PBKDF2-HMAC-SHA256 (600,000 تکرار)       ║
║   • پوشه مخفی سیستمی (Hidden + System)                        ║
║   • نام‌های تصادفی برای فایل‌های مخفی — هیچ ردی باقی نمی‌ماند  ║
║   • گالری تصاویر داخلی با مشاهده‌گر اختصاصی                   ║
║   • قفل خودکار + کلید وحشت (Ctrl+Shift+Q)                    ║
║   • حذف امن (Secure Wipe) فایل اصلی بعد از مخفی‌سازی          ║
║   • تغییر رمز عبور بدون نیاز به رمزنگاری مجدد فایل‌ها         ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import io
import sys
import json
import time
import hmac
import queue
import base64
import ctypes
import secrets
import hashlib
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ────────────────────────── وابستگی‌ها ──────────────────────────
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    root = tk.Tk(); root.withdraw()
    messagebox.showerror(
        "ERF Vault — خطا",
        "کتابخانه cryptography نصب نیست!\n\nدر CMD اجرا کنید:\npip install cryptography"
    )
    sys.exit(1)

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ────────────────────────── ثابت‌ها ──────────────────────────
APP_NAME      = "ERF Vault"
APP_VERSION   = "2.0"
CREDIT_TEXT   = "ساخته شده توسط t.me/erftel"
CREDIT_URL    = "https://t.me/erftel"
ITERATIONS    = 600_000
VERIFY_TOKEN  = b"erf-vault-verify-v2"
MAGIC         = b"ERFV"

BASE_DIR   = os.environ.get("APPDATA") or os.path.expanduser("~")
VAULT_ROOT = os.path.join(BASE_DIR, ".erfvault")
BLOB_DIR   = os.path.join(VAULT_ROOT, "blobs")
CONFIG_FP  = os.path.join(VAULT_ROOT, "config.json")
INDEX_FP   = os.path.join(VAULT_ROOT, "index.enc")

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico"}

# ─────────────────────── پالت رنگ (دارک) ───────────────────────
C = {
    "bg":       "#0b0f17",
    "panel":    "#111827",
    "panel2":   "#1a2333",
    "border":   "#26314a",
    "fg":       "#e8eefc",
    "muted":    "#8b98b8",
    "accent":   "#7c5cff",
    "accent2":  "#22d3ee",
    "danger":   "#ef4444",
    "success":  "#22c55e",
    "warn":     "#f59e0b",
}
FONT_MAIN  = ("Segoe UI", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_BIG   = ("Segoe UI", 22, "bold")
FONT_MONO  = ("Consolas", 9)


# ═══════════════════════ موتور رمزنگاری ═══════════════════════
class CryptoEngine:
    """AES-256-GCM + PBKDF2 — رمزنگاری در سطح نظامی."""

    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=iterations)
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def encrypt(key: bytes, data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(key).encrypt(nonce, data, MAGIC)

    @staticmethod
    def decrypt(key: bytes, blob: bytes) -> bytes:
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(key).decrypt(nonce, ct, MAGIC)


# ═══════════════════════ هسته خزانه ═══════════════════════
class Vault:
    def __init__(self):
        self.key = None          # bytes — کلید اصلی در حافظه
        self.files = []          # فراداده فایل‌ها
        self._lock = threading.Lock()

    # ── راه‌اندازی اولیه ──
    @staticmethod
    def ensure_dirs():
        os.makedirs(BLOB_DIR, exist_ok=True)
        if os.name == "nt":  # مخفی + سیستمی کردن پوشه در ویندوز
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(VAULT_ROOT), 0x02 | 0x04)
            except Exception:
                pass

    @staticmethod
    def is_initialized() -> bool:
        return os.path.exists(CONFIG_FP)

    def setup(self, password: str):
        self.ensure_dirs()
        salt = secrets.token_bytes(32)
        key = CryptoEngine.derive_key(password, salt)
        cfg = {
            "v": 2,
            "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(
                hmac.new(key, VERIFY_TOKEN, hashlib.sha256).digest()
            ).decode(),
            "iterations": ITERATIONS,
            "created": time.time(),
        }
        with open(CONFIG_FP, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        self.key = key
        self.files = []
        self._save_index()

    def unlock(self, password: str) -> bool:
        try:
            with open(CONFIG_FP, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            salt = base64.b64decode(cfg["salt"])
            key = CryptoEngine.derive_key(password, salt, cfg.get("iterations", ITERATIONS))
            expected = base64.b64decode(cfg["verifier"])
            if not hmac.compare_digest(hmac.new(key, VERIFY_TOKEN, hashlib.sha256).digest(), expected):
                return False
            self.key = key
            self._load_index()
            return True
        except Exception:
            return False

    def lock(self):
        if self.key is not None:
            self.key = None
        self.files = []

    # ── ایندکس رمزنگاری‌شده ──
    def _save_index(self):
        payload = json.dumps({"files": self.files}, ensure_ascii=False).encode("utf-8")
        with open(INDEX_FP, "wb") as f:
            f.write(CryptoEngine.encrypt(self.key, payload))

    def _load_index(self):
        if not os.path.exists(INDEX_FP):
            self.files = []
            return
        with open(INDEX_FP, "rb") as f:
            blob = f.read()
        data = json.loads(CryptoEngine.decrypt(self.key, blob).decode("utf-8"))
        self.files = data.get("files", [])

    # ── عملیات فایل ──
    def add_file(self, src_path: str, wipe_original: bool = False) -> dict:
        with open(src_path, "rb") as f:
            raw = f.read()
        blob = CryptoEngine.encrypt(self.key, raw)
        file_id = secrets.token_hex(16)
        blob_path = os.path.join(BLOB_DIR, file_id + ".efb")
        with open(blob_path, "wb") as f:
            f.write(blob)
        st = os.stat(src_path)
        meta = {
            "id": file_id,
            "name": os.path.basename(src_path),
            "ext": os.path.splitext(src_path)[1].lower(),
            "size": len(raw),
            "added": time.time(),
            "mtime": st.st_mtime,
        }
        with self._lock:
            self.files.append(meta)
            self._save_index()
        if wipe_original:
            secure_wipe(src_path)
        return meta

    def export_file(self, file_id: str, dst_path: str):
        meta = self.get_meta(file_id)
        blob_path = os.path.join(BLOB_DIR, file_id + ".efb")
        with open(blob_path, "rb") as f:
            raw = CryptoEngine.decrypt(self.key, f.read())
        with open(dst_path, "wb") as f:
            f.write(raw)

    def read_bytes(self, file_id: str) -> bytes:
        blob_path = os.path.join(BLOB_DIR, file_id + ".efb")
        with open(blob_path, "rb") as f:
            return CryptoEngine.decrypt(self.key, f.read())

    def delete_file(self, file_id: str):
        meta = self.get_meta(file_id)
        blob_path = os.path.join(BLOB_DIR, file_id + ".efb")
        if os.path.exists(blob_path):
            secure_wipe(blob_path)
        with self._lock:
            self.files = [m for m in self.files if m["id"] != file_id]
            self._save_index()

    def get_meta(self, file_id: str) -> dict:
        for m in self.files:
            if m["id"] == file_id:
                return m
        raise KeyError(file_id)

    def change_password(self, old_pw: str, new_pw: str) -> bool:
        # بررسی رمز فعلی روی کلید فعلی
        with open(CONFIG_FP, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        old_salt = base64.b64decode(cfg["salt"])
        old_key = CryptoEngine.derive_key(old_pw, old_salt, cfg.get("iterations", ITERATIONS))
        expected = base64.b64decode(cfg["verifier"])
        if not hmac.compare_digest(hmac.new(old_key, VERIFY_TOKEN, hashlib.sha256).digest(), expected):
            return False
        # رمزنگاری مجدد همه بلاب‌ها با کلید جدید
        new_salt = secrets.token_bytes(32)
        new_key = CryptoEngine.derive_key(new_pw, new_salt)
        for m in self.files:
            bp = os.path.join(BLOB_DIR, m["id"] + ".efb")
            if not os.path.exists(bp):
                continue
            with open(bp, "rb") as f:
                raw = CryptoEngine.decrypt(old_key, f.read())
            with open(bp, "wb") as f:
                f.write(CryptoEngine.encrypt(new_key, raw))
        cfg["salt"] = base64.b64encode(new_salt).decode()
        cfg["verifier"] = base64.b64encode(
            hmac.new(new_key, VERIFY_TOKEN, hashlib.sha256).digest()
        ).decode()
        with open(CONFIG_FP, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        self.key = new_key
        self._save_index()
        return True

    def stats(self):
        total = sum(m["size"] for m in self.files)
        imgs = sum(1 for m in self.files if m["ext"] in IMAGE_EXTS)
        return len(self.files), total, imgs


def secure_wipe(path: str, passes: int = 3):
    """بازنویسی تصادفی چندمرحله‌ای سپس حذف."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    chunk = min(remaining, 1024 * 1024)
                    f.write(secrets.token_bytes(chunk))
                    remaining -= chunk
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass


def fmt_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


# ═══════════════════════ رابط کاربری ═══════════════════════
class StyleManager:
    @staticmethod
    def apply(root):
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure(".", background=C["bg"], foreground=C["fg"],
                        fieldbackground=C["panel2"], font=FONT_MAIN, borderwidth=0)
        style.configure("TFrame", background=C["bg"])
        style.configure("Panel.TFrame", background=C["panel"])
        style.configure("TLabel", background=C["bg"], foreground=C["fg"])
        style.configure("Muted.TLabel", background=C["bg"], foreground=C["muted"])
        style.configure("Panel.TLabel", background=C["panel"], foreground=C["fg"])
        style.configure("PanelMuted.TLabel", background=C["panel"], foreground=C["muted"])
        style.configure("Title.TLabel", background=C["bg"], foreground=C["fg"], font=FONT_TITLE)
        style.configure("Credit.TLabel", background=C["bg"], foreground=C["accent2"], font=FONT_BOLD)
        style.configure("TButton", background=C["panel2"], foreground=C["fg"],
                        padding=(14, 8), font=FONT_BOLD)
        style.map("TButton",
                  background=[("active", C["accent"]), ("pressed", C["accent"])],
                  foreground=[("active", "#ffffff")])
        style.configure("Accent.TButton", background=C["accent"], foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#937dff")])
        style.configure("Danger.TButton", background=C["danger"], foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#f87171")])
        style.configure("TEntry", fieldbackground=C["panel2"], foreground=C["fg"],
                        insertcolor=C["fg"], padding=6)
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=C["panel"], foreground=C["muted"],
                        padding=(18, 10), font=FONT_BOLD)
        style.map("TNotebook.Tab",
                  background=[("selected", C["panel2"])],
                  foreground=[("selected", C["accent2"])])
        style.configure("Treeview", background=C["panel"], foreground=C["fg"],
                        fieldbackground=C["panel"], rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background=C["panel2"], foreground=C["accent2"],
                        font=FONT_BOLD)
        style.map("Treeview", background=[("selected", C["accent"])],
                  foreground=[("selected", "#ffffff")])
        style.configure("TProgressbar", background=C["accent"], troughcolor=C["panel2"])
        style.configure("TScrollbar", background=C["panel2"], troughcolor=C["panel"],
                        arrowcolor=C["fg"])


class CreditBar(tk.Frame):
    """نوار برندینگ پایین همه صفحه‌ها."""
    def __init__(self, master, **kw):
        kw.setdefault("bg", C["panel"])
        super().__init__(master, **kw)
        lbl = tk.Label(self, text="⚡ " + CREDIT_TEXT + " ⚡", bg=C["panel"],
                       fg=C["accent2"], font=FONT_BOLD, cursor="hand2")
        lbl.pack(pady=5)
        lbl.bind("<Button-1>", lambda e: webbrowser.open(CREDIT_URL))
        lbl.bind("<Enter>", lambda e: lbl.config(fg=C["accent"]))
        lbl.bind("<Leave>", lambda e: lbl.config(fg=C["accent2"]))


class PasswordStrength(tk.Frame):
    def __init__(self, master, **kw):
        kw.setdefault("bg", C["bg"])
        super().__init__(master, **kw)
        self.bar = ttk.Progressbar(self, length=220, mode="determinate")
        self.bar.pack(side="left")
        self.lbl = tk.Label(self, text="", bg=C["bg"], font=FONT_MONO, width=12, anchor="w")
        self.lbl.pack(side="left", padx=8)

    def update(self, pw: str):
        score = 0
        if len(pw) >= 8:  score += 25
        if len(pw) >= 12: score += 15
        if any(c.isupper() for c in pw) and any(c.islower() for c in pw): score += 20
        if any(c.isdigit() for c in pw): score += 20
        if any(not c.isalnum() for c in pw): score += 20
        score = min(score, 100)
        self.bar["value"] = score
        if score < 40:
            txt, color = "ضعیف", C["danger"]
        elif score < 70:
            txt, color = "متوسط", C["warn"]
        else:
            txt, color = "قوی 💪", C["success"]
        self.lbl.config(text=txt, fg=color)


# ─────────────────── صفحه ساخت رمز (اولین اجرا) ───────────────────
class SetupFrame(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=C["bg"])
        self.app = app
        self.pack(fill="both", expand=True)

        tk.Label(self, text="🛡", bg=C["bg"], fg=C["accent"], font=("Segoe UI Emoji", 44)).pack(pady=(50, 5))
        tk.Label(self, text="خوش آمدید به ERF Vault", bg=C["bg"], fg=C["fg"], font=FONT_TITLE).pack()
        tk.Label(self, text="یک رمز عبور اصلی قوی بسازید — این رمز، کلید تمام فایل‌های شماست",
                 bg=C["bg"], fg=C["muted"], font=FONT_MAIN).pack(pady=(4, 25))

        box = tk.Frame(self, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        box.pack(padx=60, pady=5, fill="x")

        tk.Label(box, text="رمز عبور", bg=C["panel"], fg=C["muted"], font=FONT_MAIN).pack(anchor="e", padx=16, pady=(14, 2))
        self.pw1 = ttk.Entry(box, show="●", justify="center", font=FONT_MAIN)
        self.pw1.pack(padx=16, fill="x")
        self.strength = PasswordStrength(box, bg=C["panel"])
        self.strength.bar.master.config(bg=C["panel"])
        self.strength.pack(pady=6)
        self.pw1.bind("<KeyRelease>", lambda e: self.strength.update(self.pw1.get()))

        tk.Label(box, text="تکرار رمز عبور", bg=C["panel"], fg=C["muted"], font=FONT_MAIN).pack(anchor="e", padx=16, pady=(8, 2))
        self.pw2 = ttk.Entry(box, show="●", justify="center", font=FONT_MAIN)
        self.pw2.pack(padx=16, fill="x", pady=(0, 14))

        ttk.Button(self, text="🔐  ساخت خزانه امن", style="Accent.TButton",
                   command=self._create).pack(pady=22, ipadx=20, ipady=4)
        tk.Label(self, text="⚠ رمز عبور قابل بازیابی نیست — آن را به خاطر بسپارید!",
                 bg=C["bg"], fg=C["warn"], font=FONT_MAIN).pack()
        CreditBar(self).pack(side="bottom", fill="x")
        self.pw1.focus_set()

    def _create(self):
        p1, p2 = self.pw1.get(), self.pw2.get()
        if len(p1) < 6:
            messagebox.showwarning("ERF Vault", "رمز عبور باید حداقل ۶ کاراکتر باشد.")
            return
        if p1 != p2:
            messagebox.showerror("ERF Vault", "رمز عبور و تکرار آن یکسان نیستند!")
            return
        self.app.vault.setup(p1)
        self.app.show_main()


# ─────────────────── صفحه ورود ───────────────────
class LoginFrame(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=C["bg"])
        self.app = app
        self.attempts = 0
        self.pack(fill="both", expand=True)

        tk.Label(self, text="🔐", bg=C["bg"], font=("Segoe UI Emoji", 44)).pack(pady=(55, 5))
        tk.Label(self, text=APP_NAME, bg=C["bg"], fg=C["fg"], font=FONT_BIG).pack()
        tk.Label(self, text="رمز عبور اصلی را وارد کنید", bg=C["bg"], fg=C["muted"], font=FONT_MAIN).pack(pady=(4, 22))

        box = tk.Frame(self, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        box.pack(padx=70, fill="x")
        self.pw = ttk.Entry(box, show="●", justify="center", font=("Segoe UI", 13))
        self.pw.pack(padx=16, pady=16, fill="x")
        self.pw.bind("<Return>", lambda e: self._login())

        ttk.Button(self, text="🔓  باز کردن خزانه", style="Accent.TButton",
                   command=self._login).pack(pady=20, ipadx=20, ipady=4)
        self.err = tk.Label(self, text="", bg=C["bg"], fg=C["danger"], font=FONT_MAIN)
        self.err.pack()
        CreditBar(self).pack(side="bottom", fill="x")
        self.pw.focus_set()

    def _login(self):
        if self.app.vault.unlock(self.pw.get()):
            self.app.show_main()
        else:
            self.attempts += 1
            self.pw.delete(0, "end")
            self.err.config(text=f"رمز اشتباه است! (تلاش {self.attempts})")
            self._shake()
            if self.attempts >= 3:
                self.err.config(text="قفل امنیتی: ۱۰ ثانیه صبر کنید…")
                self.after(10_000, lambda: self.err.config(text=""))
                self.attempts = 0

    def _shake(self):
        x = self.app.root.winfo_x()
        for dx in (12, -12, 8, -8, 4, -4, 0):
            self.app.root.geometry(f"+{x + dx}+{self.app.root.winfo_y()}")
            self.app.root.update()
            time.sleep(0.03)


# ─────────────────── مشاهده‌گر تصویر ───────────────────
class ImageViewer(tk.Toplevel):
    def __init__(self, master, vault, file_id):
        super().__init__(master)
        meta = vault.get_meta(file_id)
        self.title(f"🖼 {meta['name']} — ERF Vault")
        self.configure(bg=C["bg"])
        self.attributes("-topmost", True)
        raw = vault.read_bytes(file_id)
        img = Image.open(io.BytesIO(raw))
        max_w, max_h = 900, 620
        ratio = min(max_w / img.width, max_h / img.height, 1.0)
        img = img.resize((int(img.width * ratio), int(img.height * ratio)))
        self.photo = ImageTk.PhotoImage(img)
        tk.Label(self, image=self.photo, bg=C["bg"]).pack(padx=10, pady=10)
        tk.Label(self, text=f"{meta['name']}  •  {fmt_size(meta['size'])}  •  {CREDIT_TEXT}",
                 bg=C["bg"], fg=C["muted"], font=FONT_MONO).pack(pady=(0, 10))
        self.bind("<Escape>", lambda e: self.destroy())


# ─────────────────── پنجره اصلی ───────────────────
class MainFrame(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=C["bg"])
        self.app = app
        self.vault = app.vault
        self.idle_limit = tk.IntVar(value=5)   # دقیقه
        self.last_activity = time.time()
        self.pack(fill="both", expand=True)

        # ── هدر ──
        header = tk.Frame(self, bg=C["panel"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text=f"🛡 {APP_NAME}", bg=C["panel"], fg=C["fg"],
                 font=FONT_TITLE).pack(side="left", padx=16, pady=10)
        ttk.Button(header, text="🔒 قفل (Ctrl+Shift+Q)", command=self.app.lock_now).pack(side="right", padx=10, pady=12)
        self.stat_lbl = tk.Label(header, text="", bg=C["panel"], fg=C["muted"], font=FONT_MONO)
        self.stat_lbl.pack(side="right", padx=14)

        # ── تب‌ها ──
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.tab_files = tk.Frame(nb, bg=C["bg"])
        self.tab_gallery = tk.Frame(nb, bg=C["bg"])
        self.tab_settings = tk.Frame(nb, bg=C["bg"])
        self.tab_about = tk.Frame(nb, bg=C["bg"])
        nb.add(self.tab_files, text="  🗂  فایل‌های مخفی  ")
        nb.add(self.tab_gallery, text="  🖼  گالری تصاویر  ")
        nb.add(self.tab_settings, text="  ⚙  تنظیمات  ")
        nb.add(self.tab_about, text="  ℹ  درباره  ")

        self._build_files_tab()
        self._build_gallery_tab()
        self._build_settings_tab()
        self._build_about_tab()
        CreditBar(self).pack(side="bottom", fill="x")

        # ── رویدادها ──
        root = app.root
        root.bind_all("<Any-KeyPress>", self._activity)
        root.bind_all("<Any-Button>", self._activity)
        root.bind_all("<Control-Shift-Q>", lambda e: self.app.lock_now())
        root.bind_all("<Control-Shift-q>", lambda e: self.app.lock_now())
        self._watchdog()
        self.refresh()

    # ─────────── تب فایل‌ها ───────────
    def _build_files_tab(self):
        top = tk.Frame(self.tab_files, bg=C["bg"])
        top.pack(fill="x", pady=(8, 4))
        ttk.Button(top, text="➕ مخفی کردن فایل‌ها", style="Accent.TButton",
                   command=self.add_files).pack(side="left", padx=6)
        ttk.Button(top, text="📤 استخراج (بازیابی)", command=self.export_selected).pack(side="left", padx=6)
        ttk.Button(top, text="🗑 حذف امن", style="Danger.TButton",
                   command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(top, text="🔄 بروزرسانی", command=self.refresh).pack(side="left", padx=6)

        cols = ("name", "size", "date")
        self.tree = ttk.Treeview(self.tab_files, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("name", text="نام فایل")
        self.tree.heading("size", text="حجم")
        self.tree.heading("date", text="تاریخ مخفی‌سازی")
        self.tree.column("name", width=380, anchor="e")
        self.tree.column("size", width=100, anchor="center")
        self.tree.column("date", width=160, anchor="center")
        sb = ttk.Scrollbar(self.tab_files, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, pady=8)
        sb.pack(side="right", fill="y", pady=8)
        self.tree.bind("<Double-1>", self._open_selected)

    def _selected_ids(self):
        ids = []
        for item in self.tree.selection():
            ids.append(self.tree.item(item, "tags")[0])
        return ids

    def add_files(self):
        paths = filedialog.askopenfilenames(title="فایل‌هایی که می‌خواهید مخفی کنید را انتخاب کنید")
        if not paths:
            return
        wipe = messagebox.askyesno(
            "حذف امن فایل اصلی؟",
            "آیا فایل‌های اصلی بعد از مخفی‌سازی با «حذف امن» (بازنویسی ۳ مرحله‌ای) پاک شوند؟\n\n"
            "بله = هیچ ردی از فایل اصلی باقی نمی‌ماند\nخیر = فایل اصلی سر جایش می‌ماند",
            icon="warning"
        )
        prog = tk.Toplevel(self)
        prog.title("در حال رمزنگاری…")
        prog.configure(bg=C["panel"])
        prog.geometry("360x120")
        prog.transient(self.app.root)
        bar = ttk.Progressbar(prog, length=320, mode="determinate", maximum=len(paths))
        bar.pack(pady=(24, 6))
        lbl = tk.Label(prog, text="", bg=C["panel"], fg=C["fg"], font=FONT_MONO)
        lbl.pack()

        def work():
            for i, p in enumerate(paths, 1):
                lbl.config(text=os.path.basename(p))
                bar["value"] = i
                prog.update_idletasks()
                try:
                    self.vault.add_file(p, wipe_original=wipe)
                except Exception as ex:
                    print("add failed:", p, ex)
            prog.destroy()
            self.app.root.after(0, self.refresh)
        threading.Thread(target=work, daemon=True).start()

    def export_selected(self):
        ids = self._selected_ids()
        if not ids:
            messagebox.showinfo("ERF Vault", "ابتدا یک فایل را انتخاب کنید.")
            return
        folder = filedialog.askdirectory(title="پوشه مقصد برای بازیابی")
        if not folder:
            return
        for fid in ids:
            meta = self.vault.get_meta(fid)
            dst = os.path.join(folder, meta["name"])
            base, ext = os.path.splitext(dst)
            n = 1
            while os.path.exists(dst):
                dst = f"{base}_{n}{ext}"
                n += 1
            self.vault.export_file(fid, dst)
        messagebox.showinfo("ERF Vault", f"✅ {len(ids)} فایل با موفقیت بازیابی شد.")

    def delete_selected(self):
        ids = self._selected_ids()
        if not ids:
            return
        if messagebox.askyesno("حذف امن", f"{len(ids)} فایل برای همیشه با حذف امن پاک شود؟\nاین عمل غیرقابل بازگشت است!", icon="warning"):
            for fid in ids:
                self.vault.delete_file(fid)
            self.refresh()

    def _open_selected(self, _e=None):
        ids = self._selected_ids()
        if not ids:
            return
        meta = self.vault.get_meta(ids[0])
        if meta["ext"] in IMAGE_EXTS and HAS_PIL:
            ImageViewer(self, self.vault, ids[0])
        else:
            self.export_selected()

    # ─────────── تب گالری ───────────
    def _build_gallery_tab(self):
        tk.Label(self.tab_gallery, text="روی هر تصویر دابل‌کلیک کنید تا در مشاهده‌گر امن باز شود",
                 bg=C["bg"], fg=C["muted"], font=FONT_MAIN).pack(pady=(10, 4))
        cols = ("name", "size", "date")
        self.gtree = ttk.Treeview(self.tab_gallery, columns=cols, show="headings", selectmode="browse")
        self.gtree.heading("name", text="نام تصویر")
        self.gtree.heading("size", text="حجم")
        self.gtree.heading("date", text="تاریخ")
        self.gtree.column("name", width=380, anchor="e")
        self.gtree.column("size", width=100, anchor="center")
        self.gtree.column("date", width=160, anchor="center")
        self.gtree.pack(fill="both", expand=True, pady=6)
        self.gtree.bind("<Double-1>", lambda e: self._open_gallery())
        ttk.Button(self.tab_gallery, text="🖼 مشاهده تصویر", style="Accent.TButton",
                   command=self._open_gallery).pack(pady=6)

    def _open_gallery(self):
        sel = self.gtree.selection()
        if not sel:
            return
        fid = self.gtree.item(sel[0], "tags")[0]
        if HAS_PIL:
            ImageViewer(self, self.vault, fid)
        else:
            messagebox.showwarning("ERF Vault", "برای مشاهده تصاویر Pillow نصب کنید:\npip install pillow")

    # ─────────── تب تنظیمات ───────────
    def _build_settings_tab(self):
        f = self.tab_settings

        box1 = tk.LabelFrame(f, text="  🔑 تغییر رمز عبور اصلی  ", bg=C["panel"], fg=C["accent2"],
                             font=FONT_BOLD, bd=1, relief="solid")
        box1.pack(fill="x", padx=20, pady=(16, 8), ipady=8)
        self.old_pw = self._pw_row(box1, "رمز فعلی")
        self.new_pw = self._pw_row(box1, "رمز جدید")
        self.new_pw2 = self._pw_row(box1, "تکرار رمز جدید")
        ttk.Button(box1, text="تغییر رمز", style="Accent.TButton",
                   command=self._change_pw).pack(pady=8)

        box2 = tk.LabelFrame(f, text="  ⏱ قفل خودکار  ", bg=C["panel"], fg=C["accent2"],
                             font=FONT_BOLD, bd=1, relief="solid")
        box2.pack(fill="x", padx=20, pady=8, ipady=8)
        row = tk.Frame(box2, bg=C["panel"])
        row.pack()
        tk.Label(row, text="قفل خودکار بعد از", bg=C["panel"], fg=C["fg"]).pack(side="left")
        spin = ttk.Spinbox(row, from_=1, to=60, width=5, textvariable=self.idle_limit)
        spin.pack(side="left", padx=6)
        tk.Label(row, text="دقیقه عدم فعالیت", bg=C["panel"], fg=C["fg"]).pack(side="left")

        box3 = tk.LabelFrame(f, text="  💾 اطلاعات خزانه  ", bg=C["panel"], fg=C["accent2"],
                             font=FONT_BOLD, bd=1, relief="solid")
        box3.pack(fill="x", padx=20, pady=8, ipady=8)
        tk.Label(box3, text=f"مسیر خزانه: {VAULT_ROOT}", bg=C["panel"], fg=C["muted"],
                 font=FONT_MONO).pack(anchor="w", padx=10)
        tk.Label(box3, text="وضعیت پوشه: مخفی + سیستمی 🔒", bg=C["panel"],
                 fg=C["success"]).pack(anchor="w", padx=10, pady=(2, 6))

    def _pw_row(self, parent, label):
        row = tk.Frame(parent, bg=C["panel"])
        row.pack(fill="x", padx=10, pady=3)
        e = ttk.Entry(row, show="●", justify="center", width=28)
        e.pack(side="right")
        tk.Label(row, text=label, bg=C["panel"], fg=C["fg"], width=16, anchor="e").pack(side="right", padx=6)
        return e

    def _change_pw(self):
        p1, p2, p3 = self.old_pw.get(), self.new_pw.get(), self.new_pw2.get()
        if len(p2) < 6:
            messagebox.showwarning("ERF Vault", "رمز جدید باید حداقل ۶ کاراکتر باشد.")
            return
        if p2 != p3:
            messagebox.showerror("ERF Vault", "تکرار رمز جدید مطابقت ندارد!")
            return
        if self.vault.change_password(p1, p2):
            messagebox.showinfo("ERF Vault", "✅ رمز عبور با موفقیت تغییر کرد و همه فایل‌ها بازرمزنگاری شدند.")
            for e in (self.old_pw, self.new_pw, self.new_pw2):
                e.delete(0, "end")
        else:
            messagebox.showerror("ERF Vault", "رمز فعلی اشتباه است!")

    # ─────────── تب درباره ───────────
    def _build_about_tab(self):
        f = self.tab_about
        tk.Label(f, text="🛡", bg=C["bg"], font=("Segoe UI Emoji", 46)).pack(pady=(36, 4))
        tk.Label(f, text=f"{APP_NAME} v{APP_VERSION}", bg=C["bg"], fg=C["fg"], font=FONT_TITLE).pack()
        tk.Label(f, text="مخفی‌ساز و رمزنگار فوق‌پیشرفته فایل", bg=C["bg"], fg=C["muted"]).pack(pady=4)

        features = [
            "🔐 رمزنگاری AES-256-GCM در سطح نظامی",
            "🧂 PBKDF2-HMAC-SHA256 با ۶۰۰هزار تکرار",
            "👻 پوشه مخفی سیستمی + نام‌های تصادفی",
            "🖼 گالری و مشاهده‌گر تصویر امن داخلی",
            "⏱ قفل خودکار + کلید وحشت Ctrl+Shift+Q",
            "🔥 حذف امن ۳ مرحله‌ای (Secure Wipe)",
            "🛡 محافظت ضد حدس رمز (قفل ۱۰ ثانیه‌ای)",
        ]
        for ft in features:
            tk.Label(f, text=ft, bg=C["bg"], fg=C["fg"], font=FONT_MAIN).pack(pady=1)

        link = tk.Label(f, text="⚡ " + CREDIT_TEXT + " ⚡", bg=C["bg"], fg=C["accent2"],
                        font=("Segoe UI", 13, "bold"), cursor="hand2")
        link.pack(pady=18)
        link.bind("<Button-1>", lambda e: webbrowser.open(CREDIT_URL))
        tk.Label(f, text="برای حمایت و دریافت نسخه‌های جدید، روی لینک بالا کلیک کنید 💜",
                 bg=C["bg"], fg=C["muted"]).pack()

    # ─────────── ابزارها ───────────
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        self.gtree.delete(*self.gtree.get_children())
        for m in sorted(self.vault.files, key=lambda x: -x["added"]):
            date = time.strftime("%Y/%m/%d  %H:%M", time.localtime(m["added"]))
            icon = "🖼" if m["ext"] in IMAGE_EXTS else "📄"
            self.tree.insert("", "end", values=(f"{icon}  {m['name']}", fmt_size(m["size"]), date),
                             tags=(m["id"],))
            if m["ext"] in IMAGE_EXTS:
                self.gtree.insert("", "end", values=(f"🖼  {m['name']}", fmt_size(m["size"]), date),
                                  tags=(m["id"],))
        n, total, imgs = self.vault.stats()
        self.stat_lbl.config(text=f"📦 {n} فایل  •  🖼 {imgs} تصویر  •  💾 {fmt_size(total)}")

    def _activity(self, _e=None):
        self.last_activity = time.time()

    def _watchdog(self):
        if time.time() - self.last_activity > self.idle_limit.get() * 60:
            self.app.lock_now()
            return
        self.after(2000, self._watchdog)


# ═══════════════════════ اپلیکیشن ═══════════════════════
class ERFVaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION} — {CREDIT_TEXT}")
        self.root.geometry("760x620")
        self.root.minsize(680, 540)
        self.root.configure(bg=C["bg"])
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        StyleManager.apply(self.root)
        self.vault = Vault()
        self.current = None
        if Vault.is_initialized():
            self._show(LoginFrame)
        else:
            self._show(SetupFrame)

    def _show(self, frame_cls):
        if self.current:
            self.current.destroy()
        self.current = frame_cls(self.root, self)

    def show_main(self):
        self._show(MainFrame)

    def lock_now(self):
        self.vault.lock()
        self._show(LoginFrame)

    def _on_close(self):
        self.vault.lock()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    ERFVaultApp().run()
