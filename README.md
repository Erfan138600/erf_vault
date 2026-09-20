# erf_vault
یک مخفی کننده فایل امن
markdown
# ERF Vault v2.0 🔒
**Advanced File Vault, Encryption & Anti-Forensic Locker for Windows**

A modern, high-security desktop application built with Python (Tkinter) designed to securely encrypt, hide, and manage sensitive files and documents using state-of-the-art cryptography.

---

## ✨ Features

- 🛡️ **AES-256-GCM Encryption:** Authenticated symmetric encryption ensuring data privacy and tampering detection (AEAD).
- 🔑 **Robust Key Derivation:** PBKDF2-HMAC-SHA256 with **600,000 iterations** and a secure cryptographically random salt to withstand brute-force and hardware acceleration attacks.
- 🗂️ **Zero-Trace File Storage:** Original filenames and directory structures are concealed inside an encrypted index (`index.enc`). Actual file payloads are stored as randomized blob hashes in a hidden system-level AppData directory.
- 🧹 **Secure 3-Pass File Shredder:** Overwrites original files with random noise across 3 passes followed by hardware disk cache flushes (`fsync`), preventing any forensic recovery.
- 🖼️ **Built-in Encrypted Media Viewer:** Directly preview encrypted images (PNG, JPG, WEBP, GIF, etc.) in RAM without decrypting or writing temporary files to the disk.
- ⏱️ **Configurable Idle Auto-Lock:** Automatically locks down the vault after a user-defined period of inactivity.
- 🚨 **Panic Key Shortcut:** Instantly wipe keys from memory and lock the interface by pressing `Ctrl + Shift + Q`.
- 🛑 **Anti-Brute Force Protection:** Enforces temporary lockouts and visual feedback after 3 consecutive failed login attempts.
- 🔄 **Safe Master Password Migration:** Seamlessly re-encrypts all stored blobs on-the-fly when updating the vault master password.

---

## 🛠️ Prerequisites & Installation

Requires **Python 3.9+**.

Install the necessary dependencies:
```bash
pip install cryptography pillow
Run the application:

bash
python erf_vault.py
⚠️ Security Notice
Your master password is never stored anywhere. If forgotten, recovery of AES-256-GCM encrypted data is mathematically impossible.
Decryption keys and sensitive buffers in RAM are purged immediately upon locking or closing the vault.
Developed by: Erfan Alikhani

Telegram: t.me/erftel | t.me/erfdev

text

---

### نسخه فارسی بروزرسانی‌شده با اضافه شدن کانال/آیدی جدید:

```markdown
# ERF Vault v2.0 🔒
**نرم‌افزار امنیتی گاوصندوق، رمزنگاری و مخفی‌سازی فایل‌ها برای ویندوز**

یک ابزار قدرتمند دسکتاپ با رابط کاربری مدرن به زبان پایتون (Tkinter) جهت رمزگذاری پیشرفته، مخفی‌سازی هوشمندانه و نگهداری فوق‌امنیتی از انواع فایل‌ها و اسناد شخصی.

---

## ✨ امکانات و قابلیت‌ها

- 🛡 **رمزنگاری قدرتمند AES-256-GCM:** بالاترین استاندارد رمزنگاری متقارن همراه با حفاظت از اصالت داده‌ها (Authentication Tag).
- 🔑 **مشتق‌سازی کلید با امنیت بالا:** استفاده از الگوریتم PBKDF2 با بیش از ۶۰۰,۰۰۰ دور (Iterations) به همراه Salt اختصاصی برای مقاومت کامل در برابر حملات Brute-force و GPU Cracking.
- 🗂 **مخفی‌سازی ساختار فایل‌ها:** نام و ساختار اصلی فایل‌ها به صورت هش‌های تصادفی در مسیر مخفی سیستمی ویندوز ذخیره شده و متادیتاها به‌طور کامل رمزنگاری می‌شوند.
- 🧹 **حذف غیرقابل بازگشت (Secure Shredder):** بازنویسی داده‌های فایل اصلی در ۳ لایه با بایت‌های تصادفی و فراخوانی مستقیم کش سخت‌افزاری جهت جلوگیری قطعی از ریکاوری.
- 🖼 **گالری و نمایشگر اختصاصی:** مشاهده سریع و امن انواع فرمت‌های تصویری درون خود برنامه بدون نیاز به ذخیره موقت روی هارد دیسک.
- ⏱ **قفل هوشمند خودکار (Auto-Lock):** قفل شدن خودکار گاوصندوق در صورت عدم فعالیت در بازه زمانی تعیین‌شده.
- 🚨 **کلید وضعیت اضطراری (Panic Key):** خروج و قفل آنی محیط با کلید میانبر `Ctrl + Shift + Q`.
- 🛡 **سیستم ضد Brute-Force:** قفل زمانی محیط ورود پس از ۳ بار ورود رمز نادرست همراه با انیمیشن اخطار.
- 🔄 **تغییر امن کلید مستر:** امکان تغییر کلمه عبور با رمزنگاری مجدد بلادرنگ (Re-encryption) کلیه فایل‌های گاوصندوق.

---

## 🛠 پیش‌نیازها و نصب

برای اجرای برنامه نیاز به نسخه **Python 3.9+** دارید.

ابتدا کتابخانه‌های مورد نیاز را نصب کنید:
```bash
pip install cryptography pillow
سپس برنامه را اجرا کنید:

bash
python erf_vault.py
💡 نکات امنیتی
کلمه عبور مستر شما در هیچ مکانی ذخیره نمی‌شود؛ در صورت فراموشی رمز، بازیابی فایل‌ها با الگوریتم AES-256 عملاً غیرممکن خواهد بود.
کلید‌های حافظه رم بلافاصله پس از قفل شدن یا بستن نرم‌افزار به صورت کامل پاکسازی (Purge) می‌شوند.
توسعه داده شده توسط: عرفان علیخانی

تلگرام: t.me/erftel | t.me/erfdev
