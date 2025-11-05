# 🔍 Async Vulnerability Scanner (AVScan)

**Async-Vuln-Scanner** is a **real-time website vulnerability testing tool** built using Python `asyncio` and `aiohttp`.  
It performs **non-destructive bug bounty–style testing**, finding **valid exposed keys, tokens, sensitive files, and misconfigurations** on live web targets.

---

## 🚀 Features

- ⚡ **Asynchronous scanning** — high-speed, parallelized web checks  
- 🧠 **Detects leaked keys & secrets** (AWS keys, API keys, tokens)  
- 🕵️ **Checks for common issues:** CORS, open redirect, reflected XSS, missing security headers  
- 🔎 **Sensitive file discovery:** `.env`, `wp-config.php`, `id_rsa`, etc.  
- 📊 **Automatic reporting** — JSON, HTML, TXT, PDF saved automatically to Desktop → `AsyncScannerReports`  
- 🧩 Modular architecture — easy to extend for additional checks  
- ✅ Non-destructive and safe by default (do NOT run on targets you don't have permission to test)

---

## 🧰 Installation

```bash
# Clone the repository
git clone https://github.com/ashraful12-cmyk/async-vuln-scanner.git
cd async-vuln-scanner

# Create and activate a virtual environment (recommended)
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Optional: if your workflow needs Playwright rendering
python -m playwright install
