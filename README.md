# 🔍 Async Vulnerability Scanner (AVScan)

**Async-Vuln-Scanner** is a **real-time website vulnerability testing tool** built using Python `asyncio` and `aiohttp`.  
It performs **non-destructive bug bounty–style testing**, finding **valid exposed keys, tokens, sensitive files, and misconfigurations** on live web targets.

---

## 🚀 Features

- ⚡ **Asynchronous scanning** — high-speed, parallelized web checks
- 🧠 **Finds exposed keys & secrets** (AWS keys, tokens, API keys)
- 🕵️ **Detects real vulnerabilities:**
  - CORS misconfigurations
  - Open redirects
  - Reflected XSS
  - Missing security headers
  - Public `.env`, `config.php`, `id_rsa`, and other sensitive files
- 📊 **Automatic reporting**
  - Generates **PDF**, **TXT**, **HTML**, and **JSON** reports
  - Reports are automatically saved to your desktop
- 🧩 Modular architecture — easy to extend for other bug bounty checks
- ✅ Works safely (non-destructive testing only)

---

## 🧰 Installation

```bash
# Clone the repository
git clone https://github.com/ashraful12-cmyk/async-vuln-scanner.git
cd async-vuln-scanner

# Create a virtual environment
python -m venv .venv

# Activate it
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright (optional, for rendering)
python -m playwright install

---

---

## 🚀 Quick Run / Usage

After installing (see Installation above), you can run the scanner with the console command `avscan`.

### Basic example
```bash
# scan a website (replace with the target you are authorized to test)
avscan https://example.com

