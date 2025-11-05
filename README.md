# 🔍 Async Vulnerability Scanner (AVScan)
<p align="center">
  <img src="banner.png" width="600" alt="Async Vulnerability Scanner Banner">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Built%20with-Python%203.12-blue?logo=python" />
  <img src="https://img.shields.io/badge/Async-Enabled-green?logo=fastapi" />
  <img src="https://img.shields.io/badge/Security%20Tool-Cyber%20Scanner-orange?logo=shield" />
  <img src="https://img.shields.io/github/stars/ashraful12-cmyk/async-vuln-scanner?style=social" />
</p>

---

<p align="center">
  ⚡ **Async Vulnerability Scanner (AVScan)** – A high-performance, non-destructive web vulnerability testing tool.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" />
  <img src="https://img.shields.io/github/last-commit/ashraful12-cmyk/async-vuln-scanner" />
  <img src="https://img.shields.io/badge/Made%20for-Bug%20Bounty%20Hunters-critical" />
</p>

---


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

---

## 🚀 Quick Run / Usage

After installing (see Installation above), you can run the scanner from the terminal using the command:

```bash
# Example: scan a target website (authorized testing only)
avscan https://example.com
