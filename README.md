# 🔍 Async Vulnerability Scanner

A high-performance asynchronous vulnerability scanner built with Python and asyncio.

## ✨ Features
- ⚡ Asynchronous port scanning using `asyncio`
- 🧠 Service fingerprinting and banner grabbing
- 🕵️ CVE lookup using the NVD API
- 📊 Generates structured JSON and HTML reports
- 🧩 Modular design for easy expansion (e.g., HTTP, SSH, SMB scanning)

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/yourname/async-vuln-scanner.git
cd async-vuln-scanner

# Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # on macOS/Linux
.venv\Scripts\activate      # on Windows

# Install dependencies
pip install -r requirements.txt
