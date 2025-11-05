# scanner/scripts/run_scan.py
import asyncio
import sys
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.portscanner import scan_ports
from scanner.web_checks import scan_web
from scanner.report import generate_report  # ✅ Import once, at top


async def run(target: str):
    print(f"[+] Starting scan for {target}")

    parsed = urlparse(target if target.startswith("http") else f"https://{target}")
    host_for_requests = parsed.geturl()
    safe_name = (parsed.netloc or parsed.path).replace(":", "_").replace("/", "_")

    # Step 1: Scan common ports
    web_ports = [80, 443, 8080, 8443]
    try:
        ports_result = await scan_ports(parsed.hostname or host_for_requests, ports=web_ports)
    except TypeError:
        ports_result = await scan_ports(parsed.hostname or host_for_requests)

    open_count = sum(1 for p in ports_result if p.get("open"))
    print(f"[+] Port scan done. Found {open_count} open ports")

    # Step 2: Run web vulnerability checks
    try:
        web_vulns = await scan_web(host_for_requests)
        print(f"[+] Web checks done. Found {len(web_vulns)} issues")
    except Exception as e:
        print(f"[!] Web checks failed: {e}")
        web_vulns = []

    # Step 3: Generate and save all reports
    generate_report(
        host_for_requests,
        ports_result,
        web_vulns
    )

    print("[✓] Scan complete! Reports automatically saved to Desktop.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.scripts.run_scan <target-url>")
        sys.exit(1)
    asyncio.run(run(sys.argv[1]))
