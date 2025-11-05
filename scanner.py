# scanner/scanner.py
import asyncio
import sys
from typing import List, Dict

# imports from your other modules
from scanner.portscanner import scan_ports
from scanner.svc_fingerprint import guess_service
from scanner.cve_lookup import lookup_from_banner
from scanner.report import save_json_report, save_html_report

async def run_scan(target: str, ports: List[int] = None, concurrency: int = 200):
    if ports is None:
        ports = list(range(1, 1025))

    print(f"Starting async scan on {target} (ports {ports[0]}..{ports[-1]})")
    scan_results = await scan_ports(target, ports, concurrency=concurrency)

    # normalize and enrich results
    cves_out = []
    for r in scan_results:
        # r is {"port": int, "open": bool, "banner": str}
        if r.get("open"):
            banner = r.get("banner", "")
            service = guess_service(r["port"], banner)
            # small CVE lookup (may return empty list)
            found = lookup_from_banner(banner or service, max_results=3)
            # simplify found CVE entries for report
            for item in found:
                # try to extract common shapes
                cve_id = ""
                summary = ""
                c = item.get("cve")
                if isinstance(c, dict):
                    cve_id = c.get("id") or c.get("CVE_data_meta", {}).get("ID", "")
                    descs = c.get("descriptions") or []
                    if descs and isinstance(descs, list):
                        summary = descs[0].get("value", "") if isinstance(descs[0], dict) else str(descs[0])
                else:
                    # fallback if item is different shape
                    cve_id = item.get("cve", {}).get("id", "") if isinstance(item.get("cve"), dict) else ""
                if cve_id:
                    cves_out.append({
                        "host": target,
                        "port": r["port"],
                        "service": service,
                        "cve_id": cve_id,
                        "summary": summary
                    })
            # attach service to the result for reporting
            r["service"] = service
        else:
            r["service"] = "closed"

    report = {"host": target, "results": scan_results, "cves": cves_out}

    # save JSON + HTML reports (report.py must provide these functions)
    json_path = f"examples/{target}_report.json"
    html_path = f"examples/{target}_report.html"
    save_json_report(json_path, report)
    try:
        save_html_report(html_path, target, scan_results, cves_out)
    except Exception:
        # if save_html_report isn't implemented, ignore
        pass

    print(f"Saved {json_path} and {html_path} (if HTML generation supported)")
    return report

def main_cli():
    import argparse
    parser = argparse.ArgumentParser(description="Async Vulnerability Scanner")
    parser.add_argument("target", help="Target host or IP (only scan hosts you own/are permitted)")
    parser.add_argument("--ports", help="Comma-separated ports or range like 1-1024", default=None)
    args = parser.parse_args()

    # build ports list if passed
    ports = None
    if args.ports:
        if "-" in args.ports:
            start, end = args.ports.split("-", 1)
            ports = list(range(int(start), int(end) + 1))
        else:
            ports = [int(p) for p in args.ports.split(",") if p]

    asyncio.run(run_scan(args.target, ports=ports))

if __name__ == "__main__":
    main_cli()
