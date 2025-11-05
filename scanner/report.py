import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Union
from jinja2 import Template
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

PathLike = Union[str, Path]

# ---------------- HTML TEMPLATE ----------------
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Scan Report - {{ host }}</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; line-height: 1.4; padding: 18px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 6px; text-align: left; }
    h2 { margin-top: 20px; }
    .vuln { border: 1px solid #ccc; padding: 10px; margin: 10px 0; border-radius: 6px; }
    .sev-critical { color: #b00; font-weight: bold; }
    .sev-high { color: #c00; }
    .sev-medium { color: #b60; }
    .sev-low { color: #444; }
    pre { background: #f9f9f9; padding: 8px; overflow: auto; }
  </style>
</head>
<body>
  <h1>Scan Report - {{ host }}</h1>
  <p>Generated: {{ timestamp }}</p>

  <h2>Ports</h2>
  <table>
    <tr><th>Port</th><th>Status</th><th>Service</th><th>Banner</th></tr>
    {% for r in results %}
    <tr>
      <td>{{ r.port }}</td>
      <td>{{ 'open' if r.open else 'closed' }}</td>
      <td>{{ r.get('service', '-') }}</td>
      <td>{{ r.get('banner', '')[:100]|e }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Web Findings</h2>
  {% if web_vulns %}
    {% for v in web_vulns %}
      <div class="vuln">
        <b>ID:</b> {{ v.id }}<br>
        <b>Title:</b> {{ v.title }}<br>
        <b>Severity:</b> <span class="sev-{{ v.severity }}">{{ v.severity }}</span><br>
        <b>Description:</b> {{ v.description }}<br>
        {% if v.vulnerable_url %}<b>URL:</b> <a href="{{ v.vulnerable_url }}">{{ v.vulnerable_url }}</a><br>{% endif %}
        {% if v.evidence %}<b>Evidence:</b><pre>{{ v.evidence }}</pre>{% endif %}
      </div>
    {% endfor %}
  {% else %}
    <p>No web findings detected.</p>
  {% endif %}
</body>
</html>
"""

# ---------------- Helpers ----------------
def _ensure_path(p: PathLike) -> Path:
    """Ensure path and parent directories exist."""
    pth = Path(p)
    pth.parent.mkdir(parents=True, exist_ok=True)
    return pth

# ---------------- JSON ----------------
def save_json_report(path: PathLike, data: Dict[str, Any]):
    p = _ensure_path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, p)

# ---------------- HTML ----------------
def save_html_report(path: PathLike, host: str, results, web_vulns):
    p = _ensure_path(path)
    html = Template(HTML_TEMPLATE).render(
        host=host,
        results=results,
        web_vulns=web_vulns,
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html)
    os.replace(tmp, p)

# ---------------- TXT ----------------
def save_txt_report(path: PathLike, host: str, results, web_vulns):
    p = _ensure_path(path)
    lines = [f"Scan Report - {host}", f"Generated: {datetime.now(timezone.utc).isoformat()}", ""]
    lines.append("---- PORT SCAN ----")
    for r in results:
        lines.append(f"Port {r.get('port')}: {'open' if r.get('open') else 'closed'} ({r.get('service', '-')})")
    lines.append("\n---- WEB FINDINGS ----")
    if not web_vulns:
        lines.append("No web findings detected.")
    else:
        for v in web_vulns:
            lines.append(f"[{v.get('severity').upper()}] {v.get('title')} - {v.get('vulnerable_url', '')}")
            lines.append(f"    Desc: {v.get('description')}")
            if v.get("evidence"):
                lines.append(f"    Evidence: {v.get('evidence')[:200]}...")
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(tmp, p)

# ---------------- PDF ----------------
def save_pdf_report(path: PathLike, host: str, results, web_vulns):
    p = _ensure_path(path)
    styles = getSampleStyleSheet()
    story = [Paragraph(f"Scan Report - {host}", styles["Title"]),
             Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}", styles["Normal"]),
             Spacer(1, 12)]

    story.append(Paragraph("Port Scan Results", styles["Heading2"]))
    data = [["Port", "Open?", "Service"]]
    for r in results:
        data.append([str(r.get("port")), "open" if r.get("open") else "closed", r.get("service", "-")])
    t = Table(data)
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.lightgrey), ("GRID", (0,0), (-1,-1), 0.5, colors.grey)]))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Web Findings", styles["Heading2"]))
    if not web_vulns:
        story.append(Paragraph("No web findings detected.", styles["Normal"]))
    else:
        for v in web_vulns:
            story.append(Paragraph(f"<b>{v.get('title')}</b> ({v.get('severity','')})", styles["Heading4"]))
            story.append(Paragraph(v.get("description",""), styles["Normal"]))
            if v.get("vulnerable_url"):
                story.append(Paragraph(f"<i>URL:</i> {v.get('vulnerable_url')}", styles["Normal"]))
            if v.get("evidence"):
                story.append(Paragraph(f"<i>Evidence:</i> {v.get('evidence')[:400]}", styles["Code"]))
            story.append(Spacer(1, 8))

    tmp = p.with_suffix(p.suffix + ".tmp")
    SimpleDocTemplate(str(tmp), pagesize=A4).build(story)
    os.replace(tmp, p)

# ---------------- Output Folder ----------------
def get_desktop_reports_folder() -> Path:
    """Always save reports to user's Desktop/AsyncScannerReports"""
    desktop = Path.home() / "Desktop" / "AsyncScannerReports"
    desktop.mkdir(parents=True, exist_ok=True)
    return desktop

# ---------------- Generator ----------------
def generate_report(target: str, results: List[Dict[str, Any]], web_vulns: List[Dict[str, Any]]):
    out_dir = get_desktop_reports_folder()
    safe_name = target.replace("://", "_").replace("/", "_")

    json_path = out_dir / f"{safe_name}_report.json"
    html_path = out_dir / f"{safe_name}_report.html"
    txt_path = out_dir / f"{safe_name}_report.txt"
    pdf_path = out_dir / f"{safe_name}_report.pdf"

    data = {
        "host": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "web_findings": web_vulns
    }

    save_json_report(json_path, data)
    save_html_report(html_path, target, results, web_vulns)
    save_txt_report(txt_path, target, results, web_vulns)
    save_pdf_report(pdf_path, target, results, web_vulns)

    print(f"[+] Reports saved in: {out_dir}")
    print(f"  - {json_path.name}")
    print(f"  - {html_path.name}")
    print(f"  - {txt_path.name}")
    print(f"  - {pdf_path.name}")

    # Auto open folder in File Explorer (Windows only)
    try:
        os.startfile(out_dir)
    except Exception:
        pass

    return {
        "json": str(json_path),
        "html": str(html_path),
        "txt": str(txt_path),
        "pdf": str(pdf_path),
    }
