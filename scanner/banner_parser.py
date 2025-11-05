# scanner/banner_parser.py
import re
from typing import List

def banner_to_keywords(banner: str) -> List[str]:
    """
    Extract plausible product keywords from a banner string.
    Examples:
      "Server: nginx/1.18.0 (Ubuntu)" -> ["nginx", "nginx 1.18.0", "ubuntu"]
      "OpenSSH_7.4" -> ["openssh", "openssh 7.4"]
    """
    if not banner:
        return []

    b = banner.lower()
    kws = []

    # common web servers
    web = re.search(r"(nginx|apache|caddy|gunicorn|http\.server|python-?http|iis)(?:/([0-9\.]+))?", b)
    if web:
        name = web.group(1)
        ver = web.group(2)
        kws.append(name)
        if ver:
            kws.append(f"{name} {ver}")

    # openssh
    ssh = re.search(r"(openssh|ssh)-?(\d+\.\d+)", b)
    if ssh:
        kws.append("openssh")
        kws.append(f"openssh {ssh.group(2)}")

    # mysql / postgres
    if "mysql" in b:
        m = re.search(r"mysql(?:\s*/\s*([0-9\.]+))?", b)
        kws.append("mysql")
        if m and m.group(1):
            kws.append(f"mysql {m.group(1)}")
    if "postgres" in b or "postgresql" in b:
        kws.append("postgresql")

    # fallback: split tokens and return likely words
    tokens = re.findall(r"[a-z0-9\.-]{3,}", b)
    for t in tokens[:5]:
        if t not in kws:
            kws.append(t)
    return kws
