# scanner/svc_fingerprint.py
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    27017: "mongodb"
}

def guess_service(port:int, banner:str):
    svc = COMMON_PORTS.get(port, "unknown")
    if banner:
        b = banner.lower()
        if "ssh" in b: svc = "ssh"
        if "http" in b or "apache" in b or "nginx" in b: svc = "http"
    return svc
