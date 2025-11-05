# scanner/web_checks.py
"""
Extended async web scanner for valid exposures and keys.
Performs safe, non-destructive checks only. Designed for authorized bounty testing.
"""
import asyncio
import re
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse, urlencode
import aiohttp

DEFAULT_TIMEOUT = 10

# Regex patterns for likely secrets
KEY_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws_secret_access_key[^A-Za-z0-9]*([A-Za-z0-9/+=]{40})"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+"),
    re.compile(r"(?i)(api[_-]?key|token|secret)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]{10,}['\"]?")
]

SENSITIVE_PATHS = [
    ".env", "config.js", "config.php", "wp-config.php", ".git/config",
    ".git/HEAD", "package.json", "composer.json", "credentials.json",
    "backup.zip", "db.sql", "config.yaml", "config.yml",
    ".htpasswd", "id_rsa", "id_rsa.pub", "phpinfo.php"
]
VARIANT_SUFFIXES = ["", ".bak", ".old", ".backup", ".zip", ".txt"]

# small endpoint wordlist to probe (be polite)
COMMON_ENDPOINTS = [
    "admin", "admin/login", "api", "api/v1", "dashboard", "wp-admin",
    "sitemap.xml", ".well-known/security.txt", "backend", "login", "manage",
    "robots.txt", "favicon.ico", "healthz", "status"
]

def make_find(id_: str, title: str, severity: str, description: str,
              vulnerable_url: Optional[str] = None, parameter: Optional[str] = None,
              payload: Optional[str] = None, evidence: Optional[str] = None,
              request: Optional[Dict[str, Any]] = None, response: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "id": id_,
        "title": title,
        "severity": severity,
        "description": description,
        "vulnerable_url": vulnerable_url,
        "parameter": parameter,
        "payload": payload,
        "evidence": evidence,
        "request": request,
        "response": response
    }

async def fetch(session: aiohttp.ClientSession, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
    return await session.request(method, url, timeout=DEFAULT_TIMEOUT, allow_redirects=False, **kwargs)

async def read_text(resp: aiohttp.ClientResponse) -> str:
    return await resp.text(errors="ignore")

# ---------------- Basic header/cors/xss checks ----------------
async def check_security_headers(session: aiohttp.ClientSession, url: str) -> List[Dict]:
    results = []
    try:
        async with await fetch(session, "GET", url) as resp:
            hdr = resp.headers
            if "strict-transport-security" not in hdr:
                results.append(make_find("SEC-HSTS-01","Missing HSTS","low","Strict-Transport-Security header missing",url))
            if "x-frame-options" not in hdr and "content-security-policy" not in hdr:
                results.append(make_find("SEC-FRAME-01","Framing allowed","low","No X-Frame-Options or CSP frame-ancestors",url))
            if "x-content-type-options" not in hdr:
                results.append(make_find("SEC-CTO-01","Missing X-Content-Type-Options","low","X-Content-Type-Options: nosniff header missing",url))
            if "content-security-policy" not in hdr:
                results.append(make_find("SEC-CSP-01","Missing CSP","low","Content-Security-Policy header not present",url))
            # cookies flags
            cookies = hdr.getall("set-cookie", []) if hasattr(hdr, "getall") else hdr.get("set-cookie", None)
            if cookies:
                cookies_list = cookies if isinstance(cookies, list) else [cookies]
                for c in cookies_list:
                    parts = [p.strip().lower() for p in c.split(";")]
                    if "httponly" not in parts or "secure" not in parts:
                        results.append(make_find("SEC-COOKIE-01","Cookie flags not secure","medium",f"Cookie missing flags: {parts}",url,evidence=c))
    except Exception as e:
        results.append(make_find("ERROR","check_security_headers_failed","info",str(e),url))
    return results

async def check_cors(session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
    try:
        async with await fetch(session, "OPTIONS", url) as resp:
            hdr = resp.headers
            ao = hdr.get("access-control-allow-origin")
            if ao:
                # flag obvious permissive patterns
                if ao.strip() == "*" or ("http" in ao and ao.strip().endswith("*")):
                    return make_find("SEC-CORS-01","Permissive CORS","medium",f"Access-Control-Allow-Origin: {ao}",url,evidence=str(dict(hdr)))
    except Exception:
        pass
    return None

async def check_reflected_xss(session: aiohttp.ClientSession, base: str) -> Optional[Dict]:
    token = "XSS_PROOF_12345"
    params = {"q": token}
    try:
        async with await fetch(session, "GET", base, params=params) as resp:
            txt = await read_text(resp)
            if token in txt:
                return make_find("WEB-XSS-01","Reflected input detected","high","Query parameter value was reflected in the response body.",f"{base}?{urlencode(params)}","q",token,"Token echoed in response")
    except Exception:
        pass
    return None

async def check_open_redirect(session: aiohttp.ClientSession, base: str) -> Optional[Dict]:
    test_url = "https://example.com"
    params = ["next","url","redirect","target","return"]
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for p in params:
        test = f"{root}/?{p}={test_url}"
        try:
            async with await fetch(session, "GET", test) as resp:
                if resp.status in (301,302,303,307,308):
                    loc = resp.headers.get("Location","")
                    if test_url in loc:
                        return make_find("WEB-OR-01","Open redirect parameter found","high",f"Parameter '{p}' redirects to external host: {loc}",test,parameter=p,evidence=loc)
        except Exception:
            continue
    return None

# ---------------- Sensitive files & variants ----------------
async def probe_variant_paths(session: aiohttp.ClientSession, base_root: str, path: str) -> List[Dict]:
    findings: List[Dict] = []
    for suf in VARIANT_SUFFIXES:
        candidate = path + suf
        url = urljoin(base_root + "/", candidate.lstrip("/"))
        try:
            async with await fetch(session, "GET", url) as resp:
                if resp.status == 200:
                    txt = await read_text(resp)
                    findings.append(make_find("SENS-FILE-01","Public file (variant) accessible","high",f"Accessible variant {candidate}",url,evidence=(txt[:400] if txt else None)))
        except Exception:
            continue
    return findings

async def check_sensitive_paths(session: aiohttp.ClientSession, base: str) -> List[Dict]:
    parsed = urlparse(base)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    for p in SENSITIVE_PATHS:
        url = urljoin(base_root + "/", p.lstrip("/"))
        try:
            async with await fetch(session, "GET", url) as resp:
                status = resp.status
                if status == 200:
                    txt = await read_text(resp)
                    findings.append(make_find("SENS-FILE-01","Public file found","critical",f"File {p} returned 200",url,evidence=(txt[:400] if txt else None)))
                elif status in (401,403):
                    # try safe variants
                    variants = await probe_variant_paths(session, base_root, p)
                    if variants:
                        findings.extend(variants)
                    else:
                        findings.append(make_find("SENS-FILE-02","Protected file","info",f"{p} returned {status}",url,evidence=f"status={status}"))
        except Exception:
            continue
        await asyncio.sleep(0.03)
    return findings

# ---------------- Token detection + neighbor probing ----------------
async def probe_for_files_near_token(session: aiohttp.ClientSession, token_location_url: str) -> List[Dict]:
    findings = []
    parsed = urlparse(token_location_url)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    path_dir = "/".join(parsed.path.split("/")[:-1]) or "/"
    neighbor_candidates = [
        urljoin(base_root, path_dir + "/.env"),
        urljoin(base_root, path_dir + "/config.js"),
        urljoin(base_root, path_dir + "/config.php"),
        urljoin(base_root, "/.env"),
        urljoin(base_root, "/config.js"),
        urljoin(base_root, "/config.php"),
    ]
    seen = set()
    for u in neighbor_candidates:
        if u in seen: continue
        seen.add(u)
        try:
            async with await fetch(session, "GET", u) as resp:
                if resp.status == 200:
                    txt = await read_text(resp)
                    findings.append(make_find("SENS-FILE-03","Neighbor file exposed","high","File exposed near token location",u,evidence=(txt[:500] if txt else None)))
        except Exception:
            continue
    return findings

async def scan_for_keys_in_paths(session: aiohttp.ClientSession, base: str) -> List[Dict]:
    parsed = urlparse(base)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    findings: List[Dict] = []

    # fetch root to discover script URLs
    try:
        async with await fetch(session, "GET", base_root) as resp:
            root_txt = ""
            if resp.status == 200:
                root_txt = await read_text(resp)
                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', root_txt, re.IGNORECASE)
            else:
                js_urls = []
    except Exception:
        js_urls = []
        root_txt = ""

    candidates = {base_root, urljoin(base_root, "/static/"), urljoin(base_root, "/assets/")}
    for js in js_urls:
        full = js if js.startswith("http") else urljoin(base_root, js)
        candidates.add(full)

    for u in list(candidates):
        try:
            async with await fetch(session, "GET", u) as resp:
                if resp.status != 200:
                    continue
                txt = await read_text(resp)
                for pat in KEY_PATTERNS:
                    for m in pat.finditer(txt):
                        secret = m.group(0)
                        snippet = txt[max(0, m.start()-80):m.end()+80]
                        f = make_find("SENS-KEY-01","Possible leaked key/token","critical",f"Token-like pattern matched", u, evidence=snippet[:400], response={"match": secret})
                        findings.append(f)
                        # probe near token location
                        neighbor_findings = await probe_for_files_near_token(session, u)
                        if neighbor_findings:
                            findings.extend(neighbor_findings)
        except Exception:
            continue
        await asyncio.sleep(0.03)
    return findings

# ---------------- Small endpoint / subpath probe ----------------
async def probe_common_endpoints(session: aiohttp.ClientSession, base: str) -> List[Dict]:
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    for p in COMMON_ENDPOINTS:
        url = urljoin(root + "/", p.lstrip("/"))
        try:
            async with await fetch(session, "GET", url) as resp:
                # mark 200 as interesting to inspect (could be public admin, api, etc.)
                if resp.status == 200:
                    txt = await read_text(resp)
                    findings.append(make_find("EXPOSE-ENDPOINT-01","Public endpoint returned 200","high",f"Endpoint {p} returned 200",url,evidence=(txt[:400] if txt else None)))
                # collect 401/403 as informational
                elif resp.status in (401,403):
                    findings.append(make_find("EXPOSE-ENDPOINT-02","Endpoint protected","info",f"Endpoint {p} returned {resp.status}",url,evidence=f"status={resp.status}"))
        except Exception:
            continue
        await asyncio.sleep(0.05)
    return findings

# ---------------- Top-level runner ----------------
async def scan_web(target_url: str, throttle: float = 0.2) -> List[Dict]:
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    results: List[Dict] = []
    conn = aiohttp.TCPConnector(limit_per_host=8, ssl=False)
    headers = {"User-Agent": "async-vuln-scanner/1.3 (researcher@example.com)"}

    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        try:
            results.extend(await check_security_headers(session, target_url))
        except Exception as e:
            results.append(make_find("ERROR","check_security_headers_failed","info",str(e),target_url))
        await asyncio.sleep(throttle)

        try:
            r = await check_cors(session, target_url)
            if r: results.append(r)
        except Exception as e:
            results.append(make_find("ERROR","check_cors_failed","info",str(e),target_url))
        await asyncio.sleep(throttle)

        try:
            o = await check_open_redirect(session, target_url)
            if o: results.append(o)
        except Exception as e:
            results.append(make_find("ERROR","check_open_redirect_failed","info",str(e),target_url))
        await asyncio.sleep(throttle)

        try:
            x = await check_reflected_xss(session, target_url)
            if x: results.append(x)
        except Exception as e:
            results.append(make_find("ERROR","check_reflected_xss_failed","info",str(e),target_url))
        await asyncio.sleep(throttle)

        # probe common endpoints
        try:
            e = await probe_common_endpoints(session, target_url)
            if e: results.extend(e)
        except Exception as e:
            results.append(make_find("ERROR","probe_common_endpoints_failed","info",str(e),target_url))
        await asyncio.sleep(throttle)

        # sensitive files scan
        try:
            s = await check_sensitive_paths(session, target_url)
            if s: results.extend(s)
        except Exception as e:
            results.append(make_find("ERROR","check_sensitive_paths_failed","info",str(e),target_url))
        await asyncio.sleep(throttle)

        # key/token scanning
        try:
            k = await scan_for_keys_in_paths(session, target_url)
            if k: results.extend(k)
        except Exception as e:
            results.append(make_find("ERROR","scan_for_keys_failed","info",str(e),target_url))

    return results
