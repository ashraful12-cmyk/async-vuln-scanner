# scanner/cve_lookup.py
import os
import requests
import time
import json
from typing import List, Dict, Optional
from pathlib import Path

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
CACHE_DIR = Path(".cache_nvd")
CACHE_DIR.mkdir(exist_ok=True)

def _call_nvd(params: Dict, max_retries: int = 2) -> Optional[Dict]:
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    for attempt in range(max_retries):
        try:
            resp = requests.get(NVD_BASE, headers=headers, params=params, timeout=20)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            # simple backoff
            time.sleep(1 + attempt * 2)
    return None

def _cache_get(key: str):
    p = CACHE_DIR / (key + ".json")
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return None

def _cache_set(key: str, data):
    p = CACHE_DIR / (key + ".json")
    p.write_text(json.dumps(data), encoding="utf-8")

def extract_cve_details(nvd_item: Dict) -> Dict:
    """
    Normalize one NVD vulnerability item into a useful dict:
    {
      "cve_id": "CVE-YYYY-NNNN",
      "summary": "...",
      "published": "2024-01-01T12:00:00Z",
      "lastModified": "...",
      "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/..."} (if available),
      "references": ["https://...", ...]
    }
    """
    details = {}
    # NVD v2 shape: vulnerability -> cve -> id, descriptions, metrics, references
    vuln = nvd_item.get("cve") or {}
    details["cve_id"] = vuln.get("id") or vuln.get("CVE_data_meta", {}).get("ID", "")
    # descriptions often an array of dicts
    descs = vuln.get("descriptions") or []
    details["summary"] = ""
    for d in descs:
        if isinstance(d, dict) and d.get("lang", "").lower().startswith("en"):
            details["summary"] = d.get("value", "")
            break
    details["published"] = nvd_item.get("published") or nvd_item.get("publishedDate") or ""
    details["lastModified"] = nvd_item.get("lastModified") or nvd_item.get("lastModifiedDate") or ""
    # CVSS (try v3 then v2) - NVD v2 uses metrics: {'cvssMetricV31':[...]} etc.
    details["cvss"] = {}
    metrics = nvd_item.get("metrics", {}) or {}
    # try cvss v3.1 or 3.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            m = arr[0]
            cvss = m.get("cvssData") or m.get("cvssV3") or m.get("cvssV2") or {}
            if cvss:
                details["cvss"]["score"] = cvss.get("baseScore") or cvss.get("baseSeverity") or None
                details["cvss"]["vector"] = cvss.get("vectorString") or cvss.get("vector")
                break
    # references - NVD shape might have 'references' or 'cve'->'references'
    refs = []
    # try multiple places
    refs_raw = vuln.get("references") or nvd_item.get("references") or {}
    if isinstance(refs_raw, dict):
        # sometimes {'reference_data': [...]}
        for k in ("reference_data", "references", "reference"):
            arr = refs_raw.get(k)
            if isinstance(arr, list):
                for r in arr:
                    url = r.get("url") or r.get("url")
                    if url:
                        refs.append(url)
    elif isinstance(refs_raw, list):
        for r in refs_raw:
            url = r.get("url") or (r.get("url") if isinstance(r, dict) else None)
            if url:
                refs.append(url)
    # fallback: try to parse from NVD item top-level 'references'
    if not refs:
        # some NVD shapes include flattened 'references' list
        for ref in (nvd_item.get("references") or []):
            if isinstance(ref, dict):
                url = ref.get("url") or ref.get("link")
                if url:
                    refs.append(url)
    details["references"] = list(dict.fromkeys(refs))  # unique preserve order
    return details

def query_cves_by_keyword(keyword: str, max_results: int = 10) -> List[Dict]:
    """
    Search NVD for keyword and return a list of normalized CVE dicts.
    Caches results per keyword to .cache_nvd/
    """
    key = f"kw_{keyword.replace(' ', '_')}"
    cached = _cache_get(key)
    if cached:
        return cached

    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    resp = _call_nvd(params)
    results = []
    if resp:
        vulns = resp.get("vulnerabilities") or resp.get("vulnerability") or []
        for v in vulns:
            # v might be a dict with "cve" child or already an item
            item = v.get("cve") and v or v
            normalized = extract_cve_details(item)
            if normalized.get("cve_id"):
                results.append(normalized)

    _cache_set(key, results)
    return results
