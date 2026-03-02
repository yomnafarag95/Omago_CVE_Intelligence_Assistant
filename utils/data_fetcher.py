"""
utils/data_fetcher.py
─────────────────────
Multi-layer CVE data architecture:
  Layer 1 – NVD        : Authoritative baseline (130K+ CVEs, rich CVSS/CWE data)
  Layer 2 – CISA KEV   : Confirmed exploitation signals (1,100+ actively exploited)
  Layer 3 – Exploit-DB : Weaponization indicators (15K+ exploit PoCs)

All three layers are merged into a unified CVE intelligence record.
"""

import os
import json
import requests
import pandas as pd
from typing import Optional, Dict, List


# ── Layer 1: NVD ─────────────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd_cve(cve_id: str) -> Optional[Dict]:
    """Fetch a single CVE from NVD by ID."""
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key and api_key != "your_nvd_api_key_here" else {}

    try:
        resp = requests.get(
            NVD_BASE,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        item = vulns[0]["cve"]
        return _parse_nvd_item(item)
    except Exception:
        return None


def fetch_nvd_recent(results_per_page: int = 20) -> List[Dict]:
    """Fetch the most recently updated CVEs from NVD."""
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key and api_key != "your_nvd_api_key_here" else {}

    try:
        resp = requests.get(
            NVD_BASE,
            params={"resultsPerPage": results_per_page},
            headers=headers,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return [_parse_nvd_item(v["cve"]) for v in data.get("vulnerabilities", [])]
    except Exception:
        return []


def _parse_nvd_item(item: Dict) -> Dict:
    """Extract key fields from a raw NVD CVE record."""
    desc = ""
    for d in item.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    cvss_score = None
    cvss_severity = "UNKNOWN"
    cvss_vector = ""
    metrics = item.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = entries[0].get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
            cvss_vector = cvss_data.get("vectorString", "")
            break

    cwes = []
    for weakness in item.get("weaknesses", []):
        for wd in weakness.get("description", []):
            cwes.append(wd.get("value", ""))

    return {
        "cve_id": item.get("id", ""),
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cwe": cwes,
        "published": item.get("published", ""),
        "last_modified": item.get("lastModified", ""),
        "source": "NVD",
    }


# ── Layer 2: CISA KEV ─────────────────────────────────────────────────────────

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache: Optional[Dict] = None


def fetch_kev_catalog() -> Dict[str, Dict]:
    """
    Download and cache the full CISA KEV catalog.
    Returns a dict keyed by CVE ID for O(1) lookup.
    """
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    try:
        resp = requests.get(KEV_URL, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        _kev_cache = {v["cveID"]: v for v in vulns}
        return _kev_cache
    except Exception:
        return {}


def is_in_kev(cve_id: str) -> Optional[Dict]:
    """Return KEV record if CVE is in the catalog, else None."""
    catalog = fetch_kev_catalog()
    return catalog.get(cve_id)


def get_kev_stats() -> Dict:
    """Return summary statistics for the KEV catalog."""
    catalog = fetch_kev_catalog()
    if not catalog:
        return {"total": 0, "vendors": [], "ransomware_count": 0}

    vendors = {}
    ransomware = 0
    for v in catalog.values():
        vendor = v.get("vendorProject", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1
        if v.get("knownRansomwareCampaignUse", "").lower() == "known":
            ransomware += 1

    top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "total": len(catalog),
        "top_vendors": top_vendors,
        "ransomware_count": ransomware,
        "non_ransomware_count": len(catalog) - ransomware,
    }


def get_recent_kev(n: int = 5) -> List[Dict]:
    """Return the n most recently added KEV entries."""
    catalog = fetch_kev_catalog()
    if not catalog:
        return []
    items = sorted(catalog.values(), key=lambda x: x.get("dateAdded", ""), reverse=True)
    return items[:n]


# ── Layer 3: Exploit-DB ───────────────────────────────────────────────────────

EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

_exploitdb_cache: Optional[pd.DataFrame] = None


def fetch_exploitdb() -> pd.DataFrame:
    """
    Download and cache the Exploit-DB CSV.
    Returns a DataFrame with CVE-mapped exploit records.
    """
    global _exploitdb_cache
    if _exploitdb_cache is not None:
        return _exploitdb_cache

    try:
        resp = requests.get(EXPLOITDB_CSV, timeout=30)
        resp.raise_for_status()
        from io import StringIO
        df = pd.read_csv(StringIO(resp.text), on_bad_lines="skip")
        # Normalize column names
        df.columns = [c.strip().lower() for c in df.columns]
        _exploitdb_cache = df
        return df
    except Exception:
        return pd.DataFrame()


def get_exploitdb_for_cve(cve_id: str) -> List[Dict]:
    """Find Exploit-DB entries that reference a given CVE ID."""
    df = fetch_exploitdb()
    if df.empty:
        return []
    # Search in description column for the CVE ID
    mask = df.get("description", pd.Series(dtype=str)).str.contains(cve_id, case=False, na=False)
    matches = df[mask]
    results = []
    for _, row in matches.iterrows():
        results.append({
            "exploit_id": row.get("id", ""),
            "description": row.get("description", ""),
            "date": row.get("date", ""),
            "type": row.get("type", ""),
            "platform": row.get("platform", ""),
            "source": "Exploit-DB",
        })
    return results


# ── Unified CVE Intelligence Lookup ──────────────────────────────────────────

def get_full_cve_intelligence(cve_id: str) -> Dict:
    """
    Merge all three data layers for a single CVE ID.

    Returns a unified intelligence record with:
    - NVD description, CVSS score, CWE
    - KEV exploitation status
    - Exploit-DB weaponization proof
    - Priority score (0-3) based on active evidence
    """
    cve_id = cve_id.strip().upper()

    nvd = fetch_nvd_cve(cve_id)
    kev = is_in_kev(cve_id)
    exploits = get_exploitdb_for_cve(cve_id)

    # Priority scoring
    priority = 0
    if nvd and nvd.get("cvss_score"):
        score = float(nvd["cvss_score"])
        if score >= 9.0:
            priority += 1
        elif score >= 7.0:
            priority += 0.5
    if kev:
        priority += 1  # Active exploitation confirmed
    if exploits:
        priority += 1  # Weaponized PoC available

    # Build unified context string for RAG injection
    context_parts = []
    if nvd:
        context_parts.append(
            f"[NVD] {cve_id}: {nvd['description']} "
            f"CVSS: {nvd['cvss_score']} ({nvd['cvss_severity']}) "
            f"Vector: {nvd['cvss_vector']} CWE: {', '.join(nvd['cwe'])}"
        )
    if kev:
        context_parts.append(
            f"[CISA KEV] ACTIVELY EXPLOITED. Vendor: {kev.get('vendorProject')} "
            f"Product: {kev.get('product')} "
            f"Ransomware: {kev.get('knownRansomwareCampaignUse', 'Unknown')} "
            f"Due date: {kev.get('dueDate', 'N/A')}"
        )
    if exploits:
        context_parts.append(
            f"[Exploit-DB] {len(exploits)} public exploit(s) found. "
            f"Types: {', '.join(set(e['type'] for e in exploits if e['type']))}"
        )

    return {
        "cve_id": cve_id,
        "nvd": nvd,
        "kev": kev,
        "exploits": exploits,
        "priority_score": round(priority, 1),
        "rag_context": "\n".join(context_parts),
        "found": bool(nvd or kev or exploits),
    }


def build_rag_context_for_query(query: str) -> str:
    """
    Attempt to extract a CVE ID from free-text query and build context.
    Falls back to empty string if no CVE ID found.
    """
    import re
    pattern = r"CVE-\d{4}-\d{4,7}"
    matches = re.findall(pattern, query, flags=re.IGNORECASE)
    if not matches:
        return ""

    contexts = []
    for cve_id in matches[:3]:  # Limit to 3 CVEs per query
        intel = get_full_cve_intelligence(cve_id)
        if intel["found"]:
            contexts.append(intel["rag_context"])
    return "\n\n".join(contexts)
