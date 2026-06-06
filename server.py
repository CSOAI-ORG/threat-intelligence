"""threat-intelligence-mcp — MEOK AI Labs.

Correlates public CVE feeds (NVD, OSV.dev, GitHub Security Advisories)
to endpoint and package inventories. Pure Python; no native deps.

Tools:
  - cve_lookup(cve_id)
  - match_endpoints_to_cves(endpoints, packages=None)
  - severity_routing(cve_ids)
  - cve_list_recent(severity="HIGH", days=7)

Rate limits honoured:
  - NVD  : 5 req / 30 s unauthed, 50 req / 30 s with NVD_API_KEY
  - OSV  : unauthed, no published limit (be polite: max 4 in flight)
  - GHSA : 60 req / hr unauthed, 5000 req / hr with GH_TOKEN
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import urllib.request
import urllib.error

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "threat-intelligence",
    instructions=(
        "Correlate public CVE feeds (NVD, OSV.dev, GitHub Security Advisories) "
        "to endpoint and package inventories. Returns prioritised, evidence-backed "
        "remediation lists. Use cve_lookup for a single CVE; match_endpoints_to_cves "
        "to cross-reference an endpoint or package list; severity_routing to order "
        "a set of CVE IDs by CVSS+KEV+EPSS; cve_list_recent for the latest by severity."
    ),
)

# ---------- endpoints ---------------------------------------------------------

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_QUERY = "https://api.osv.dev/v1/query"
_GHSA_LIST = "https://api.github.com/advisories"

# ---------- rate-limit state --------------------------------------------------

_NVD_MIN_INTERVAL = 6.0 if not os.environ.get("NVD_API_KEY") else 0.6
_last_nvd_call = 0.0
_ghsa_window: list[float] = []


def _throttle_nvd() -> None:
    """Respect NVD's published 5/30s (no key) or 50/30s (with key) rate limit."""
    global _last_nvd_call
    now = time.monotonic()
    wait = _NVD_MIN_INTERVAL - (now - _last_nvd_call)
    if wait > 0:
        time.sleep(wait)
    _last_nvd_call = time.monotonic()


def _throttle_ghsa() -> None:
    """Sliding 1-hour window cap of 60 unauthed / 5000 authed."""
    cap = 5000 if os.environ.get("GH_TOKEN") else 60
    now = time.monotonic()
    while _ghsa_window and (now - _ghsa_window[0]) > 3600:
        _ghsa_window.pop(0)
    if len(_ghsa_window) >= cap:
        sleep_for = 3600 - (now - _ghsa_window[0]) + 1
        time.sleep(min(sleep_for, 5))
    _ghsa_window.append(time.monotonic())


# ---------- low-level HTTP ----------------------------------------------------


def _http_json(url: str, *, method: str = "GET", body: Optional[dict] = None,
               headers: Optional[dict] = None, timeout: int = 20) -> dict:
    """Tiny urllib wrapper; returns parsed JSON. Raises on HTTP error."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if os.environ.get("GH_TOKEN") and "github.com" in url:
        req.add_header("Authorization", f"Bearer {os.environ['GH_TOKEN']}")
    if os.environ.get("NVD_API_KEY") and "nvd.nist.gov" in url:
        req.add_header("apiKey", os.environ["NVD_API_KEY"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_http_body": e.read().decode("utf-8", "replace")}
    except urllib.error.URLError as e:
        return {"_url_error": str(e)}


# ---------- tool: cve_lookup --------------------------------------------------


@mcp.tool(name="cve_lookup")
async def cve_lookup(cve_id: str) -> dict:
    """Look up a single CVE by ID (e.g. ``CVE-2024-3094``) from the NVD.

    Returns the NVD record, including CVSS v3.1 base score, references,
    descriptions, and the published/modified timestamps.
    """
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id.strip(), re.IGNORECASE):
        return {"error": f"Invalid CVE id: {cve_id!r}", "expected": "CVE-YYYY-NNNN"}
    _throttle_nvd()
    url = f"{_NVD_BASE}?cveId={quote(cve_id.strip().upper())}"
    raw = _http_json(url)
    if "_http_error" in raw:
        return {"cve_id": cve_id.upper(), "found": False, "nvd_error": raw}
    vulns = raw.get("vulnerabilities") or []
    if not vulns:
        return {"cve_id": cve_id.upper(), "found": False}
    c = vulns[0].get("cve") or {}
    metrics = c.get("metrics") or {}
    cvss = (
        (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData") or {}
    )
    return {
        "cve_id": c.get("id"),
        "found": True,
        "published": c.get("published"),
        "last_modified": c.get("lastModified"),
        "descriptions": [
            d.get("value")
            for d in (c.get("descriptions") or [])
            if d.get("lang") == "en"
        ],
        "cvss_v3": {
            "base_score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
        } if cvss else None,
        "references": [
            {"url": r.get("url"), "tags": r.get("tags")}
            for r in (c.get("references") or [])
        ][:25],
        "weaknesses": [
            w.get("description", [{}])[0].get("value")
            for w in (c.get("weaknesses") or [])
        ],
    }


# ---------- tool: match_endpoints_to_cves -------------------------------------


def _endpoint_keywords(endpoint: str) -> List[str]:
    """Pull product-ish keywords out of an endpoint or HTTP-verb-prefixed path."""
    e = re.sub(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", "", endpoint.strip(),
               flags=re.IGNORECASE)
    parts = re.split(r"[/.\-_:]", e)
    return [p for p in parts if 3 <= len(p) <= 24 and p.lower() not in {
        "api", "v1", "v2", "v3", "http", "https", "json", "xml", "html",
    }]


@mcp.tool(name="match_endpoints_to_cves")
async def match_endpoints_to_cves(
    endpoints: List[str],
    packages: Optional[List[str]] = None,
    cpe_keywords: Optional[List[str]] = None,
) -> dict:
    """Given an endpoint list (and optional ecosystem packages), return matching CVEs.

    ``endpoints``  : list of strings, e.g. ``["/api/v1/users", "POST /login"]``
    ``packages``   : list of ``ecosystem:name`` pairs, e.g. ``["pypi:requests"]``
    ``cpe_keywords``: optional CPE words to constrain NVD CPE-match searches

    Returns a dict keyed by ``endpoint`` (or ``package``) with the matched CVEs
    from NVD, OSV, and GHSA, plus a unified ``findings`` list sorted by severity.
    """
    findings: Dict[str, Any] = {}
    overall: List[dict] = []

    for ep in endpoints or []:
        kws = _endpoint_keywords(ep)
        if not kws:
            findings[ep] = {"endpoint": ep, "matches": [], "note": "no usable keywords"}
            continue
        kw = " ".join(kws[:4])
        _throttle_nvd()
        nvd = _http_json(
            f"{_NVD_BASE}?keywordSearch={quote(kw)}&resultsPerPage=10"
        )
        nvd_items = []
        for v in (nvd.get("vulnerabilities") or [])[:10]:
            c = v.get("cve") or {}
            metrics = c.get("metrics") or {}
            cvss = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData") or {}
            nvd_items.append({
                "id": c.get("id"),
                "score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity"),
            })
        findings[ep] = {"endpoint": ep, "keywords": kws, "nvd_matches": nvd_items}
        overall.extend({"source": "nvd", "via": ep, **i} for i in nvd_items)

    for pkg in packages or []:
        eco, _, name = pkg.partition(":")
        if not (eco and name):
            findings[f"package:{pkg}"] = {"error": "expected ecosystem:name"}
            continue
        osv = _http_json(_OSV_QUERY, method="POST", body={"package": {
            "name": name, "ecosystem": eco.upper(),
        }})
        osv_items = []
        for v in (osv.get("vulns") or [])[:10]:
            sev = (v.get("severity") or [])
            score = None
            for s in sev:
                if s.get("type") == "CVSS_V3":
                    m = re.search(r"CVSS:3\.\d/.*", s.get("score") or "")
                    if m:
                        # Parse base score out of vector
                        mv = re.search(r":(\d+\.\d+)$", m.group(0))
                        if mv:
                            try:
                                score = float(mv.group(1))
                            except ValueError:
                                pass
            osv_items.append({
                "id": v.get("id"),
                "summary": (v.get("summary") or "")[:160],
                "score": score,
            })
        findings[f"package:{pkg}"] = {"package": pkg, "osv_matches": osv_items}
        overall.extend({"source": "osv", "via": pkg, **i} for i in osv_items)

    # de-dup by id (keep highest score)
    by_id: Dict[str, dict] = {}
    for f in overall:
        fid = f.get("id")
        if not fid:
            continue
        prev = by_id.get(fid)
        if (prev or {}).get("score", -1) < (f.get("score") or -1):
            by_id[fid] = f
    ranked = sorted(
        by_id.values(),
        key=lambda x: (x.get("score") or -1, x.get("id") or ""),
        reverse=True,
    )
    return {"findings_by_target": findings, "ranked": ranked}


# ---------- tool: severity_routing --------------------------------------------


def _kev_lookup(cve_id: str) -> bool:
    """Return True if the CVE is in the CISA KEV catalog."""
    try:
        with urllib.request.urlopen(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15,
        ) as r:
            data = json.loads(r.read().decode("utf-8"))
        for v in data.get("vulnerabilities") or []:
            if (v.get("cveID") or "").upper() == cve_id.upper():
                return True
    except Exception:
        return False
    return False


def _epss_lookup(cve_id: str) -> Optional[float]:
    """Return EPSS probability in [0,1], or None on error."""
    try:
        with urllib.request.urlopen(
            f"https://api.first.org/data/v1/epss?cve={quote(cve_id.upper())}",
            timeout=10,
        ) as r:
            data = json.loads(r.read().decode("utf-8"))
        for row in (data.get("data") or []):
            if (row.get("cve") or "").upper() == cve_id.upper():
                try:
                    return float(row.get("epss") or 0.0)
                except (TypeError, ValueError):
                    return None
    except Exception:
        return None
    return None


@mcp.tool(name="severity_routing")
async def severity_routing(cve_ids: List[str]) -> dict:
    """Order a list of CVE IDs by remediation priority.

    Priority signal: CVSS v3 base score (NVD), CISA KEV membership, EPSS score.
    Returns each CVE with its routing decision:
      - "patch_now"  : in KEV OR (CVSS >= 9.0 AND EPSS >= 0.5)
      - "patch_soon" : CVSS >= 7.0 OR EPSS >= 0.2
      - "patch_later": everything else with a known score
      - "unknown"    : no data found
    """
    out: List[dict] = []
    for raw in cve_ids or []:
        cve_id = (raw or "").strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
            out.append({"cve_id": raw, "decision": "unknown", "reason": "invalid id"})
            continue
        rec = await cve_lookup(cve_id)
        if not rec.get("found"):
            out.append({"cve_id": cve_id, "decision": "unknown",
                        "reason": "not in NVD"})
            continue
        cvss = (rec.get("cvss_v3") or {}).get("base_score")
        kev = _kev_lookup(cve_id)
        epss = _epss_lookup(cve_id)
        if kev or ((cvss or 0) >= 9.0 and (epss or 0) >= 0.5):
            decision = "patch_now"
        elif (cvss or 0) >= 7.0 or (epss or 0) >= 0.2:
            decision = "patch_soon"
        else:
            decision = "patch_later"
        out.append({
            "cve_id": cve_id,
            "cvss": cvss,
            "kev": kev,
            "epss": epss,
            "decision": decision,
        })
    out.sort(key=lambda x: (
        {"patch_now": 0, "patch_soon": 1, "patch_later": 2, "unknown": 3}.get(
            x["decision"], 4),
        -(x.get("cvss") or 0),
        -(x.get("epss") or 0),
    ))
    return {"routing": out, "as_of": datetime.now(timezone.utc).isoformat()}


# ---------- tool: cve_list_recent ---------------------------------------------


@mcp.tool(name="cve_list_recent")
async def cve_list_recent(severity: str = "HIGH", days: int = 7,
                          keyword: Optional[str] = None) -> dict:
    """List recent CVEs from the NVD by minimum severity.

    ``severity`` : one of LOW, MEDIUM, HIGH, CRITICAL
    ``days``     : window length in days (1..120, default 7)
    ``keyword``  : optional free-text filter
    """
    sev = severity.upper()
    if sev not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return {"error": f"invalid severity: {severity!r}"}
    if not 1 <= days <= 120:
        return {"error": f"days out of range: {days}"}
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    # NVD expects ISO 8601 with Z suffix
    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    _throttle_nvd()
    params = (
        f"lastModStartDate={quote(pub_start)}&lastModEndDate={quote(pub_end)}"
        f"&resultsPerPage=40"
    )
    if keyword:
        params += f"&keywordSearch={quote(keyword)}"
    raw = _http_json(f"{_NVD_BASE}?{params}")
    if "_http_error" in raw:
        return {"error": "nvd", "detail": raw}
    out: List[dict] = []
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_rank = severity_rank[sev]
    for v in raw.get("vulnerabilities") or []:
        c = v.get("cve") or {}
        metrics = c.get("metrics") or {}
        cvss_list = (metrics.get("cvssMetricV31") or []) + (
            metrics.get("cvssMetricV30") or [])
        cvss = (cvss_list[0].get("cvssData") if cvss_list else None) or {}
        s = cvss.get("baseSeverity") or "UNKNOWN"
        if severity_rank.get(s, 0) < min_rank:
            continue
        out.append({
            "id": c.get("id"),
            "severity": s,
            "score": cvss.get("baseScore"),
            "published": c.get("published"),
            "summary": next(
                (d.get("value") for d in (c.get("descriptions") or [])
                 if d.get("lang") == "en"), ""),
        })
    out.sort(key=lambda x: x.get("published") or "", reverse=True)
    return {"severity_min": sev, "window_days": days, "count": len(out),
            "items": out}


# ---------- entry point -------------------------------------------------------


def main() -> None:
    """Run the FastMCP server over stdio (Smithery/Gateway default)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
