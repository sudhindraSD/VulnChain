"""
epss_coverage_and_fetch.py -- Check EPSS coverage, fetch missing EPSS scores, and rebuild labels.
================================================================================================
Part B of Phase 5 Continuation II.
"""

import json
import urllib.request
import urllib.error
import time
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent

GRAPH_51 = PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json"
EPSS_DATA_ARCHIVED = PROJECT_ROOT / "TrainModel" / "epss_data.json"
OSV_CACHE = PROJECT_ROOT / ".osv_records_cache.json"
OUTPUT_EPSS_DATA = PROJECT_ROOT / "phase5" / "epss_data_51repo.json"
OUTPUT_REPORT = PROJECT_ROOT / "phase5" / "part_b_epss_coverage_report.json"

FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev():
    """Fetch CISA KEV list of CVEs."""
    print("  Fetching CISA KEV catalog...")
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "VulnChain/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            kev_cves = set(vuln["cveID"] for vuln in data.get("vulnerabilities", []))
            print(f"  [OK] CISA KEV fetched: {len(kev_cves)} CVEs")
            return kev_cves
    except Exception as e:
        print(f"  [WARN] Failed to fetch CISA KEV: {e}. Falling back to archived KEV flag.")
        return set()


def fetch_epss_scores_batch(cve_list, batch_size=60):
    """Fetch EPSS scores from FIRST.org API in batches."""
    print(f"  Fetching EPSS scores for {len(cve_list)} CVEs from FIRST.org (batches of {batch_size})...")
    epss_map = {}
    
    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i : i + batch_size]
        cve_param = ",".join(batch)
        url = f"{FIRST_EPSS_URL}?cve={cve_param}"
        
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VulnChain/2.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for row in data.get("data", []):
                    cve_id = row.get("cve")
                    epss = float(row.get("epss", 0.0))
                    percentile = float(row.get("percentile", 0.0))
                    epss_map[cve_id] = (epss, percentile)
            print(f"    Batch {i//batch_size + 1}/{(len(cve_list)-1)//batch_size + 1}: fetched {len(batch)} CVEs")
        except Exception as e:
            print(f"    [ERROR] Batch {i//batch_size + 1} failed: {e}")
        time.sleep(0.2)  # courteous rate limit

    return epss_map


def main():
    print("=" * 60)
    print("  PART B: EPSS Coverage Completion & Label Rebuild")
    print("=" * 60)

    # 1. Load data
    with open(GRAPH_51, encoding="utf-8") as f:
        g51 = json.load(f)
    with open(EPSS_DATA_ARCHIVED, encoding="utf-8") as f:
        archived_epss = json.load(f)
    with open(OSV_CACHE, encoding="utf-8") as f:
        osv = json.load(f)

    cve_nodes = g51["nodes"]["CVE"]
    print(f"Total CVE nodes in 51-repo graph: {len(cve_nodes)}")

    # 2. Analyze current coverage BEFORE fetch
    cov_before = {"real_epss": 0, "cvss_fallback": 0, "neither": 0}
    ghsa_to_cve = {}
    ghsa_to_cvss = {}
    cves_to_fetch = []

    for c in cve_nodes:
        ghsa_id = c["id"]
        # Extract CVSS from node feature or osv
        node_cvss = c["features"][0] if c.get("features") else None
        osv_rec = osv.get(ghsa_id, {})
        aliases = osv_rec.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        
        # Determine CVSS score
        cvss = node_cvss if (node_cvss and node_cvss > 0) else None
        if not cvss and ghsa_id in archived_epss:
            cvss = archived_epss[ghsa_id].get("cvss_score")
        ghsa_to_cvss[ghsa_id] = cvss
        ghsa_to_cve[ghsa_id] = cve_alias

        # Current state before fetch
        if ghsa_id in archived_epss and archived_epss[ghsa_id].get("epss_score") is not None:
            cov_before["real_epss"] += 1
        elif cvss is not None and cvss > 0:
            cov_before["cvss_fallback"] += 1
        else:
            cov_before["neither"] += 1

        # Check if we can fetch real EPSS
        already_has_epss = (ghsa_id in archived_epss and archived_epss[ghsa_id].get("epss_score") is not None)
        if not already_has_epss and cve_alias:
            cves_to_fetch.append(cve_alias)

    print("\n--- Coverage BEFORE Fetch (among 883 CVEs) ---")
    print(f"  Real EPSS:        {cov_before['real_epss']} ({cov_before['real_epss']/len(cve_nodes):.1%})")
    print(f"  CVSS fallback:    {cov_before['cvss_fallback']} ({cov_before['cvss_fallback']/len(cve_nodes):.1%})")
    print(f"  Neither (0.0):    {cov_before['neither']} ({cov_before['neither']/len(cve_nodes):.1%})")
    print(f"  CVEs eligible for FIRST.org fetch: {len(cves_to_fetch)}")

    # 3. Fetch KEV + EPSS
    kev_cves = fetch_cisa_kev()
    unique_cves_to_fetch = sorted(set(cves_to_fetch))
    epss_fetched = fetch_epss_scores_batch(unique_cves_to_fetch)
    print(f"  Fetched EPSS scores for {len(epss_fetched)}/{len(unique_cves_to_fetch)} CVEs")

    # 4. Build comprehensive epss_data_51repo.json
    new_epss_data = {}
    cov_after = {"real_epss": 0, "cvss_fallback": 0, "neither": 0, "in_cisa_kev": 0}

    for c in cve_nodes:
        ghsa_id = c["id"]
        cve_alias = ghsa_to_cve[ghsa_id]
        cvss = ghsa_to_cvss[ghsa_id]

        # Check KEV
        in_kev = False
        if cve_alias and cve_alias in kev_cves:
            in_kev = True
        elif ghsa_id in archived_epss and archived_epss[ghsa_id].get("in_cisa_kev"):
            in_kev = True

        # Check EPSS: newly fetched > archived > None
        epss_score = None
        epss_pct = None
        if cve_alias and cve_alias in epss_fetched:
            epss_score, epss_pct = epss_fetched[cve_alias]
        elif ghsa_id in archived_epss and archived_epss[ghsa_id].get("epss_score") is not None:
            epss_score = archived_epss[ghsa_id]["epss_score"]
            epss_pct = archived_epss[ghsa_id].get("epss_percentile")

        new_epss_data[ghsa_id] = {
            "ghsa_id": ghsa_id,
            "cve_id": cve_alias,
            "cvss_score": cvss,
            "epss_score": epss_score,
            "epss_percentile": epss_pct,
            "in_cisa_kev": in_kev,
        }

        if in_kev:
            cov_after["in_cisa_kev"] += 1

        if epss_score is not None:
            cov_after["real_epss"] += 1
        elif cvss is not None and cvss > 0:
            cov_after["cvss_fallback"] += 1
        else:
            cov_after["neither"] += 1

    print("\n--- Coverage AFTER Fetch (among 883 CVEs) ---")
    print(f"  Real EPSS:        {cov_after['real_epss']} ({cov_after['real_epss']/len(cve_nodes):.1%}) [gain: +{cov_after['real_epss'] - cov_before['real_epss']}]")
    print(f"  CVSS fallback:    {cov_after['cvss_fallback']} ({cov_after['cvss_fallback']/len(cve_nodes):.1%})")
    print(f"  Neither (0.0):    {cov_after['neither']} ({cov_after['neither']/len(cve_nodes):.1%})")
    print(f"  In CISA KEV:      {cov_after['in_cisa_kev']}")

    # Save new EPSS data
    with open(OUTPUT_EPSS_DATA, "w", encoding="utf-8") as f:
        json.dump(new_epss_data, f, indent=2)
    print(f"\n[OK] Saved 51-repo EPSS data to: {OUTPUT_EPSS_DATA}")

    # 5. Reconcile 751 vs 978 (own-CVE packages with non-zero EPSS)
    # 978 packages have hasVulnerability edges in 51-repo graph
    has_vuln_pkgs = set(e["source"] for e in g51["edges"]["hasVulnerability"])
    print(f"\n--- Reconciling 751 vs 978 ---")
    print(f"  Total packages with hasVulnerability edges: {len(has_vuln_pkgs)}")

    # Check for each package what CVEs it has and why some had EPSS = 0
    pkg_cves = defaultdict(list)
    for e in g51["edges"]["hasVulnerability"]:
        pkg_cves[e["source"]].append(e["target"])

    pkgs_with_real_epss = 0
    pkgs_with_cvss_only = 0
    pkgs_with_neither = 0
    pkgs_without_cve_alias = 0

    for pid in has_vuln_pkgs:
        cves = pkg_cves[pid]
        # Check if any CVE has real EPSS
        has_real = any(new_epss_data[c]["epss_score"] is not None for c in cves if c in new_epss_data)
        has_cvss = any(new_epss_data[c]["cvss_score"] is not None for c in cves if c in new_epss_data)
        has_alias = any(new_epss_data[c]["cve_id"] is not None for c in cves if c in new_epss_data)

        if has_real:
            pkgs_with_real_epss += 1
        elif has_cvss:
            pkgs_with_cvss_only += 1
        else:
            pkgs_with_neither += 1

        if not has_alias:
            pkgs_without_cve_alias += 1

    print(f"  Packages with real EPSS:         {pkgs_with_real_epss}")
    print(f"  Packages with CVSS-only:        {pkgs_with_cvss_only}")
    print(f"  Packages with neither (0.0):    {pkgs_with_neither}")
    print(f"  Packages with alias-less GHSA:  {pkgs_without_cve_alias}")

    # 6. Save Part B Report
    report = {
        "cve_coverage_before": cov_before,
        "cve_coverage_after": cov_after,
        "total_cves": len(cve_nodes),
        "reconciliation_751_vs_978": {
            "total_packages_with_has_vuln": len(has_vuln_pkgs),
            "pkgs_with_real_epss": pkgs_with_real_epss,
            "pkgs_with_cvss_only": pkgs_with_cvss_only,
            "pkgs_with_neither": pkgs_with_neither,
            "pkgs_without_cve_alias": pkgs_without_cve_alias,
            "mechanism": "In the previous run, only 326 9-repo CVEs were in epss_data.json. 557 CVEs had no EPSS entry, so they fell back to cvss/100 if cvss existed, or 0.0 if not. Furthermore, some packages only had pure GHSA advisories with no CVE alias and no CVSS."
        }
    }
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[OK] Saved Part B report to: {OUTPUT_REPORT}")


if __name__ == "__main__":
    main()
