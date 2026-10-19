"""
check_temporal_split.py -- Analyze temporal split by newest-contributing-CVE published date
=========================================================================================
"""

import json
from pathlib import Path
from collections import defaultdict, deque

PROJECT_ROOT = Path(__file__).resolve().parent.parent

GRAPH_51 = PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json"
EPSS_DATA_51 = PROJECT_ROOT / "phase5" / "epss_data_51repo.json"
EPSS_LABELS = PROJECT_ROOT / "phase5" / "epss_labels_51repo.json"
OSV_CACHE = PROJECT_ROOT / ".osv_records_cache.json"


def main():
    print("=== Analyzing Temporal Split for EPSS Arms ===")
    with open(GRAPH_51, encoding="utf-8") as f:
        graph = json.load(f)
    with open(EPSS_DATA_51, encoding="utf-8") as f:
        epss_data = json.load(f)
    with open(EPSS_LABELS, encoding="utf-8") as f:
        labels = json.load(f)
    with open(OSV_CACHE, encoding="utf-8") as f:
        osv = json.load(f)

    # Adjacency
    deps_of = defaultdict(list)
    for e in graph["edges"]["dependsOn"]:
        deps_of[e["source"]].append(e["target"])
    vuln_cves = defaultdict(list)
    for e in graph["edges"]["hasVulnerability"]:
        vuln_cves[e["source"]].append(e["target"])
    pkg_feats = {n["id"]: n["features"] for n in graph["nodes"]["Package"]}

    # CVE published dates
    cve_dates = {}
    for c in graph["nodes"]["CVE"]:
        ghsa = c["id"]
        if ghsa in osv and osv[ghsa].get("published"):
            cve_dates[ghsa] = osv[ghsa]["published"][:10]

    # For each non-zero package, find all contributing CVEs with epss > 0
    cve_epss = {}
    for ghsa, info in epss_data.items():
        if info.get("in_cisa_kev"):
            cve_epss[ghsa] = 1.0
        else:
            s = info.get("epss_score")
            if s is None:
                c = info.get("cvss_score")
                s = (c / 100.0) if c else 0.0
            cve_epss[ghsa] = s

    pkg_newest_date = {}
    pkg_contributing_cves = {}

    for pid, ldata in labels.items():
        if ldata["epss_risk"] <= 0:
            continue
        # BFS up to depth 5
        visited = {pid: 0}
        q = deque([pid])
        contrib_cves = set()
        while q:
            cur = q.popleft()
            d = visited[cur]
            if cur in vuln_cves:
                for c in vuln_cves[cur]:
                    if cve_epss.get(c, 0.0) > 0:
                        contrib_cves.add(c)
            if d < 5:
                for nxt in deps_of.get(cur, ()):
                    if nxt not in visited and nxt in pkg_feats:
                        visited[nxt] = d + 1
                        q.append(nxt)

        dates = [cve_dates[c] for c in contrib_cves if c in cve_dates]
        if dates:
            pkg_newest_date[pid] = max(dates)
            pkg_contributing_cves[pid] = contrib_cves

    print(f"Total non-zero packages: {len(labels)} total -> {sum(1 for v in labels.values() if v['epss_risk']>0)} nz")
    print(f"Non-zero packages with resolved dates: {len(pkg_newest_date)}")

    all_dates = sorted(pkg_newest_date.values())
    n = len(all_dates)
    print(f"Newest-contributing-CVE date range: {all_dates[0]} to {all_dates[-1]}")
    print(f"Quartiles: Q1={all_dates[n//4]}, Q2={all_dates[n//2]}, Q3={all_dates[3*n//4]}")

    # Evaluate candidate cutoff dates to ensure test set >= 150 non-zero nodes
    for cutoff in ["2026-01-01", "2026-03-01", "2026-05-01", "2026-06-01", "2026-07-01", "2026-08-01"]:
        n_train = sum(1 for d in all_dates if d < cutoff)
        n_test = sum(1 for d in all_dates if d >= cutoff)
        print(f"  Cutoff {cutoff}: Train={n_train}, Test={n_test} (>=150 gate: {'PASS' if n_test >= 150 else 'FAIL'})")


if __name__ == "__main__":
    main()
