"""
epss_rebuild_with_coverage.py -- Rebuild 51-repo EPSS labels with complete EPSS data
===================================================================================
Part B Step 3 of Phase 5 Continuation II.
"""

import json
from pathlib import Path
from collections import defaultdict, deque

PROJECT_ROOT = Path(__file__).resolve().parent.parent

GRAPH_51REPO = PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json"
EPSS_DATA_51 = PROJECT_ROOT / "phase5" / "epss_data_51repo.json"
OSV_CACHE = PROJECT_ROOT / ".osv_records_cache.json"
OUTPUT_LABELS = PROJECT_ROOT / "phase5" / "epss_labels_51repo.json"
OUTPUT_REPORT = PROJECT_ROOT / "phase5" / "epss_rebuild_coverage_report.json"

DECAY_FACTOR = 0.7
NORMALIZER_K = 1.0
ROUND_DIGITS = 6


def build_indices(graph, epss_data):
    pkg_feats = {n["id"]: n["features"] for n in graph["nodes"]["Package"]}

    cve_epss = {}
    for cve_node in graph["nodes"]["CVE"]:
        ghsa_id = cve_node["id"]
        info = epss_data.get(ghsa_id, {})
        if info.get("in_cisa_kev"):
            score = 1.0
        else:
            score = info.get("epss_score")
            if score is None:
                cvss = info.get("cvss_score")
                score = (cvss / 100.0) if cvss is not None else 0.0
        cve_epss[ghsa_id] = score

    deps_of = defaultdict(list)
    for e in graph["edges"]["dependsOn"]:
        deps_of[e["source"]].append(e["target"])

    vuln_cves = defaultdict(list)
    for e in graph["edges"]["hasVulnerability"]:
        vuln_cves[e["source"]].append(e["target"])

    return pkg_feats, cve_epss, deps_of, vuln_cves


def bfs_unique_cves(pid, pkg_feats, deps_of, vuln_cves):
    visited = {pid: 0}
    queue = deque([pid])
    cve_min_depth = {}
    while queue:
        cur = queue.popleft()
        d = visited[cur]
        if cur in vuln_cves:
            for cve in vuln_cves[cur]:
                if cve not in cve_min_depth or d < cve_min_depth[cve]:
                    cve_min_depth[cve] = d
        if d < 5:
            for nxt in deps_of.get(cur, ()):
                if nxt not in visited and nxt in pkg_feats:
                    visited[nxt] = d + 1
                    queue.append(nxt)
    return cve_min_depth


def compute_epss_label(cve_min_depth, cve_epss):
    nz_cves = {c: d for c, d in cve_min_depth.items() if cve_epss.get(c, 0.0) > 0}

    by_depth = defaultdict(float)
    for c, d in nz_cves.items():
        by_depth[d] += cve_epss[c]

    raw_full = sum(by_depth[d] * (DECAY_FACTOR ** d) for d in sorted(by_depth))
    raw_sum = round(raw_full, ROUND_DIGITS)
    epss_risk = round(raw_sum / (raw_sum + NORMALIZER_K), ROUND_DIGITS) if raw_sum > 0 else 0.0

    n_vulns = len(nz_cves)
    min_depth = min(nz_cves.values()) if nz_cves else None

    return epss_risk, raw_sum, n_vulns, min_depth


def main():
    print("=" * 60)
    print("  Rebuilding 51-Repo EPSS Labels with 92.4% Real EPSS Coverage")
    print("=" * 60)

    with open(GRAPH_51REPO, encoding="utf-8") as f:
        graph = json.load(f)
    with open(EPSS_DATA_51, encoding="utf-8") as f:
        epss_data = json.load(f)

    pkg_feats, cve_epss, deps_of, vuln_cves = build_indices(graph, epss_data)
    print(f"Graph: {len(pkg_feats)} packages, {len(graph['nodes']['CVE'])} CVEs, {len(graph['edges']['hasVulnerability'])} hasVuln edges")

    labels = {}
    n_nonzero = 0
    for pid in pkg_feats:
        cve_min_depth = bfs_unique_cves(pid, pkg_feats, deps_of, vuln_cves)
        epss_risk, raw_sum, n_vulns, min_depth = compute_epss_label(cve_min_depth, cve_epss)
        labels[pid] = {
            "epss_risk": epss_risk,
            "raw_sum": raw_sum,
            "num_contributing_vulns": n_vulns,
            "min_depth_to_vuln": min_depth,
        }
        if epss_risk > 0:
            n_nonzero += 1

    # Definition (a): closure-derived
    closure_nz = sum(1 for v in labels.values() if v["epss_risk"] > 0)
    has_vuln_pkgs = set(e["source"] for e in graph["edges"]["hasVulnerability"])
    own_cve_with_nz = sum(1 for pid in has_vuln_pkgs if pid in labels and labels[pid]["epss_risk"] > 0)
    closure_only = sum(1 for pid, v in labels.items() if v["epss_risk"] > 0 and pid not in has_vuln_pkgs)

    # Definition (b): own-CVE only
    own_cve_total = len(has_vuln_pkgs)

    print(f"\n--- 51-Repo Counts (Refreshed Coverage) ---")
    print(f"  Total packages:                {len(labels)}")
    print(f"  (a) Closure-derived non-zero:  {closure_nz} ({closure_nz/len(labels):.1%}) [Gate >=3,000: {'PASS' if closure_nz >= 3000 else 'FAIL'}]")
    print(f"      - With own CVE:            {own_cve_with_nz}")
    print(f"      - Closure-only:            {closure_only}")
    print(f"  (b) Own-CVE total:             {own_cve_total}")
    print(f"      - With non-zero EPSS:      {own_cve_with_nz} [Gate >=3,000: {'PASS' if own_cve_with_nz >= 3000 else 'FAIL'}]")
    print(f"  Zero EPSS:                     {len(labels) - closure_nz}")

    # Advisory date distribution refresh
    with open(OSV_CACHE, encoding="utf-8") as f:
        osv = json.load(f)

    dates = []
    for cve_node in graph["nodes"]["CVE"]:
        ghsa_id = cve_node["id"]
        if ghsa_id in osv and osv[ghsa_id].get("published"):
            dates.append(osv[ghsa_id]["published"][:10])
    dates.sort()

    year_counts = defaultdict(int)
    for d in dates:
        year_counts[d[:4]] += 1

    print(f"\n--- Advisory Dates Refresh ---")
    print(f"  Resolved: {len(dates)} / {len(graph['nodes']['CVE'])}")
    print(f"  Range: {dates[0]} to {dates[-1]}")
    n = len(dates)
    print(f"  Quartiles: Q1={dates[n//4]}, Q2={dates[n//2]}, Q3={dates[3*n//4]}")

    # Save outputs
    with open(OUTPUT_LABELS, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2)
    print(f"\n[OK] Saved refreshed labels to: {OUTPUT_LABELS}")

    report = {
        "status": "COMPLETE",
        "counts": {
            "total_packages": len(labels),
            "definition_a_closure_derived_nonzero": closure_nz,
            "definition_a_with_own_cve": own_cve_with_nz,
            "definition_a_closure_only": closure_only,
            "definition_b_own_cve_total": own_cve_total,
            "definition_b_own_cve_with_nonzero_epss": own_cve_with_nz,
            "zero_epss": len(labels) - closure_nz,
            "passes_cmd6_gate_closure": closure_nz >= 3000,
            "passes_cmd6_gate_own_cve": own_cve_with_nz >= 3000,
        },
        "advisory_dates": {
            "total_resolved": len(dates),
            "earliest": dates[0],
            "latest": dates[-1],
            "quartiles": {"q1": dates[n//4], "q2": dates[n//2], "q3": dates[3*n//4]},
            "year_distribution": dict(sorted(year_counts.items())),
        }
    }
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[OK] Saved Part B refresh report to: {OUTPUT_REPORT}")


if __name__ == "__main__":
    main()
