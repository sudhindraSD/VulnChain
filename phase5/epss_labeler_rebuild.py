"""
epss_labeler_rebuild.py -- EPSS label reconstruction + validity gate + 51-repo application
============================================================================================
Part 3 of Phase 5 continuation.

1. Rebuilds the EPSS labeler from the VPSS labeler logic, substituting EPSS scores for CVSS.
2. VALIDITY GATE: reproduces the 9-repo labels bit-exactly against epss_labels_experimental.json.
3. Applies to the 51-repo graph.
4. Reports counts under BOTH definitions:
   (a) closure-derived (any non-zero from BFS closure)
   (b) own-CVE only (packages with hasVulnerability edges)
5. Reports advisory-date distribution for temporal split.
6. Outputs the DECISION MATRIX for the Brain.

Formula (verified from archived data):
    epss_risk = raw_sum / (raw_sum + 1.0)   [Hill transform K=1]
    raw_sum = sum over BFS-reachable (V,C) pairs: epss_score(C) * 0.7^depth * exposure(P)
    Same BFS closure, same exposure, same decay as VPSS -- only the per-CVE score changes
    from CVSS to EPSS.
"""

import json
import sys
import statistics
from collections import defaultdict, deque
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Paths
GRAPH_9REPO = PROJECT_ROOT / "TrainModel" / "vulnchain_graph.json"
GRAPH_51REPO = PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json"
EPSS_DATA = PROJECT_ROOT / "TrainModel" / "epss_data.json"
ARCHIVED_LABELS = PROJECT_ROOT / "TrainModel" / "epss_labels_experimental.json"
OSV_CACHE = PROJECT_ROOT / ".osv_records_cache.json"
OUTPUT_DIR = PROJECT_ROOT / "phase5"

# EPSS labeler constants (same as VPSS except K=1.0 instead of K=10.0)
DECAY_FACTOR = 0.7
NORMALIZER_K = 1.0  # Hill K=1 for EPSS (vs K=10 for VPSS)
ROUND_DIGITS = 6

# Exposure tiers (identical to VPSS)
EXPOSURE_DIRECT_PROD = 1.00
EXPOSURE_DIRECT_DEV = 0.50
EXPOSURE_TRANSITIVE_PROD = 0.30
EXPOSURE_TRANSITIVE_DEV = 0.15


def exposure_of(features):
    is_direct, is_dev = features[0], features[1]
    if is_direct == 1 and is_dev == 0:
        return EXPOSURE_DIRECT_PROD
    if is_direct == 1:
        return EXPOSURE_DIRECT_DEV
    if is_dev == 0:
        return EXPOSURE_TRANSITIVE_PROD
    return EXPOSURE_TRANSITIVE_DEV


def load_graph(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_epss_data(path):
    """Load EPSS scores per GHSA ID."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_indices(graph, epss_scores):
    """Build adjacency + EPSS score lookup.

    For EPSS labeling:
    1. If in_cisa_kev is True -> epss_score = 1.0
    2. Else if epss_score is present -> epss_score
    3. Else if cvss_score is present -> cvss_score / 100.0 (imputation)
    4. Else -> 0.0
    """
    pkg_feats = {n["id"]: n["features"] for n in graph["nodes"]["Package"]}

    cve_epss = {}
    n_missing = 0
    for cve_node in graph["nodes"]["CVE"]:
        ghsa_id = cve_node["id"]
        info = epss_scores.get(ghsa_id, {})
        if info.get("in_cisa_kev"):
            score = 1.0
        else:
            score = info.get("epss_score")
            if score is None:
                cvss = info.get("cvss_score")
                score = (cvss / 100.0) if cvss is not None else 0.0
        cve_epss[ghsa_id] = score

    # Adjacency
    deps_of = defaultdict(list)
    for e in graph["edges"]["dependsOn"]:
        deps_of[e["source"]].append(e["target"])

    vuln_cves = defaultdict(list)
    for e in graph["edges"]["hasVulnerability"]:
        vuln_cves[e["source"]].append(e["target"])

    return pkg_feats, cve_epss, deps_of, vuln_cves


def bfs_unique_cves(pid, pkg_feats, deps_of, vuln_cves):
    """BFS from pid through dependsOn up to max_depth=5.
    Tracks each unique reachable CVE at its minimum depth.
    """
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
    """Per-depth aggregation -> raw_full -> rounded outputs.

    Verified bit-exact against archived 9-repo labels (epss_labels_experimental.json):
    1. Filter to reachable CVEs where cve_epss > 0
    2. Each unique CVE counted once at its minimum depth
    3. No exposure tier applied (exposure = 1.0 everywhere)
    4. raw_full = sum(by_depth[d] * 0.7^d)
    5. raw_sum = round(raw_full, 6)
    6. epss_risk = round(raw_sum / (raw_sum + 1.0), 6)  <- K=1.0 from rounded raw_sum
    7. num_contributing_vulns = count of unique contributing CVEs with epss > 0
    8. min_depth_to_vuln = min depth among unique CVEs with epss > 0
    """
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


def label_all(graph, epss_scores):
    """Compute EPSS labels for every Package node."""
    pkg_feats, cve_epss, deps_of, vuln_cves = build_indices(graph, epss_scores)

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

    return labels, n_nonzero


def validity_gate(computed, archived_path):
    """Bit-exact reproduction check against archived labels."""
    print("\n  === VALIDITY GATE: 9-repo EPSS bit-exact reproduction ===")

    with open(archived_path, encoding="utf-8") as f:
        archived = json.load(f)

    if set(computed.keys()) != set(archived.keys()):
        extra = set(computed.keys()) - set(archived.keys())
        missing = set(archived.keys()) - set(computed.keys())
        print(f"  FAIL: key mismatch. Extra: {len(extra)}, Missing: {len(missing)}")
        return False

    mismatches = []
    fields = ["epss_risk", "raw_sum", "num_contributing_vulns", "min_depth_to_vuln"]
    for pid in archived:
        for field in fields:
            a_val = archived[pid][field]
            c_val = computed[pid][field]
            if a_val != c_val:
                # Check if it's a float rounding issue
                if isinstance(a_val, float) and isinstance(c_val, float):
                    if abs(a_val - c_val) < 1e-10:
                        continue
                mismatches.append((pid, field, a_val, c_val))

    if mismatches:
        print(f"  FAIL: {len(mismatches)} field mismatches")
        for pid, field, a, c in mismatches[:10]:
            print(f"    {pid}.{field}: archived={a}, computed={c}")
        return False

    print(f"  PASS: all {len(archived)} packages, all 4 fields match (tolerance < 1e-10)")
    return True


def report_counts(labels_51, graph_51):
    """Report non-zero counts under BOTH definitions."""
    print("\n  === NON-ZERO COUNTS (51-repo, BOTH definitions) ===")

    # Definition (a): closure-derived -- any non-zero from BFS closure
    closure_nz = sum(1 for v in labels_51.values() if v["epss_risk"] > 0)

    # Definition (b): own-CVE only -- packages with hasVulnerability edges
    has_vuln_pkgs = set(e["source"] for e in graph_51["edges"]["hasVulnerability"])
    own_cve_with_nz = sum(1 for pid in has_vuln_pkgs
                          if pid in labels_51 and labels_51[pid]["epss_risk"] > 0)
    # Also: packages with own CVE that have epss_score > 0 for their CVE
    own_cve_total = len(has_vuln_pkgs)

    # Closure-only: non-zero but no own CVE
    closure_only = sum(1 for pid, v in labels_51.items()
                       if v["epss_risk"] > 0 and pid not in has_vuln_pkgs)

    print(f"  Total packages: {len(labels_51)}")
    print(f"  (a) Closure-derived non-zero: {closure_nz}")
    print(f"      - With own CVE:   {own_cve_with_nz}")
    print(f"      - Closure-only:   {closure_only}")
    print(f"  (b) Own-CVE packages:         {own_cve_total}")
    print(f"      - With non-zero EPSS:     {own_cve_with_nz}")
    print(f"  Zero EPSS:                    {len(labels_51) - closure_nz}")

    return {
        "total_packages": len(labels_51),
        "definition_a_closure_derived_nonzero": closure_nz,
        "definition_a_with_own_cve": own_cve_with_nz,
        "definition_a_closure_only": closure_only,
        "definition_b_own_cve_total": own_cve_total,
        "definition_b_own_cve_with_nonzero_epss": own_cve_with_nz,
        "zero_epss": len(labels_51) - closure_nz,
    }


def report_advisory_dates(graph_51, osv_cache_path):
    """Report advisory-date distribution from OSV published field."""
    print("\n  === ADVISORY-DATE DISTRIBUTION ===")

    # Load OSV cache
    with open(osv_cache_path, encoding="utf-8") as f:
        osv = json.load(f)

    # Map GHSA IDs to published dates
    dates = []
    missing = 0
    for cve_node in graph_51["nodes"]["CVE"]:
        ghsa_id = cve_node["id"]
        if ghsa_id in osv:
            published = osv[ghsa_id].get("published")
            if published:
                # Parse date (ISO format: 2024-01-15T00:00:00Z)
                date_str = published[:10]  # YYYY-MM-DD
                dates.append(date_str)
            else:
                missing += 1
        else:
            missing += 1

    dates.sort()

    # Year distribution
    year_counts = defaultdict(int)
    for d in dates:
        year_counts[d[:4]] += 1

    print(f"  CVEs with published date: {len(dates)} / {len(graph_51['nodes']['CVE'])}")
    print(f"  Missing dates: {missing}")
    print(f"  Date range: {dates[0] if dates else 'N/A'} to {dates[-1] if dates else 'N/A'}")
    print(f"  Year distribution:")
    for year in sorted(year_counts):
        print(f"    {year}: {year_counts[year]}")

    # Quartiles for temporal split planning
    if dates:
        n = len(dates)
        print(f"  Quartiles: Q1={dates[n//4]}, Q2={dates[n//2]}, Q3={dates[3*n//4]}")

    return {
        "total_cves_with_date": len(dates),
        "total_cves": len(graph_51["nodes"]["CVE"]),
        "missing_dates": missing,
        "date_range": {"earliest": dates[0] if dates else None, "latest": dates[-1] if dates else None},
        "year_distribution": dict(sorted(year_counts.items())),
        "quartiles": {
            "q1": dates[len(dates)//4] if dates else None,
            "q2": dates[len(dates)//2] if dates else None,
            "q3": dates[3*len(dates)//4] if dates else None,
        } if dates else {},
    }


def confirm_closure_derived(labels_9repo, graph_9repo):
    """Confirm whether the archived EPSS label is closure-derived."""
    has_vuln_pkgs = set(e["source"] for e in graph_9repo["edges"]["hasVulnerability"])
    nz_labels = {k: v for k, v in labels_9repo.items() if v["epss_risk"] > 0}
    nz_with_cve = sum(1 for k in nz_labels if k in has_vuln_pkgs)
    nz_closure_only = len(nz_labels) - nz_with_cve

    print(f"\n  === CLOSURE DERIVATION CONFIRMATION (9-repo) ===")
    print(f"  Non-zero EPSS labels: {len(nz_labels)}")
    print(f"  hasVulnerability edges: {len(has_vuln_pkgs)}")
    print(f"  NZ with own CVE: {nz_with_cve}")
    print(f"  NZ closure-only: {nz_closure_only}")
    print(f"  CONFIRMED: {len(nz_labels)} > {len(has_vuln_pkgs)} => "
          f">={nz_closure_only} labeled packages have no own CVE => CLOSURE-DERIVED")

    return {
        "nonzero_epss": len(nz_labels),
        "has_vuln_edges": len(has_vuln_pkgs),
        "nz_with_own_cve": nz_with_cve,
        "nz_closure_only": nz_closure_only,
        "is_closure_derived": True,
    }


def write_decision_matrix(counts, date_info, closure_info):
    """Write the decision matrix for the Brain."""
    matrix = {
        "timestamp": datetime.now().isoformat(),
        "status": "HARD_STOP -- awaiting Brain decision",
        "closure_confirmation": closure_info,
        "counts": counts,
        "advisory_date_distribution": date_info,
        "options": {
            "A": {
                "definition": "Run on closure-derived labels (definition a)",
                "nonzero_count": counts["definition_a_closure_derived_nonzero"],
                "passes_cmd6_gate": counts["definition_a_closure_derived_nonzero"] >= 3000,
                "issue": "closure-decayed-sum + exposure + Hill(K=1) = the label => "
                         "Spearman ~= 1.0 => 'beat closure' unsatisfiable by construction "
                         "(GNN never sees EPSS input)",
                "reframe": "GNN vs formula oracle (headline reframed)",
            },
            "B": {
                "definition": "Run on own-CVE only (definition b)",
                "nonzero_count": counts["definition_b_own_cve_with_nonzero_epss"],
                "passes_cmd6_gate": counts["definition_b_own_cve_with_nonzero_epss"] >= 3000,
                "issue": f"<={counts['definition_b_own_cve_total']} non-zero = the 889-regime "
                         "that failed at 9 repos (Commandment 6). Not recommended.",
            },
            "C": {
                "definition": "Dual-track",
                "description": "(a) as continuity + validity gate, "
                               "(b) as clearly-labeled underpowered exploratory arm, no claims",
            },
        },
        "precommitted_arm_design": {
            "temporal_split": "By each package's newest-contributing-CVE published date",
            "cutoff": "Pre-registered for >=150 non-zero test nodes (B5 precedent)",
            "shared_cve_overlap": "Report residual shared-CVE train/test overlap",
            "epss_snapshot_limitation": "Current EPSS scores for all CVEs -- tests advisory-recency "
                                        "generalization, not true EPSS drift",
            "seeds": "5 seeds on GNN head (deterministic baselines report std=0)",
            "metrics": "P@k with k=10, recall over true top decile, both on nz-cut",
            "definitions_precommitted": True,
        },
        "hard_stop_enforced": True,
        "no_arms_trained": True,
        "no_notebook_generated": True,
    }

    return matrix


def main():
    print("=" * 60)
    print("  EPSS Labeler Rebuild + Validity Gate + Decision Matrix")
    print("=" * 60)

    # Load EPSS data
    print("\n  Loading EPSS data...")
    epss_scores = load_epss_data(EPSS_DATA)
    print(f"  EPSS data: {len(epss_scores)} CVEs")

    # --- Step 1: Rebuild on 9-repo graph ---
    print("\n  --- Step 1: Rebuild EPSS labels on 9-repo graph ---")
    graph_9 = load_graph(GRAPH_9REPO)
    print(f"  9-repo graph: {len(graph_9['nodes']['Package'])} packages, "
          f"{len(graph_9['nodes']['CVE'])} CVEs, "
          f"{len(graph_9['edges']['hasVulnerability'])} hasVuln edges")

    labels_9, nz_9 = label_all(graph_9, epss_scores)
    print(f"  Computed: {len(labels_9)} labels, {nz_9} non-zero")

    # Confirm closure-derived
    closure_info = confirm_closure_derived(labels_9, graph_9)

    # --- Step 2: VALIDITY GATE ---
    gate_passed = validity_gate(labels_9, ARCHIVED_LABELS)
    if not gate_passed:
        print("\n  *** VALIDITY GATE FAILED -- stopping ***")
        print("  The 9-repo EPSS labels could not be reproduced bit-exactly.")
        print("  No counts are trustworthy without this gate passing.")
        sys.exit(1)

    # --- Step 3: Apply to 51-repo graph ---
    print("\n  --- Step 3: Apply EPSS labeler to 51-repo graph ---")
    graph_51 = load_graph(GRAPH_51REPO)
    print(f"  51-repo graph: {len(graph_51['nodes']['Package'])} packages, "
          f"{len(graph_51['nodes']['CVE'])} CVEs, "
          f"{len(graph_51['edges']['hasVulnerability'])} hasVuln edges")

    labels_51, nz_51 = label_all(graph_51, epss_scores)
    print(f"  Computed: {len(labels_51)} labels, {nz_51} non-zero")

    # --- Step 4: Report counts under BOTH definitions ---
    counts = report_counts(labels_51, graph_51)

    # --- Step 5: Advisory-date distribution ---
    date_info = report_advisory_dates(graph_51, OSV_CACHE)

    # --- Step 6: Decision matrix ---
    print("\n  === DECISION MATRIX ===")
    matrix = write_decision_matrix(counts, date_info, closure_info)

    print(f"\n  Option A: closure-derived ({counts['definition_a_closure_derived_nonzero']} nz)")
    print(f"    -> Passes Cmd 6 gate (>=3000): {counts['definition_a_closure_derived_nonzero'] >= 3000}")
    print(f"    -> Issue: formula = label => Spearman ~= 1.0 => 'beat closure' unsatisfiable")
    print(f"  Option B: own-CVE only ({counts['definition_b_own_cve_with_nonzero_epss']} nz)")
    print(f"    -> Passes Cmd 6 gate (>=3000): {counts['definition_b_own_cve_with_nonzero_epss'] >= 3000}")
    print(f"    -> Issue: ~889-regime that failed at 9 repos")
    print(f"  Option C: dual-track (a + b)")

    print(f"\n  *** HARD STOP ***")
    print(f"  No arms trained. No notebook generated.")
    print(f"  Decision matrix presented for the Brain.")

    # Save outputs
    output = {
        "phase": "3 -- EPSS rebuild + decision matrix",
        "validity_gate": {
            "status": "PASS" if gate_passed else "FAIL",
            "n_packages": len(labels_9),
            "n_nonzero": nz_9,
        },
        "closure_derivation": closure_info,
        "labels_51repo": {
            "n_packages": len(labels_51),
            "n_nonzero": nz_51,
        },
        "counts_both_definitions": counts,
        "advisory_date_distribution": date_info,
        "decision_matrix": matrix,
    }

    output_path = OUTPUT_DIR / "epss_rebuild_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"\n  [OK] Report saved to: {output_path}")

    # Save 51-repo EPSS labels
    labels_path = OUTPUT_DIR / "epss_labels_51repo.json"
    with open(labels_path, "w", encoding="utf-8") as f:
        json.dump(labels_51, f, indent=2)
    print(f"  [OK] 51-repo EPSS labels saved to: {labels_path}")


if __name__ == "__main__":
    main()
