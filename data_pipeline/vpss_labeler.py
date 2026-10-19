"""
VulnChain VPSS Labeler (reconstructed)
---------------------------------------
Computes the Vulnerability Propagation Severity Score (VPSS) for every
Package node in the merged heterogeneous graph, producing the training
labels for VulnGAT.

RECONSTRUCTION NOTE (2026-11):
    The original vpss_labeler.py was accidentally lost. This file is a
    bit-exact reconstruction, reverse-engineered from the data itself and
    verified against the existing TrainModel/vpss_labels.json on the 9-repo
    graph: 5,578 / 5,578 packages reproduce ALL four fields exactly
    (vpss, raw_sum, num_contributing_vulns, min_depth_to_vuln).

Formula (verified bit-exact):
    For each Package P, BFS outward through dependsOn edges
    (source = dependent, target = dependency). For every vulnerable
    package V reachable at shortest-path depth d (P itself = depth 0),
    every CVE C attached to V contributes:

        contribution(C, V, d) = CVSS(C) * 0.7^d * exposure(P)

    Crucially, contributions are aggregated PER DEPTH LEVEL first, then
    scaled (this exact accumulation order is what makes the floats
    bit-identical to the original):

        level_sum(d)  = sum of CVSS(C) over all (V, C) at depth d
        raw_full      = sum over d of: level_sum(d) * 0.7^d * exposure(P)

    exposure(P) is derived from P's OWN feature vector (dims 0/1):
        direct + prod  -> 1.00
        direct + dev   -> 0.50
        transitive+prod-> 0.30
        transitive+dev -> 0.15

    Normalization (K = 10.0):
        vpss     = round(raw_full / (raw_full + 10.0), 6)   <- from FULL raw
        raw_sum  = round(raw_full, 6)                       <- rounded separately

    NOTE: vpss is computed from the UNROUNDED raw_full. Rounding raw_sum
    first and then normalizing produces off-by-1e-6 drift on boundary
    cases (e.g. test-exclude@1.1.0).

    num_contributing_vulns = number of (V, C) pairs (NOT deduped by CVE).
    min_depth_to_vuln      = min depth d over all pairs, else null.
    CVSS null              -> median-imputed, computed FRESH from the current
                              graph's CVE pool each run (matches merge_graph.py
                              STEP 5c convention; no stale constants). On the
                              9-repo graph this never fires because merge_graph
                              imputes upstream. Path empirically verified
                              2026-09-14 via null-injection tests: single-null
                              -> imputed 7.5 (live median), 76-null shifted
                              pool -> imputed 6.9, hand-recomputed labels exact.

Stdlib only -- no pip install required.

Usage:
    python vpss_labeler.py                    # write labels (default paths)
    python vpss_labeler.py --verify           # cross-check vs existing labels
    python vpss_labeler.py --graph G --out L  # custom paths
"""

import argparse
import json
import statistics
import sys
from collections import defaultdict, deque
from pathlib import Path

# ---------------------------------------------------------------------------
# CONFIG -- adjust these two paths if needed
# ---------------------------------------------------------------------------
DEFAULT_GRAPH = Path(r"C:\Users\Admin\Desktop\Major VulnChain\TrainModel\vulnchain_graph.json")
DEFAULT_OUT = Path(r"C:\Users\Admin\Desktop\Major VulnChain\TrainModel\vpss_labels.json")

# --- VPSS hyperparameters (locked -- changing these invalidates all labels) ---
DECAY_FACTOR = 0.7          # per-depth attenuation of CVSS mass
NORMALIZER = 10.0           # K in vpss = raw / (raw + K)
ROUND_DIGITS = 6            # storage precision

# CVSS null handling: median-impute, matching merge_graph.py STEP 5c
# (pipeline convention). On the 9-repo graph this never fires because
# merge_graph imputes upstream before the labeler runs.
CVSS_IMPUTE_STRATEGY = "median"   # "median" (pipeline convention) or a float

# exposure tiers, keyed off Package feature dims [0]=is_direct, [1]=is_dev
EXPOSURE_DIRECT_PROD = 1.00
EXPOSURE_DIRECT_DEV = 0.50
EXPOSURE_TRANSITIVE_PROD = 0.30
EXPOSURE_TRANSITIVE_DEV = 0.15


def exposure_of(features):
    """Exposure multiplier from the labeled package's OWN feature vector."""
    is_direct, is_dev = features[0], features[1]
    if is_direct == 1 and is_dev == 0:
        return EXPOSURE_DIRECT_PROD
    if is_direct == 1:
        return EXPOSURE_DIRECT_DEV
    if is_dev == 0:
        return EXPOSURE_TRANSITIVE_PROD
    return EXPOSURE_TRANSITIVE_DEV


def load_graph(graph_path):
    with open(graph_path, encoding="utf-8") as f:
        return json.load(f)


def build_indices(graph):
    """Adjacency + vulnerability lookups, preserving edge-file order."""
    pkg_feats = {n["id"]: n["features"] for n in graph["nodes"]["Package"]}

    # CVSS lookup with median imputation for nulls (merge_graph.py STEP 5c
    # convention). If merge_graph already imputed, this is a no-op.
    known = [n["cvss_score"] for n in graph["nodes"]["CVE"]
             if n.get("cvss_score") is not None]
    if not known:
        sys.exit("no CVE has a parseable cvss_score -- cannot median-impute")
    if isinstance(CVSS_IMPUTE_STRATEGY, str):
        imputed_value = round(statistics.median(known), 1)  # same rounding as merge_graph
    else:
        imputed_value = float(CVSS_IMPUTE_STRATEGY)

    cve_cvss = {}
    n_imputed = 0
    for n in graph["nodes"]["CVE"]:
        cvss = n.get("cvss_score")
        if cvss is None:
            cve_cvss[n["id"]] = imputed_value
            n_imputed += 1
        else:
            cve_cvss[n["id"]] = cvss
    if n_imputed:
        print(f"  WARNING: {n_imputed} CVEs had null cvss_score -> imputed {imputed_value} "
              f"(median computed fresh from this graph's CVE pool; "
              f"merge_graph.py normally imputes upstream)",
              file=sys.stderr)

    deps_of = defaultdict(list)      # source (dependent) -> [targets]
    for e in graph["edges"]["dependsOn"]:
        deps_of[e["source"]].append(e["target"])

    vuln_cves = defaultdict(list)    # vulnerable pkg -> [cve ids]
    for e in graph["edges"]["hasVulnerability"]:
        vuln_cves[e["source"]].append(e["target"])

    return pkg_feats, cve_cvss, deps_of, vuln_cves


def bfs_contributions(pid, pkg_feats, deps_of, vuln_cves):
    """BFS from pid through dependsOn; yield (cvss, depth) per (V, C) pair.

    Visited-set semantics: a package already reached at a shallower depth
    is never re-expanded, so each (V, C) pair is counted exactly once at
    its shortest-path depth.
    """
    visited = {pid: 0}
    queue = deque([pid])
    contribs = []
    while queue:
        cur = queue.popleft()
        d = visited[cur]
        if cur in vuln_cves:
            for cve in vuln_cves[cur]:
                contribs.append((cve, d))
        for nxt in deps_of.get(cur, ()):
            if nxt not in visited and nxt in pkg_feats:
                visited[nxt] = d + 1
                queue.append(nxt)
    return contribs


def compute_vpss(contribs, cve_cvss, exposure):
    """Per-depth aggregation -> raw_full -> rounded outputs.

    Accumulation order is bit-significant; do not 'simplify' it:
      1. level_sum(d) = sum of CVSS over pairs at depth d
      2. raw_full    += level_sum(d) * 0.7^d * exposure   (per depth, ascending)
      3. raw_sum     = round(raw_full, 6)
      4. vpss        = round(raw_full / (raw_full + K), 6)  <- from FULL raw
    """
    by_depth = defaultdict(float)
    for cve, d in contribs:
        by_depth[d] += cve_cvss[cve]

    raw_full = 0.0
    for d in sorted(by_depth):
        raw_full += by_depth[d] * (DECAY_FACTOR ** d) * exposure

    raw_sum = round(raw_full, ROUND_DIGITS)
    vpss = round(raw_full / (raw_full + NORMALIZER), ROUND_DIGITS) if raw_full > 0 else 0.0
    return vpss, raw_sum


def label_all(graph):
    """Compute VPSS labels for every Package node. Returns (labels, stats)."""
    pkg_feats, cve_cvss, deps_of, vuln_cves = build_indices(graph)

    labels = {}
    n_vulnerable = 0
    for pid, feats in pkg_feats.items():
        exposure = exposure_of(feats)
        contribs = bfs_contributions(pid, pkg_feats, deps_of, vuln_cves)

        if contribs:
            n_vulnerable += 1
            vpss, raw_sum = compute_vpss(contribs, cve_cvss, exposure)
            min_depth = min(d for _, d in contribs)
        else:
            vpss, raw_sum, min_depth = 0.0, 0.0, None

        labels[pid] = {
            "vpss": vpss,
            "raw_sum": raw_sum,
            "num_contributing_vulns": len(contribs),
            "min_depth_to_vuln": min_depth,
        }

    stats = {
        "total_packages": len(pkg_feats),
        "vulnerable_reach": n_vulnerable,
        "clean_reach": len(pkg_feats) - n_vulnerable,
    }
    return labels, stats


def verify(labels, existing_path):
    """Field-by-field diff against a previously generated labels file."""
    with open(existing_path, encoding="utf-8") as f:
        existing = json.load(f)

    fields = ("vpss", "raw_sum", "num_contributing_vulns", "min_depth_to_vuln")
    mismatches = {k: [] for k in fields}
    only_new = set(labels) - set(existing)
    only_old = set(existing) - set(labels)

    for pid, new in labels.items():
        if pid not in existing:
            continue
        old = existing[pid]
        for k in fields:
            if new[k] != old[k]:
                mismatches[k].append(pid)

    total_bad = set().union(*(v for v in mismatches.values())) if any(mismatches.values()) else set()
    print(f"verify vs {existing_path}")
    print(f"  packages compared : {len(labels) - len(only_new)}")
    print(f"  only in new file  : {len(only_new)}")
    print(f"  only in old file  : {len(only_old)}")
    for k in fields:
        print(f"  {k:>22} mismatches: {len(mismatches[k])}"
              + (f"  {mismatches[k][:5]}" if mismatches[k] else ""))
    print(f"  {'TOTAL ANY-FIELD mismatches':>25}: {len(total_bad)}")
    return len(total_bad) == 0 and not only_new and not only_old


def main():
    ap = argparse.ArgumentParser(description="VulnChain VPSS labeler (bit-exact reconstruction)")
    ap.add_argument("--graph", type=Path, default=DEFAULT_GRAPH, help="merged graph JSON")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output labels JSON")
    ap.add_argument("--verify", type=Path, nargs="?", const=DEFAULT_OUT, default=None,
                    help="cross-check output against existing labels file "
                         "(defaults to --out path if a path is not given)")
    args = ap.parse_args()

    if not args.graph.exists():
        sys.exit(f"graph not found: {args.graph}")

    print(f"loading graph: {args.graph}")
    graph = load_graph(args.graph)
    n_pkg = len(graph["nodes"]["Package"])
    n_cve = len(graph["nodes"]["CVE"])
    n_dep = len(graph["edges"]["dependsOn"])
    n_vuln = len(graph["edges"]["hasVulnerability"])
    print(f"  {n_pkg} packages, {n_cve} CVEs, {n_dep} dependsOn, {n_vuln} hasVulnerability edges")

    labels, stats = label_all(graph)
    print(f"labeled {stats['total_packages']} packages "
          f"({stats['vulnerable_reach']} with reachable vulns, "
          f"{stats['clean_reach']} clean)")

    if args.verify is not None:
        if not args.verify.exists():
            sys.exit(f"verify target not found: {args.verify}")
        ok = verify(labels, args.verify)
        if not ok:
            sys.exit("VERIFICATION FAILED -- labels not written")
        print("VERIFICATION PASSED -- bit-exact; no files written (--verify is read-only)")
        return  # read-only mode: never write when verifying

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
