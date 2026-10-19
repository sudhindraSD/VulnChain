"""
gate_b1_nonzero_precheck.py — Phase 4 Gate B1 (WORKER_ORDERS_PHASE4.md Section 3.B1)

Converts the "~200+ expected non-zero VPSS in the test set" estimate into a
MEASURED number immediately after Step 2 (OSV extraction), BEFORE the expensive
Steps 3-4 (embeddings, author extraction) burn time.

Why this works at Step 2: VPSS zero/non-zero is purely STRUCTURAL. A package
has vpss > 0 iff at least one (vulnerable package, CVE) pair is reachable via
dependsOn BFS (self = depth 0). CVSS is always median-imputed > 0, and decay
(0.7^d) and exposure (>= 0.15) are strictly positive, so CVSS magnitude can
never turn a structurally-reachable vulnerability into a zero label.

MAL- records are excluded (merge policy drops them from CVE nodes).

Gate: test-set non-zero count >= 150 -> PASS (proceed to Steps 3-4).
      < 150 -> STOP AND REPORT (worker must not continue Phase B).

Usage:
    python gate_b1_nonzero_precheck.py
"""

import json
import sys
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # phase4/ -> project root
GRAPH = ROOT / "package_graph.json"
VULN_EDGES = ROOT / "hasVulnerability_edges.json"
SPLIT = ROOT / "phase4" / "repo_split_mapping_51repo.json"

GATE_THRESHOLD = 150


def bfs_reaches_vulnerable(pid, deps_of, vulnerable_pkgs):
    """True iff pid or any dependsOn-descendant is vulnerable (VPSS > 0)."""
    visited = {pid}
    queue = deque([pid])
    while queue:
        cur = queue.popleft()
        if cur in vulnerable_pkgs:
            return True
        for nxt in deps_of.get(cur, ()):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return False


def main():
    with open(GRAPH, encoding="utf-8") as f:
        graph = json.load(f)
    with open(VULN_EDGES, encoding="utf-8") as f:
        vuln_edges = json.load(f)
    with open(SPLIT, encoding="utf-8") as f:
        split = json.load(f)

    deps_of = defaultdict(list)
    for e in graph["edges"]:
        if e.get("type") == "dependsOn":
            deps_of[e["source"]].append(e["target"])

    vulnerable_pkgs = {e["source"] for e in vuln_edges
                       if not e["target"].startswith("MAL-")}
    any_mal_srcs = {e["source"] for e in vuln_edges if e["target"].startswith("MAL-")}

    print(f"packages in graph            : {len(graph['nodes']):,}")
    print(f"dependsOn edges              : {sum(len(v) for v in deps_of.values()):,}")
    print(f"packages with >=1 non-MAL CVE: {len(vulnerable_pkgs):,}")
    if any_mal_srcs:
        only_mal = any_mal_srcs - vulnerable_pkgs
        print(f"sources with any MAL edge    : {len(any_mal_srcs):,} "
              f"(of which only-MAL, fully excluded: {len(only_mal):,})")

    results = {}
    for name, key in (("test (saleor-storefront)", "test_pkg_ids"),
                      ("val (practica)", "val_pkg_ids")):
        ids = split[key]
        nonzero = [pid for pid in ids if bfs_reaches_vulnerable(pid, deps_of, vulnerable_pkgs)]
        results[key] = len(nonzero)
        print(f"\n{name}")
        print(f"  exclusive nodes          : {len(ids):,}")
        print(f"  non-zero VPSS (measured) : {len(nonzero):,}")
        print(f"  rate                     : {len(nonzero) / len(ids) * 100:.1f}%")

    total_nonzero = 0
    for node in graph["nodes"]:
        if bfs_reaches_vulnerable(node["id"], deps_of, vulnerable_pkgs):
            total_nonzero += 1
    print(f"\nwhole-graph non-zero VPSS    : {total_nonzero:,} / {len(graph['nodes']):,} "
          f"({total_nonzero / len(graph['nodes']) * 100:.1f}%)")

    test_count = results["test_pkg_ids"]
    print("\n" + "=" * 50)
    if test_count >= GATE_THRESHOLD:
        print(f"GATE B1: PASS ({test_count} >= {GATE_THRESHOLD}) -- proceed to Steps 3-4")
    else:
        print(f"GATE B1: FAIL ({test_count} < {GATE_THRESHOLD}) -- STOP AND REPORT")
        sys.exit(1)


if __name__ == "__main__":
    main()
