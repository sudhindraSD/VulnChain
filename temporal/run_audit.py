import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GRAPH_PATH = ROOT / "phase4" / "vulnchain_graph.json"
CACHE_PATH = ROOT / ".osv_records_cache.json"
SPLIT_PATH = ROOT / "phase4" / "repo_split_mapping_51repo.json"
VULNS_PATH = ROOT / "data_pipeline" / "osv_vulns.json"


def run_audit():
    with open(GRAPH_PATH, encoding="utf-8") as f:
        graph = json.load(f)
    with open(CACHE_PATH, encoding="utf-8") as f:
        osv_cache = json.load(f)
    with open(SPLIT_PATH, encoding="utf-8") as f:
        split_mapping = json.load(f)
    with open(VULNS_PATH, encoding="utf-8") as f:
        osv_vulns = json.load(f)

    # 1. Inspect 873 vuln IDs
    unique_vuln_ids = set()
    for vlist in osv_vulns.values():
        unique_vuln_ids.update(vlist)

    total_873 = len(unique_vuln_ids)
    in_cache = [vid for vid in unique_vuln_ids if vid in osv_cache]
    missing_cache = [vid for vid in unique_vuln_ids if vid not in osv_cache]
    no_published_cache = [
        vid
        for vid in unique_vuln_ids
        if vid in osv_cache and not osv_cache[vid].get("published")
    ]

    print("=== TASK 1: VULN ID AUDIT ===")
    print(f"Total unique vuln IDs in osv_vulns.json: {total_873}")
    print(f"Found in .osv_records_cache.json: {len(in_cache)}")
    print(f"Missing from .osv_records_cache.json: {len(missing_cache)}")
    print(
        f"Missing published date among cached records: {len(no_published_cache)}"
    )
    for m in missing_cache:
        print(f"  Missing ID: {m}")

    # Build full published date map (include the 2 MAL- IDs from OSV.dev schema)
    pub_dates = {}
    affected_ranges = {}
    for vid in in_cache:
        rec = osv_cache[vid]
        pub_dates[vid] = rec.get("published")[:10]
        affected_ranges[vid] = rec.get("affected", [])

    # The 2 MAL IDs have known upstream OSV published dates
    pub_dates["MAL-2022-5972"] = "2022-06-20"
    pub_dates["MAL-2023-462"] = "2023-04-27"

    # 2. Setup splits and graph
    pkg_nodes = {n["id"]: n for n in graph["nodes"]["Package"]}
    total_pkgs = len(pkg_nodes)
    splits = {
        "train": set(split_mapping["train_pkg_ids"]),
        "val": set(split_mapping["val_pkg_ids"]),
        "test": set(split_mapping["test_pkg_ids"]),
    }

    print("\n=== SPLIT SIZES ===")
    for s, pset in splits.items():
        print(f"  {s}: {len(pset)} ({len(pset)/total_pkgs*100:.2f}%)")

    # Direct hasVulnerability edges
    pkg_direct_cves = defaultdict(list)
    for e in graph["edges"]["hasVulnerability"]:
        pkg_direct_cves[e["source"]].append(e["target"])

    # Also check osv_vulns direct mapping (includes MAL-2022-5972 on scrypt-shim)
    # Both give identical results for post-T because both MAL- IDs are 2022/2023.

    cutoffs = ["2024-07-01", "2025-01-01", "2025-07-01"]

    print("\n=== TASK 2 & 3: DIRECT TEMPORAL LABELS ===")
    direct_results = {}
    for T in cutoffs:
        direct_results[T] = {}
        print(f"\n--- Cutoff T = {T} ---")
        for s_name in ["train", "val", "test"]:
            pset = splits[s_name]
            n_total = len(pset)
            pos_A = 0
            pos_B = 0
            pre_T = 0
            for pid in pset:
                cves = pkg_direct_cves.get(pid, [])
                dates = [pub_dates[c] for c in cves if c in pub_dates]
                has_post = any(d > T for d in dates)
                has_pre = any(d <= T for d in dates)
                if has_pre:
                    pre_T += 1
                if has_post:
                    pos_B += 1
                    if not has_pre:
                        pos_A += 1
            direct_results[T][s_name] = {
                "total": n_total,
                "label_A": pos_A,
                "label_B": pos_B,
                "pre_T": pre_T,
            }
            print(
                f"  {s_name:5} (N={n_total:5}): Label A = {pos_A:4} ({pos_A/n_total*100:.2f}%) | "
                f"Label B = {pos_B:4} ({pos_B/n_total*100:.2f}%) | "
                f"Pre-T = {pre_T:4} ({pre_T/n_total*100:.2f}%)"
            )

    # Transitive labels (via dependency graph)
    deps_of = defaultdict(list)
    for e in graph["edges"]["dependsOn"]:
        deps_of[e["source"]].append(e["target"])

    pkg_trans_cves = defaultdict(set)
    for pid in pkg_nodes:
        q = deque([pid])
        visited = {pid}
        while q:
            curr = q.popleft()
            if curr in pkg_direct_cves:
                pkg_trans_cves[pid].update(pkg_direct_cves[curr])
            for dep in deps_of.get(curr, []):
                if dep not in visited:
                    visited.add(dep)
                    q.append(dep)

    print("\n=== TRANSITIVE (SUPPLY CHAIN REACHABILITY) LABELS ===")
    trans_results = {}
    for T in cutoffs:
        trans_results[T] = {}
        print(f"\n--- Cutoff T = {T} ---")
        for s_name in ["train", "val", "test"]:
            pset = splits[s_name]
            n_total = len(pset)
            pos_A = 0
            pos_B = 0
            pre_T = 0
            for pid in pset:
                cves = pkg_trans_cves.get(pid, set())
                dates = [pub_dates[c] for c in cves if c in pub_dates]
                has_post = any(d > T for d in dates)
                has_pre = any(d <= T for d in dates)
                if has_pre:
                    pre_T += 1
                if has_post:
                    pos_B += 1
                    if not has_pre:
                        pos_A += 1
            trans_results[T][s_name] = {
                "total": n_total,
                "label_A": pos_A,
                "label_B": pos_B,
                "pre_T": pre_T,
            }
            print(
                f"  {s_name:5} (N={n_total:5}): Transitive Label A = {pos_A:4} ({pos_A/n_total*100:.2f}%) | "
                f"Label B = {pos_B:4} ({pos_B/n_total*100:.2f}%) | "
                f"Pre-T = {pre_T:4} ({pre_T/n_total*100:.2f}%)"
            )

    return direct_results, trans_results


if __name__ == "__main__":
    run_audit()
