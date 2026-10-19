import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GRAPH_PATH = ROOT / "phase4" / "vulnchain_graph.json"
CACHE_PATH = ROOT / ".osv_records_cache.json"
OUT_GRAPH_PATH = ROOT / "temporal" / "pre_t_graph.json"

T = "2024-07-01"


def build_pre_t_graph():
    print("=" * 80)
    print(f"BUILDING PRE-T GRAPH (Cutoff T = {T})")
    print("=" * 80)

    with open(GRAPH_PATH, encoding="utf-8") as f:
        graph = json.load(f)
    with open(CACHE_PATH, encoding="utf-8") as f:
        osv = json.load(f)

    cve_dates = {
        cid: rec["published"][:10]
        for cid, rec in osv.items()
        if rec.get("published")
    }

    # Before stats
    orig_pkgs = graph["nodes"]["Package"]
    orig_cves = graph["nodes"]["CVE"]
    orig_auths = graph["nodes"]["Author"]
    orig_deps = graph["edges"]["dependsOn"]
    orig_hv = graph["edges"]["hasVulnerability"]
    orig_mb = graph["edges"]["maintainedBy"]
    orig_ib = graph["edges"]["introducedBy"]

    print("--- COUNTS BEFORE (Original 51-Repo Graph) ---")
    print(
        f"  Package nodes:         {len(orig_pkgs):6,d} (10-dim, dim 6 unmasked)"
    )
    print(f"  CVE nodes:             {len(orig_cves):6,d}")
    print(f"  Author nodes:          {len(orig_auths):6,d} (7-dim)")
    print(
        f"  Total nodes:          "
        f" {len(orig_pkgs) + len(orig_cves) + len(orig_auths):6,d}"
    )
    print(f"  dependsOn edges:       {len(orig_deps):6,d}")
    print(f"  hasVulnerability edges:{len(orig_hv):6,d}")
    print(f"  maintainedBy edges:    {len(orig_mb):6,d}")
    print(f"  introducedBy edges:    {len(orig_ib):6,d}")
    print(
        f"  Total edges:          "
        f" {len(orig_deps) + len(orig_hv) + len(orig_mb) + len(orig_ib):6,d}"
    )

    # Filter CVE nodes to pre-T
    pre_t_cves = [
        c
        for c in orig_cves
        if c["id"] in cve_dates and cve_dates[c["id"]] <= T
    ]
    pre_t_cve_ids = set(c["id"] for c in pre_t_cves)

    # Filter hasVulnerability edges
    pre_t_hv = [e for e in orig_hv if e["target"] in pre_t_cve_ids]
    pre_t_vuln_pkgs = set(e["source"] for e in pre_t_hv)

    # Filter introducedBy edges
    pre_t_ib = [e for e in orig_ib if e["source"] in pre_t_cve_ids]

    # Rebuild Package nodes:
    # Time-safe dims kept:
    # 0: is_direct_dependency
    # 1: is_dev_dependency
    # 2: out_degree
    # 3: depth_in_tree
    # 6: has_known_cve_history (rebuilt: 1 if in pre_t_vuln_pkgs else 0)
    # Non-time-safe dims zeroed: 4, 5, 7, 8, 9
    rebuilt_pkgs = []
    dim6_ones = 0
    for node in orig_pkgs:
        pid = node["id"]
        old_feats = node["features"]
        new_dim6 = 1 if pid in pre_t_vuln_pkgs else 0
        if new_dim6 == 1:
            dim6_ones += 1
        new_feats = [
            old_feats[0],  # is_direct
            old_feats[1],  # is_dev
            old_feats[2],  # out_degree
            old_feats[3],  # depth_in_tree
            0,  # version_recency_days (zeroed)
            0,  # versions_behind_latest (zeroed)
            new_dim6,  # has_known_cve_history (rebuilt from pre-T)
            0.0,  # weekly_downloads_log (zeroed)
            0,  # is_deprecated (zeroed)
            0,  # license_risk_flag (zeroed)
        ]
        rebuilt_pkgs.append({
            "id": pid,
            "type": "Package",
            "features": new_feats,
        })

    # Rebuild Author nodes:
    # Non-time-safe dims zeroed: 0 (account_age), 1 (total_maintained), 2 (cve_pkgs),
    # 3 (days_since_commit), 6 (reputation)
    # Time-safe dims: 4 (is_org), 5 (has_2fa)
    rebuilt_auths = []
    for node in orig_auths:
        old_feats = node["features"]
        new_feats = [
            0,  # account_age_days
            0,  # total_packages_maintained
            0,  # packages_with_known_cves
            0,  # days_since_last_commit
            old_feats[4],  # is_organization
            0,  # has_2fa
            0.0,  # reputation_score
        ]
        rebuilt_auths.append({
            "id": node["id"],
            "type": "Author",
            "features": new_feats,
        })

    # Keep all dependsOn and maintainedBy
    rebuilt_deps = orig_deps
    rebuilt_mb = orig_mb

    diff_cves = len(orig_cves) - len(pre_t_cves)
    diff_hv = len(orig_hv) - len(pre_t_hv)
    diff_ib = len(orig_ib) - len(pre_t_ib)
    total_nodes_after = len(rebuilt_pkgs) + len(pre_t_cves) + len(rebuilt_auths)
    total_edges_after = len(rebuilt_deps) + len(pre_t_hv) + len(rebuilt_mb) + len(pre_t_ib)

    print("\n--- COUNTS AFTER (Pre-T Graph at T = 2024-07-01) ---")
    print(f"  Package nodes:         {len(rebuilt_pkgs):6,d} (10-dim, dim 6 rebuilt = {dim6_ones} ones, 5 non-time-safe dims zeroed)")
    print(f"  CVE nodes:             {len(pre_t_cves):6,d} ({diff_cves} post-T CVEs dropped)")
    print(f"  Author nodes:          {len(rebuilt_auths):6,d} (7-dim, 5 non-time-safe dims zeroed)")
    print(f"  Total nodes:           {total_nodes_after:6,d}")
    print(f"  dependsOn edges:       {len(rebuilt_deps):6,d} (unchanged)")
    print(f"  hasVulnerability edges:{len(pre_t_hv):6,d} ({diff_hv} post-T edges dropped)")
    print(f"  maintainedBy edges:    {len(rebuilt_mb):6,d} (unchanged)")
    print(f"  introducedBy edges:    {len(pre_t_ib):6,d} ({diff_ib} post-T edges dropped)")
    print(f"  Total edges:           {total_edges_after:6,d}")

    out_graph = {
        "metadata": {
            "cutoff_date": T,
            "description": (
                "VulnChain pre-T frozen graph (only CVEs and edges published"
                " on/before 2024-07-01)"
            ),
            "node_counts": {
                "Package": len(rebuilt_pkgs),
                "CVE": len(pre_t_cves),
                "Author": len(rebuilt_auths),
            },
            "edge_counts": {
                "dependsOn": len(rebuilt_deps),
                "hasVulnerability": len(pre_t_hv),
                "maintainedBy": len(rebuilt_mb),
                "introducedBy": len(pre_t_ib),
            },
        },
        "nodes": {
            "Package": rebuilt_pkgs,
            "CVE": pre_t_cves,
            "Author": rebuilt_auths,
        },
        "edges": {
            "dependsOn": rebuilt_deps,
            "hasVulnerability": pre_t_hv,
            "maintainedBy": rebuilt_mb,
            "introducedBy": pre_t_ib,
        },
    }

    with open(OUT_GRAPH_PATH, "w", encoding="utf-8") as f:
        json.dump(out_graph, f)
    print(
        f"\n[OK] Successfully saved pre-T graph to {OUT_GRAPH_PATH} "
        f"({OUT_GRAPH_PATH.stat().st_size / 1024 / 1024:.2f} MB)"
    )


if __name__ == "__main__":
    build_pre_t_graph()
