"""
VulnChain Graph Merge Script
-----------------------------
Merges all 3 node types (Package, CVE, Author) and all 4 edge types
(dependsOn, hasVulnerability, maintainedBy, introducedBy) into a single
heterogeneous graph file: vulnchain_graph.json

Steps:
  1. Load all source files
  2. Merge Package nodes (original + supplementary)
  3. Drop dangling edges (MAL- prefixed, any remaining orphans)
  4. Backfill has_known_cve_history (dim 6) from hasVulnerability edges
  5. Median imputation for null/sentinel features
  6. Convert Author features from dict to ordered array
  7. Write final merged graph with metadata
  8. Run validation checks

Author feature order (7-dim, locked per VULNCHAIN_DESIGN_v1.0.md):
  0: account_age_days
  1: total_packages_maintained
  2: packages_with_known_cves
  3: days_since_last_commit
  4: is_organization
  5: has_2fa
  6: reputation_score
"""

import json
import statistics
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
BASE = Path(r"C:\Users\Admin\Desktop\Major VulnChain")
# Phase 4: 51-repo merged graph must not touch the 9-repo artifact in TrainModel/
OUTPUT = BASE / "phase4" / "vulnchain_graph.json"

# Source files
PACKAGE_GRAPH = BASE / "package_graph.json"
SUPPLEMENT = BASE / "supplement_packages.json"
CVE_NODES = BASE / "cve_nodes_embedded.json"
AUTHOR_NODES = BASE / "author_nodes.json"
HV_EDGES = BASE / "hasVulnerability_edges.json"
MB_EDGES = BASE / "maintainedBy_edges.json"
IB_EDGES = BASE / "introducedBy_edges.json"

# Locked feature orders
AUTHOR_FEATURE_ORDER = [
    "account_age_days",
    "total_packages_maintained",
    "packages_with_known_cves",
    "days_since_last_commit",
    "is_organization",
    "has_2fa",
    "reputation_score",
]

PACKAGE_FEATURE_ORDER = [
    "is_direct_dependency",
    "is_dev_dependency",
    "out_degree",
    "depth_in_tree",
    "version_recency_days",
    "versions_behind_latest",
    "has_known_cve_history",
    "weekly_downloads_log",
    "is_deprecated",
    "license_risk_flag",
]


# ---------------------------------------------------------------------------
# STEP 1: Load all source files
# ---------------------------------------------------------------------------
def load_all():
    print("=" * 60)
    print("STEP 1: Loading source files")
    print("=" * 60)

    with open(PACKAGE_GRAPH) as f:
        pg = json.load(f)
    print(f"  package_graph.json: {len(pg['nodes'])} nodes, {len(pg['edges'])} edges")

    if SUPPLEMENT.exists():
        with open(SUPPLEMENT) as f:
            supplement = json.load(f)
    else:
        supplement = []  # Phase 4: 51-repo extraction is complete, no supplement pass needed
    print(f"  supplement_packages.json: {len(supplement)} nodes")

    with open(CVE_NODES) as f:
        cve_nodes = json.load(f)
    print(f"  cve_nodes_embedded.json: {len(cve_nodes)} nodes")

    with open(AUTHOR_NODES) as f:
        author_nodes = json.load(f)
    print(f"  author_nodes.json: {len(author_nodes)} nodes")

    with open(HV_EDGES) as f:
        hv_edges = json.load(f)
    print(f"  hasVulnerability_edges.json: {len(hv_edges)} edges")

    with open(MB_EDGES) as f:
        mb_edges = json.load(f)
    print(f"  maintainedBy_edges.json: {len(mb_edges)} edges")

    with open(IB_EDGES) as f:
        ib_edges = json.load(f)
    print(f"  introducedBy_edges.json: {len(ib_edges)} edges")

    return pg, supplement, cve_nodes, author_nodes, hv_edges, mb_edges, ib_edges


# ---------------------------------------------------------------------------
# STEP 2: Merge Package nodes
# ---------------------------------------------------------------------------
def merge_package_nodes(pg, supplement):
    print("\n" + "=" * 60)
    print("STEP 2: Merging Package nodes")
    print("=" * 60)

    pkg_nodes = {n["id"]: n for n in pg["nodes"]}
    dep_edges = pg["edges"]

    # Add supplement nodes (these should NOT overlap with existing)
    overlap = 0
    for sn in supplement:
        if sn["id"] in pkg_nodes:
            overlap += 1
        else:
            pkg_nodes[sn["id"]] = sn

    print(f"  Original: {len(pg['nodes'])}")
    print(f"  Supplement: {len(supplement)} (overlap: {overlap})")
    print(f"  Merged: {len(pkg_nodes)}")

    return pkg_nodes, dep_edges


# ---------------------------------------------------------------------------
# STEP 3: Drop dangling edges
# ---------------------------------------------------------------------------
def drop_dangling_edges(pkg_ids, cve_ids, author_ids, dep_edges, hv_edges, mb_edges, ib_edges):
    print("\n" + "=" * 60)
    print("STEP 3: Dropping dangling edges")
    print("=" * 60)

    drop_log = {
        "dependsOn": {"count": 0, "ids": set()},
        "hasVulnerability": {"count": 0, "ids": set()},
        "maintainedBy": {"count": 0, "ids": set()},
        "introducedBy": {"count": 0, "ids": set()},
    }

    # dependsOn: Package -> Package
    clean_dep = []
    for e in dep_edges:
        if e["source"] in pkg_ids and e["target"] in pkg_ids:
            clean_dep.append(e)
        else:
            drop_log["dependsOn"]["count"] += 1
            if e["source"] not in pkg_ids:
                drop_log["dependsOn"]["ids"].add(f"src:{e['source']}")
            if e["target"] not in pkg_ids:
                drop_log["dependsOn"]["ids"].add(f"tgt:{e['target']}")

    # hasVulnerability: Package -> CVE
    clean_hv = []
    for e in hv_edges:
        if e["source"] in pkg_ids and e["target"] in cve_ids:
            clean_hv.append(e)
        else:
            drop_log["hasVulnerability"]["count"] += 1
            if e["target"] not in cve_ids:
                drop_log["hasVulnerability"]["ids"].add(e["target"])

    # maintainedBy: Package -> Author
    clean_mb = []
    for e in mb_edges:
        if e["source"] in pkg_ids and e["target"] in author_ids:
            clean_mb.append(e)
        else:
            drop_log["maintainedBy"]["count"] += 1

    # introducedBy: CVE -> Author
    clean_ib = []
    for e in ib_edges:
        if e["source"] in cve_ids and e["target"] in author_ids:
            clean_ib.append(e)
        else:
            drop_log["introducedBy"]["count"] += 1
            if e["source"] not in cve_ids:
                drop_log["introducedBy"]["ids"].add(e["source"])

    for edge_type, info in drop_log.items():
        count = info["count"]
        ids = info["ids"]
        if count > 0:
            print(f"  {edge_type}: dropped {count} edges")
            if ids:
                # Show first 10 dangling IDs
                sample = sorted(ids)[:10]
                print(f"    dangling IDs: {sample}{'...' if len(ids) > 10 else ''}")
        else:
            print(f"  {edge_type}: 0 dropped (clean)")

    total_dropped = sum(v["count"] for v in drop_log.values())
    print(f"  TOTAL dropped: {total_dropped}")

    return clean_dep, clean_hv, clean_mb, clean_ib, drop_log


# ---------------------------------------------------------------------------
# STEP 4: Backfill has_known_cve_history
# ---------------------------------------------------------------------------
def backfill_cve_history(pkg_nodes, hv_edges):
    print("\n" + "=" * 60)
    print("STEP 4: Backfilling has_known_cve_history (feature dim 6)")
    print("=" * 60)

    # Find all Package IDs that have at least one hasVulnerability edge
    vuln_pkg_ids = set(e["source"] for e in hv_edges)

    count = 0
    for node_id, node in pkg_nodes.items():
        if node_id in vuln_pkg_ids:
            node["features"][6] = 1
            count += 1

    print(f"  Packages with has_known_cve_history=1: {count}")
    print(f"  Packages with has_known_cve_history=0: {len(pkg_nodes) - count}")

    return pkg_nodes


# ---------------------------------------------------------------------------
# STEP 5: Median imputation
# ---------------------------------------------------------------------------
def median_impute_packages(pkg_nodes):
    print("\n" + "=" * 60)
    print("STEP 5a: Median imputation — Package features")
    print("=" * 60)

    # Feature indices that use -1 as sentinel
    sentinel_features = {
        4: "version_recency_days",
        5: "versions_behind_latest",
    }

    for idx, name in sentinel_features.items():
        # Collect known values (not -1)
        known = [n["features"][idx] for n in pkg_nodes.values() if n["features"][idx] != -1]
        if not known:
            print(f"  {name}: no known values, skipping")
            continue

        med = statistics.median(known)
        med_rounded = round(med)  # These are integer-valued features

        # Replace sentinels
        replaced = 0
        for n in pkg_nodes.values():
            if n["features"][idx] == -1:
                n["features"][idx] = med_rounded
                replaced += 1

        print(f"  {name}: median={med_rounded}, replaced {replaced} sentinels")

    return pkg_nodes


def median_impute_authors(author_nodes):
    print("\n" + "=" * 60)
    print("STEP 5b: Median imputation — Author features")
    print("=" * 60)

    null_features = ["account_age_days", "days_since_last_commit"]

    for feat_name in null_features:
        # Collect known values (not None)
        known = [n["features"][feat_name] for n in author_nodes if n["features"][feat_name] is not None]
        if not known:
            print(f"  {feat_name}: no known values, skipping")
            continue

        med = statistics.median(known)
        med_rounded = round(med)

        replaced = 0
        for n in author_nodes:
            if n["features"][feat_name] is None:
                n["features"][feat_name] = med_rounded
                replaced += 1

        print(f"  {feat_name}: median={med_rounded}, replaced {replaced} nulls")

    return author_nodes


def median_impute_cve(cve_nodes):
    print("\n" + "=" * 60)
    print("STEP 5c: Median imputation — CVE CVSS scores")
    print("=" * 60)

    known = [n["cvss_score"] for n in cve_nodes if n.get("cvss_score") is not None]
    if not known:
        print("  No known CVSS scores, skipping")
        return cve_nodes

    med = round(statistics.median(known), 1)

    replaced = 0
    for n in cve_nodes:
        if n.get("cvss_score") is None:
            n["cvss_score"] = med
            replaced += 1

    print(f"  CVSS median={med}, replaced {replaced} nulls")

    return cve_nodes


# ---------------------------------------------------------------------------
# STEP 6: Convert Author features dict -> array
# ---------------------------------------------------------------------------
def convert_author_features(author_nodes):
    print("\n" + "=" * 60)
    print("STEP 6: Converting Author features to ordered arrays")
    print("=" * 60)

    converted = []
    for n in author_nodes:
        feat_array = []
        for key in AUTHOR_FEATURE_ORDER:
            val = n["features"].get(key, 0)
            if val is None:
                val = 0  # Safety net — should already be imputed
            feat_array.append(val)

        converted.append({
            "id": n["id"],
            "type": "Author",
            "features": feat_array,
        })

    print(f"  Converted {len(converted)} Author nodes to 7-dim arrays")

    # Verify
    bad = [n for n in converted if len(n["features"]) != 7]
    if bad:
        print(f"  WARNING: {len(bad)} nodes have wrong feature length!")
    else:
        print("  All nodes verified: 7-dim [OK]")

    return converted


# ---------------------------------------------------------------------------
# STEP 7: Assemble and write final graph
# ---------------------------------------------------------------------------
def assemble_graph(pkg_nodes, cve_nodes, author_nodes,
                   dep_edges, hv_edges, mb_edges, ib_edges, drop_log, impute_log):
    print("\n" + "=" * 60)
    print("STEP 7: Assembling final graph")
    print("=" * 60)

    # Format Package nodes
    final_pkg = []
    for n in pkg_nodes.values():
        final_pkg.append({
            "id": n["id"],
            "type": "Package",
            "features": n["features"],
        })

    # Format CVE nodes (keep embedding separate from scalar features)
    final_cve = []
    for n in cve_nodes:
        final_cve.append({
            "id": n["id"],
            "type": "CVE",
            "cvss_score": n["cvss_score"],
            "embedding": n["embedding"],
        })

    print(f"  Package nodes: {len(final_pkg)}")
    print(f"  CVE nodes: {len(final_cve)}")
    print(f"  Author nodes: {len(author_nodes)}")
    total_nodes = len(final_pkg) + len(final_cve) + len(author_nodes)
    print(f"  TOTAL nodes: {total_nodes}")
    print()
    print(f"  dependsOn edges: {len(dep_edges)}")
    print(f"  hasVulnerability edges: {len(hv_edges)}")
    print(f"  maintainedBy edges: {len(mb_edges)}")
    print(f"  introducedBy edges: {len(ib_edges)}")
    total_edges = len(dep_edges) + len(hv_edges) + len(mb_edges) + len(ib_edges)
    print(f"  TOTAL edges: {total_edges}")

    graph = {
        "metadata": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "description": "VulnChain heterogeneous graph — 3 node types, 4 edge types",
            "repos": sorted({r for n in pkg_nodes.values() for r in n.get("repo_sources", [])}),
            "exclusions": "strapi (Yarn Berry lockfile), redos-detector (empty clone: Windows colon-in-path) — documented limitations",
            "node_counts": {
                "Package": len(final_pkg),
                "CVE": len(final_cve),
                "Author": len(author_nodes),
                "total": total_nodes,
            },
            "edge_counts": {
                "dependsOn": len(dep_edges),
                "hasVulnerability": len(hv_edges),
                "maintainedBy": len(mb_edges),
                "introducedBy": len(ib_edges),
                "total": total_edges,
            },
            "edges_dropped": {k: v["count"] for k, v in drop_log.items()},
            "feature_schemas": {
                "Package": {"dim": 10, "order": PACKAGE_FEATURE_ORDER},
                "CVE": {"dim": "768 (SentenceBERT all-mpnet-base-v2, frozen) + 1 CVSS score"},
                "Author": {"dim": 7, "order": AUTHOR_FEATURE_ORDER},
            },
            "imputation": impute_log,
        },
        "nodes": {
            "Package": final_pkg,
            "CVE": final_cve,
            "Author": author_nodes,
        },
        "edges": {
            "dependsOn": dep_edges,
            "hasVulnerability": hv_edges,
            "maintainedBy": mb_edges,
            "introducedBy": ib_edges,
        },
    }

    return graph


# ---------------------------------------------------------------------------
# STEP 8: Validation
# ---------------------------------------------------------------------------
def validate(graph):
    print("\n" + "=" * 60)
    print("STEP 8: Validation")
    print("=" * 60)

    errors = []

    # Build ID sets
    pkg_ids = set(n["id"] for n in graph["nodes"]["Package"])
    cve_ids = set(n["id"] for n in graph["nodes"]["CVE"])
    author_ids = set(n["id"] for n in graph["nodes"]["Author"])

    # Check 1: No dangling edges
    for e in graph["edges"]["dependsOn"]:
        if e["source"] not in pkg_ids:
            errors.append(f"dependsOn dangling source: {e['source']}")
        if e["target"] not in pkg_ids:
            errors.append(f"dependsOn dangling target: {e['target']}")

    for e in graph["edges"]["hasVulnerability"]:
        if e["source"] not in pkg_ids:
            errors.append(f"hasVuln dangling source: {e['source']}")
        if e["target"] not in cve_ids:
            errors.append(f"hasVuln dangling target: {e['target']}")

    for e in graph["edges"]["maintainedBy"]:
        if e["source"] not in pkg_ids:
            errors.append(f"maintainedBy dangling source: {e['source']}")
        if e["target"] not in author_ids:
            errors.append(f"maintainedBy dangling target: {e['target']}")

    for e in graph["edges"]["introducedBy"]:
        if e["source"] not in cve_ids:
            errors.append(f"introducedBy dangling source: {e['source']}")
        if e["target"] not in author_ids:
            errors.append(f"introducedBy dangling target: {e['target']}")

    dangling_count = len(errors)
    print(f"  Dangling edges: {dangling_count} {'[OK]' if dangling_count == 0 else '[FAIL]'}")
    if dangling_count > 0:
        for err in errors[:10]:
            print(f"    {err}")

    # Check 2: No null/None in features
    null_count = 0
    for n in graph["nodes"]["Package"]:
        if None in n["features"]:
            null_count += 1
    for n in graph["nodes"]["Author"]:
        if None in n["features"]:
            null_count += 1
    for n in graph["nodes"]["CVE"]:
        if n.get("cvss_score") is None:
            null_count += 1
    print(f"  Null features: {null_count} {'[OK]' if null_count == 0 else '[FAIL]'}")

    # Check 3: No -1 sentinels in Package features (dims 4, 5)
    sentinel_count = 0
    for n in graph["nodes"]["Package"]:
        if n["features"][4] == -1 or n["features"][5] == -1:
            sentinel_count += 1
    print(f"  Remaining -1 sentinels (dims 4,5): {sentinel_count} {'[OK]' if sentinel_count == 0 else '[FAIL]'}")

    # Check 4: Feature dimensions
    bad_pkg = [n for n in graph["nodes"]["Package"] if len(n["features"]) != 10]
    bad_author = [n for n in graph["nodes"]["Author"] if len(n["features"]) != 7]
    bad_cve = [n for n in graph["nodes"]["CVE"] if len(n.get("embedding", [])) != 768]
    print(f"  Package features != 10-dim: {len(bad_pkg)} {'[OK]' if len(bad_pkg) == 0 else '[FAIL]'}")
    print(f"  Author features != 7-dim: {len(bad_author)} {'[OK]' if len(bad_author) == 0 else '[FAIL]'}")
    print(f"  CVE embeddings != 768-dim: {len(bad_cve)} {'[OK]' if len(bad_cve) == 0 else '[FAIL]'}")

    # Check 5: No duplicate node IDs within each type
    dup_pkg = len(graph["nodes"]["Package"]) - len(pkg_ids)
    dup_cve = len(graph["nodes"]["CVE"]) - len(cve_ids)
    dup_author = len(graph["nodes"]["Author"]) - len(author_ids)
    print(f"  Duplicate Package IDs: {dup_pkg} {'[OK]' if dup_pkg == 0 else '[FAIL]'}")
    print(f"  Duplicate CVE IDs: {dup_cve} {'[OK]' if dup_cve == 0 else '[FAIL]'}")
    print(f"  Duplicate Author IDs: {dup_author} {'[OK]' if dup_author == 0 else '[FAIL]'}")

    # Check 6: Cross-type ID collisions
    pkg_cve = pkg_ids & cve_ids
    pkg_author = pkg_ids & author_ids
    cve_author = cve_ids & author_ids
    collision_count = len(pkg_cve) + len(pkg_author) + len(cve_author)
    print(f"  Cross-type ID collisions: {collision_count} {'[OK]' if collision_count == 0 else '[FAIL]'}")

    total_checks = 6
    passed = sum([
        dangling_count == 0,
        null_count == 0,
        sentinel_count == 0,
        len(bad_pkg) + len(bad_author) + len(bad_cve) == 0,
        dup_pkg + dup_cve + dup_author == 0,
        collision_count == 0,
    ])

    print(f"\n  RESULT: {passed}/{total_checks} checks passed")
    return passed == total_checks


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    # Load
    pg, supplement, cve_nodes, author_nodes, hv_edges, mb_edges, ib_edges = load_all()

    # Merge packages
    pkg_nodes, dep_edges = merge_package_nodes(pg, supplement)

    # Build ID sets
    pkg_ids = set(pkg_nodes.keys())
    cve_ids = set(n["id"] for n in cve_nodes)
    author_ids = set(n["id"] for n in author_nodes)

    # Drop dangling
    clean_dep, clean_hv, clean_mb, clean_ib, drop_log = drop_dangling_edges(
        pkg_ids, cve_ids, author_ids, dep_edges, hv_edges, mb_edges, ib_edges
    )

    # Backfill CVE history
    pkg_nodes = backfill_cve_history(pkg_nodes, clean_hv)

    # Median imputation
    pkg_nodes = median_impute_packages(pkg_nodes)
    author_nodes = median_impute_authors(author_nodes)
    cve_nodes = median_impute_cve(cve_nodes)

    # Build imputation log for metadata
    impute_log = "Median imputation applied to: Package version_recency_days (-1), " \
                 "Package versions_behind_latest (-1), Author account_age_days (null), " \
                 "Author days_since_last_commit (null), CVE cvss_score (null)"

    # Convert author features
    author_nodes_converted = convert_author_features(author_nodes)

    # Assemble
    graph = assemble_graph(
        pkg_nodes, cve_nodes, author_nodes_converted,
        clean_dep, clean_hv, clean_mb, clean_ib, drop_log, impute_log
    )

    # Validate
    all_passed = validate(graph)

    if all_passed:
        print(f"\n{'=' * 60}")
        print(f"Writing final graph to {OUTPUT}")
        print(f"{'=' * 60}")
        with open(OUTPUT, "w", encoding="utf-8") as f:
            json.dump(graph, f)
        file_size = OUTPUT.stat().st_size
        print(f"  File size: {file_size / 1024 / 1024:.1f} MB")
        print("\n[OK] MERGE COMPLETE -- vulnchain_graph.json is ready for training")
    else:
        print(f"\n❌ VALIDATION FAILED — not writing output file. Fix errors above.")


if __name__ == "__main__":
    main()
