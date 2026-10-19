"""
generate_repo_split.py — 51-repo provenance-clean split generator (Phase 4, Step B0)

Codifies the Provenance Rule (see CURRENT_CONTEXT.md Section 9.3) as persistent
code, replacing the session-generated repo_split_mapping.json whose lack of a
generation script is how the 69.8% test contamination went unnoticed.

Rule:
    A package node p is assigned to evaluation split S (val or test) if and
    only if EVERY repo in p's repo_sources belongs to S's repo group.
    Mixed-provenance nodes (and all-train nodes) are assigned to TRAIN: they
    contribute to message passing and training loss, but are never evaluated on.

Selected evaluation repos (pre-registered in WORKER_ORDERS_PHASE4.md Section 0):
    Test: saleor-storefront  (1,341 exclusive nodes expected)
    Val:  practica           (  541 exclusive nodes expected)

Input : package_graph.json           (12,405 flat nodes, each with repo_sources)
Output: phase4/repo_split_mapping_51repo.json

Usage:
    python generate_repo_split.py
"""

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GRAPH_PATH = ROOT / "package_graph.json"
OUT_PATH = ROOT / "phase4" / "repo_split_mapping_51repo.json"

TEST_REPOS = {"saleor-storefront"}
VAL_REPOS = {"practica"}


def classify(repo_sources):
    """Provenance Rule: eval split only if ALL sources belong to that group."""
    rs = set(repo_sources)
    if rs and rs <= TEST_REPOS:
        return "test"
    if rs and rs <= VAL_REPOS:
        return "val"
    return "train"  # all-train OR mixed provenance -> train


def main():
    if not GRAPH_PATH.exists():
        sys.exit(f"graph not found: {GRAPH_PATH}")

    with open(GRAPH_PATH, encoding="utf-8") as f:
        graph = json.load(f)

    nodes = graph["nodes"]
    print(f"loaded {len(nodes)} nodes from {GRAPH_PATH.name}")

    missing_provenance = [n["id"] for n in nodes if not n.get("repo_sources")]
    if missing_provenance:
        sys.exit(f"{len(missing_provenance)} nodes have empty/missing repo_sources "
                 f"(e.g. {missing_provenance[:3]}) -- provenance unrecoverable, aborting")

    split_ids = {"train": [], "val": [], "test": []}
    node_repo_sources = {}
    for node in nodes:
        pid = node["id"]
        split_ids[classify(node["repo_sources"])].append(pid)
        node_repo_sources[pid] = node["repo_sources"]

    # ---- verification ----
    sets = {k: set(v) for k, v in split_ids.items()}
    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        overlap = sets[a] & sets[b]
        if overlap:
            sys.exit(f"LEAKAGE: {len(overlap)} nodes in both {a} and {b}: {list(overlap)[:5]}")

    for split, group in (("val", VAL_REPOS), ("test", TEST_REPOS)):
        impure = [pid for pid in split_ids[split]
                  if not set(node_repo_sources[pid]) <= group]
        if impure:
            sys.exit(f"LEAKAGE: {len(impure)} {split} nodes have provenance outside "
                     f"{group}: {impure[:5]}")

    multi_repo = sum(1 for pid in split_ids["train"] if len(node_repo_sources[pid]) > 1)
    touches_eval = sum(1 for pid in split_ids["train"]
                       if set(node_repo_sources[pid]) & (VAL_REPOS | TEST_REPOS))

    counts = {k: len(v) for k, v in split_ids.items()}
    assert sum(counts.values()) == len(nodes), "split lost nodes"

    print("\n=== 51-Repo Provenance-Clean Split ===")
    for k in ("train", "val", "test"):
        print(f"  {k:>5}: {counts[k]:>6,}  ({counts[k] / len(nodes) * 100:.1f}%)")
    print(f"  total: {len(nodes):>6,}")
    print(f"  train nodes in >1 repo (shared topology): {multi_repo:,}")
    print(f"  train nodes whose provenance touches val/test repos (absorbed mixed): {touches_eval:,}")
    print(f"  leakage: 0 overlap, 0 impure eval nodes -- CLOSED")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "train_pkg_ids": split_ids["train"],
            "val_pkg_ids": split_ids["val"],
            "test_pkg_ids": split_ids["test"],
            "_metadata": {
                "generated": datetime.now().isoformat(timespec="seconds"),
                "generator": "generate_repo_split.py",
                "rule": "Provenance Rule: node in eval split S iff EVERY repo_source in S's repo group; mixed -> train",
                "repo_groups": {
                    "test_repos": sorted(TEST_REPOS),
                    "val_repos": sorted(VAL_REPOS),
                    "train_repos": "all remaining repos in package_graph.json",
                },
                "counts": counts,
                "node_repo_sources": node_repo_sources,
            },
        }, f, indent=2)
    print(f"\nwrote {OUT_PATH}")


if __name__ == "__main__":
    main()
