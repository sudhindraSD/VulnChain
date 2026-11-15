"""
STEP 4 proof CLI:  python -m vulnchain.proof <lockfile> [--json OUT]

Prints, for every flagged package, the exact dependency path from the project
root to a vulnerable descendant, with versions, advisory IDs and a frozen
model score. All selection rules are fixed in PROOF_PROTOCOL.md.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import graph
from .advisories import offline_advisories, model_scores, KB_REL, CACHE_REL


def build_report(lock_path: str, root: Path | None = None):
    root = root or graph.repo_root()
    data, lock_sha = graph.read_lockfile(lock_path)
    nodes, children, parents, edges, root_key, root_name, root_version = graph.build_graph(data)
    adv = offline_advisories(root)
    scores = model_scores(root)
    depth = graph.depths_from_root(nodes, children, root_key)
    dist, vulnerable = graph.distances_to_vulnerable(nodes, parents, adv)
    paths, truncated, cap_reason = graph.enumerate_paths(
        nodes, children, dist, vulnerable, root_key
    )
    best = graph.select_paths(nodes, paths)

    reachable = set(depth)
    has_desc = set(dist)
    all_non_root = {k for k in nodes if k != root_key}
    excluded_not_reachable = sorted(all_non_root - reachable)
    excluded_no_vuln_descendant = sorted((all_non_root & reachable) - has_desc)
    flagged_keys = sorted(all_non_root & reachable & has_desc, key=lambda k: (nodes[k]["pid"], k))

    flagged = []
    for key in flagged_keys:
        node = nodes[key]
        chosen = best.get(key)
        if chosen is None:
            rec = {
                "package": node["pid"],
                "lock_key": key,
                "paths": [],
                "no_path_reason": "NO_PATH_WITHIN_CAPS",
                "advisory_ids": [],
                "advisory_endpoint": None,
                "hops": None,
                "model_score": scores.get(node["pid"]),
                "model_score_resolved": node["pid"] in scores,
                "direct": node["direct"],
                "dev": node["dev"],
                "depth": depth.get(key),
            }
        else:
            path_keys = chosen[1]
            endpoint = nodes[path_keys[-1]]
            rec = {
                "package": node["pid"],
                "lock_key": key,
                "paths": [[nodes[k]["pid"] for k in path_keys]],
                "no_path_reason": None,
                "advisory_ids": adv.get(endpoint["pid"], []),
                "advisory_endpoint": endpoint["pid"],
                "hops": len(path_keys) - 1,
                "model_score": scores.get(node["pid"]),
                "model_score_resolved": node["pid"] in scores,
                "direct": node["direct"],
                "dev": node["dev"],
                "depth": depth.get(key),
            }
        flagged.append(rec)

    return {
        "schema": "vulnchain-proof/flagged_packages/1",
        "lockfile": str(lock_path),
        "lockfile_sha256": lock_sha,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "advisory_source": [KB_REL, CACHE_REL],
        "root": f"{root_name}@{root_version}",
        "counts": {
            "lockfile_entries": len(nodes),
            "edges": len(edges),
            "vulnerable_nodes": len(vulnerable),
            "enumerated_paths": len(paths),
            "flagged_packages": len(flagged),
            "paths_printed": sum(len(r["paths"]) for r in flagged),
            "excluded_not_reachable": len(excluded_not_reachable),
            "excluded_no_vulnerable_descendant": len(excluded_no_vuln_descendant),
            "no_path_within_caps": sum(1 for r in flagged if not r["paths"]),
            "model_score_unresolved": sum(1 for r in flagged if not r["model_score_resolved"]),
            "truncated": truncated,
            "truncation_reason": cap_reason,
            "max_hops": graph.MAX_HOPS,
            "max_paths": graph.MAX_PATHS,
        },
        "flagged": flagged,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m vulnchain.proof")
    ap.add_argument("lockfile", help="path to npm package-lock.json")
    ap.add_argument("--json", dest="json_out", default=None, help="write flagged_packages.json here")
    ap.add_argument("--repo-root", default=None, help="override repository root")
    args = ap.parse_args(argv)

    root = Path(args.repo_root).resolve() if args.repo_root else graph.repo_root()
    report = build_report(args.lockfile, root)

    print("=" * 78)
    print("  VulnChain STEP 4 proof CLI -- exact dependency paths")
    print("=" * 78)
    print(f"lockfile        : {report['lockfile']}")
    print(f"lockfile sha256 : {report['lockfile_sha256']}")
    print(f"project root    : {report['root']}")
    c = report["counts"]
    print(
        f"counts          : entries={c['lockfile_entries']} edges={c['edges']} "
        f"vulnerable={c['vulnerable_nodes']} flagged={c['flagged_packages']} "
        f"printed_paths={c['paths_printed']} enumerated={c['enumerated_paths']}"
    )
    print(f"caps            : MAX_HOPS={c['max_hops']} MAX_PATHS={c['max_paths']} "
          f"truncated={c['truncated']} ({c['truncation_reason']})")
    print("-" * 78)
    for r in report["flagged"]:
        score = "UNRESOLVED" if r["model_score"] is None else f"{r['model_score']:.6f}"
        print(f"FLAGGED {r['package']}")
        if r["paths"]:
            print(f"  path        : {' -> '.join(r['paths'][0])}")
            print(f"  advisory_ids: {', '.join(r['advisory_ids']) or 'NONE'}")
            print(f"  endpoint    : {r['advisory_endpoint']}  hops={r['hops']}")
        else:
            print(f"  path        : NO_PATH ({r['no_path_reason']})")
            print(f"  advisory_ids: NONE")
        print(f"  model_score : {score}")
    print("-" * 78)
    print(f"model_score UNRESOLVED : {c['model_score_unresolved']}")
    print(f"no_path_within_caps   : {c['no_path_within_caps']}")
    print(f"excluded_not_reachable: {c['excluded_not_reachable']}")
    print(f"excluded_no_vuln_desc : {c['excluded_no_vulnerable_descendant']}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
