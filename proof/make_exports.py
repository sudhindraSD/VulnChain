"""
Regenerate all STEP 4 proof exports under proof/out/ (single source of truth).

Runs, in order: CLI report, independent verifier, npm audit comparison,
offline/online agreement, case studies; then builds graph_subgraph.json,
audit_scores.json and meta.json; finally validates every JSON.

Usage:
  python proof/make_exports.py --lockfile demo/sample-lock.json \
      --out-dir proof/out --repo-root .
"""
import argparse
import hashlib
import json
import re
import statistics
import subprocess
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT_DEFAULT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT_DEFAULT))

import verify_paths
import compare_npm_audit
import offline_online
import case_studies
from vulnchain.proof.cli import build_report

NODE_CAP = 300
REQUIRED_EXPORTS = [
    "flagged_packages.json",
    "verify_report.json",
    "npm_audit_comparison.json",
    "graph_subgraph.json",
    "audit_scores.json",
    "meta.json",
]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(obj, path):
    Path(path).write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def parse_audit_scores(root):
    """LP_original / LP_clean / HR / BFS parsed from the frozen gate table, never typed."""
    rel = "phase5/HYBRID_GATE.md"
    text = (root / rel).read_text(encoding="utf-8")
    patterns = {
        "LP_original": r"\|\s*`LP_original`\s*\|\s*([0-9]+\.[0-9]+)\s*±\s*([0-9]+\.[0-9]+)",
        "LP_clean": r"\|\s*`LP_clean`[^\n]*\|\s*([0-9]+\.[0-9]+)\s*±\s*([0-9]+\.[0-9]+)",
        "HR": r"\|\s*VulnGAT-HR \(unchanged\)\s*\|\s*([0-9]+\.[0-9]+)\s*±\s*([0-9]+\.[0-9]+)",
        "BFS": r"\|\s*BFS \(unchanged, for reference\)\s*\|\s*([0-9]+\.[0-9]+)\s*±\s*([0-9]+\.[0-9]+)",
    }
    values, lines = {}, {}
    for key, pattern in patterns.items():
        m = re.search(pattern, text)
        if m:
            values[key] = {"mean": float(m.group(1)), "std": float(m.group(2))}
            lines[key] = m.group(0)
        else:
            values[key] = None
            lines[key] = None
    return {
        "parsed_from": rel,
        "source_sha256": sha256(root / rel),
        "values": values,
        "source_lines": lines,
        "parse_failures": [k for k, v in values.items() if v is None],
    }


def parse_task_d(root):
    """Task D numbers PARSED from phase5/confirm_metrics.json (never typed)."""
    rel = "phase5/confirm_metrics.json"
    doc = json.loads((root / rel).read_text(encoding="utf-8"))
    rows = doc["rows"]
    verdict = doc["verdict"]

    def mean(key):
        return sum(r[key] for r in rows) / len(rows)

    deltas = [r["CANDIDATE-LP_clean"] for r in rows]
    return {
        "parsed_from": rel,
        "source_sha256": sha256(root / rel),
        "seed_list": [r["seed"] for r in rows],
        "rows": rows,
        "verdict": verdict,
        "computed_from_rows_not_typed": {
            "n_seeds": len(rows),
            "mean_CANDIDATE": mean("CANDIDATE"),
            "mean_LP_clean": mean("LP_clean"),
            "mean_HR": mean("HR"),
            "mean_CANDIDATE_perm": mean("CANDIDATE_perm"),
            "mean_PERM_ALL": mean("PERM_ALL"),
            "mean_paired_delta_CANDIDATE_minus_LP_clean": mean("CANDIDATE-LP_clean"),
            "sd_paired_delta_ddof1": statistics.stdev(deltas) if len(deltas) > 1 else None,
        },
    }


def build_subgraphs(model, advisories, flagged_doc, verify_doc):
    """Subgraphs built from verify_paths.py's independent parser, cap 300 nodes."""
    nodes = model["nodes"]
    children = defaultdict(list)
    for key, node in nodes.items():
        for dep in sorted(node["deps"]):
            dst = verify_paths.resolve_edge(key, dep, model)
            if dst is not None:
                children[key].append(dst)

    depth = {"": 0}
    q = deque([""])
    while q:
        cur = q.popleft()
        for nxt in children.get(cur, []):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                q.append(nxt)
    root_deps = nodes[""]["deps"]

    verify_map = {
        (r.get("package"), r.get("path_index")): r
        for r in verify_doc.get("paths", [])
    }
    out = []
    for rec in flagged_doc.get("flagged", []):
        start_keys = list(model["pid_index"].get(rec["package"], []))
        closure, seen = [], set()
        queue = deque(start_keys)
        while queue:
            key = queue.popleft()
            if key in seen:
                continue
            seen.add(key)
            closure.append(key)
            for child in children.get(key, []):
                if child not in seen:
                    queue.append(child)
        included = closure[:NODE_CAP]
        included_set = set(included)
        truncated = len(closure) > NODE_CAP

        node_rows = []
        for key in included:
            node = nodes[key]
            is_direct = (key.count("node_modules/") == 1) and (node["name"] in root_deps)
            node_rows.append({
                "id": node["pid"],
                "direct": bool(is_direct),
                "depth": depth.get(key),
                "advisories": advisories.get(node["pid"], []),
            })
        edge_rows = []
        edge_seen = set()
        for key in included:
            for child in children.get(key, []):
                if child in included_set:
                    pair = (nodes[key]["pid"], nodes[child]["pid"])
                    if pair not in edge_seen:
                        edge_seen.add(pair)
                        edge_rows.append({"from": pair[0], "to": pair[1]})

        path = rec["paths"][0] if rec.get("paths") else None
        vrow = verify_map.get((rec["package"], 0), {})
        out.append({
            "package": rec["package"],
            "nodes": node_rows,
            "edges": edge_rows,
            "verified_path": path,
            "verified_path_pass": bool(vrow.get("pass")) if vrow else None,
            "truncated": truncated,
            "closure_size": len(closure),
            "node_cap": NODE_CAP,
        })
    return {
        "schema": "vulnchain-proof/graph_subgraph/1",
        "parser": "proof/verify_paths.py::parse_lockfile (independent parser)",
        "node_cap": NODE_CAP,
        "counts": {
            "subgraphs": len(out),
            "truncated_subgraphs": sum(1 for r in out if r["truncated"]),
            "max_closure_size": max((r["closure_size"] for r in out), default=0),
        },
        "subgraphs": out,
    }


def git_head(root):
    try:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip() or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="make_exports.py")
    ap.add_argument("--lockfile", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--repo-root", default=str(ROOT_DEFAULT))
    args = ap.parse_args(argv)

    root = Path(args.repo_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    kb = root / "phase5/bench_run/vulnchain_graph.json"
    cache = root / "phase5/bench_run/osv_cache.json"

    print("make_exports.py -- regenerating proof/out/ from frozen inputs")
    # R5 reads this file; default is empty so `tool_bug` never fires silently.
    tool_bug_path = out_dir / "tool_bug_cases.json"
    if not tool_bug_path.exists():
        dump({}, tool_bug_path)

    # 1. CLI report
    flagged = build_report(args.lockfile, root)
    dump(flagged, out_dir / "flagged_packages.json")
    print("  [1] flagged_packages.json  flagged=%d paths=%d" % (
        flagged["counts"]["flagged_packages"], flagged["counts"]["paths_printed"]))

    # 2. Independent verifier
    model = verify_paths.parse_lockfile(args.lockfile)
    advisories = verify_paths.load_advisories(kb, cache)
    verify_doc = verify_paths.verify_document(flagged, model, advisories)
    dump(verify_doc, out_dir / "verify_report.json")
    print("  [2] verify_report.json     pass=%d fail=%d" % (
        verify_doc["counts"]["paths_pass"], verify_doc["counts"]["paths_fail"]))

    # 3. npm audit comparison
    rc = compare_npm_audit.main([
        args.lockfile, "--kb", str(kb), "--cache", str(cache),
        "--json", str(out_dir / "npm_audit_comparison.json"),
        "--tool-bug-cases", str(tool_bug_path),
    ])
    print("  [3] npm_audit_comparison.json (rc=%d)" % rc)

    # 4. offline / online agreement
    offline_online.main([
        args.lockfile, "--kb", str(kb), "--cache", str(cache),
        "--json", str(out_dir / "offline_online.json"),
    ])
    print("  [4] offline_online.json written")

    # 5. case studies
    case_studies.main([
        "--flagged", str(out_dir / "flagged_packages.json"),
        "--verify", str(out_dir / "verify_report.json"),
        "--comparison", str(out_dir / "npm_audit_comparison.json"),
        "--json", str(out_dir / "case_studies.json"),
    ])
    print("  [5] case_studies.json written")

    # 6. subgraph export from the independent parser
    subgraphs = build_subgraphs(model, advisories, flagged, verify_doc)
    dump(subgraphs, out_dir / "graph_subgraph.json")
    print("  [6] graph_subgraph.json    subgraphs=%d truncated=%d" % (
        subgraphs["counts"]["subgraphs"], subgraphs["counts"]["truncated_subgraphs"]))

    # 7. audit scores (parsed, never typed)
    dump({
        "schema": "vulnchain-proof/audit_scores/1",
        "LP_original": parse_audit_scores(root)["values"]["LP_original"],
        "LP_clean": parse_audit_scores(root)["values"]["LP_clean"],
        "HR": parse_audit_scores(root)["values"]["HR"],
        "BFS": parse_audit_scores(root)["values"]["BFS"],
        "score_source": parse_audit_scores(root),
        "task_d": parse_task_d(root),
    }, out_dir / "audit_scores.json")
    print("  [7] audit_scores.json written")

    # 8. meta
    dump({
        "schema": "vulnchain-proof/meta/1",
        "source_commit": git_head(root),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lockfile": str(args.lockfile),
        "lockfile_sha256": sha256(root / args.lockfile) if (root / args.lockfile).exists() else sha256(args.lockfile),
        "advisory_source_sha256": {
            "phase5/bench_run/vulnchain_graph.json": sha256(kb),
            "phase5/bench_run/osv_cache.json": sha256(cache),
        },
    }, out_dir / "meta.json")
    print("  [8] meta.json written")

    # Validate every required export.
    print("  --- validation ---")
    all_valid = True
    for name in REQUIRED_EXPORTS:
        p = out_dir / name
        try:
            json.loads(p.read_text(encoding="utf-8"))
            print("  VALID %-32s %8d bytes" % (name, p.stat().st_size))
        except Exception as exc:
            all_valid = False
            print("  INVALID %-30s %s" % (name, exc))
    print("  ALL_SIX_VALID=%s" % all_valid)
    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main())
