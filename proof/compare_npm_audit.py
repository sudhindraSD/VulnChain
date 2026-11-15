"""
npm audit comparison for the STEP 4 proof module.

Runs `npm audit --json` on the exact sample lockfile, forms the three
pre-registered groups, and labels every discrepancy item with exactly one
cause from the FIXED rule list in PROOF_PROTOCOL.md section 4. Items matching
no rule are labelled UNEXPLAINED. No item is forced into a rule.

Usage:
  python proof/compare_npm_audit.py <lockfile> --kb <graph.json> \
      --cache <osv_cache.json> --json <npm_audit_comparison.json>
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_paths  # independent lockfile parser; stdlib-only

ADVISORY_ID_RE = re.compile(r"(GHSA-[0-9a-z\-]+|CVE-\d{4}-\d+)")

CAUSE_RULES = [
    "advisory_db_differences",   # R1
    "version_range_resolution",  # R2
    "dev_vs_prod_scope",         # R3
    "transitive_depth",          # R4
    "tool_bug",                  # R5
]


def build_temp_project(lock_path, tmpdir):
    raw = Path(lock_path).read_bytes()
    data = json.loads(raw.decode("utf-8"))
    root = (data.get("packages", {}) or {}).get("", {}) or {}
    package_json = {
        "name": root.get("name") or data.get("name") or "root",
        "version": root.get("version") or data.get("version") or "0.0.0",
        "private": True,
        "dependencies": dict(root.get("dependencies") or {}),
        "devDependencies": dict(root.get("devDependencies") or {}),
    }
    (Path(tmpdir) / "package.json").write_text(json.dumps(package_json, indent=2), encoding="utf-8")
    (Path(tmpdir) / "package-lock.json").write_bytes(raw)
    return package_json


def run_npm_audit(tmpdir, timeout=240):
    # On Windows npm is npm.cmd; shutil.which with an explicit suffix resolves it
    # without shell=True (which would hide the real argv from the log).
    npm_bin = shutil.which("npm.cmd") or shutil.which("npm") or "npm"
    command = "npm audit --json"
    try:
        proc = subprocess.run(
            [npm_bin, "audit", "--json"],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "command": command,
            "resolved_binary": npm_bin,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "error": None,
        }
    except Exception as exc:
        return {
            "command": command,
            "resolved_binary": npm_bin,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "error": type(exc).__name__ + ": " + str(exc),
        }


def npm_items(audit_doc, model):
    """Return (items set, ids_by_name, range_by_name, unmatched_nodes, metadata)."""
    vulns = audit_doc.get("vulnerabilities", {}) or {}
    ids_by_name = defaultdict(set)
    range_by_name = {}
    items = set()
    unmatched = []

    for name, rec in vulns.items():
        range_by_name[name] = rec.get("range")
        for via in rec.get("via", []) or []:
            if isinstance(via, dict):
                for field in ("url", "name", "title", "dependency"):
                    for found in ADVISORY_ID_RE.findall(str(via.get(field, ""))):
                        ids_by_name[name].add(found)
        for node_path in rec.get("nodes", []) or []:
            key = node_path.lstrip("./")
            if key not in model["keys"]:
                matches = [k for k in model["keys"] if k and k.endswith(key)]
                key = matches[0] if matches else None
            if key is None:
                unmatched.append({"name": name, "node": node_path})
                continue
            items.add(model["nodes"][key]["pid"])
    return (
        items,
        {k: sorted(v) for k, v in ids_by_name.items()},
        range_by_name,
        unmatched,
        audit_doc.get("metadata", {}) or {},
    )


def depths(model):
    children = defaultdict(list)
    for key, node in model["nodes"].items():
        for dep in sorted(node["deps"]):
            dst = verify_paths.resolve_edge(key, dep, model)
            if dst is not None:
                children[key].append(dst)
    out = {"": 0}
    q = deque([""])
    while q:
        cur = q.popleft()
        for nxt in children.get(cur, []):
            if nxt not in out:
                out[nxt] = out[cur] + 1
                q.append(nxt)
    by_pid = {}
    for key, d in out.items():
        pid = model["nodes"][key]["pid"]
        by_pid[pid] = min(by_pid.get(pid, 10 ** 9), d)
    return by_pid


def classify(pid, group, facts, advisories, ids_by_name, range_by_name, depth_by_pid, tool_bug_cases):
    name, version = pid.rsplit("@", 1)
    vc_ids = advisories.get(pid, [])
    npm_ids = ids_by_name.get(name, [])
    range_str = range_by_name.get(name)
    all_dev = facts["all_dev"]
    other_version = facts["other_version_advisory"]
    depth = depth_by_pid.get(pid)
    evidence = {
        "vc_ids": vc_ids,
        "npm_ids": npm_ids,
        "range": range_str,
        "all_dev": all_dev,
        "other_version_advisory": other_version,
        "depth_from_root": depth,
        "tool_bug_case_listed": pid in tool_bug_cases,
    }

    # R1: npm cites advisory IDs that our frozen source lacks / are disjoint.
    if npm_ids and (not vc_ids or not (set(vc_ids) & set(npm_ids))):
        cause = CAUSE_RULES[0]
    # R2: same name advised at another version, or npm's range string excludes
    # the exact installed version. Absent range string does NOT satisfy R2.
    elif other_version or (range_str is not None and version not in range_str):
        cause = CAUSE_RULES[1]
    # R3: every lockfile entry for this pid is dev-only.
    elif all_dev:
        cause = CAUSE_RULES[2]
    # R4: shortest verified path from root is >= 5 edges (frozen analyzer cap).
    elif depth is not None and depth >= 5:
        cause = CAUSE_RULES[3]
    # R5: only fires for explicitly recorded failing cases.
    elif pid in tool_bug_cases:
        cause = CAUSE_RULES[4]
    else:
        cause = "UNEXPLAINED"
    return {"item": pid, "group": group, "cause": cause, "evidence": evidence}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="compare_npm_audit.py")
    ap.add_argument("lockfile")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--json", dest="json_out", required=True)
    ap.add_argument("--tool-bug-cases", default=None)
    args = ap.parse_args(argv)

    model = verify_paths.parse_lockfile(args.lockfile)
    advisories = verify_paths.load_advisories(args.kb, args.cache)
    tool_bug_cases = {}
    if args.tool_bug_cases and Path(args.tool_bug_cases).exists():
        tool_bug_cases = json.loads(Path(args.tool_bug_cases).read_text(encoding="utf-8"))

    tmpdir = tempfile.mkdtemp(prefix="vulnchain_npm_audit_")
    try:
        package_json = build_temp_project(args.lockfile, tmpdir)
        run = run_npm_audit(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    base = {
        "schema": "vulnchain-proof/npm_audit_comparison/1",
        "lockfile": str(args.lockfile),
        "command": run["command"],
        "resolved_binary": run["resolved_binary"],
        "exit_code": run["exit_code"],
        "stderr": run["stderr"][:2000],
        "stdout_sha256": hashlib.sha256(run["stdout"].encode("utf-8", "replace")).hexdigest(),
        "stdout_bytes": len(run["stdout"]),
        "reconstructed_package_json": package_json,
        "advisory_source": [str(args.kb), str(args.cache)],
    }

    if run["error"]:
        base.update({
            "status": "NOT_COMPLETED",
            "error": run["error"],
            "groups": {"found_by_both": [], "vulnchain_only": [], "npm_audit_only": []},
            "causes": [],
            "counts": {},
            "unexplained_count": None,
        })
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
        print("npm audit comparison NOT_COMPLETED: " + run["error"])
        return 1

    try:
        audit_doc = json.loads(run["stdout"])
    except json.JSONDecodeError as exc:
        base.update({
            "status": "NOT_COMPLETED",
            "error": "invalid JSON from npm audit: " + str(exc),
            "stdout_excerpt": run["stdout"][:1000],
            "groups": {"found_by_both": [], "vulnchain_only": [], "npm_audit_only": []},
            "causes": [],
            "counts": {},
            "unexplained_count": None,
        })
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
        print("npm audit comparison NOT_COMPLETED: invalid JSON")
        return 1

    npm_set, ids_by_name, range_by_name, unmatched, metadata = npm_items(audit_doc, model)
    vc_set = {pid for pid in advisories if pid in model["pid_index"]}
    both = sorted(vc_set & npm_set)
    vc_only = sorted(vc_set - npm_set)
    npm_only = sorted(npm_set - vc_set)

    pid_to_keys = model["pid_index"]
    adv_by_name = defaultdict(set)
    for pid in advisories:
        adv_by_name[pid.rsplit("@", 1)[0]].add(pid)
    depth_by_pid = depths(model)

    causes = []
    for group, items in (("vulnchain_only", vc_only), ("npm_audit_only", npm_only)):
        for pid in items:
            keys = pid_to_keys.get(pid, [])
            name, version = pid.rsplit("@", 1)
            facts = {
                "all_dev": bool(keys) and all(model["nodes"][k]["dev"] for k in keys),
                "other_version_advisory": any(
                    other != pid for other in adv_by_name.get(name, ())
                ),
            }
            causes.append(classify(
                pid, group, facts, advisories, ids_by_name, range_by_name,
                depth_by_pid, tool_bug_cases,
            ))
    for pid in both:
        causes.append({"item": pid, "group": "found_by_both", "cause": "NOT_A_DISCREPANCY", "evidence": {}})

    cause_counts = defaultdict(int)
    for c in causes:
        cause_counts[c["cause"]] += 1

    base.update({
        "status": "COMPLETED",
        "error": None,
        "npm_audit_metadata_vulnerabilities": metadata.get("vulnerabilities", {}),
        "npm_audit_vulnerability_entries": len(audit_doc.get("vulnerabilities", {}) or {}),
        "unmatched_npm_nodes": unmatched,
        "groups": {
            "found_by_both": both,
            "vulnchain_only": vc_only,
            "npm_audit_only": npm_only,
        },
        "causes": causes,
        "counts": {
            "vc_items": len(vc_set),
            "npm_items": len(npm_set),
            "found_by_both": len(both),
            "vulnchain_only": len(vc_only),
            "npm_audit_only": len(npm_only),
            "discrepancy_items": len(vc_only) + len(npm_only),
            "unmatched_npm_nodes": len(unmatched),
            "cause_counts": dict(sorted(cause_counts.items())),
        },
        "unexplained_count": sum(1 for c in causes if c["cause"] == "UNEXPLAINED"),
    })

    out = Path(args.json_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
    c = base["counts"]
    print("npm audit --json exit_code=%s entries=%s" % (run["exit_code"], base["npm_audit_vulnerability_entries"]))
    print("  vc_items=%d npm_items=%d" % (c["vc_items"], c["npm_items"]))
    print("  found_by_both=%d vulnchain_only=%d npm_audit_only=%d" % (
        c["found_by_both"], c["vulnchain_only"], c["npm_audit_only"]))
    print("  UNEXPLAINED=%d  cause_counts=%s" % (base["unexplained_count"], c["cause_counts"]))
    print("  wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
