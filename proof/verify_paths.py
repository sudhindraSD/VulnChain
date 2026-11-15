"""
INDEPENDENT path verifier for the STEP 4 proof module.

Independence rule (PROOF_PROTOCOL.md section 2): this file parses
package-lock.json directly with its own parser and imports NOTHING from the
project's graph, model, or feature code. Every import below is Python stdlib.

Usage:
  python proof/verify_paths.py <lockfile> <flagged_packages.json> \
      --kb <vulnchain_graph.json> --cache <osv_cache.json> --json <out>
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Own lockfile parser (deliberately separate from vulnchain.proof.graph)
# ---------------------------------------------------------------------------


def _flatten_v1(deps, parent_key, entries):
    for name, meta in (deps or {}).items():
        key = (parent_key + "/node_modules/" + name) if parent_key else ("node_modules/" + name)
        children = meta.get("dependencies") or {}
        dev_children = meta.get("devDependencies") or {}
        declared = {n: "*" for n in children}
        for n in dev_children:
            declared.setdefault(n, "*")
        entries[key] = {
            "version": meta.get("version", "0.0.0"),
            "dev": bool(meta.get("dev", False)),
            "dependencies": declared,
        }
        if children:
            _flatten_v1(children, key, entries)


def parse_lockfile(path):
    """Return a dict holding the independently parsed lockfile model."""
    raw = Path(path).read_bytes()
    data = json.loads(raw.decode("utf-8"))

    if isinstance(data.get("packages"), dict) and data["packages"]:
        entries = data["packages"]
        root = entries.get("", {}) or {}
        root_name = root.get("name") or data.get("name") or "root"
        root_version = root.get("version") or data.get("version") or "0.0.0"
        root_deps = dict(root.get("dependencies") or {})
        root_deps.update(root.get("devDependencies") or {})
    else:
        deps = data.get("dependencies") or {}
        root_name = data.get("name") or "root"
        root_version = data.get("version") or "0.0.0"
        root_deps = {n: "*" for n in deps}
        entries = {"": {"dependencies": dict(root_deps)}}
        _flatten_v1(deps, "", entries)

    nodes = {}
    for key, meta in entries.items():
        meta = meta or {}
        if key == "":
            name, version = root_name, root_version
            declared = set(root_deps)
            dev = False
        else:
            name = key.split("node_modules/")[-1]
            version = str(meta.get("version", "0.0.0"))
            declared = set(meta.get("dependencies") or {})
            declared |= set(meta.get("devDependencies") or {})
            dev = bool(meta.get("dev", False))
        nodes[key] = {
            "key": key,
            "name": name,
            "version": version,
            "pid": name + "@" + version,
            "deps": declared,
            "dev": dev,
        }

    by_name = defaultdict(list)
    pid_index = defaultdict(list)
    for key, node in nodes.items():
        pid_index[node["pid"]].append(key)
        if key:
            by_name[node["name"]].append(key)
    for value in by_name.values():
        value.sort()
    for value in pid_index.values():
        value.sort()

    return {
        "nodes": nodes,
        "keys": set(nodes),
        "by_name": by_name,
        "pid_index": pid_index,
        "root_pid": nodes[""]["pid"],
    }


def load_advisories(kb_path, cache_path):
    """ADV_OFF: pid -> sorted advisory IDs from the two frozen source files."""
    acc = defaultdict(set)
    kb = json.loads(Path(kb_path).read_text(encoding="utf-8"))
    for edge in (kb.get("edges", {}) or {}).get("hasVulnerability", []) or []:
        src, tgt = edge.get("source"), edge.get("target")
        if src and tgt:
            acc[src].add(tgt)
    cache = json.loads(Path(cache_path).read_text(encoding="utf-8"))
    for pid, entry in cache.items():
        cid = (entry or {}).get("cve_id")
        if cid:
            acc[pid].add(cid)
    return {pid: sorted(ids) for pid, ids in acc.items() if ids}


def candidate_keys(parent_key, dep_name):
    """npm nested resolution scopes, nearest first, ending at root level."""
    if not parent_key:
        return ["node_modules/" + dep_name]
    candidates = [parent_key + "/node_modules/" + dep_name]
    segments = parent_key.split("/node_modules/")
    for i in range(len(segments) - 1, 0, -1):
        scope = "/node_modules/".join(segments[:i])
        candidates.append(scope + "/node_modules/" + dep_name)
    candidates.append("node_modules/" + dep_name)
    return candidates


def resolve_edge(parent_key, dep_name, model):
    for candidate in candidate_keys(parent_key, dep_name):
        if candidate in model["by_name"].get(dep_name, ()):
            return candidate
    return None


def _name_of(pid):
    return pid.rsplit("@", 1)[0]


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_one(path, printed_advisory_ids, model, advisories):
    result = {
        "path": path,
        "pass": False,
        "failing_edge": None,
        "failing_check": None,
    }
    if not path:
        result["failing_check"] = "EMPTY_PATH"
        return result
    if path[0] != model["root_pid"]:
        result["failing_check"] = "ROOT_MISMATCH"
        result["failing_edge"] = {
            "from": None,
            "to": path[0],
            "reason": "first element is not the project root " + model["root_pid"],
        }
        return result

    nodes = model["nodes"]
    pid_index = model["pid_index"]
    chosen = []
    last_failure = [None]

    def rec(i, used):
        if i == len(path):
            endpoint = path[-1]
            known = advisories.get(endpoint, [])
            if not known:
                last_failure[0] = {
                    "from": path[-2] if len(path) > 1 else None,
                    "to": endpoint,
                    "reason": "endpoint_has_no_advisory_id_in_source",
                }
                return False
            printed = printed_advisory_ids or []
            if not set(printed).issubset(set(known)):
                last_failure[0] = {
                    "from": path[-2] if len(path) > 1 else None,
                    "to": endpoint,
                    "reason": "printed_advisory_ids_not_subset_of_source",
                }
                return False
            return True

        pid = path[i]
        options = [""] if i == 0 else list(pid_index.get(pid, ()))
        if not options:
            last_failure[0] = {
                "from": path[i - 1] if i > 0 else None,
                "to": pid,
                "reason": "no_lockfile_node_with_exact_name_and_version",
            }
            return False

        for key in options:
            if key in used:
                last_failure[0] = {
                    "from": path[i - 1] if i > 0 else None,
                    "to": pid,
                    "reason": "repeated_lockfile_node_key_path_not_simple",
                }
                continue
            if nodes[key]["pid"] != pid:
                last_failure[0] = {
                    "from": path[i - 1] if i > 0 else None,
                    "to": pid,
                    "reason": "endpoint_version_mismatch",
                }
                continue
            if i > 0:
                parent_key = chosen[-1]
                dep_name = _name_of(pid)
                if dep_name not in nodes[parent_key]["deps"]:
                    last_failure[0] = {
                        "from": path[i - 1],
                        "to": pid,
                        "reason": "dependency_not_declared_by_parent",
                    }
                    continue
                resolved = resolve_edge(parent_key, dep_name, model)
                if resolved != key:
                    last_failure[0] = {
                        "from": path[i - 1],
                        "to": pid,
                        "reason": "nested_node_modules_resolution_mismatch_resolved_to:" + str(resolved),
                    }
                    continue
            chosen.append(key)
            if rec(i + 1, used | {key}):
                return True
            chosen.pop()
        return False

    ok = rec(0, set())
    result["pass"] = bool(ok)
    if not ok:
        result["failing_edge"] = last_failure[0]
        edge = last_failure[0] or {}
        reason = edge.get("reason", "")
        if reason.startswith("endpoint_") or reason.startswith("printed_"):
            result["failing_check"] = "ADVISORY_ENDPOINT"
        elif "version" in reason:
            result["failing_check"] = "VERSION"
        elif "repeated" in reason:
            result["failing_check"] = "NOT_SIMPLE"
        else:
            result["failing_check"] = "EDGE"
    return result


def verify_document(flagged_doc, model, advisories):
    rows = []
    for rec in flagged_doc.get("flagged", []):
        for idx, path in enumerate(rec.get("paths", [])):
            row = verify_one(path, rec.get("advisory_ids", []), model, advisories)
            row["package"] = rec.get("package")
            row["path_index"] = idx
            rows.append(row)
        if not rec.get("paths"):
            rows.append({
                "package": rec.get("package"),
                "path_index": None,
                "path": [],
                "pass": False,
                "failing_edge": None,
                "failing_check": "NO_PATH_PRINTED",
            })
    total = len(rows)
    passed = sum(1 for r in rows if r["pass"])
    return {
        "schema": "vulnchain-proof/verify_report/1",
        "lockfile": flagged_doc.get("lockfile"),
        "flagged_packages_source": "flagged_packages.json",
        "advisory_source": flagged_doc.get("advisory_source", []),
        "paths": rows,
        "counts": {
            "paths_total": total,
            "paths_pass": passed,
            "paths_fail": total - passed,
            "packages_total": len(flagged_doc.get("flagged", [])),
            "packages_with_no_path": sum(1 for r in rows if r["failing_check"] == "NO_PATH_PRINTED"),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="verify_paths.py")
    ap.add_argument("lockfile")
    ap.add_argument("flagged_json")
    ap.add_argument("--kb", required=True, help="phase5/bench_run/vulnchain_graph.json")
    ap.add_argument("--cache", required=True, help="phase5/bench_run/osv_cache.json")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args(argv)

    model = parse_lockfile(args.lockfile)
    advisories = load_advisories(args.kb, args.cache)
    flagged_doc = json.loads(Path(args.flagged_json).read_text(encoding="utf-8"))
    report = verify_document(flagged_doc, model, advisories)

    c = report["counts"]
    print("verify_paths.py (independent parser; stdlib imports only)")
    print("  lockfile entries : %d" % len(model["nodes"]))
    print("  advisory ids     : %d pids" % len(advisories))
    print("  paths_total      : %d" % c["paths_total"])
    print("  paths_pass       : %d" % c["paths_pass"])
    print("  paths_fail       : %d" % c["paths_fail"])
    for r in report["paths"]:
        if not r["pass"]:
            print("  FAIL %s %s %s" % (r["package"], r["failing_check"], r["failing_edge"]))
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("  wrote %s" % out)
    return 0 if c["paths_fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
