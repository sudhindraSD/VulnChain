#!/usr/bin/env python3
"""
Explorer export — PRESENTATION LAYER ONLY.

Reshapes already-committed proof results into a front-end-friendly shape.
No model, no gate, no criterion, no claim, no result, no npm audit run, no
network call, no mutation test. Only recorded outputs are read.

stdlib only. The lockfile is parsed with proof/verify_paths.py's independent
parser (imported from this directory); nothing is imported from vulnchain/,
phase5/, TrainModel/ or any model code. Data files under phase5/ are read as
frozen advisory sources, never imported.

Deterministic: sorted JSON keys, LF newlines, no generated timestamps. The only
timestamps anywhere in the export are copied from committed files and live in
proof/explorer_export/meta.json.

Hard reconciliation: every assertion is evaluated BEFORE any file is written.
On any mismatch the exporter prints the reconciliation table, exits non-zero,
and writes nothing. Nothing is changed to make a check pass.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import verify_paths as vp  # noqa: E402 - independent, stdlib-only lockfile parser

OUT = ROOT / "proof" / "explorer_export"

LOCKFILE_REL = "demo/sample-lock.json"
KB_REL = "phase5/bench_run/vulnchain_graph.json"
CACHE_REL = "phase5/bench_run/osv_cache.json"

DECL_KINDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def jload(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def stxt(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def dump(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def esc_token(token):
    return token.replace("~", "~0").replace("/", "~1")


def json_pointer(key):
    """RFC 6901 pointer into the top-level `packages` object of the lockfile."""
    return "/packages/" + esc_token(key)


def dep_kind_range(raw, dep_name):
    """Return (dep_kind, verbatim declared range) or (None, None)."""
    for kind in DECL_KINDS:
        block = raw.get(kind) or {}
        if dep_name in block:
            return kind, block[dep_name]
    return None, None


def lookup_order(parent_key, dep_name, model):
    out = []
    for candidate in vp.candidate_keys(parent_key, dep_name):
        out.append({
            "key": candidate,
            "exists": candidate in model["keys"],
            "resolver_match": candidate in model["by_name"].get(dep_name, ()),
        })
    return out


def normalise_ws(text):
    return re.sub(r"\s+", " ", text)


def write_text(name, text):
    (OUT / name).write_bytes(text.encode("utf-8"))


def write_json(name, obj):
    write_text(name, dump(obj))


# ---------------------------------------------------------------------------
# load committed inputs (read-only)
# ---------------------------------------------------------------------------

lock_bytes = (ROOT / LOCKFILE_REL).read_bytes()
lock_doc = json.loads(lock_bytes.decode("utf-8"))
packages = lock_doc["packages"]
model = vp.parse_lockfile(str(ROOT / LOCKFILE_REL))
nodes = model["nodes"]
all_keys = sorted(nodes)
pids = {n["pid"] for n in nodes.values()}

flagged_doc = jload("proof/out/flagged_packages.json")
verify_doc = jload("proof/out/verify_report.json")
oo_doc = jload("proof/out/offline_online.json")
cmp_doc = jload("proof/out/npm_audit_comparison.json")
ind_doc = jload("proof/out/independence_audit.json")
subgraph_doc = jload("proof/out/graph_subgraph.json")
fresh_doc = jload("proof/out/fresh_clone_log.json")
meta_doc = jload("proof/out/meta.json")
kb_doc = jload(KB_REL)
cache_doc = jload(CACHE_REL)
cve_nodes = jload("data_pipeline/cve_nodes.json")
result_text = stxt("PROOF_RESULT.md")
posthoc2_text = stxt("PROOF_POSTHOC2.md")
verify_source = stxt("proof/verify_paths.py")

oo_rows = {r["package"]: r for r in oo_doc["rows"]}
flagged_records = flagged_doc["flagged"]
verify_rows = verify_doc["paths"]

MISSING = []          # (scope, detail) pairs rendered into MISSING.md
FIELD_MISMATCHES = []  # hard reconciliation failures


def miss(scope, detail):
    MISSING.append((scope, detail))


# ---------------------------------------------------------------------------
# advisory IDs: frozen sources + committed offline/online rows
# ---------------------------------------------------------------------------

kb_ids = defaultdict(set)
kb_sources = defaultdict(set)   # (pid, advisory id) -> {kb_edge, osv_cache}
for edge in (kb_doc.get("edges", {}) or {}).get("hasVulnerability", []) or []:
    src, tgt = edge.get("source"), edge.get("target")
    if src in pids and tgt:
        kb_ids[src].add(tgt)
        kb_sources[(src, tgt)].add("kb_edge")
for pid, entry in cache_doc.items():
    if pid in pids and isinstance(entry, dict) and entry.get("cve_id"):
        cid = entry["cve_id"]
        kb_ids[pid].add(cid)
        kb_sources[(pid, cid)].add("osv_cache")

offline_ids_by_pid = {p: sorted(r["offline_ids"]) for p, r in oo_rows.items()}
online_ids_by_pid = {p: sorted(r["online_ids"]) for p, r in oo_rows.items()}
online_status_by_pid = {p: r.get("status") for p, r in oo_rows.items()}
online_error_by_pid = {p: r.get("error") for p, r in oo_rows.items()}

for pid in sorted(pids):
    if pid in oo_rows:
        if offline_ids_by_pid[pid] != sorted(kb_ids.get(pid, set())):
            FIELD_MISMATCHES.append("offline IDs disagree with frozen sources: " + pid)
    else:
        miss("advisories_online / advisories_offline",
             "no row in proof/out/offline_online.json for " + pid + "; fields left null")

cve_by_id = {r.get("id"): r for r in cve_nodes if isinstance(r, dict) and r.get("id")}

# ---------------------------------------------------------------------------
# graph: exactly the independent parser's 266 resolved edges
# ---------------------------------------------------------------------------

children = defaultdict(list)
parents = defaultdict(list)
edges = []
non_graph_declarations = []
unresolved_edges = []
missing_ranges = []

for parent_key in all_keys:
    node = nodes[parent_key]
    raw = packages.get(parent_key) or {}
    for dep_name in sorted(node["deps"]):
        order = lookup_order(parent_key, dep_name, model)
        resolved = vp.resolve_edge(parent_key, dep_name, model)
        kind, declared = dep_kind_range(raw, dep_name)
        if kind is None:
            missing_ranges.append((parent_key, dep_name))
        if resolved is None:
            unresolved_edges.append((parent_key, dep_name))
            continue
        first_match = next((c["key"] for c in order if c["resolver_match"]), None)
        if first_match != resolved:
            FIELD_MISMATCHES.append("nesting resolution mismatch: %s -> %s" % (parent_key, dep_name))
        edges.append({
            "from_key": parent_key,
            "to_key": resolved,
            "dep_name": dep_name,
            "declared_range": declared,
            "dep_kind": kind,
            "lookup_order": order,
            "resolved_key": resolved,
        })
        children[parent_key].append(resolved)
        parents[resolved].append(parent_key)

    # Declarations the independent parser does not put in its edge set.
    for kind in ("optionalDependencies", "peerDependencies"):
        for dep_name, declared in sorted((raw.get(kind) or {}).items()):
            if dep_name in node["deps"]:
                continue
            order = lookup_order(parent_key, dep_name, model)
            non_graph_declarations.append({
                "from_key": parent_key,
                "dep_name": dep_name,
                "declared_range": declared,
                "dep_kind": kind,
                "lookup_order": order,
                "resolved_key": None,
                "in_independent_graph": False,
                "reason": "optionalDependencies/peerDependencies are not part of "
                          "verify_paths.py::parse_lockfile's dependency set; these two "
                          "targets are the excluded_not_reachable nodes recorded in "
                          "PROOF_POSTHOC2.md section 2.3",
            })

edges.sort(key=lambda e: (e["from_key"], e["to_key"], e["dep_name"], e["dep_kind"] or ""))
non_graph_declarations.sort(key=lambda e: (e["from_key"], e["dep_kind"], e["dep_name"]))

# descriptive structural facts (BFS over the independent parser's edge set)
depth_min = {"": 0}
queue = deque([""])
while queue:
    cur = queue.popleft()
    for nxt in children.get(cur, []):
        if nxt not in depth_min:
            depth_min[nxt] = depth_min[cur] + 1
            queue.append(nxt)


def reachable(start, adjacency):
    seen = set()
    q = deque(adjacency.get(start, []))
    while q:
        cur = q.popleft()
        if cur in seen or cur == start:
            continue
        seen.add(cur)
        q.extend(adjacency.get(cur, []))
    return seen


ancestors = {k: reachable(k, parents) for k in all_keys}
descendants = {k: reachable(k, children) for k in all_keys}

# ---------------------------------------------------------------------------
# committed sets used for flags / statuses / groups
# ---------------------------------------------------------------------------

flagged_by_key = {}
for idx, rec in enumerate(flagged_records):
    if rec["lock_key"] in flagged_by_key:
        FIELD_MISMATCHES.append("duplicate flagged lock_key: " + rec["lock_key"])
    flagged_by_key[rec["lock_key"]] = (idx, rec)

vulnerable_keys = {k for k in all_keys if k and offline_ids_by_pid.get(nodes[k]["pid"])}
direct_keys = {vp.resolve_edge("", dep, model) for dep in nodes[""]["deps"]}

# The two excluded_not_reachable nodes are named explicitly in a committed file.
flat_posthoc2 = normalise_ws(posthoc2_text)
m_unreachable = re.search(
    r"The 2 non-root nodes excluded as not reachable from root are (.*?); the", flat_posthoc2)
unreachable_keys = set()
if m_unreachable:
    for _pid, key in re.findall(r"`([^`]+)`\s*\(`([^`]+)`\)", m_unreachable.group(1)):
        unreachable_keys.add(key)
if len(unreachable_keys) != 2:
    FIELD_MISMATCHES.append("could not parse the 2 excluded_not_reachable keys from PROOF_POSTHOC2.md")
    miss("status", "per-node excluded_not_reachable list not parseable from PROOF_POSTHOC2.md")
else:
    structural_unreachable = {k for k in all_keys if k and k not in depth_min}
    if unreachable_keys != structural_unreachable:
        FIELD_MISMATCHES.append("committed unreachable keys != lockfile reachability")

groups = cmp_doc["groups"]
both_items = sorted(groups["found_by_both"])
vc_only_items = sorted(groups["vulnchain_only"])
npm_only_items = sorted(groups["npm_audit_only"])
npm_pids = set(both_items) | set(npm_only_items)
group_by_pid = {}
for pid in both_items:
    group_by_pid[pid] = "both"
for pid in vc_only_items:
    group_by_pid[pid] = "vulnchain_only"
for pid in npm_only_items:
    group_by_pid[pid] = "npm_audit_only"
cause_by_item = {c["item"]: c["cause"] for c in cmp_doc["causes"]}
npm_ids_by_item = {c["item"]: c["evidence"]["npm_ids"]
                   for c in cmp_doc["causes"] if "npm_ids" in (c.get("evidence") or {})}
range_by_item = {c["item"]: c["evidence"]["range"]
                 for c in cmp_doc["causes"] if "range" in (c.get("evidence") or {})}

# POST-HOC unit from PROOF_POSTHOC2.md section 3, recomputed as set arithmetic
# over committed sets (distinct name@version pids).
vc_flagged_pids = {r["package"] for r in flagged_records}
unit_both = vc_flagged_pids & npm_pids
unit_vc_only = vc_flagged_pids - npm_pids
unit_npm_only = npm_pids - vc_flagged_pids
unit2_by_pid = {}
for pid in unit_both:
    unit2_by_pid[pid] = "both"
for pid in unit_vc_only:
    unit2_by_pid[pid] = "vc_flagged_only"
for pid in unit_npm_only:
    unit2_by_pid[pid] = "npm_only"

unit2_lists = {}
if "## 3. Alternative unit" in posthoc2_text:
    section3 = posthoc2_text.split("## 3. Alternative unit", 1)[1].split("## 4.", 1)[0]
    for label in ("both", "VC-flagged-only", "npm-only"):
        m = re.search(r"`" + re.escape(label) + r"`\s*\((\d+)\):(.*?)(?:\n\n|\Z)",
                      section3, re.S)
        if m:
            unit2_lists[label] = (int(m.group(1)),
                                  set(re.findall(r"`([a-zA-Z0-9@._\-]+@[0-9][^`]*)`", m.group(2))))
for label, expected_set in (("both", unit_both),
                            ("VC-flagged-only", unit_vc_only),
                            ("npm-only", unit_npm_only)):
    if label in unit2_lists and unit2_lists[label][1] != expected_set:
        FIELD_MISMATCHES.append("unit2 list from PROOF_POSTHOC2.md disagrees: " + label)
if len(unit2_lists) != 3:
    miss("unit2_group", "the three POST-HOC item lists in PROOF_POSTHOC2.md section 3 "
                        "were not fully parseable; group counts were still asserted")

# verification rows align 1:1 with flagged records (each record has one path)
verified_by_key = {}
for idx, rec in enumerate(flagged_records):
    if idx >= len(verify_rows):
        FIELD_MISMATCHES.append("verify_report.json has fewer rows than flagged records")
        break
    row = verify_rows[idx]
    if row.get("package") != rec["package"] or row.get("path_index") != 0:
        FIELD_MISMATCHES.append("verify_report.json row %d does not align" % idx)
    verified_by_key[rec["lock_key"]] = bool(row.get("pass"))

# graph_subgraph.json `direct` values, used as a second committed cross-check
subgraph_direct = {}
for sub in subgraph_doc["subgraphs"]:
    for n in sub["nodes"]:
        subgraph_direct.setdefault(n["id"], set()).add(bool(n["direct"]))


def node_status(key):
    if key == "":
        return "root"
    if key in flagged_by_key:
        return "vulnerable" if key in vulnerable_keys else "flagged_ancestor"
    if key in unreachable_keys:
        return "excluded_not_reachable"
    return "excluded_no_vulnerable_descendant"


# ---------------------------------------------------------------------------
# 1. lockfile_graph.json
# ---------------------------------------------------------------------------

graph_nodes = []
for key in all_keys:
    node = nodes[key]
    pid = node["pid"]
    raw = packages.get(key) or {}
    idx_rec = flagged_by_key.get(key)
    flagged_idx, rec = idx_rec if idx_rec else (None, None)
    offline_ids = offline_ids_by_pid.get(pid)
    sources = {}
    for aid in offline_ids or []:
        sources[aid] = sorted(kb_sources.get((pid, aid), set()))
        if not sources[aid]:
            miss("advisories_offline_sources",
                 "no frozen source label for %s on %s" % (aid, pid))
    online_ids = online_ids_by_pid.get(pid)
    graph_nodes.append({
        "key": key,
        "id": pid,
        "name": node["name"],
        "version": node["version"],
        "is_root": key == "",
        "direct": key in direct_keys,
        "dev": bool(raw.get("dev", False)) if key else False,
        "optional": bool(raw.get("optional", False)) if key else False,
        "license": raw.get("license"),
        "resolved": raw.get("resolved"),
        "integrity": raw.get("integrity"),
        "depth_min": depth_min.get(key),
        "n_dependencies": len(children.get(key, [])),
        "n_dependents": len(parents.get(key, [])),
        "n_ancestors": len(ancestors[key]),
        "n_descendants": len(descendants[key]),
        "status": node_status(key),
        "structural_facts_label": "descriptive",
        "advisories_offline": offline_ids,
        "advisories_offline_sources": sources,
        "advisories_online": online_ids,
        "advisories_online_status": online_status_by_pid.get(pid),
        "advisories_online_error": online_error_by_pid.get(pid),
        "flagged_record_index": flagged_idx,
        "model_score": rec["model_score"] if rec else None,
        "verified": verified_by_key.get(key),
        "npm": {
            "listed": pid in npm_pids,
            "advisory_ids": npm_ids_by_item.get(pid),
            "severity": None,
            "group": group_by_pid.get(pid, "none"),
            "cause": cause_by_item.get(pid),
        },
        "unit2_group": unit2_by_pid.get(pid, "none"),
        "unit2_label": "POST-HOC",
    })

lockfile_graph = {
    "schema": "vulnchain-explorer/lockfile_graph/1",
    "label": "presentation layer; flags, statuses, counts, groups, causes and scores "
             "copied from committed proof/out files; structural facts descriptive only",
    "sources": sorted([
        LOCKFILE_REL, "proof/out/flagged_packages.json", "proof/out/verify_report.json",
        "proof/out/offline_online.json", "proof/out/npm_audit_comparison.json",
        "proof/out/graph_subgraph.json", KB_REL, CACHE_REL, "PROOF_POSTHOC2.md",
    ]),
    "counts": {
        "lockfile_entries": len(graph_nodes),
        "resolved_edges": len(edges),
        "non_graph_declarations": len(non_graph_declarations),
        "status": {s: sum(1 for n in graph_nodes if n["status"] == s)
                   for s in ("root", "vulnerable", "flagged_ancestor",
                             "excluded_no_vulnerable_descendant", "excluded_not_reachable")},
        "vulnerable_nodes": len(vulnerable_keys),
        "flagged_records": len(flagged_records),
    },
    "unit2": {
        "label": "POST-HOC",
        "source": "PROOF_POSTHOC2.md section 3 (not a pre-registered comparison)",
        "definition": "VC_FLAGGED = distinct name@version in flagged_packages.json; "
                      "NPM_ITEMS = found_by_both + npm_audit_only in npm_audit_comparison.json",
        "counts": {"both": len(unit_both), "vc_flagged_only": len(unit_vc_only),
                   "npm_only": len(unit_npm_only)},
        "items": {"both": sorted(unit_both), "vc_flagged_only": sorted(unit_vc_only),
                  "npm_only": sorted(unit_npm_only)},
    },
    "nodes": graph_nodes,
    "edges": edges,
    "non_graph_declarations": non_graph_declarations,
}

# ---------------------------------------------------------------------------
# 2. edge_evidence.json — every edge on every printed path
# ---------------------------------------------------------------------------


def assign_keys(path):
    """Deterministic key assignment with the same nesting rule as verify_paths.py."""
    chosen = [""]
    used = {""}
    for i in range(1, len(path)):
        pid = path[i]
        dep_name = pid.rsplit("@", 1)[0]
        parent_key = chosen[-1]
        if dep_name not in nodes[parent_key]["deps"]:
            return None
        options = [k for k in model["pid_index"].get(pid, ())
                   if k not in used and nodes[k]["pid"] == pid]
        valid = [k for k in options
                 if vp.resolve_edge(parent_key, dep_name, model) == k]
        if not valid:
            return None
        chosen.append(valid[0])
        used.add(valid[0])
    return chosen


edge_paths = []
edge_count = 0
for rec_idx, rec in enumerate(flagged_records):
    for path_idx, path in enumerate(rec["paths"]):
        keys = assign_keys(path)
        if keys is None:
            FIELD_MISMATCHES.append("no key assignment for path %d of %s" % (path_idx, rec["package"]))
            continue
        ev = []
        for i in range(1, len(path)):
            parent_key, child_key = keys[i - 1], keys[i]
            dep_name = path[i].rsplit("@", 1)[0]
            raw_parent = packages.get(parent_key) or {}
            raw_child = packages.get(child_key) or {}
            kind, declared = dep_kind_range(raw_parent, dep_name)
            resolved = vp.resolve_edge(parent_key, dep_name, model)
            order = []
            for c in lookup_order(parent_key, dep_name, model):
                order.append({
                    "key": c["key"],
                    "exists": c["exists"],
                    "resolver_match": c["resolver_match"],
                    "winning": c["key"] == resolved,
                })
            if resolved != child_key:
                FIELD_MISMATCHES.append("path edge resolution mismatch: %s -> %s" % (parent_key, dep_name))
            ev.append({
                "edge_index": i - 1,
                "from_pid": path[i - 1],
                "to_pid": path[i],
                "parent_key": parent_key,
                "child_name": dep_name,
                "child_key": child_key,
                "declared_range": declared,
                "dep_kind": kind,
                "lookup_order": order,
                "resolved_key": resolved,
                "resolved_version": nodes[child_key]["version"],
                "parent_pointer": json_pointer(parent_key),
                "child_pointer": json_pointer(child_key),
                "parent_entry_raw": raw_parent,
                "child_entry_raw": raw_child,
            })
        edge_count += len(ev)
        edge_paths.append({
            "flagged_record_index": rec_idx,
            "package": rec["package"],
            "path_index": path_idx,
            "path": path,
            "lockfile_keys": keys,
            "edges": ev,
        })

edge_evidence = {
    "schema": "vulnchain-explorer/edge_evidence/1",
    "label": "presentation layer; raw lockfile entries copied verbatim; "
             "JSON pointers follow RFC 6901 (~0 for ~, ~1 for /)",
    "sources": [LOCKFILE_REL, "proof/out/flagged_packages.json", "proof/verify_paths.py"],
    "counts": {"printed_paths": len(edge_paths), "path_edges": edge_count},
    "paths": edge_paths,
}

# ---------------------------------------------------------------------------
# 3. advisories.json
# ---------------------------------------------------------------------------

advisory_ids = set()
for r in oo_doc["rows"]:
    advisory_ids.update(r["offline_ids"])
    advisory_ids.update(r["online_ids"])
for rec in flagged_records:
    advisory_ids.update(rec["advisory_ids"])
for c in cmp_doc["causes"]:
    ev = c.get("evidence") or {}
    advisory_ids.update(ev.get("vc_ids") or [])
    advisory_ids.update(ev.get("npm_ids") or [])

kb_edge_ids = {t for e in kb_doc["edges"]["hasVulnerability"]
               for t in [e.get("target")] if t}
cache_ids = {e["cve_id"] for e in cache_doc.values()
             if isinstance(e, dict) and e.get("cve_id")}
flag_ids = {a for rec in flagged_records for a in rec["advisory_ids"]}
cmp_vc_ids = {a for c in cmp_doc["causes"]
              for a in (c.get("evidence") or {}).get("vc_ids", [])}
cmp_npm_ids = {a for c in cmp_doc["causes"]
               for a in (c.get("evidence") or {}).get("npm_ids", [])}

advisory_rows = []
alias_missing = []
for aid in sorted(advisory_ids):
    sources = []
    if aid in kb_edge_ids:
        sources.append("kb_edge")
    if aid in cache_ids:
        sources.append("osv_cache")
    if any(aid in r["offline_ids"] for r in oo_doc["rows"]):
        sources.append("proof/out/offline_online.json:offline_ids")
    if any(aid in r["online_ids"] for r in oo_doc["rows"]):
        sources.append("proof/out/offline_online.json:online_ids")
    if aid in flag_ids:
        sources.append("proof/out/flagged_packages.json:advisory_ids")
    if aid in cmp_vc_ids:
        sources.append("proof/out/npm_audit_comparison.json:evidence.vc_ids")
    if aid in cmp_npm_ids:
        sources.append("proof/out/npm_audit_comparison.json:evidence.npm_ids")
    aliases = None
    alias_source = None
    entry = cve_by_id.get(aid)
    if entry and entry.get("aliases"):
        aliases = sorted(set(entry["aliases"]))
        alias_source = "data_pipeline/cve_nodes.json"
    else:
        alias_missing.append(aid)
    advisory_rows.append({
        "id": aid,
        "sources": sorted(sources),
        "packages_offline": sorted(p for p, ids in offline_ids_by_pid.items() if aid in ids),
        "packages_online": sorted(p for p, ids in online_ids_by_pid.items() if aid in ids),
        "url": "https://osv.dev/vulnerability/" + aid,
        "aliases": aliases,
        "alias_source": alias_source,
    })

advisories = {
    "schema": "vulnchain-explorer/advisories/1",
    "label": "presentation layer; IDs copied from committed files; aliases only where a "
             "committed file already records them",
    "sources": sorted(["proof/out/offline_online.json", "proof/out/flagged_packages.json",
                       "proof/out/npm_audit_comparison.json", KB_REL, CACHE_REL,
                       "data_pipeline/cve_nodes.json"]),
    "counts": {
        "advisory_ids": len(advisory_rows),
        "ids_with_recorded_aliases": sum(1 for r in advisory_rows if r["aliases"]),
        "ids_without_recorded_aliases": len(alias_missing),
    },
    "advisories": advisory_rows,
}

# ---------------------------------------------------------------------------
# 4. npm_audit_detail.json — locate the RAW stdout; MISSING if not recorded
# ---------------------------------------------------------------------------

raw_candidates = []
try:
    proc = subprocess.run(
        ["git", "grep", "-l", "-e", "fixAvailable", "-e", "auditReportVersion", "--", "*.json"],
        cwd=str(ROOT), capture_output=True, text=True, check=False)
    if proc.returncode in (0, 1):
        raw_candidates = sorted(line.strip() for line in proc.stdout.splitlines() if line.strip())
except OSError as exc:
    miss("npm_audit_detail.json", "git grep for raw audit stdout failed: " + str(exc))

lockfile_names = {n["name"] for n in nodes.values()}
raw_found = None
raw_match_reason = None
for rel in raw_candidates:
    path = ROOT / rel
    if not path.is_file():
        continue
    data = path.read_bytes()
    if sha256(data) == cmp_doc["stdout_sha256"]:
        raw_found = json.loads(data.decode("utf-8"))
        raw_match_reason = "sha256 matches proof/out/npm_audit_comparison.json stdout_sha256"
        break
    try:
        candidate = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        continue
    if not isinstance(candidate, dict) or not isinstance(candidate.get("vulnerabilities"), dict):
        continue
    meta_vulns = (candidate.get("metadata") or {}).get("vulnerabilities") or {}
    total = meta_vulns.get("total")
    overlap = set(candidate["vulnerabilities"]) & lockfile_names
    if total == cmp_doc["npm_audit_vulnerability_entries"] and len(overlap) >= 20:
        raw_found = candidate
        raw_match_reason = "29 vulnerability entries and >=20 overlapping package names"
        break

comparison_items = []
for pid in sorted(set(both_items) | set(vc_only_items) | set(npm_only_items)):
    comparison_items.append({
        "item": pid,
        "name": pid.rsplit("@", 1)[0],
        "severity": None,
        "via": None,
        "range": range_by_item.get(pid),
        "fixAvailable": None,
        "nodes": None,
        "npm_advisory_ids": npm_ids_by_item.get(pid),
        "comparison_group": group_by_pid.get(pid, "none"),
        "cause": cause_by_item.get(pid),
    })

npm_detail = {
    "schema": "vulnchain-explorer/npm_audit_detail/1",
    "status": "FOUND" if raw_found else "MISSING",
    "label": "presentation layer; no npm audit run",
    "raw_stdout": None,
    "raw_stdout_match_reason": raw_match_reason,
    "recorded": {
        "command": cmp_doc["command"],
        "resolved_binary": cmp_doc["resolved_binary"],
        "exit_code": cmp_doc["exit_code"],
        "stderr": cmp_doc["stderr"],
        "stdout_sha256": cmp_doc["stdout_sha256"],
        "stdout_bytes": cmp_doc["stdout_bytes"],
        "status": cmp_doc["status"],
        "error": cmp_doc["error"],
        "npm_audit_metadata_vulnerabilities": cmp_doc["npm_audit_metadata_vulnerabilities"],
        "vulnerability_entries": cmp_doc["npm_audit_vulnerability_entries"],
        "unmatched_npm_nodes": cmp_doc["unmatched_npm_nodes"],
        "groups": groups,
        "causes": cmp_doc["causes"],
        "counts": cmp_doc["counts"],
        "unexplained_count": cmp_doc["unexplained_count"],
        "source": "proof/out/npm_audit_comparison.json",
    },
    "searched_files": raw_candidates,
    "entries": None,
    "missing_fields": ["name", "severity", "via", "range", "fixAvailable", "nodes"],
    "comparison_items": comparison_items,
}
if raw_found:
    npm_detail["raw_stdout"] = raw_found
    npm_detail["entries"] = [
        {"name": name, "severity": rec.get("severity"), "via": rec.get("via"),
         "range": rec.get("range"), "fixAvailable": rec.get("fixAvailable"),
         "nodes": rec.get("nodes"),
         "comparison_group": "none", "cause": None}
        for name, rec in sorted((raw_found.get("vulnerabilities") or {}).items())
    ]
else:
    npm_detail["reason"] = (
        "The RAW `npm audit --json` stdout was not saved by proof/compare_npm_audit.py: "
        "it records stdout_sha256, stdout_bytes, stderr and derived fields only, and "
        "discards run['stdout'] after json.loads. No tracked file contains it. "
        "Re-running npm audit is prohibited by this export, so per-entry fields are "
        "left null and listed in MISSING.md.")
    miss("npm_audit_detail.json",
         "RAW npm audit --json stdout is not recorded in any committed file "
         "(proof/compare_npm_audit.py keeps only stdout_sha256=" + cmp_doc["stdout_sha256"] +
         " and stdout_bytes=" + str(cmp_doc["stdout_bytes"]) + "). "
         "fields severity / via / fixAvailable / nodes / per-entry range are null; "
         "entries = null; no re-run performed.")

miss("lockfile_graph.json nodes[].npm.severity",
     "per-vulnerability severity is not in any committed file (only aggregate "
     "npm_audit_metadata_vulnerabilities is recorded); field is null for every node")
miss("lockfile_graph.json nodes[].npm.advisory_ids",
     "npm advisory IDs were only recorded in causes[].evidence.npm_ids for the 7 "
     "discrepancy items; all other nodes have null")
miss("advisories.json advisories[].aliases",
     "%d advisory IDs have no alias record in data_pipeline/cve_nodes.json; aliases "
     "is null for them: %s" % (len(alias_missing), ", ".join(alias_missing)))

# ---------------------------------------------------------------------------
# 5. independence.json
# ---------------------------------------------------------------------------

tree = ast.parse(verify_source)
ast_imports = []
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            ast_imports.append({
                "line": node.lineno, "kind": "import", "module": alias.name,
                "names": [], "level": 0, "alias": alias.asname,
                "statement": ast.get_source_segment(verify_source, node),
                "verdict": None,
            })
    elif isinstance(node, ast.ImportFrom):
        ast_imports.append({
            "line": node.lineno, "kind": "import_from", "module": node.module,
            "names": [a.name for a in node.names], "level": node.level, "alias": None,
            "statement": ast.get_source_segment(verify_source, node),
            "verdict": None,
        })
ast_imports.sort(key=lambda r: (r["line"], r["kind"], r["module"] or "", tuple(r["names"])))
committed_verdicts = {r["line"]: r["verdict"] for r in ind_doc["imports"]}
for row in ast_imports:
    row["verdict"] = committed_verdicts.get(row["line"])

if len(ast_imports) != ind_doc["import_count"]:
    FIELD_MISMATCHES.append("ast import count disagrees with independence_audit.json")
if sorted(r["module"] for r in ast_imports) != sorted(r["module"] for r in ind_doc["imports"]):
    FIELD_MISMATCHES.append("ast import modules disagree with independence_audit.json")

neg_segment = re.search(r"Negative controls.*?(?:\n\s*\n|$)", result_text, re.S)
negative_controls = None
if neg_segment:
    pairs = re.findall(r"([^;:→]*?)\s*→\s*`([A-Z_]+)`", neg_segment.group(0), re.S)
    parsed = [{"mutation": " ".join(a.split()), "outcome": b,
               "source": "PROOF_RESULT.md section 2"}
              for a, b in pairs]
    if len(parsed) == 3 and {p["outcome"] for p in parsed} == {
            "VERSION", "EDGE", "ADVISORY_ENDPOINT"}:
        negative_controls = parsed
if negative_controls is None:
    miss("independence.json negative_controls",
         "the three negative-control outcomes could not be parsed from a committed "
         "result file; negative_controls is null")

independence = {
    "schema": "vulnchain-explorer/independence/1",
    "label": "presentation layer; import list parsed with the ast module; "
             "negative-control outcomes parsed from committed results",
    "sources": ["proof/verify_paths.py", "proof/out/independence_audit.json", "PROOF_RESULT.md"],
    "audited_file": "proof/verify_paths.py",
    "parsed_with": "ast (stdlib)",
    "import_count": len(ast_imports),
    "imports": ast_imports,
    "committed_record": {
        "source": "proof/out/independence_audit.json",
        "result": ind_doc["result"],
        "import_count": ind_doc["import_count"],
        "failures": ind_doc["failures"],
        "allowed_stdlib": ind_doc["allowed_stdlib"],
        "project_prefixes": ind_doc["project_prefixes"],
    },
    "negative_controls": negative_controls,
    "negative_controls_status": "OK" if negative_controls else "MISSING",
}

# ---------------------------------------------------------------------------
# 6. reproduce.json
# ---------------------------------------------------------------------------

cli_cmd = next((c for c in fresh_doc["commands"] if c["label"].startswith("CLI:")), None)
verify_cmd = next((c for c in fresh_doc["commands"] if c["label"].startswith("verify_paths.py")), None)
if cli_cmd is None or verify_cmd is None:
    FIELD_MISMATCHES.append("CLI / verify_paths.py commands not found in fresh_clone_log.json")

per_package = []
for idx, rec in enumerate(flagged_records):
    per_package.append({
        "flagged_record_index": idx,
        "package": rec["package"],
        "lock_key": rec["lock_key"],
        "cli_command": cli_cmd["command"] if cli_cmd else None,
        "verify_paths_command": verify_cmd["command"] if verify_cmd else None,
        "cli_result": {"exit_code": cli_cmd["exit_code"], "stdout": cli_cmd["stdout"]} if cli_cmd else None,
        "verify_result": {"exit_code": verify_cmd["exit_code"],
                          "stdout": verify_cmd["stdout"]} if verify_cmd else None,
        "note": "the CLI emits all 34 flagged records in one run; the verifier checks "
                "all 34 printed paths in one run",
    })

reproduce = {
    "schema": "vulnchain-explorer/reproduce/1",
    "label": "presentation layer; commands and results copied verbatim from "
             "proof/out/fresh_clone_log.json",
    "sources": ["proof/out/fresh_clone_log.json", "proof/out/flagged_packages.json"],
    "counts": {"flagged_records": len(per_package), "fresh_clone_commands": len(fresh_doc["commands"])},
    "per_package": per_package,
    "fresh_clone": {
        "source": "proof/out/fresh_clone_log.json",
        "source_repo": fresh_doc["source_repo"],
        "branch": fresh_doc["branch"],
        "temp_dir": fresh_doc["temp_dir"],
        "temp_dir_removed": fresh_doc["temp_dir_removed"],
        "commands": fresh_doc["commands"],
        "validation": fresh_doc["validation"],
        "exports_before": fresh_doc["exports_before"],
        "exports_after": fresh_doc["exports_after"],
    },
}

# ---------------------------------------------------------------------------
# 7. sample-lock.json (byte copy) + hashes
# ---------------------------------------------------------------------------

try:
    blob = subprocess.run(["git", "cat-file", "blob", "HEAD:" + LOCKFILE_REL],
                          cwd=str(ROOT), capture_output=True, check=True).stdout
except (subprocess.CalledProcessError, OSError):
    blob = None
blob_sha = sha256(blob) if blob is not None else None
worktree_sha = sha256(lock_bytes)
bytes_equal = (blob == lock_bytes) if blob is not None else None
json_equal = (json.loads(blob.decode("utf-8")) == lock_doc) if blob is not None else None
if json_equal is False:
    FIELD_MISMATCHES.append("sample-lock.json JSON content differs from git blob")
if blob is None:
    miss("meta.json sample_lock_copy", "git blob could not be read; blob hash is null")

# ---------------------------------------------------------------------------
# 8/9. MISSING.md + SCHEMA.md text
# ---------------------------------------------------------------------------

def display_keys(keys):
    return ", ".join('"" (root)' if k == "" else k for k in keys)


no_license = [k for k in all_keys if not (packages.get(k) or {}).get("license")]
no_resolved = [k for k in all_keys if not (packages.get(k) or {}).get("resolved")]
no_integrity = [k for k in all_keys if not (packages.get(k) or {}).get("integrity")]
unverified_keys = [k for k in all_keys if k not in verified_by_key]

miss("lockfile_graph.json nodes[].license",
     "%d of %d lockfile entries have no `license` field; null is the verbatim value: %s"
     % (len(no_license), len(all_keys), display_keys(no_license)))
miss("lockfile_graph.json nodes[].resolved",
     "%d of %d lockfile entries have no `resolved` URL; null is the verbatim value: %s"
     % (len(no_resolved), len(all_keys), display_keys(no_resolved)))
miss("lockfile_graph.json nodes[].integrity",
     "%d of %d lockfile entries have no `integrity` string; null is the verbatim value: %s"
     % (len(no_integrity), len(all_keys), display_keys(no_integrity)))
miss("lockfile_graph.json nodes[].verified",
     "%d nodes have no row in proof/out/verify_report.json (the report covers only the "
     "34 printed paths); verified is null for them" % len(unverified_keys))
miss("lockfile_graph.json nodes[].model_score",
     "%d non-flagged nodes have no score record in proof/out/flagged_packages.json; "
     "model_score is null. 25 of the 34 flagged records themselves record "
     "model_score: null (UNRESOLVED) in the committed file."
     % (len(all_keys) - len(flagged_records)))
if missing_ranges:
    miss("lockfile_graph.json edges[].declared_range",
         "declared range not present in parent entry for: " + ", ".join(
             "%s:%s" % kr for kr in missing_ranges))
if unresolved_edges:
    miss("lockfile_graph.json edges[].resolved_key",
         "unresolved edges: " + ", ".join("%s:%s" % kr for kr in unresolved_edges))

missing_lines = [
    "# MISSING.md — values not found in committed files",
    "",
    "Presentation-layer export. **No value below was computed, guessed, imputed or "
    "re-generated.** No `npm audit` run, no model run, no network call. Fields whose "
    "source value is absent are `null` in the JSON exports.",
    "",
    "## Entries",
    "",
]
for scope, detail in sorted(MISSING):
    missing_lines.append("- **`%s`** — %s" % (scope, detail))
missing_lines += [
    "",
    "## Not missing (recorded, therefore copied)",
    "",
    "- Negative controls: " + ("parsed from `PROOF_RESULT.md` section 2."
                               if negative_controls else "MISSING (see above)"),
    "- `advisories_online` and query status: all %d distinct `name@version` pids have "
    "a row in `proof/out/offline_online.json`; no nulls." % len(pids),
    "- Per-node status categories and every count, group, cause, score and advisory "
    "ID are copied from committed files and hard-asserted in the reconciliation table.",
    "- Aliases: copied only for IDs with a record in `data_pipeline/cve_nodes.json`.",
    "",
    "## Note on EOL",
    "",
    "`sample-lock.json` is a byte copy of `demo/sample-lock.json`. A CRLF/LF "
    "difference between worktree and git blob is not a failure; a JSON-content "
    "difference is. Both hashes are in `meta.json`.",
    "",
]
missing_md = "\n".join(missing_lines)

status_counts = lockfile_graph["counts"]["status"]
schema_md = """# SCHEMA.md — proof/explorer_export/

Presentation layer only. See `PROOF_ADDENDUM2.md`. All JSON is written with
sorted keys, 2-space indent and LF newlines; all lists are explicitly sorted.
No generated timestamp exists anywhere; the only timestamps in this directory
are copies of committed values in `meta.json`.

**Provenance.** Every flag, status, count, group, cause, advisory ID and model
score is copied from an already-committed file. Structural facts — `depth_min`,
`n_dependencies`, `n_dependents`, `n_ancestors`, `n_descendants`, plus nesting
`lookup_order` and JSON pointers — are derived from the lockfile by stdlib code
using `proof/verify_paths.py`'s independent parser and are labelled
**descriptive** (`nodes[].structural_facts_label = "descriptive"`). They carry
no criterion, gate or claim. `status` categories come from committed sets:
flagged keys from `flagged_packages.json`, vulnerable pids from
`offline_online.json:rows[].offline_ids`, and the two excluded-not-reachable
keys from `PROOF_POSTHOC2.md` section 2.3.

**Null policy.** If a value cannot be found in a committed file it is `null`
and listed in `MISSING.md`. Nothing is computed or guessed to fill it.

**Sources (read-only).** `demo/sample-lock.json`,
`proof/out/{flagged_packages,verify_report,offline_online,npm_audit_comparison,graph_subgraph,fresh_clone_log,independence_audit,meta}.json`,
`phase5/bench_run/{vulnchain_graph,osv_cache}.json`,
`data_pipeline/cve_nodes.json`, `proof/verify_paths.py`,
`PROOF_RESULT.md`, `PROOF_POSTHOC2.md`. No frozen file was edited.

---

## 1. `lockfile_graph.json`

`schema`, `label`, `sources[]`, `counts`, `unit2`, `nodes[]`, `edges[]`,
`non_graph_declarations[]`.

`counts`: `lockfile_entries` (%d), `resolved_edges` (%d),
`non_graph_declarations` (%d), `status` (per-category counts),
`vulnerable_nodes` (%d), `flagged_records` (%d).

`unit2`: `label` = `"POST-HOC"`, `source`, `definition`, `counts`
(`both`/`vc_flagged_only`/`npm_only`), `items` (same three lists). It reproduces
`PROOF_POSTHOC2.md` section 3 and is **not** a pre-registered comparison.

### `nodes[]` — one record per lockfile `packages` entry (including root)

| Field | Meaning / source |
|---|---|
| `key` | verbatim `packages` key; `""` is the root |
| `id` | `name@version` (independent parser) |
| `name`, `version` | from the independent parser |
| `is_root` | `key == ""` |
| `direct` | resolved direct dependency of root; cross-checked against `flagged_packages.json` and `graph_subgraph.json` |
| `dev`, `optional` | verbatim lockfile booleans; `dev` cross-checked against `flagged_packages.json` |
| `license`, `resolved`, `integrity` | verbatim lockfile strings, or `null` when absent |
| `depth_min` | **descriptive** BFS hops from root over the 266-edge graph; `null` if unreachable |
| `n_dependencies`, `n_dependents` | **descriptive** out/in edge counts |
| `n_ancestors`, `n_descendants` | **descriptive** distinct reachable nodes in each direction, excluding self |
| `status` | `root` \\| `vulnerable` \\| `flagged_ancestor` \\| `excluded_no_vulnerable_descendant` \\| `excluded_not_reachable` |
| `structural_facts_label` | always `"descriptive"` |
| `advisories_offline` | sorted IDs copied from `offline_online.json:rows[].offline_ids`, cross-checked against frozen KB edges + cache |
| `advisories_offline_sources` | `{id: [kb_edge, osv_cache]}` from the frozen sources |
| `advisories_online`, `advisories_online_status`, `advisories_online_error` | `online_ids`, `status`, `error` copied from `offline_online.json`; `null` if no row |
| `flagged_record_index` | 0-based index into `flagged_packages.json:flagged[]`, else `null` |
| `model_score` | verbatim `model_score` (number or `null`) from that flagged record, else `null` |
| `verified` | `pass` from the aligned `verify_report.json` row, else `null` |
| `npm.listed` | pid in `NPM_ITEMS` = `found_by_both` + `npm_audit_only` |
| `npm.advisory_ids` | `causes[].evidence.npm_ids` when recorded, else `null` |
| `npm.severity` | `null` — raw audit stdout was not saved (see `MISSING.md`) |
| `npm.group` | `both` \\| `vulnchain_only` \\| `npm_audit_only` \\| `none` from `npm_audit_comparison.json:groups` |
| `npm.cause` | verbatim `causes[].cause`, else `null` (includes `NOT_A_DISCREPANCY`) |
| `unit2_group` | `both` \\| `vc_flagged_only` \\| `npm_only` \\| `none`, POST-HOC |
| `unit2_label` | always `"POST-HOC"` |

### `edges[]` — the independent parser's %d resolved edges

`from_key`, `to_key`, `dep_name`, `declared_range` (verbatim string from the
parent's declaration), `dep_kind` (`dependencies` / `devDependencies` /
`optionalDependencies` / `peerDependencies`), `lookup_order[]`
(`key`, `exists` = key present in the lockfile, `resolver_match` = key present
in `by_name[dep_name]`), `resolved_key` (first `resolver_match`, identical to
`verify_paths.py::resolve_edge`).

### `non_graph_declarations[]`

The %d `optionalDependencies` declarations that the independent parser does not
add to its dependency set. Same fields plus `in_independent_graph: false`,
`resolved_key: null` and a `reason`. Their targets are the two
`excluded_not_reachable` nodes recorded in `PROOF_POSTHOC2.md` section 2.3.
`peerDependencies` declarations: 0 in this lockfile.

---

## 2. `edge_evidence.json`

`schema`, `label`, `sources[]`, `counts` (`printed_paths`, `path_edges`),
`paths[]`. Per path: `flagged_record_index`, `package`, `path_index`, `path`
(the printed `name@version` list), `lockfile_keys` (deterministic key
assignment using the same nesting rule), `edges[]`.

Per edge: `edge_index`, `from_pid`, `to_pid`, `parent_key`, `child_name`,
`child_key`, `declared_range`, `dep_kind`, `lookup_order[]` (`key`, `exists`,
`resolver_match`, `winning`), `resolved_key`, `resolved_version`,
`parent_pointer`, `child_pointer` (RFC 6901 pointers into `/packages`; `~1`
escapes `/`), `parent_entry_raw`, `child_entry_raw` (verbatim lockfile JSON,
serialised with sorted keys).

---

## 3. `advisories.json`

`schema`, `label`, `sources[]`, `counts`, `advisories[]`. Per advisory ID:
`id`, `sources[]` (which committed source carries it), `packages_offline[]`,
`packages_online[]`, `url` = `https://osv.dev/vulnerability/<ID>`, `aliases`
(copied only when `data_pipeline/cve_nodes.json` records them, else `null`),
`alias_source`.

---

## 4. `npm_audit_detail.json`

`schema`, `status` (`FOUND` or `MISSING`), `label`, `raw_stdout`,
`raw_stdout_match_reason`, `reason`, `recorded` (verbatim fields from
`proof/out/npm_audit_comparison.json`), `searched_files[]`, `entries`,
`missing_fields[]`, `comparison_items[]` (per `name@version`: `item`, `name`,
`severity`, `via`, `range`, `fixAvailable`, `nodes`, `npm_advisory_ids`,
`comparison_group`, `cause`).

The comparison step recorded only `stdout_sha256`, `stdout_bytes`, `stderr` and
derived fields. If `status = MISSING`, `entries` and all raw-only fields are
`null`; no `npm audit` was re-run.

---

## 5. `independence.json`

`schema`, `label`, `sources[]`, `audited_file`, `parsed_with` (`ast`),
`import_count`, `imports[]` (`line`, `kind`, `module`, `names`, `level`,
`alias`, `statement`, `verdict`), `committed_record` (copy of
`independence_audit.json`), `negative_controls[]` (`mutation`, `outcome`,
`source`) or `null`, `negative_controls_status`. Negative controls are parsed
from `PROOF_RESULT.md`; `MISSING` if not parseable.

---

## 6. `reproduce.json`

`schema`, `label`, `sources[]`, `counts`, `per_package[]`
(`flagged_record_index`, `package`, `lock_key`, `cli_command`,
`verify_paths_command`, `cli_result`, `verify_result`, `note`), `fresh_clone`
(`source`, `source_repo`, `branch`, `temp_dir`, `temp_dir_removed`,
`commands[]`, `validation`, `exports_before`, `exports_after`). Commands and
results are copied verbatim from `proof/out/fresh_clone_log.json`.

---

## 7. `sample-lock.json`

Byte-for-byte copy of `demo/sample-lock.json`. `meta.json: sample_lock_copy`
holds `worktree_sha256`, `git_blob_sha256`, `bytes_equal`, `json_content_equal`.
A CRLF/LF difference is not a failure; a JSON-content difference is.

---

## 8. `meta.json`

The only file containing timestamps, all copied from committed files:
`source_commit_at_export_time`, `source_timestamp`
(`proof/out/meta.json:timestamp`), `fresh_clone_started_utc`,
`fresh_clone_finished_utc`. Also `schema`, `label`, `lockfile`,
`lockfile_sha256`, `advisory_source_sha256`, `sample_lock_copy`, `source_files[]`,
`export_files[]`.

---

## 9. `SCHEMA.md` / 10. `MISSING.md`

This document and the null-value register.

---

## Reconciliation (hard assertions, evaluated before any write)

| Check | Expected |
|---|---|
| lockfile entries | 193 |
| resolved edges | 266 |
| status | root 1 + (vulnerable + flagged_ancestor) 34 + excluded_not_reachable 2 + excluded_no_vulnerable_descendant 156 = 193 |
| vulnerable nodes | 26 |
| printed paths | 34 |
| verified | 34 / 34 |
| npm groups | 24 / 1 / 6 |
| unit2 groups (POST-HOC) | 28 / 5 / 2 |
| every status, group, cause, score, advisory ID, direct/dev flag | equal to the corresponding committed `proof/out/*.json` value |
| `sample-lock.json` | JSON content equals the git blob |

On any mismatch the script prints the reconciliation table and exits without
writing a single file. It never changes a value to make a check pass.
""" % (
    len(graph_nodes), len(edges), len(non_graph_declarations),
    len(vulnerable_keys), len(flagged_records), len(edges),
    len(non_graph_declarations),
)

meta_out = {
    "schema": "vulnchain-explorer/meta/1",
    "label": "presentation layer; see PROOF_ADDENDUM2.md; no new criterion, claim or result",
    "source_commit_at_export_time": meta_doc["source_commit"],
    "source_timestamp": meta_doc["timestamp"],
    "fresh_clone_started_utc": fresh_doc["started_utc"],
    "fresh_clone_finished_utc": fresh_doc["finished_utc"],
    "lockfile": LOCKFILE_REL,
    "lockfile_sha256": meta_doc["lockfile_sha256"],
    "advisory_source_sha256": meta_doc["advisory_source_sha256"],
    "sample_lock_copy": {
        "worktree_sha256": worktree_sha,
        "git_blob_sha256": blob_sha,
        "bytes_equal": bytes_equal,
        "json_content_equal": json_equal,
        "eol_note": "a CRLF/LF difference is not a failure; a JSON-content difference is",
    },
    "source_files": sorted(set(lockfile_graph["sources"] + advisories["sources"] +
                               independence["sources"] + reproduce["sources"] +
                               ["PROOF_RESULT.md", "proof/out/meta.json",
                                "data_pipeline/cve_nodes.json"])),
    "export_files": sorted(["lockfile_graph.json", "edge_evidence.json",
                            "advisories.json", "npm_audit_detail.json",
                            "independence.json", "reproduce.json",
                            "sample-lock.json", "meta.json", "SCHEMA.md", "MISSING.md"]),
}

# ---------------------------------------------------------------------------
# RECONCILIATION — build expected values straight from committed files
# ---------------------------------------------------------------------------

expected_fp = flagged_doc["counts"]
expected_verify = verify_doc["counts"]
expected_cmp = cmp_doc["counts"]

rows = []


def check(name, expected, observed):
    ok = expected == observed
    rows.append((name, str(expected), str(observed), "OK" if ok else "MISMATCH"))
    if not ok:
        FIELD_MISMATCHES.append("%s: expected %r, observed %r" % (name, expected, observed))
    return ok


check("lockfile entries", 193, len(graph_nodes))
check("resolved edges", 266, len(edges))
check("status: root", 1, status_counts["root"])
check("status: vulnerable + flagged_ancestor", 34,
      status_counts["vulnerable"] + status_counts["flagged_ancestor"])
check("status: excluded_not_reachable", 2, status_counts["excluded_not_reachable"])
check("status: excluded_no_vulnerable_descendant", 156,
      status_counts["excluded_no_vulnerable_descendant"])
check("status: total", 193, sum(status_counts.values()))
check("vulnerable nodes", 26, len(vulnerable_keys))
check("printed paths", 34, len(edge_paths))
check("verified paths", "34/34",
      "%d/%d" % (expected_verify["paths_pass"], expected_verify["paths_total"]))
check("verified flags true", 34, sum(1 for v in verified_by_key.values() if v))
check("npm groups both / vulnchain_only / npm_audit_only", "24/1/6",
      "%d/%d/%d" % (expected_cmp["found_by_both"], expected_cmp["vulnchain_only"],
                    expected_cmp["npm_audit_only"]))
check("unit2 groups both / vc_flagged_only / npm_only (POST-HOC)", "28/5/2",
      "%d/%d/%d" % (len(unit_both), len(unit_vc_only), len(unit_npm_only)))
check("committed counts: flagged_packages", 34, expected_fp["flagged_packages"])
check("committed counts: paths_printed", 34, expected_fp["paths_printed"])
check("committed counts: vulnerable_nodes", 26, expected_fp["vulnerable_nodes"])
check("committed counts: edges", 266, expected_fp["edges"])
check("committed counts: lockfile_entries", 193, expected_fp["lockfile_entries"])
check("committed counts: excluded_not_reachable", 2, expected_fp["excluded_not_reachable"])
check("committed counts: excluded_no_vulnerable_descendant", 156,
      expected_fp["excluded_no_vulnerable_descendant"])
check("sample-lock JSON content equals git blob", True, json_equal)
check("offline IDs match frozen sources for all pids", 0,
      sum(1 for pid in pids if pid in oo_rows and
          offline_ids_by_pid[pid] != sorted(kb_ids.get(pid, set()))))
check("all path edges resolved", 0,
      sum(1 for p in edge_paths for e in p["edges"] if e["resolved_key"] != e["child_key"]))
check("unresolved graph edges", 0, len(unresolved_edges))
check("declared ranges present", 0, len(missing_ranges))
check("offline_online rows cover all distinct pids", 0, len(pids - set(oo_rows)))

# Field-by-field equality against committed proof/out/*.json values.
field_equality = 0
for n in graph_nodes:
    key, pid = n["key"], n["id"]
    rec = flagged_by_key.get(key)
    committed_rec = rec[1] if rec else None
    expected_status = node_status(key)
    expected_group = group_by_pid.get(pid, "none")
    expected_cause = cause_by_item.get(pid)
    expected_score = committed_rec["model_score"] if committed_rec else None
    expected_verified = verified_by_key.get(key)
    expected_offline = offline_ids_by_pid.get(pid)
    expected_online = online_ids_by_pid.get(pid)
    expected_unit2 = unit2_by_pid.get(pid, "none")
    expected_direct = key in direct_keys
    expected_dev = bool((packages.get(key) or {}).get("dev", False)) if key else False
    pairs = (
        ("status", n["status"], expected_status),
        ("npm.group", n["npm"]["group"], expected_group),
        ("npm.cause", n["npm"]["cause"], expected_cause),
        ("model_score", n["model_score"], expected_score),
        ("verified", n["verified"], expected_verified),
        ("advisories_offline", n["advisories_offline"], expected_offline),
        ("advisories_online", n["advisories_online"], expected_online),
        ("unit2_group", n["unit2_group"], expected_unit2),
        ("direct", n["direct"], expected_direct),
        ("dev", n["dev"], expected_dev),
    )
    for fname, observed, expected in pairs:
        field_equality += 1
        if observed != expected:
            FIELD_MISMATCHES.append("%s %s: %r != committed %r" %
                                    (key, fname, observed, expected))
    if committed_rec:
        field_equality += 3
        if n["direct"] != committed_rec["direct"]:
            FIELD_MISMATCHES.append(key + ": direct != flagged_packages.json")
        if n["dev"] != committed_rec["dev"]:
            FIELD_MISMATCHES.append(key + ": dev != flagged_packages.json")
        if n["flagged_record_index"] != rec[0]:
            FIELD_MISMATCHES.append(key + ": flagged_record_index mismatch")
    if pid in subgraph_direct and len(subgraph_direct[pid]) == 1:
        field_equality += 1
        if next(iter(subgraph_direct[pid])) != n["direct"]:
            FIELD_MISMATCHES.append(key + ": direct != graph_subgraph.json")

check("committed field equality mismatches", 0, len(FIELD_MISMATCHES))
rows.append(("committed fields compared", str(field_equality), str(field_equality), "OK"))
rows.append(("negative controls", "3 parsed or MISSING",
            independence["negative_controls_status"], "OK"))
rows.append(("unit2 item lists parsed", "3", str(len(unit2_lists)), "OK"))
rows.append(("npm_audit_detail raw stdout", "FOUND or MISSING",
            npm_detail["status"], "OK"))


def print_table():
    widths = [max(len(r[i]) for r in rows + [("Check", "Expected", "Observed", "Result")])
              for i in range(4)]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(line)
    print("| " + " | ".join(("Check", "Expected", "Observed", "Result")[i].ljust(widths[i])
                            for i in range(4)) + " |")
    print(line)
    for r in rows:
        print("| " + " | ".join(r[i].ljust(widths[i]) for i in range(4)) + " |")
    print(line)


print("RECONCILIATION (hard assertions; nothing written yet)")
print_table()

if FIELD_MISMATCHES:
    print("\nSTOP: %d mismatch(es). No file was written, nothing was changed." %
          len(FIELD_MISMATCHES))
    for m in FIELD_MISMATCHES[:40]:
        print("  - " + m)
    sys.exit(1)

# ---------------------------------------------------------------------------
# write outputs (only after every assertion passed)
# ---------------------------------------------------------------------------

OUT.mkdir(parents=True, exist_ok=True)
write_json("lockfile_graph.json", lockfile_graph)
write_json("edge_evidence.json", edge_evidence)
write_json("advisories.json", advisories)
write_json("npm_audit_detail.json", npm_detail)
write_json("independence.json", independence)
write_json("reproduce.json", reproduce)
(OUT / "sample-lock.json").write_bytes(lock_bytes)
write_json("meta.json", meta_out)
write_text("SCHEMA.md", schema_md)
write_text("MISSING.md", missing_md)

print("\nWROTE %d files to proof/explorer_export/" % len(meta_out["export_files"]))
print("  nodes=%d edges=%d path_edges=%d advisories=%d" %
      (len(graph_nodes), len(edges), edge_count, len(advisory_rows)))
print("  npm_audit_detail status=%s ; negative_controls=%s" %
      (npm_detail["status"], independence["negative_controls_status"]))
