"""
Project-side lockfile parser and mechanical path finder for the proof CLI.

This module is deliberately NOT used by proof/verify_paths.py, which has its own
independent parser (see PROOF_PROTOCOL.md section 2).
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from pathlib import Path

MAX_HOPS = 8
MAX_PATHS = 200000


def repo_root() -> Path:
    """.../VulnChain  (this file lives at <root>/vulnchain/proof/graph.py)."""
    return Path(__file__).resolve().parents[2]


def read_lockfile(path: str | Path):
    p = Path(path)
    raw = p.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    return data, hashlib.sha256(raw).hexdigest()


def _walk_v1(deps: dict, parent_key: str, out: dict) -> None:
    for name, meta in deps.items():
        key = (parent_key + "/node_modules/" + name) if parent_key else ("node_modules/" + name)
        children = meta.get("dependencies", {}) or {}
        entry = {
            "version": meta.get("version", "0.0.0"),
            "dev": bool(meta.get("dev", False)),
            "dependencies": {n: "*" for n in children},
        }
        # root-level v1 entries may carry devDependencies too
        for dn in (meta.get("devDependencies", {}) or {}):
            entry["dependencies"].setdefault(dn, "*")
        out[key] = entry
        if children:
            _walk_v1(children, key, out)


def normalise(data: dict):
    """Return (packages_dict, root_name, root_version, root_deps, root_devdeps)."""
    if isinstance(data.get("packages"), dict) and data["packages"]:
        pkgs = data["packages"]
        root = pkgs.get("", {}) or {}
        root_name = root.get("name") or data.get("name") or "root"
        root_version = root.get("version") or data.get("version") or "0.0.0"
        root_deps = dict(root.get("dependencies", {}) or {})
        root_devdeps = dict(root.get("devDependencies", {}) or {})
        return pkgs, root_name, root_version, root_deps, root_devdeps

    # lockfileVersion 1: nested "dependencies" tree -> flat packages-like dict
    deps = data.get("dependencies", {}) or {}
    root_name = data.get("name") or "root"
    root_version = data.get("version") or "0.0.0"
    root_deps = {n: "*" for n in deps}
    pkgs = {
        "": {
            "name": root_name,
            "version": root_version,
            "dependencies": dict(root_deps),
            "devDependencies": {},
        }
    }
    _walk_v1(deps, "", pkgs)
    return pkgs, root_name, root_version, root_deps, {}


def resolve(parent_key: str, dep_name: str, keys: set) -> str | None:
    """npm nested node_modules resolution, nearest-first, ending at root level."""
    candidates = []
    if parent_key == "":
        candidates.append("node_modules/" + dep_name)
    else:
        cur = parent_key
        while True:
            candidates.append(cur + "/node_modules/" + dep_name)
            idx = cur.rfind("/node_modules/")
            if idx < 0:
                break
            cur = cur[:idx]
        candidates.append("node_modules/" + dep_name)
    for c in candidates:
        if c in keys:
            return c
    return None


def build_graph(data: dict):
    """Return (nodes, children, parents, edges, root_key, root_name, root_version)."""
    pkgs, root_name, root_version, root_deps, root_devdeps = normalise(data)
    keys = set(pkgs)
    root_key = ""
    direct_names = set(root_deps) | set(root_devdeps)

    nodes = {}
    for key in sorted(keys):
        meta = pkgs[key] or {}
        if key == root_key:
            name, version = root_name, root_version
            deps = dict(root_deps)
            for dn, dv in root_devdeps.items():
                deps.setdefault(dn, dv)
            dev, direct = False, False
        else:
            name = key.split("node_modules/")[-1]
            version = str(meta.get("version", "0.0.0"))
            deps = dict(meta.get("dependencies", {}) or {})
            for dn in (meta.get("devDependencies", {}) or {}):
                deps.setdefault(dn, "*")
            dev = bool(meta.get("dev", False))
            direct = (key.count("node_modules/") == 1) and (name in direct_names)
        nodes[key] = {
            "key": key,
            "name": name,
            "version": version,
            "pid": f"{name}@{version}",
            "deps": deps,
            "dev": dev,
            "direct": direct,
        }

    children = defaultdict(list)
    parents = defaultdict(list)
    edges = []
    for key in sorted(nodes):
        for dep_name in sorted(nodes[key]["deps"]):
            dst = resolve(key, dep_name, keys)
            if dst is None:
                continue
            edges.append((key, dst))
            children[key].append(dst)
            parents[dst].append(key)
    for k in children:
        children[k] = sorted(set(children[k]), key=lambda x: nodes[x]["pid"])
    for k in parents:
        parents[k] = sorted(set(parents[k]), key=lambda x: nodes[x]["pid"])
    return nodes, children, parents, edges, root_key, root_name, root_version


def depths_from_root(nodes, children, root_key=""):
    depth = {root_key: 0}
    q = deque([root_key])
    while q:
        cur = q.popleft()
        for nxt in children.get(cur, []):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                q.append(nxt)
    return depth


def distances_to_vulnerable(nodes, parents, advisory_off):
    vulnerable = {k for k, n in nodes.items() if advisory_off.get(n["pid"])}
    dist = {k: 0 for k in vulnerable}
    q = deque(sorted(vulnerable, key=lambda k: nodes[k]["pid"]))
    while q:
        cur = q.popleft()
        for par in parents.get(cur, []):
            if par not in dist:
                dist[par] = dist[cur] + 1
                q.append(par)
    return dist, vulnerable


def enumerate_paths(nodes, children, dist, vulnerable, root_key=""):
    """
    All simple root -> first-vulnerable-node paths, <= MAX_HOPS edges, pruned
    to nodes that can still reach a vulnerable node. Deterministic ordering.
    Returns (paths, truncated, cap_reason).
    """
    paths = []
    truncated = False
    cap_reason = None

    def dfs(cur, path, visited):
        nonlocal truncated, cap_reason
        if truncated:
            return
        if len(paths) >= MAX_PATHS:
            truncated, cap_reason = True, "MAX_PATHS"
            return
        if cur in vulnerable and cur != root_key:
            # Record this path, but KEEP exploring: a vulnerable node may itself
            # have vulnerable descendants, and those deeper flagged packages
            # must also appear on a root-to-vulnerable-descendant path.
            paths.append(list(path))
        if len(path) - 1 >= MAX_HOPS:
            truncated, cap_reason = True, "MAX_HOPS"
            return
        for nxt in children.get(cur, []):
            if nxt in visited or nxt not in dist:
                continue
            visited.add(nxt)
            path.append(nxt)
            dfs(nxt, path, visited)
            path.pop()
            visited.remove(nxt)
            if truncated:
                return

    dfs(root_key, [root_key], {root_key})
    return paths, truncated, cap_reason


def select_paths(nodes, paths):
    """For each node on a path, shortest path (tie: lexicographic pid sequence)."""
    best = {}
    for path in paths:
        key = (len(path) - 1, tuple(nodes[k]["pid"] for k in path))
        for node_key in path[1:]:
            if node_key not in best or key < best[node_key][0]:
                best[node_key] = (key, path)
    return best
