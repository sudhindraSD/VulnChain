"""
VulnChain Package Node + dependsOn Edge Extractor
----------------------------------------------------
Walks cloned repos under REPOS_DIR, parses package.json + package-lock.json
(handles monorepos with multiple nested package.json/lockfile pairs), and
builds the 10-dim Package node feature vectors + dependsOn edges per the
locked VulnChain schema.

Stdlib only -- no pip install required.

Feature order (10-dim Package node vector):
  0: is_direct_dependency      (0/1)
  1: is_dev_dependency         (0/1)
  2: out_degree                (int, raw count of declared deps)
  3: depth_in_tree              (int, levels of nesting in node_modules)
  4: version_recency_days       (float, days since this version was published)
  5: versions_behind_latest     (int, approx count of newer versions released)
  6: has_known_cve_history      (0/1) -- PLACEHOLDER, always 0 for now.
                                 Real value requires OSV/NVD/GHSA cross-ref,
                                 which is a separate pipeline stage.
  7: weekly_downloads_log       (float, log10(weekly downloads + 1))
  8: is_deprecated              (0/1)
  9: license_risk_flag          (0/1, 1 if missing/non-standard license)

Output: a single JSON file with "nodes" and "edges" lists.
"""

import json
import os
import re
import urllib.request
import urllib.error
import math
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# CONFIG -- adjust these two paths if needed
# ---------------------------------------------------------------------------
REPOS_DIR = Path(r"C:\Users\Admin\Desktop\Major VulnChain\repos")
OUTPUT_FILE = Path(r"C:\Users\Admin\Desktop\Major VulnChain\package_graph.json")
CACHE_FILE = Path(r"C:\Users\Admin\Desktop\Major VulnChain\npm_registry_cache.json")

COMMON_LICENSES = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "MPL-2.0", "CC0-1.0", "Unlicense"
}

MAX_WORKERS = 10  # concurrent npm registry calls -- keep modest, be polite

# v1 walker instrumentation data, keyed by repo_name.
# Populated by parse_npm_lockfile() when it takes the v1 path.
_v1_instrumentation = {}  # repo_name -> {"depth_truncations": [...], "cycle_breaks": [...]}


# ---------------------------------------------------------------------------
# STEP 1: figure out what kind of lockfile setup each repo has
# ---------------------------------------------------------------------------
def detect_repo_lockfile_strategy(repo_path: Path):
    """A repo can have: a root npm lockfile (covers all nested package.json
    via workspaces), a root yarn lockfile, OR no lockfile at all (rare, but
    happens for libraries like express that intentionally don't commit one).
    Returns one of: ('npm', lockfile_path), ('yarn', lockfile_path), ('none', None)
    """
    root_npm_lock = repo_path / "package-lock.json"
    if root_npm_lock.exists():
        return ("npm", root_npm_lock)

    root_yarn_lock = repo_path / "yarn.lock"
    if root_yarn_lock.exists():
        return ("yarn", root_yarn_lock)

    # fallback: scan for any npm lockfile anywhere (non-root monorepo layouts)
    any_npm = next((p for p in repo_path.rglob("package-lock.json")
                     if "node_modules" not in p.parts), None)
    if any_npm:
        return ("npm", any_npm)

    any_yarn = next((p for p in repo_path.rglob("yarn.lock")
                      if "node_modules" not in p.parts and "docs" not in p.parts), None)
    if any_yarn:
        return ("yarn", any_yarn)

    return ("none", None)


def find_all_package_json(repo_path: Path):
    return [p for p in repo_path.rglob("package.json") if "node_modules" not in p.parts]


# ---------------------------------------------------------------------------
# STEP 2a: parse an npm-style package-lock.json (v1, v2, or v3 format)
# ---------------------------------------------------------------------------
def parse_npm_lockfile(lock_path: Path, root_pkg_json_path: Path, repo_name: str):
    """Returns (nodes_dict, edges_list, status) for one npm lockfile.
    Supports all three lockfileVersion formats:
      v1 (npm 6):  nested "dependencies" tree only
      v2 (npm 7-8): flat "packages" map + nested "dependencies" (backward compat)
      v3 (npm 9+): flat "packages" map only
    """
    with open(root_pkg_json_path, "r", encoding="utf-8") as f:
        pkg_json = json.load(f)
    direct_deps = set(pkg_json.get("dependencies", {}).keys())
    dev_deps = set(pkg_json.get("devDependencies", {}).keys())

    with open(lock_path, "r", encoding="utf-8") as f:
        lock = json.load(f)

    nodes = {}
    edges = []

    packages = lock.get("packages")
    if packages:
        # ---------- v2/v3 path: flat "packages" map ----------
        for key, entry in packages.items():
            if key == "":
                continue
            name = entry.get("name")
            if not name:
                match = re.search(r"node_modules/((?:@[^/]+/)?[^/]+)$", key)
                name = match.group(1) if match else None
            version = entry.get("version")
            if not name or not version:
                continue

            node_id = f"{name}@{version}"
            depth = key.count("node_modules/")
            is_dev = bool(entry.get("dev", False))
            declared_deps = entry.get("dependencies", {})
            out_degree = len(declared_deps)
            is_direct = depth == 1 and (name in direct_deps or name in dev_deps)

            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id, "name": name, "version": version,
                    "is_direct_dependency": int(is_direct),
                    "is_dev_dependency": int(is_dev or name in dev_deps),
                    "out_degree": out_degree, "depth_in_tree": depth,
                    "repo_sources": set(),
                }
            nodes[node_id]["repo_sources"].add(repo_name)

            for dep_name in declared_deps.keys():
                target_id = _resolve_dep_version(packages, key, dep_name)
                if target_id:
                    edges.append((node_id, target_id))

        return nodes, edges, "ok"

    # ---------- v1 path: nested "dependencies" tree ----------
    v1_deps = lock.get("dependencies")
    if not v1_deps:
        return nodes, edges, "empty_lockfile"

    result = _parse_npm_v1_dependencies(
        v1_deps, direct_deps, dev_deps, repo_name
    )
    # v1 parser returns (nodes, edges, status, depth_truncations, cycle_breaks)
    v1_nodes, v1_edges, v1_status = result[0], result[1], result[2]
    # Store instrumentation data for batch callers
    _v1_instrumentation[repo_name] = {
        "depth_truncations": result[3] if len(result) > 3 else [],
        "cycle_breaks": result[4] if len(result) > 4 else [],
    }
    return v1_nodes, v1_edges, v1_status


def _resolve_dep_version(packages, parent_key, dep_name):
    """Best-effort resolution of a declared dependency name to its
    resolved version, by walking up node_modules nesting (npm's actual
    resolution algorithm), falling back to a global name match."""
    parts = parent_key.split("node_modules/")
    for i in range(len(parts), 0, -1):
        candidate_key = "node_modules/".join(parts[:i]) + f"node_modules/{dep_name}"
        candidate_key = candidate_key.replace("node_modules/node_modules/", "node_modules/")
        if candidate_key in packages:
            v = packages[candidate_key].get("version")
            if v:
                return f"{dep_name}@{v}"
    # fallback: any top-level match
    top_key = f"node_modules/{dep_name}"
    if top_key in packages:
        v = packages[top_key].get("version")
        if v:
            return f"{dep_name}@{v}"
    return None


def _parse_npm_v1_dependencies(v1_deps, direct_deps, dev_deps, repo_name):
    """Parse lockfileVersion 1's nested 'dependencies' tree.

    v1 structure:
      lock["dependencies"] = {
        "pkg-name": {
          "version": "1.2.3",
          "resolved": "https://...",
          "dev": true/false,
          "requires": {"dep-name": "^2.0.0", ...},
          "dependencies": { ... nested overrides ... }
        }, ...
      }

    npm v6 uses hoisting: most packages live at the top level, but when
    two packages need different versions of the same transitive dep, the
    conflicting version gets nested under the parent. We build a flat
    name→version lookup from the top level first, then let nested entries
    override for their subtree when resolving edges.
    """
    nodes = {}
    edges = []

    # Instrumentation counters for batch extraction auditing
    depth_truncations = []  # list of (node_id, depth) that hit MAX_WALK_DEPTH
    cycle_breaks = []       # list of (node_id, depth) that hit visited_ancestors

    # First pass: collect all nodes recursively and build a flat lookup
    # for version resolution (top-level entries are the "hoisted" versions).
    top_level_versions = {}  # name → version (hoisted/top-level)

    MAX_WALK_DEPTH = 50

    def _walk(deps_dict, depth, parent_path_versions, visited_ancestors=None):
        """Recursively walk the nested dependencies tree.
        parent_path_versions: dict of name→version visible from this scope
        (includes overrides from nested dependencies above us).
        visited_ancestors: set of node_ids on current branch to guard against cycles.
        """
        if depth > MAX_WALK_DEPTH:
            depth_truncations.append(("_subtree_", depth))
            return

        if visited_ancestors is None:
            visited_ancestors = set()

        for name, entry in deps_dict.items():
            version = entry.get("version")
            if not name or not version:
                continue

            node_id = f"{name}@{version}"
            is_dev = bool(entry.get("dev", False))
            requires = entry.get("requires", {})
            out_degree = len(requires)
            is_direct = depth == 1 and (name in direct_deps or name in dev_deps)

            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id, "name": name, "version": version,
                    "is_direct_dependency": int(is_direct),
                    "is_dev_dependency": int(is_dev or name in dev_deps),
                    "out_degree": out_degree, "depth_in_tree": depth,
                    "repo_sources": set(),
                    "_requires": requires,      # stash for edge resolution
                    "_scope_versions": None,     # will be set below
                }
            nodes[node_id]["repo_sources"].add(repo_name)

            if depth == 1:
                top_level_versions[name] = version

            # Build the version scope visible to THIS node's requires:
            # start with parent scope, override with any nested deps here
            nested = entry.get("dependencies", {})
            local_scope = dict(parent_path_versions)
            local_scope[name] = version  # self is visible
            for nested_name, nested_entry in nested.items():
                nv = nested_entry.get("version")
                if nv:
                    local_scope[nested_name] = nv

            # Store the scope for edge resolution
            if nodes[node_id]["_scope_versions"] is None:
                nodes[node_id]["_scope_versions"] = local_scope

            # Recurse into nested dependencies with cycle protection
            if nested:
                if node_id in visited_ancestors:
                    cycle_breaks.append((node_id, depth))
                    continue
                _walk(nested, depth + 1, local_scope, visited_ancestors | {node_id})

    _walk(v1_deps, 1, {})

    # Second pass: resolve edges using requires + scope
    for node_id, node in nodes.items():
        requires = node.pop("_requires", {})
        scope = node.pop("_scope_versions", {}) or {}

        for dep_name in requires:
            # Look up in this node's scope first, then fall back to top-level
            resolved_version = scope.get(dep_name) or top_level_versions.get(dep_name)
            if resolved_version:
                target_id = f"{dep_name}@{resolved_version}"
                if target_id in nodes:
                    edges.append((node_id, target_id))

    return nodes, edges, "ok", depth_truncations, cycle_breaks


# ---------------------------------------------------------------------------
# STEP 2b: parse a yarn.lock (classic v1 text format)
# ---------------------------------------------------------------------------
def parse_yarn_lockfile(lock_path: Path, root_pkg_json_path: Path, repo_name: str):
    """Classic yarn.lock looks like blocks of:
        "pkg-name@^1.0.0", "pkg-name@^1.2.0":
          version "1.2.3"
          resolved "..."
          dependencies:
            dep-name "^2.0.0"
    We parse this with simple line-based state tracking (no external yaml lib
    needed -- yarn.lock is NOT valid YAML despite appearances). Yarn Berry
    (v2+) lockfiles use a different "__metadata" header; we detect and skip
    those gracefully since the format differs substantially.
    """
    with open(root_pkg_json_path, "r", encoding="utf-8") as f:
        pkg_json = json.load(f)
    direct_deps = set(pkg_json.get("dependencies", {}).keys())
    dev_deps = set(pkg_json.get("devDependencies", {}).keys())

    with open(lock_path, "r", encoding="utf-8") as f:
        text = f.read()

    if "__metadata:" in text[:2000]:
        return {}, [], "yarn_berry_unsupported"

    nodes = {}
    edges = []
    # range_to_resolved maps a declared "name@range" string -> resolved name@version
    range_to_resolved = {}
    blocks = re.split(r"\n(?=\S)", text)  # split on lines starting at column 0

    parsed_blocks = []  # (header_specs:list[str], version, deps:dict[name->range])
    for block in blocks:
        lines = block.splitlines()
        if not lines or not lines[0].strip() or lines[0].startswith("#"):
            continue
        header = lines[0].rstrip(":").strip()
        if not header or "@" not in header:
            continue
        specs = [s.strip().strip('"') for s in header.split(",")]
        version_match = re.search(r'version\s+"?([\w\.\-\+]+)"?', block)
        if not version_match:
            continue
        version = version_match.group(1)

        deps = {}
        in_deps_block = False
        dep_indent = None
        for line in lines[1:]:
            stripped = line.strip()
            if re.match(r"^(dependencies|optionalDependencies):\s*$", stripped):
                in_deps_block = True
                continue
            if in_deps_block:
                indent = len(line) - len(line.lstrip())
                if dep_indent is None:
                    dep_indent = indent
                if indent < dep_indent or not stripped:
                    in_deps_block = False
                    continue
                m = re.match(r'^"?([^"\s]+)"?\s+"?([^"]+)"?$', stripped)
                if m:
                    deps[m.group(1)] = m.group(2)
        parsed_blocks.append((specs, version, deps))

    # derive package name from a spec like "name@^1.0.0" or "@scope/name@^1.0.0"
    def name_from_spec(spec):
        if spec.startswith("@"):
            parts = spec.split("@")
            return "@" + parts[1]
        return spec.split("@")[0]

    for specs, version, deps in parsed_blocks:
        name = name_from_spec(specs[0])
        node_id = f"{name}@{version}"
        for spec in specs:
            range_to_resolved[spec] = node_id
        if node_id not in nodes:
            is_direct = name in direct_deps or name in dev_deps
            nodes[node_id] = {
                "id": node_id, "name": name, "version": version,
                "is_direct_dependency": int(is_direct),
                "is_dev_dependency": int(name in dev_deps),
                "out_degree": len(deps), "depth_in_tree": 1 if is_direct else 2,
                "repo_sources": set(), "_raw_deps": deps,
            }
        nodes[node_id]["repo_sources"].add(repo_name)

    for node_id, node in nodes.items():
        for dep_name, dep_range in node.pop("_raw_deps", {}).items():
            spec = f"{dep_name}@{dep_range}"
            target_id = range_to_resolved.get(spec)
            if target_id:
                edges.append((node_id, target_id))

    return nodes, edges, "ok"


# ---------------------------------------------------------------------------
# STEP 2c: fallback for repos with NO lockfile -- parse package.json directly.
# Gives only direct dependencies with their declared semver RANGE as the
# "version" (not a resolved exact version, since none exists). Shallower
# data than the lockfile-based parsers, but still real and usable.
# ---------------------------------------------------------------------------
def parse_no_lockfile(repo_path: Path, repo_name: str):
    nodes = {}
    edges = []
    for pkg_json_path in find_all_package_json(repo_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                pkg_json = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        deps = pkg_json.get("dependencies", {})
        dev_deps = pkg_json.get("devDependencies", {})
        all_deps = {**deps, **{k: v for k, v in dev_deps.items()}}

        for name, version_range in all_deps.items():
            node_id = f"{name}@{version_range}"  # NOTE: range, not resolved version
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id, "name": name, "version": version_range,
                    "is_direct_dependency": 1,
                    "is_dev_dependency": int(name in dev_deps and name not in deps),
                    "out_degree": 0,  # unknown without a lockfile
                    "depth_in_tree": 1,
                    "repo_sources": set(),
                    "_unresolved_version": True,
                }
            nodes[node_id]["repo_sources"].add(repo_name)

    return nodes, edges, "ok_unresolved"


# ---------------------------------------------------------------------------
# STEP 2c: unified parser that auto-detects npm vs yarn format
# ---------------------------------------------------------------------------
def parse_lockfile_pair(pkg_json_path: Path, lock_path: Path, repo_name: str):
    """Detects lockfile type (npm or yarn) and parses accordingly."""
    try:
        with open(lock_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[WARN] Failed to read {lock_path}: {e}")
        return {}, [], "read_error"
    
    if not content.strip():
        print(f"[WARN] Empty lockfile: {lock_path}")
        return {}, [], "empty_lockfile"
    
    try:
        # Try npm format first (JSON)
        if content.strip().startswith("{"):
            try:
                json.loads(content)  # validate JSON
                return parse_npm_lockfile(lock_path, pkg_json_path, repo_name)
            except json.JSONDecodeError as e:
                print(f"[WARN] Invalid JSON in {lock_path}: {e}")
                return {}, [], "invalid_json"
        # Otherwise assume yarn format (text-based)
        else:
            return parse_yarn_lockfile(lock_path, pkg_json_path, repo_name)
    except Exception as e:
        print(f"[ERROR] Failed to parse {lock_path}: {e}")
        return {}, [], "parse_error"


# ---------------------------------------------------------------------------
# STEP 3: npm registry lookups (cached) for recency / deprecation / license / downloads
# ---------------------------------------------------------------------------
def load_cache():
    if CACHE_FILE.exists():
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f)


def fetch_registry_metadata(name):
    """Fetch package metadata (versions/time/deprecated/license) from
    registry.npmjs.org, and weekly downloads from api.npmjs.org."""
    result = {"versions_time": {}, "deprecated_versions": set(), "license": None, "weekly_downloads": 0}
    try:
        safe_name = name.replace("/", "%2F") if name.startswith("@") else name
        url = f"https://registry.npmjs.org/{safe_name}"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.load(resp)
        result["versions_time"] = data.get("time", {})
        versions = data.get("versions", {})
        result["deprecated_versions"] = {
            v for v, meta in versions.items() if meta.get("deprecated")
        }
        latest_tag = data.get("dist-tags", {}).get("latest")
        if latest_tag and latest_tag in versions:
            lic = versions[latest_tag].get("license")
            result["license"] = lic if isinstance(lic, str) else None
    except Exception:
        pass

    try:
        dl_url = f"https://api.npmjs.org/downloads/point/last-week/{name}"
        with urllib.request.urlopen(dl_url, timeout=10) as resp:
            dl_data = json.load(resp)
        result["weekly_downloads"] = dl_data.get("downloads", 0)
    except Exception:
        pass

    return result


def get_metadata_for_all(names, cache):
    to_fetch = [n for n in names if n not in cache]
    print(f"Fetching npm registry metadata for {len(to_fetch)} new packages "
          f"({len(names) - len(to_fetch)} already cached)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_registry_metadata, n): n for n in to_fetch}
        for i, future in enumerate(as_completed(futures), 1):
            name = futures[future]
            try:
                cache[name] = future.result()
                cache[name]["deprecated_versions"] = list(cache[name]["deprecated_versions"])
            except Exception as e:
                cache[name] = {"versions_time": {}, "deprecated_versions": [], "license": None, "weekly_downloads": 0}
            if i % 50 == 0:
                print(f"  ...{i}/{len(to_fetch)} fetched")
                save_cache(cache)  # periodic checkpoint

    save_cache(cache)
    return cache


# ---------------------------------------------------------------------------
# STEP 4: compute the final 10-dim feature vector per node
# ---------------------------------------------------------------------------
def compute_features(node, meta):
    versions_time = meta.get("versions_time", {})
    deprecated_versions = set(meta.get("deprecated_versions", []))
    license_str = meta.get("license")
    weekly_downloads = meta.get("weekly_downloads", 0)

    version = node["version"]
    pub_date_str = versions_time.get(version)
    if pub_date_str:
        pub_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
        recency_days = (datetime.now(timezone.utc) - pub_date).days
    else:
        recency_days = -1  # unknown

    # versions_behind_latest: count entries published after this version's date
    versions_behind = -1
    if pub_date_str:
        dated = [(v, t) for v, t in versions_time.items() if v not in ("created", "modified")]
        try:
            dated_sorted = sorted(dated, key=lambda x: x[1])
            idx_self = next((i for i, (v, _) in enumerate(dated_sorted) if v == version), None)
            if idx_self is not None:
                versions_behind = len(dated_sorted) - 1 - idx_self
        except Exception:
            versions_behind = -1

    is_deprecated = int(version in deprecated_versions)
    license_risk = int(license_str is None or license_str not in COMMON_LICENSES)
    downloads_log = round(math.log10(weekly_downloads + 1), 4)

    return [
        node["is_direct_dependency"],
        node["is_dev_dependency"],
        node["out_degree"],
        node["depth_in_tree"],
        recency_days,
        versions_behind,
        0,  # has_known_cve_history -- PLACEHOLDER, see module docstring
        downloads_log,
        is_deprecated,
        license_risk,
    ]


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    if not REPOS_DIR.exists():
        print(f"ERROR: {REPOS_DIR} does not exist. Update REPOS_DIR at the top of this script.")
        return

    all_nodes = {}
    all_edges = []
    skipped = []

    for repo_path in sorted(p for p in REPOS_DIR.iterdir() if p.is_dir()):
        repo_name = repo_path.name
        try:
            lock_type, lock_path = detect_repo_lockfile_strategy(repo_path)
            if lock_type == "none":
                print(f"  [!] {repo_name}: no lockfile found")
                continue
            
            pkg_jsons = find_all_package_json(repo_path)
            if not pkg_jsons:
                print(f"  [!] {repo_name}: no package.json found")
                continue
            
            root_pkg_json = pkg_jsons[0]  # use root package.json
            print(f"== {repo_name}: {lock_type.upper()} lockfile found ==")
            
            try:
                nodes, edges, status = parse_lockfile_pair(root_pkg_json, lock_path, repo_name)
                if status != "ok" and status != "ok_unresolved":
                    skipped.append((str(lock_path), status))
                    continue
                for node_id, node in nodes.items():
                    if node_id in all_nodes:
                        all_nodes[node_id]["repo_sources"] |= node["repo_sources"]
                    else:
                        all_nodes[node_id] = node
                all_edges.extend(edges)
            except Exception as e:
                print(f"[ERROR] Failed to process {lock_path}: {e}")
                skipped.append((str(lock_path), f"exception: {e}"))
        except Exception as e:
            print(f"[ERROR] Failed to process repo {repo_name}: {e}")
            skipped.append((repo_name, f"repo_error: {e}"))
            continue

    print(f"\nTotal unique package@version nodes: {len(all_nodes)}")
    print(f"Total dependsOn edges: {len(all_edges)}")
    if skipped:
        print(f"Skipped (unsupported lockfile format): {len(skipped)} -- {skipped[:5]}{'...' if len(skipped) > 5 else ''}")

    unique_names = {n["name"] for n in all_nodes.values()}
    cache = load_cache()
    cache = get_metadata_for_all(unique_names, cache)

    final_nodes = []
    for node in all_nodes.values():
        meta = cache.get(node["name"], {})
        features = compute_features(node, meta)
        final_nodes.append({
            "id": node["id"],
            "name": node["name"],
            "version": node["version"],
            "repo_sources": sorted(node["repo_sources"]),
            "features": features,
        })

    final_edges = [{"source": s, "target": t, "type": "dependsOn"} for s, t in all_edges]

    output = {
        "feature_order": [
            "is_direct_dependency", "is_dev_dependency", "out_degree", "depth_in_tree",
            "version_recency_days", "versions_behind_latest", "has_known_cve_history_PLACEHOLDER",
            "weekly_downloads_log", "is_deprecated", "license_risk_flag"
        ],
        "nodes": final_nodes,
        "edges": final_edges,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\nDone. Wrote {len(final_nodes)} nodes and {len(final_edges)} edges to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()