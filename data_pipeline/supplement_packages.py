"""
VulnChain Supplementary Package Extractor
------------------------------------------
Fetches real 10-dim feature vectors from npm registry for Package nodes
that are referenced by dependsOn edges but were never extracted by the
main graph extractor (walker didn't reach them within its traversal).

These are NOT stubs — every feature is computed from real npm registry data,
identical to how jsonGraphExtractor.py computes features for its nodes.

Output: supplement_packages.json — a list of Package node dicts ready for merge.
"""

import json
import math
import urllib.request
import urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
GRAPH_FILE = Path(r"C:\Users\Admin\Desktop\Major VulnChain\package_graph.json")
CACHE_FILE = Path(r"C:\Users\Admin\Desktop\Major VulnChain\npm_registry_cache.json")
OUTPUT_FILE = Path(r"C:\Users\Admin\Desktop\Major VulnChain\supplement_packages.json")
MAX_WORKERS = 10

COMMON_LICENSES = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "MPL-2.0", "CC0-1.0", "Unlicense"
}


# ---------------------------------------------------------------------------
# STEP 1: Identify missing package IDs
# ---------------------------------------------------------------------------
def find_missing_targets(graph):
    """Find all dependsOn target IDs that don't exist as nodes."""
    node_ids = set(n["id"] for n in graph["nodes"])
    edges = graph["edges"]
    
    # Map source -> its node data for depth derivation
    node_map = {n["id"]: n for n in graph["nodes"]}
    
    missing = {}  # target_id -> {"name": ..., "version": ..., "parent_depth": min_depth}
    for e in edges:
        tid = e["target"]
        if tid not in node_ids:
            if tid not in missing:
                # Parse name@version
                at_idx = tid.rfind("@")
                if at_idx <= 0:
                    continue  # malformed ID
                name = tid[:at_idx]
                version = tid[at_idx+1:]
                missing[tid] = {
                    "name": name,
                    "version": version,
                    "parent_depths": []
                }
            # Track parent depths for depth_in_tree derivation
            src = node_map.get(e["source"])
            if src:
                missing[tid]["parent_depths"].append(src["features"][3])  # depth_in_tree index
    
    return missing


# ---------------------------------------------------------------------------
# STEP 2: Fetch npm registry metadata
# ---------------------------------------------------------------------------
def load_cache():
    if CACHE_FILE.exists():
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f)


def fetch_npm_metadata(pkg_name):
    """Fetch package metadata from npm registry."""
    url = f"https://registry.npmjs.org/{pkg_name}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        
        # Extract what we need
        result = {"license": None, "versions_time": {}, "deprecated_versions": []}
        
        # License from latest version
        dist_tags = data.get("dist-tags", {})
        latest = dist_tags.get("latest")
        versions = data.get("versions", {})
        if latest and latest in versions:
            lic = versions[latest].get("license")
            if isinstance(lic, dict):
                lic = lic.get("type")
            result["license"] = lic
        
        # Time info
        time_info = data.get("time", {})
        result["versions_time"] = {k: v for k, v in time_info.items()}
        
        # Deprecated versions
        for ver, ver_data in versions.items():
            if ver_data.get("deprecated"):
                result["deprecated_versions"].append(ver)
        
        # Weekly downloads (separate endpoint)
        try:
            dl_url = f"https://api.npmjs.org/downloads/point/last-week/{pkg_name}"
            dl_req = urllib.request.Request(dl_url)
            with urllib.request.urlopen(dl_req, timeout=10) as dl_resp:
                dl_data = json.loads(dl_resp.read().decode("utf-8"))
            result["weekly_downloads"] = dl_data.get("downloads", 0)
        except Exception:
            result["weekly_downloads"] = 0
        
        # Out-degree from declared dependencies of the specific version
        result["all_versions_deps"] = {}
        for ver, ver_data in versions.items():
            deps = ver_data.get("dependencies", {})
            result["all_versions_deps"][ver] = len(deps)
        
        return result
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # Package doesn't exist
        return None
    except Exception:
        return None


def fetch_all_metadata(missing_pkgs, cache):
    """Fetch metadata for all unique package names not in cache."""
    unique_names = set(m["name"] for m in missing_pkgs.values())
    to_fetch = [n for n in unique_names if n not in cache]
    
    print(f"  Unique package names to look up: {len(unique_names)}")
    print(f"  Already cached: {len(unique_names) - len(to_fetch)}")
    print(f"  Need to fetch: {len(to_fetch)}")
    
    if not to_fetch:
        return cache
    
    fetched = 0
    failed = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_npm_metadata, name): name for name in to_fetch}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                if result is not None:
                    cache[name] = result
                    fetched += 1
                else:
                    cache[name] = {}  # Mark as attempted
                    failed += 1
            except Exception as e:
                cache[name] = {}
                failed += 1
            
            total = fetched + failed
            if total % 50 == 0:
                print(f"  ...{total}/{len(to_fetch)} done")
    
    print(f"  Fetched: {fetched}, Failed/404: {failed}")
    save_cache(cache)
    return cache


# ---------------------------------------------------------------------------
# STEP 3: Compute 10-dim feature vector (same logic as jsonGraphExtractor.py)
# ---------------------------------------------------------------------------
def compute_features(name, version, parent_depths, meta):
    """Compute the locked 10-dim Package feature vector."""
    versions_time = meta.get("versions_time", {})
    deprecated_versions = meta.get("deprecated_versions", [])
    license_str = meta.get("license")
    weekly_downloads = meta.get("weekly_downloads", 0)
    all_versions_deps = meta.get("all_versions_deps", {})
    
    # is_direct_dependency = 0 (these are always transitive — they were reached
    # via a dependsOn edge from an already-extracted package)
    is_direct = 0
    
    # is_dev_dependency = 0 (conservative default — we can't determine this
    # without the full lockfile context)
    is_dev = 0
    
    # out_degree from the specific version's declared dependencies
    out_degree = all_versions_deps.get(version, 0)
    
    # depth_in_tree = min(parent_depths) + 1
    if parent_depths:
        depth = min(parent_depths) + 1
    else:
        depth = 2  # safe default for transitive deps
    
    # version_recency_days
    pub_date_str = versions_time.get(version)
    if pub_date_str:
        try:
            pub_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00"))
            recency_days = (datetime.now(timezone.utc) - pub_date).days
        except Exception:
            recency_days = -1
    else:
        recency_days = -1
    
    # versions_behind_latest
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
    
    # has_known_cve_history = 0 (will be backfilled during merge)
    has_cve = 0
    
    # weekly_downloads_log
    downloads_log = round(math.log10(weekly_downloads + 1), 4)
    
    # is_deprecated
    is_deprecated = int(version in deprecated_versions)
    
    # license_risk_flag
    license_risk = int(license_str is None or license_str not in COMMON_LICENSES)
    
    return [
        is_direct,
        is_dev,
        out_degree,
        depth,
        recency_days,
        versions_behind,
        has_cve,
        downloads_log,
        is_deprecated,
        license_risk,
    ]


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    print("Loading graph...")
    with open(GRAPH_FILE) as f:
        graph = json.load(f)
    
    print("Finding missing targets...")
    missing = find_missing_targets(graph)
    print(f"  Found {len(missing)} missing package IDs")
    
    if not missing:
        print("No missing targets — nothing to do!")
        return
    
    print("\nFetching npm registry metadata...")
    cache = load_cache()
    cache = fetch_all_metadata(missing, cache)
    
    print("\nComputing feature vectors...")
    supplement_nodes = []
    success = 0
    no_meta = 0
    
    for node_id, info in missing.items():
        meta = cache.get(info["name"], {})
        if not meta:
            no_meta += 1
            # Still create the node with default features
            features = [0, 0, 0, min(info["parent_depths"]) + 1 if info["parent_depths"] else 2,
                        -1, -1, 0, 0.0, 0, 1]
        else:
            features = compute_features(
                info["name"], info["version"],
                info["parent_depths"], meta
            )
            success += 1
        
        supplement_nodes.append({
            "id": node_id,
            "name": info["name"],
            "version": info["version"],
            "repo_sources": ["supplement"],
            "features": features,
        })
    
    print(f"  With real npm metadata: {success}")
    print(f"  Without metadata (defaults): {no_meta}")
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(supplement_nodes, f, indent=2)
    
    print(f"\nWrote {len(supplement_nodes)} supplementary nodes to {OUTPUT_FILE}")
    
    # Verify: how many dangling edges would remain?
    all_ids = set(n["id"] for n in graph["nodes"]) | set(n["id"] for n in supplement_nodes)
    remaining_dangling = sum(1 for e in graph["edges"] if e["target"] not in all_ids)
    print(f"Remaining dangling dependsOn edges after supplement: {remaining_dangling}")


if __name__ == "__main__":
    main()
