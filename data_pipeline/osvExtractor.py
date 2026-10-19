"""
VulnChain — OSV.dev vulnerability extractor
Reads package_graph.json, queries OSV.dev in batches for each unique
(name, version) pair, and writes out:
  - osv_vulns.json        : raw OSV responses per package (cached)
  - hasVulnerability_edges.json : Package -> CVE/GHSA edges for the graph
  - cve_seed_ids.json     : deduped list of vuln IDs to feed into NVD/GHSA next

Run locally:  python osv_extractor.py
"""

import json
import time
import requests
from pathlib import Path

INPUT_FILE = "package_graph.json"
CACHE_FILE = "osv_vulns.json"          # resumable cache: id -> OSV result
EDGES_OUT = "hasVulnerability_edges.json"
CVE_SEED_OUT = "cve_seed_ids.json"

BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 100      # OSV allows up to 1000/request, staying conservative
ECOSYSTEM = "npm"     # all 10 repos are JS/Node


def load_packages():
    with open(INPUT_FILE) as f:
        data = json.load(f)
    # dedupe by (name, version) — same package can appear across multiple repos
    seen = {}
    for n in data["nodes"]:
        key = (n["name"], n["version"])
        if key not in seen:
            seen[key] = n["id"]
    print(f"Loaded {len(data['nodes'])} nodes -> {len(seen)} unique (name, version) pairs")
    return seen  # {(name, version): node_id}


def load_cache():
    if Path(CACHE_FILE).exists():
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def query_osv_batch(pairs_batch):
    """pairs_batch: list of (name, version) tuples"""
    queries = [
        {"package": {"name": name, "ecosystem": ECOSYSTEM}, "version": version}
        for name, version in pairs_batch
    ]
    resp = requests.post(BATCH_URL, json={"queries": queries}, timeout=30)
    resp.raise_for_status()
    return resp.json()["results"]  # list aligned with queries, each has "vulns": [...]


def main():
    packages = load_packages()  # {(name, version): node_id}
    cache = load_cache()        # node_id -> [vuln_id, ...] (already resolved)

    todo = [(k, v) for k, v in packages.items() if v not in cache]
    print(f"{len(todo)} pairs left to query ({len(cache)} already cached)")

    for i in range(0, len(todo), BATCH_SIZE):
        chunk = todo[i:i + BATCH_SIZE]
        pairs = [k for k, _ in chunk]
        node_ids = [v for _, v in chunk]

        try:
            results = query_osv_batch(pairs)
        except requests.exceptions.RequestException as e:
            print(f"  batch {i}-{i+len(chunk)} failed: {e}, retrying once after 5s")
            time.sleep(5)
            try:
                results = query_osv_batch(pairs)
            except requests.exceptions.RequestException as e2:
                print(f"  batch {i}-{i+len(chunk)} failed again: {e2}, skipping this batch")
                continue

        for node_id, result in zip(node_ids, results):
            vuln_ids = [v["id"] for v in result.get("vulns", [])]
            cache[node_id] = vuln_ids

        save_cache(cache)  # checkpoint after every batch — safe to Ctrl+C and resume
        print(f"  processed {min(i+BATCH_SIZE, len(todo))}/{len(todo)}  "
              f"(this batch: {sum(1 for r in results if r.get('vulns'))} packages had hits)")
        time.sleep(1)  # be polite to the API

    # ---- Build outputs ----
    edges = []
    all_vuln_ids = set()
    vulnerable_packages = 0

    for node_id, vuln_ids in cache.items():
        if vuln_ids:
            vulnerable_packages += 1
        for vid in vuln_ids:
            edges.append({"source": node_id, "target": vid, "type": "hasVulnerability"})
            all_vuln_ids.add(vid)

    with open(EDGES_OUT, "w") as f:
        json.dump(edges, f, indent=2)

    with open(CVE_SEED_OUT, "w") as f:
        json.dump(sorted(all_vuln_ids), f, indent=2)

    print()
    print("=== Done ===")
    print(f"Packages with >=1 vuln: {vulnerable_packages} / {len(packages)}")
    print(f"Total hasVulnerability edges: {len(edges)}")
    print(f"Unique vuln IDs (CVE/GHSA) to resolve next via NVD+GHSA: {len(all_vuln_ids)}")
    print(f"-> {EDGES_OUT}")
    print(f"-> {CVE_SEED_OUT}")


if __name__ == "__main__":
    main()