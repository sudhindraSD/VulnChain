"""
VulnChain — OSV full-record fetcher
Reads cve_seed_ids.json (from osv_extractor.py), fetches the full OSV
record for each ID via GET /v1/vulns/{id}, and builds CVE node data:
  - cve_nodes.json : one entry per vuln ID with severity, summary/details
                     text (for SentenceBERT), affected ranges, aliases
  - vague_ids.json : IDs with no usable severity/description — candidates
                     for the synthetic-text fallback path

Skips the 12 MAL- (malicious package) IDs by default — different schema,
no CVSS concept. Flip INCLUDE_MAL to True if you want them fetched too.

Run locally:  pip install requests cvss
              python osv_record_fetcher.py
"""

import json
import time
import requests
from pathlib import Path
from cvss import CVSS2, CVSS3, CVSS4

SEED_FILE = "cve_seed_ids.json"
CACHE_FILE = ".osv_records_cache.json"   # resumable cache: id -> full record
NODES_OUT = "cve_nodes.json"
VAGUE_OUT = "vague_ids.json"

GET_URL = "https://api.osv.dev/v1/vulns/{}"
INCLUDE_MAL = False


def load_ids():
    with open(SEED_FILE) as f:
        ids = json.load(f)
    if not INCLUDE_MAL:
        skipped = [i for i in ids if i.startswith("MAL-")]
        ids = [i for i in ids if not i.startswith("MAL-")]
        print(f"Skipping {len(skipped)} MAL- entries (malicious package DB, different schema)")
    print(f"{len(ids)} IDs to fetch full records for")
    return ids


def load_cache():
    if Path(CACHE_FILE).exists():
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def fetch_record(vuln_id):
    resp = requests.get(GET_URL.format(vuln_id), timeout=15)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def parse_cvss_vector(vector, cvss_type):
    """Convert a CVSS vector string into its numeric base score (0-10)."""
    try:
        if cvss_type == "CVSS_V2":
            score = CVSS2(vector).base_score
        elif cvss_type == "CVSS_V3":
            score = CVSS3(vector).base_score
        elif cvss_type == "CVSS_V4":
            score = CVSS4(vector).base_score
        else:
            # unknown type string — try v3 first (most common), fall back v2
            try:
                score = CVSS3(vector).base_score
            except Exception:
                score = CVSS2(vector).base_score
        return float(score)  # cvss lib returns Decimal — not JSON-serializable as-is
    except Exception:
        return None  # malformed vector, treat as no CVSS available


def extract_cvss(record):
    """Find a severity[] entry, return (numeric_score, raw_vector) or (None, None)."""
    for sev in record.get("severity", []):
        sev_type = sev.get("type", "")
        if sev_type.startswith("CVSS"):
            vector = sev.get("score")  # OSV's field is confusingly named 'score' but holds the vector string
            numeric = parse_cvss_vector(vector, sev_type)
            if numeric is not None:
                return numeric, vector
    return None, None


def main():
    ids = load_ids()
    cache = load_cache()

    todo = [i for i in ids if i not in cache]
    print(f"{len(todo)} left to fetch ({len(cache)} cached)")

    for idx, vid in enumerate(todo, 1):
        try:
            record = fetch_record(vid)
        except requests.exceptions.RequestException as e:
            print(f"  {vid} failed: {e}, retrying once after 3s")
            time.sleep(3)
            try:
                record = fetch_record(vid)
            except requests.exceptions.RequestException as e2:
                print(f"  {vid} failed again: {e2}, skipping")
                continue

        cache[vid] = record  # None if 404 (shouldn't happen but just in case)

        if idx % 50 == 0 or idx == len(todo):
            save_cache(cache)
            print(f"  fetched {idx}/{len(todo)}")

        time.sleep(0.1)  # OSV has no published rate limit, still be polite

    save_cache(cache)

    # ---- Build outputs ----
    cve_nodes = []
    vague_ids = []

    for vid, record in cache.items():
        if record is None:
            vague_ids.append(vid)
            continue

        summary = record.get("summary", "") or ""
        details = record.get("details", "") or ""
        text = (summary + " " + details).strip()
        cvss_score, cvss_vector = extract_cvss(record)
        aliases = record.get("aliases", [])
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)

        node = {
            "id": vid,
            "cve_alias": cve_alias,
            "text_for_embedding": text,
            "cvss_score": cvss_score,      # numeric 0-10, this is your feature
            "cvss_vector": cvss_vector,    # raw string, kept for reference/debugging
            "affected": record.get("affected", []),
            "aliases": aliases,
        }
        cve_nodes.append(node)

        # vague = no usable text AND no CVSS — nothing to embed or score meaningfully
        if len(text) < 20 and cvss_score is None:
            vague_ids.append(vid)

    with open(NODES_OUT, "w") as f:
        json.dump(cve_nodes, f, indent=2)

    with open(VAGUE_OUT, "w") as f:
        json.dump(vague_ids, f, indent=2)

    with_cvss = sum(1 for n in cve_nodes if n["cvss_score"] is not None)
    with_cve_alias = sum(1 for n in cve_nodes if n["cve_alias"])

    print()
    print("=== Done ===")
    print(f"Total CVE/GHSA nodes built: {len(cve_nodes)}")
    print(f"  with CVSS vector: {with_cvss}")
    print(f"  with a CVE alias (rare but check): {with_cve_alias}")
    print(f"Vague IDs (need synthetic-text fallback): {len(vague_ids)}")
    print(f"-> {NODES_OUT}")
    print(f"-> {VAGUE_OUT}")


if __name__ == "__main__":
    main()