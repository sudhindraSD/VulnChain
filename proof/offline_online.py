"""
Offline vs online advisory agreement for the STEP 4 proof module.

OFFLINE = ADV_OFF from the two frozen local files only, zero network calls.
ONLINE  = ADV_ON from a live https://api.osv.dev/v1/query POST per package,
          zero cached advisories mixed in. Timeout 8 s, zero retries,
          8 concurrent workers (PROOF_PROTOCOL.md section 5).

Formula (fixed):
    D           = { p : online_query_status(p) == "OK" }
    agree_count = |{ p in D : ADV_OFF(p) == ADV_ON(p) }|
    A           = agree_count / |D|    (N/A if |D| == 0)

Usage:
  python proof/offline_online.py <lockfile> --kb <graph.json> \
      --cache <osv_cache.json> --json <offline_online.json>
"""
import argparse
import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_paths

OSV_URL = "https://api.osv.dev/v1/query"
TIMEOUT_S = 8
WORKERS = 8


def query_online(pid):
    name, version = pid.rsplit("@", 1)
    body = json.dumps({
        "version": version,
        "package": {"name": name, "ecosystem": "npm"},
    }).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "VulnChain-Proof/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        ids = sorted({v.get("id") for v in (doc.get("vulns") or []) if v.get("id")})
        return {"status": "OK", "online_ids": ids, "error": None}
    except Exception as exc:
        return {
            "status": "NO_ONLINE_RESULT",
            "online_ids": None,
            "error": type(exc).__name__ + ": " + str(exc),
        }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="offline_online.py")
    ap.add_argument("lockfile")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--json", dest="json_out", required=True)
    args = ap.parse_args(argv)

    model = verify_paths.parse_lockfile(args.lockfile)
    offline = verify_paths.load_advisories(args.kb, args.cache)
    pids = sorted({node["pid"] for node in model["nodes"].values()})

    started = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(query_online, pids))
    elapsed = round(time.time() - started, 3)

    rows = []
    for pid, res in zip(pids, results):
        off_ids = offline.get(pid, [])
        on_ids = res["online_ids"]
        agree = None if on_ids is None else (off_ids == on_ids)
        rows.append({
            "package": pid,
            "offline_ids": off_ids,
            "online_ids": on_ids,
            "status": res["status"],
            "error": res["error"],
            "agree": agree,
        })

    evaluated = [r for r in rows if r["status"] == "OK"]
    agree_count = sum(1 for r in evaluated if r["agree"])
    no_result = [r["package"] for r in rows if r["status"] != "OK"]
    rate = (agree_count / len(evaluated)) if evaluated else None

    report = {
        "schema": "vulnchain-proof/offline_online/1",
        "lockfile": str(args.lockfile),
        "definitions": {
            "offline": "ADV_OFF: frozen KB hasVulnerability edges + osv_cache.json cve_id; zero network calls",
            "online": "ADV_ON: live POST https://api.osv.dev/v1/query per package; zero cached advisories",
            "timeout_s": TIMEOUT_S,
            "workers": WORKERS,
            "retries": 0,
            "comparison": "exact string-set equality ADV_OFF(p) == ADV_ON(p); empty == empty counts as agreement",
            "formula": "A = |{p in D : ADV_OFF(p) == ADV_ON(p)}| / |D|,  D = {p : status == 'OK'}",
        },
        "elapsed_seconds": elapsed,
        "rows": rows,
        "counts": {
            "units_total": len(rows),
            "evaluated_D": len(evaluated),
            "agree_count": agree_count,
            "disagree_count": len(evaluated) - agree_count,
            "no_online_result_count": len(no_result),
            "offline_only_count": sum(
                1 for r in evaluated if r["offline_ids"] and not r["online_ids"]
            ),
            "online_only_count": sum(
                1 for r in evaluated if r["online_ids"] and not r["offline_ids"]
            ),
            "both_nonempty_disagree_count": sum(
                1 for r in evaluated
                if r["offline_ids"] and r["online_ids"] and not r["agree"]
            ),
            "both_empty_agree_count": sum(
                1 for r in evaluated
                if not r["offline_ids"] and not r["online_ids"] and r["agree"]
            ),
        },
        "agreement_rate": rate,
        "no_online_result_packages": no_result,
    }

    out = Path(args.json_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    c = report["counts"]
    print("offline/online: units=%d D=%d agree=%d rate=%s" % (
        c["units_total"], c["evaluated_D"], c["agree_count"],
        "N/A" if rate is None else "%.6f" % rate))
    print("  no_online_result=%d offline_only=%d online_only=%d both_nonempty_disagree=%d" % (
        c["no_online_result_count"], c["offline_only_count"],
        c["online_only_count"], c["both_nonempty_disagree_count"]))
    print("  wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
