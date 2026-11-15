"""
Case-study generator for the STEP 4 proof module.

Applies the rule fixed in PROOF_PROTOCOL.md section 6 with no judgement and
no cherry-picking:
  CS1 deepest verified path (max edges; tie-break alphabetical by name@version)
  CS2 alphabetically first item of vulnchain_only (EMPTY if group empty)
  CS3 alphabetically first item of npm_audit_only (EMPTY if group empty)

Usage:
  python proof/case_studies.py --flagged <flagged_packages.json> \
      --verify <verify_report.json> --comparison <npm_audit_comparison.json> \
      --json <case_studies.json>
"""
import argparse
import json
import sys
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def path_for_endpoint(flagged_doc, verify_doc, item):
    """First printed path ending at `item`, alphabetically by flagged package."""
    verify_by_key = {
        (r.get("package"), r.get("path_index")): r
        for r in verify_doc.get("paths", [])
    }
    candidates = []
    for rec in flagged_doc.get("flagged", []):
        for idx, path in enumerate(rec.get("paths", [])):
            if path and path[-1] == item:
                candidates.append((rec["package"], idx, path, rec))
    if not candidates:
        return {
            "path": None,
            "path_label": "NO_PATH",
            "advisory_ids": [],
            "verification": "NO_PATH_TO_VERIFY",
        }
    package, idx, path, rec = min(candidates, key=lambda t: (t[0], t[1]))
    row = verify_by_key.get((package, idx), {})
    return {
        "path": path,
        "path_label": " -> ".join(path),
        "printed_for_flagged_package": package,
        "advisory_ids": rec.get("advisory_ids", []),
        "verification": "PASS" if row.get("pass") else "FAIL",
        "failing_edge": row.get("failing_edge"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="case_studies.py")
    ap.add_argument("--flagged", required=True)
    ap.add_argument("--verify", required=True)
    ap.add_argument("--comparison", required=True)
    ap.add_argument("--json", dest="json_out", required=True)
    args = ap.parse_args(argv)

    flagged_doc = load(args.flagged)
    verify_doc = load(args.verify)
    comp = load(args.comparison)

    # CS1: deepest VERIFIED printed path.
    passing = [r for r in verify_doc.get("paths", []) if r.get("pass") and r.get("path")]
    cs1 = {"case": "CS1_deepest_verified_path", "rule": "max edges in a passing verify_paths.py row; tie-break alphabetical by name@version"}
    if passing:
        best_hops = max(len(r["path"]) - 1 for r in passing)
        tied = sorted(
            [r for r in passing if len(r["path"]) - 1 == best_hops],
            key=lambda r: str(r.get("package")),
        )
        row = tied[0]
        package = row["package"]
        rec = next((r for r in flagged_doc.get("flagged", []) if r["package"] == package), {})
        idx = row.get("path_index", 0)
        paths = rec.get("paths", [])
        path = paths[idx] if idx is not None and idx < len(paths) else row["path"]
        cs1.update({
            "selected": package,
            "hops": best_hops,
            "tie_count": len(tied),
            "path": path,
            "path_label": " -> ".join(path),
            "advisory_ids": rec.get("advisory_ids", []),
            "verification": "PASS",
            "failing_edge": None,
        })
    else:
        cs1.update({
            "selected": None, "hops": None, "tie_count": 0,
            "path": None, "path_label": "NO_PASSING_PATH", "advisory_ids": [],
            "verification": "NO_PASSING_PATH", "failing_edge": None,
        })

    vc_only = comp.get("groups", {}).get("vulnchain_only", [])
    npm_only = comp.get("groups", {}).get("npm_audit_only", [])

    cs2 = {
        "case": "CS2_vulnchain_only",
        "rule": "alphabetically first item of vulnchain_only; EMPTY if group empty",
        "group_count": len(vc_only),
    }
    if vc_only:
        item = sorted(vc_only)[0]
        cs2["selected"] = item
        cs2.update(path_for_endpoint(flagged_doc, verify_doc, item))
        cs2["cause"] = next(
            (c["cause"] for c in comp.get("causes", []) if c["item"] == item), None
        )
    else:
        cs2.update({
            "selected": "EMPTY", "path": None, "path_label": "EMPTY",
            "advisory_ids": [], "verification": "EMPTY", "cause": None,
        })

    cs3 = {
        "case": "CS3_npm_audit_only",
        "rule": "alphabetically first item of npm_audit_only; EMPTY if group empty",
        "group_count": len(npm_only),
    }
    if npm_only:
        item = sorted(npm_only)[0]
        cs3["selected"] = item
        cs3.update(path_for_endpoint(flagged_doc, verify_doc, item))
        cs3["cause"] = next(
            (c["cause"] for c in comp.get("causes", []) if c["item"] == item), None
        )
    else:
        cs3.update({
            "selected": "EMPTY", "path": None, "path_label": "EMPTY",
            "advisory_ids": [], "verification": "EMPTY", "cause": None,
        })

    report = {
        "schema": "vulnchain-proof/case_studies/1",
        "selection": "mechanical; no cherry-picking; tie-break alphabetical ascending",
        "cases": [cs1, cs2, cs3],
    }
    out = Path(args.json_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for c in report["cases"]:
        print("%s -> %s (hops=%s, verification=%s)" % (
            c["case"], c.get("selected"), c.get("hops"), c.get("verification")))
    print("  wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
