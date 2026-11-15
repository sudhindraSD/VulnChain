"""
PHASE 4 independence audit.

Lists EVERY import statement in proof/verify_paths.py via AST. Any import from
project graph/model/feature code, any relative import, or any module outside
the pre-registered stdlib allow-list is a FAIL (PROOF_PROTOCOL.md section 2).

Usage:
  python proof/independence_audit.py --file proof/verify_paths.py \
      --json proof/out/independence_audit.json
"""
import argparse
import ast
import json
import sys
from pathlib import Path

ALLOWED_STDLIB = {
    "argparse", "collections", "hashlib", "json", "os", "pathlib", "re", "sys", "typing",
}
PROJECT_PREFIXES = (
    "vulnchain", "phase5", "data_pipeline", "webapp", "TrainModel",
    "core", "model", "models", "graph", "features", "verify_paths",
    "compare_npm_audit", "offline_online", "case_studies", "make_exports",
)


def extract_imports(source):
    tree = ast.parse(source)
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                rows.append({
                    "line": node.lineno,
                    "kind": "import",
                    "module": alias.name,
                    "names": [],
                    "level": 0,
                    "alias": alias.asname,
                    "statement": ast.get_source_segment(source, node),
                })
        elif isinstance(node, ast.ImportFrom):
            rows.append({
                "line": node.lineno,
                "kind": "import_from",
                "module": node.module,
                "names": [a.name for a in node.names],
                "level": node.level,
                "alias": None,
                "statement": ast.get_source_segment(source, node),
            })
    return sorted(rows, key=lambda r: (r["line"], r["kind"], r["module"] or ""))


def classify(row):
    module = row["module"] or ""
    top = module.split(".")[0]
    if row["level"] and row["level"] > 0:
        return "FAIL_RELATIVE_IMPORT"
    if any(module == p or module.startswith(p + ".") or top == p for p in PROJECT_PREFIXES):
        return "FAIL_PROJECT_IMPORT"
    if top not in ALLOWED_STDLIB:
        return "FAIL_NOT_IN_ALLOWLIST"
    return "OK_STDLIB"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="independence_audit.py")
    ap.add_argument("--file", required=True)
    ap.add_argument("--json", dest="json_out", required=True)
    args = ap.parse_args(argv)

    path = Path(args.file)
    source = path.read_text(encoding="utf-8")
    imports = extract_imports(source)
    for row in imports:
        row["verdict"] = classify(row)
    failures = [r for r in imports if r["verdict"] != "OK_STDLIB"]
    passed = len(failures) == 0

    report = {
        "schema": "vulnchain-proof/independence_audit/1",
        "audited_file": str(path),
        "allowed_stdlib": sorted(ALLOWED_STDLIB),
        "project_prefixes": list(PROJECT_PREFIXES),
        "import_count": len(imports),
        "imports": imports,
        "failures": failures,
        "result": "PASS" if passed else "FAIL",
    }
    out = Path(args.json_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("independence audit: %d imports, result=%s" % (len(imports), report["result"]))
    for row in imports:
        print("  L%-3d %-12s %-24s %s" % (
            row["line"], row["kind"], row["module"] or "(relative)", row["verdict"]))
    for row in failures:
        print("  FAIL: %s" % row["statement"])
    print("  wrote %s" % out)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
