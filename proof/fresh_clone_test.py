"""
PHASE 3 fresh-clone test for the STEP 4 proof module.

Clones the proof-module branch into a temp dir, creates a fresh virtualenv,
installs from scratch, then runs CLI + verify_paths.py + make_exports.py on
demo/sample-lock.json and confirms every required JSON regenerates and is valid.
Every exact command and its result is logged to proof/out/fresh_clone_log.json.

Usage:
  python proof/fresh_clone_test.py --repo-root . --log proof/out/fresh_clone_log.json
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = [
    "flagged_packages.json",
    "verify_report.json",
    "npm_audit_comparison.json",
    "graph_subgraph.json",
    "audit_scores.json",
    "meta.json",
]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, cwd, label, timeout=900):
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
        )
        return {
            "label": label,
            "command": " ".join('"%s"' % a if " " in a else a for a in argv),
            "argv": [str(a) for a in argv],
            "cwd": str(cwd),
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-8000:],
            "stderr": proc.stderr[-4000:],
            "error": None,
        }
    except Exception as exc:
        return {
            "label": label,
            "command": " ".join(str(a) for a in argv),
            "argv": [str(a) for a in argv],
            "cwd": str(cwd),
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "error": type(exc).__name__ + ": " + str(exc),
        }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fresh_clone_test.py")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--branch", default="proof-module")
    ap.add_argument("--keep-temp", action="store_true")
    args = ap.parse_args(argv)

    src = Path(args.repo_root).resolve()
    tmp = Path(tempfile.mkdtemp(prefix="vulnchain_fresh_clone_"))
    clone = tmp / "clone"
    venv = tmp / "freshvenv"
    venv_py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    log = {
        "schema": "vulnchain-proof/fresh_clone_log/1",
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_repo": str(src),
        "temp_dir": str(tmp),
        "branch": args.branch,
        "commands": [],
        "exports_before": {},
        "exports_after": {},
        "validation": {},
    }

    def record(entry):
        log["commands"].append(entry)
        print("  [%s] exit=%s" % (entry["label"], entry["exit_code"]))
        if entry["error"]:
            print("       ERROR " + entry["error"])
        return entry

    print("fresh-clone test: %s" % tmp)
    e = record(run(["git", "clone", "--no-hardlinks", "--branch", args.branch, str(src), str(clone)], tmp, "git clone", timeout=300))
    clone_ok = e["exit_code"] == 0 and clone.exists()

    install_ok = False
    if clone_ok:
        e = record(run([sys.executable, "-m", "venv", str(venv)], tmp, "python -m venv", timeout=300))
        if e["exit_code"] == 0:
            e = record(run([str(venv_py), "-m", "pip", "install", "--no-deps", "-e", "."], clone, "pip install -e . --no-deps", timeout=600))
            install_ok = e["exit_code"] == 0
            if not install_ok:
                # Fallback is logged, never hidden.
                e2 = record(run([str(venv_py), "-m", "pip", "install", "--no-build-isolation", "--no-deps", "-e", "."], clone, "pip install --no-build-isolation -e . --no-deps (fallback)", timeout=600))
                install_ok = e2["exit_code"] == 0

    for name in REQUIRED:
        p = clone / "proof/out" / name
        if p.exists():
            log["exports_before"][name] = {"sha256": sha256(p), "bytes": p.stat().st_size}

    if clone_ok and install_ok:
        record(run([str(venv_py), "-m", "vulnchain.proof", "demo/sample-lock.json", "--json", "proof/out/flagged_packages.json"], clone, "CLI: python -m vulnchain.proof"))
        record(run([str(venv_py), "proof/verify_paths.py", "demo/sample-lock.json", "proof/out/flagged_packages.json", "--kb", "phase5/bench_run/vulnchain_graph.json", "--cache", "phase5/bench_run/osv_cache.json", "--json", "proof/out/verify_report.json"], clone, "verify_paths.py"))
        record(run([str(venv_py), "proof/make_exports.py", "--lockfile", "demo/sample-lock.json", "--out-dir", "proof/out", "--repo-root", "."], clone, "make_exports.py (all six exports)", timeout=900))

        validation_snippet = (
            "import json,pathlib,sys;"
            "names=%r;"
            "d=pathlib.Path('proof/out');"
            "out={n:(d/n).exists() for n in names};"
            "[json.loads((d/n).read_text()) for n in names if out[n]];"
            "print(json.dumps(out));"
            "sys.exit(0 if all(out.values()) else 1)" % REQUIRED
        )
        record(run([str(venv_py), "-c", validation_snippet], clone, "validate all six JSON files", timeout=120))

    for name in REQUIRED:
        p = clone / "proof/out" / name
        if p.exists():
            after = {"sha256": sha256(p), "bytes": p.stat().st_size}
            before = log["exports_before"].get(name)
            after["changed_from_committed_copy"] = (before is not None and before["sha256"] != after["sha256"])
            try:
                json.loads(p.read_text(encoding="utf-8"))
                after["valid_json"] = True
            except Exception as exc:
                after["valid_json"] = False
                after["validation_error"] = str(exc)
            log["exports_after"][name] = after
        else:
            log["exports_after"][name] = {"exists": False, "valid_json": False}

    all_valid = all(v.get("valid_json") for v in log["exports_after"].values())
    all_run_ok = all(
        e["exit_code"] == 0 for e in log["commands"]
        if e["label"] in (
            "git clone", "python -m venv", "CLI: python -m vulnchain.proof",
            "verify_paths.py", "make_exports.py (all six exports)",
            "validate all six JSON files",
        )
    )
    install_entries = [e for e in log["commands"] if e["label"].startswith("pip install")]
    install_run_ok = any(e["exit_code"] == 0 for e in install_entries)
    passed = clone_ok and install_ok and install_run_ok and all_valid and all_run_ok

    log["validation"] = {
        "clone_ok": clone_ok,
        "install_ok": install_ok,
        "all_six_valid": all_valid,
        "all_required_commands_exit_zero": all_run_ok,
        "criterion_c_pass": passed,
    }
    log["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    log["temp_dir_removed"] = not args.keep_temp

    out = Path(args.log)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
    print("  criterion (c) PASS=%s; all_six_valid=%s" % (passed, all_valid))
    print("  log written to %s" % out)

    if not args.keep_temp:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
