"""
rerun_inferences.py -- Re-run all 7 lockfiles x 2 arms with instrumented analyze_project.py
"""
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOCKFILES = [
    ("legacy_app", PROJECT_ROOT / "TrainModel" / "scratch" / "legacy_app_lock.json", "hr_legacy_app_lock.json", "old_legacy_app_lock.json"),
    ("marked", PROJECT_ROOT / "TrainModel" / "scratch" / "marked_lock.json", "hr_marked_lock.json", "old_marked_lock.json"),
    ("meteor", PROJECT_ROOT / "TrainModel" / "scratch" / "meteor_lock.json", "hr_meteor_lock.json", "old_meteor_lock.json"),
    ("modern_clean", PROJECT_ROOT / "TrainModel" / "scratch" / "modern_clean_lock.json", "hr_modern_clean_lock.json", "old_modern_clean_lock.json"),
    ("socket_io", PROJECT_ROOT / "TrainModel" / "scratch" / "socket_io_lock.json", "hr_socket_io_lock.json", "old_socket_io_lock.json"),
    ("user_package_lock", PROJECT_ROOT / "TrainModel" / "user_package_lock.json", "hr_user_package_lock.json", "old_user_package_lock.json"),
    ("vuln_test", PROJECT_ROOT / "TrainModel" / "scratch" / "vuln_test_lock.json", "hr_vuln_test_lock.json", "old_vuln_test_lock.json"),
]

BENCH_HR = PROJECT_ROOT / "phase5" / "bench_run"
BENCH_OLD = PROJECT_ROOT / "phase5" / "bench_run_astrained"

def is_already_updated(file_path):
    if not file_path.exists():
        return False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read(2048)
            return "has_own_cve" in content
    except:
        return False

def run_cmd(cwd, cmd):
    print(f"[{cwd.name}] Running: {' '.join(cmd)}", flush=True)
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  ERROR (code {res.returncode}): {res.stderr[-500:]}", flush=True)
        sys.exit(1)
    else:
        print(f"  OK", flush=True)

def main():
    print("=== Re-running 7 lockfiles x 2 arms ===", flush=True)
    for name, lock_path, hr_out, old_out in LOCKFILES:
        print(f"\n--- {name} ---", flush=True)
        # HR arm
        hr_out_path = BENCH_HR / hr_out
        if is_already_updated(hr_out_path):
            print(f"  [bench_run] SKIP (already updated: {hr_out})", flush=True)
        else:
            cmd_hr = [sys.executable, "analyze_project.py", str(lock_path), "--json", str(hr_out_path)]
            run_cmd(BENCH_HR, cmd_hr)

        # Old arm
        old_out_path = BENCH_OLD / old_out
        if is_already_updated(old_out_path):
            print(f"  [bench_run_astrained] SKIP (already updated: {old_out})", flush=True)
        else:
            cmd_old = [sys.executable, "analyze_project.py", str(lock_path), "--json", str(old_out_path)]
            run_cmd(BENCH_OLD, cmd_old)

    print("\n[ALL COMPLETE] All 14 runs finished cleanly.", flush=True)

if __name__ == "__main__":
    main()
