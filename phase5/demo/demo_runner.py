"""
Phase 5 Demo Runner -- VulnChain vs npm audit side-by-side
==========================================================
Runs the staged analyze_project.py (VulnGAT-HR merged checkpoint) and
npm audit --json on the same lockfiles.  Produces:
  - demo_comparison.json  (machine-readable)
  - DEMO_REPORT.md        (human-readable side-by-side)

Lockfiles:
  1. Personal 132-package lockfile  (TrainModel/user_package_lock.json)
  2. Scratch lockfiles from TrainModel/scratch/

All runs use the HR merged checkpoint in phase5/bench_run/ -- zero code
edits to analyze_project.py, same KB, same pipeline.
"""

import json
import os
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

# -- Paths --
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # Major VulnChain
BENCH_RUN = PROJECT_ROOT / "phase5" / "bench_run"
ANALYZE_PY = BENCH_RUN / "analyze_project.py"
DEMO_DIR = Path(__file__).resolve().parent

# Lockfiles to demo
LOCKFILES = {
    "personal_132pkg": PROJECT_ROOT / "TrainModel" / "user_package_lock.json",
    "vuln_test":       PROJECT_ROOT / "TrainModel" / "scratch" / "vuln_test_lock.json",
    "legacy_app":      PROJECT_ROOT / "TrainModel" / "scratch" / "legacy_app_lock.json",
}


def run_vulnchain(lockfile_path: Path, output_json: Path) -> dict:
    """Run analyze_project.py on a lockfile and return parsed JSON."""
    cmd = [
        sys.executable, str(ANALYZE_PY),
        str(lockfile_path),
        "--json", str(output_json)
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(BENCH_RUN), timeout=120
    )
    if result.returncode != 0:
        print(f"  [WARN] VulnChain returned code {result.returncode}")
        print(f"  stderr: {result.stderr[:500]}")

    if output_json.exists():
        with open(output_json, encoding="utf-8") as f:
            return json.load(f)
    return {}


def run_npm_audit(lockfile_path: Path) -> dict:
    """Run npm audit --json on a lockfile directory and return parsed JSON.

    npm audit requires a package.json + package-lock.json in a directory.
    We create a temporary directory with both files.
    """
    tmpdir = tempfile.mkdtemp(prefix="vulnchain_audit_")
    try:
        # Read the lockfile to extract the project name
        with open(lockfile_path, encoding="utf-8") as f:
            lock_data = json.load(f)

        project_name = lock_data.get("name", "demo-project")
        project_version = lock_data.get("version", "1.0.0")

        # Build a minimal package.json from the lockfile's top-level deps
        deps = {}
        if "packages" in lock_data and "" in lock_data["packages"]:
            root_deps = lock_data["packages"][""].get("dependencies", {})
            deps = {k: v for k, v in root_deps.items()}
        elif "dependencies" in lock_data:
            # lockfileVersion 1 -- extract top-level
            for name, meta in lock_data["dependencies"].items():
                deps[name] = meta.get("version", "*")

        pkg_json = {
            "name": project_name if project_name else "demo-project",
            "version": project_version if project_version else "1.0.0",
            "dependencies": deps
        }

        # Write both files
        with open(os.path.join(tmpdir, "package.json"), "w", encoding="utf-8") as f:
            json.dump(pkg_json, f, indent=2)
        shutil.copy2(str(lockfile_path), os.path.join(tmpdir, "package-lock.json"))

        # Run npm audit
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True,
            cwd=tmpdir, timeout=60,
            shell=True
        )
        # npm audit exits non-zero when vulnerabilities found -- that's expected
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"  [WARN] npm audit produced non-JSON output")
            return {"error": result.stdout[:500], "stderr": result.stderr[:500]}
    except Exception as e:
        return {"error": str(e)}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def extract_vulnchain_summary(vc_data: dict) -> dict:
    """Extract the key comparison fields from VulnChain output."""
    if not vc_data:
        return {"error": "no data"}

    packages = vc_data.get("packages", [])
    summary = vc_data.get("summary", {})
    attack_paths = vc_data.get("attack_paths", [])

    # Top flagged packages (score >= 0.40)
    flagged = [p for p in packages if p["risk_score"] >= 0.40]

    # Decompose: own-CVE vs propagation-only
    own_cve_flags = [p for p in flagged if p.get("cve")]
    prop_only_flags = [p for p in flagged if not p.get("cve")]

    # Top-10 ranked list with propagation paths
    top10 = []
    for p in packages[:10]:
        pkg_paths = [ap for ap in attack_paths if ap["sink"] == p["package"] or ap["root"] == p["package"]]
        top10.append({
            "rank": len(top10) + 1,
            "package": p["package"],
            "risk_score": round(p["risk_score"], 4),
            "cve": p.get("cve"),
            "is_direct": p["is_direct"],
            "propagation_paths": [
                {
                    "chain": " -> ".join(ap["chain"]),
                    "hops": ap["hops"],
                    "cve": ap["cve"]
                }
                for ap in pkg_paths[:3]  # up to 3 paths per package
            ]
        })

    return {
        "total_packages": vc_data.get("total_packages", 0),
        "summary": summary,
        "flagged_count": len(flagged),
        "own_cve_flags": len(own_cve_flags),
        "propagation_only_flags": len(prop_only_flags),
        "attack_paths_found": len(attack_paths),
        "top10_ranked": top10
    }


def extract_npm_audit_summary(audit_data: dict) -> dict:
    """Extract the key comparison fields from npm audit output."""
    if "error" in audit_data:
        return audit_data

    # npm audit v7+ format
    metadata = audit_data.get("metadata", {})
    vulns = audit_data.get("vulnerabilities", {})
    advisories = audit_data.get("advisories", {})

    if metadata:
        # New format (npm 7+)
        vuln_meta = metadata.get("vulnerabilities", {})
        total_vulns = sum(vuln_meta.get(sev, 0) for sev in ["critical", "high", "moderate", "low", "info"])
        severity_breakdown = {
            "critical": vuln_meta.get("critical", 0),
            "high": vuln_meta.get("high", 0),
            "moderate": vuln_meta.get("moderate", 0),
            "low": vuln_meta.get("low", 0),
            "info": vuln_meta.get("info", 0),
            "total": vuln_meta.get("total", total_vulns)
        }

        # Flat list of affected packages
        affected = []
        for pkg_name, vuln_info in vulns.items():
            if isinstance(vuln_info, dict):
                affected.append({
                    "package": pkg_name,
                    "severity": vuln_info.get("severity", "unknown"),
                    "via": [v if isinstance(v, str) else v.get("title", "unknown")
                            for v in vuln_info.get("via", [])],
                    "fix_available": vuln_info.get("fixAvailable", False)
                })

        return {
            "total_dependencies": metadata.get("dependencies", {}).get("total", 0),
            "total_vulnerabilities": severity_breakdown["total"],
            "severity_breakdown": severity_breakdown,
            "affected_packages": affected[:20],  # cap at 20 for readability
            "flat_advisory_count": len(advisories) if advisories else severity_breakdown["total"]
        }
    elif advisories:
        # Older format
        severity_counts = {}
        for adv_id, adv in advisories.items():
            sev = adv.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "total_advisories": len(advisories),
            "severity_breakdown": severity_counts,
            "affected_packages": [
                {"advisory": adv.get("title", ""), "module": adv.get("module_name", ""), "severity": adv.get("severity", "")}
                for adv in list(advisories.values())[:20]
            ]
        }
    else:
        return {"raw_keys": list(audit_data.keys()), "note": "unexpected format"}


def generate_report(comparisons: list) -> str:
    """Generate the DEMO_REPORT.md markdown."""
    lines = []
    lines.append("# VulnChain vs npm audit -- Side-by-Side Demo Report")
    lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Model:** VulnGAT-HR (frozen encoder + refit head, 51-repo KB)")
    lines.append(f"**Checkpoint:** `phase5/models/vulngat_hr_full.pt`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("npm audit provides a **flat list** of known CVEs affecting your dependency tree.")
    lines.append("VulnChain provides a **ranked risk assessment** that considers:")
    lines.append("- Vulnerability severity (CVSS)")
    lines.append("- Dependency graph topology (blast radius)")
    lines.append("- Propagation through transitive dependencies")
    lines.append("- Package exposure context (direct/transitive, dev/prod)")
    lines.append("")
    lines.append("The key difference: npm audit says *\"you have N advisories\"*;")
    lines.append("VulnChain says *\"here are your highest-risk packages, ranked, with the")
    lines.append("propagation paths that make them dangerous.\"*")
    lines.append("")

    for comp in comparisons:
        name = comp["lockfile_name"]
        vc = comp["vulnchain"]
        npm = comp["npm_audit"]

        lines.append(f"---")
        lines.append(f"")
        lines.append(f"## Lockfile: `{name}`")
        lines.append(f"")

        # Summary table
        lines.append("### At-a-Glance Comparison")
        lines.append("")
        lines.append("| Metric | npm audit | VulnChain |")
        lines.append("|--------|-----------|-----------|")

        npm_total = npm.get("total_vulnerabilities", npm.get("total_advisories", "?"))
        npm_crit = npm.get("severity_breakdown", {}).get("critical", "?")
        npm_high = npm.get("severity_breakdown", {}).get("high", "?")

        vc_total = vc.get("total_packages", "?")
        vc_flagged = vc.get("flagged_count", "?")
        vc_summary = vc.get("summary", {})

        lines.append(f"| Total packages analyzed | {npm.get('total_dependencies', '?')} | {vc_total} |")
        lines.append(f"| Vulnerability alerts | {npm_total} (flat advisories) | {vc_flagged} (risk >= 0.40) |")
        lines.append(f"| Critical | {npm_crit} | {vc_summary.get('critical', '?')} |")
        lines.append(f"| High | {npm_high} | {vc_summary.get('high', '?')} |")
        lines.append(f"| Own-CVE flags | -- | {vc.get('own_cve_flags', '?')} |")
        lines.append(f"| Propagation-only flags | -- | {vc.get('propagation_only_flags', '?')} |")
        lines.append(f"| Attack paths traced | -- | {vc.get('attack_paths_found', '?')} |")
        lines.append("")

        # npm audit affected list
        lines.append("### npm audit: Flat Advisory List")
        lines.append("")
        npm_affected = npm.get("affected_packages", [])
        if npm_affected:
            lines.append("| Package | Severity | Via | Fix Available |")
            lines.append("|---------|----------|-----|---------------|")
            for pkg in npm_affected[:15]:
                via_str = ", ".join(pkg.get("via", [])[:2]) if "via" in pkg else pkg.get("advisory", "")
                fix = "[Y]" if pkg.get("fix_available") else "[N]"
                sev = pkg.get("severity", "?")
                name_str = pkg.get("package", pkg.get("module", "?"))
                lines.append(f"| {name_str} | {sev} | {via_str} | {fix} |")
            lines.append("")
        else:
            lines.append("*(No advisories or unexpected format)*\n")

        # VulnChain ranked top-10
        lines.append("### VulnChain: Ranked Top-10 with Propagation Paths")
        lines.append("")
        top10 = vc.get("top10_ranked", [])
        if top10:
            for item in top10:
                cve_str = f" [!] `{item['cve']}`" if item["cve"] else " *(propagation-elevated)*"
                direct = "direct" if item["is_direct"] else "transitive"
                lines.append(f"**#{item['rank']}** `{item['package']}` -- **{item['risk_score']:.4f}**{cve_str} ({direct})")

                if item["propagation_paths"]:
                    for pp in item["propagation_paths"]:
                        lines.append(f"  - Path ({pp['hops']} hops, {pp['cve']}): `{pp['chain']}`")
                lines.append("")
        else:
            lines.append("*(No data)*\n")

        # Key insight
        lines.append("### Key Insight")
        lines.append("")
        if vc.get("propagation_only_flags", 0) > 0:
            lines.append(f"> VulnChain flagged **{vc['propagation_only_flags']}** packages that have no CVE of their own")
            lines.append(f"> but are elevated by propagation through vulnerable transitive dependencies.")
            lines.append(f"> npm audit would not flag these packages at all -- they are the blast radius")
            lines.append(f"> of the vulnerabilities, not the vulnerabilities themselves.")
        else:
            lines.append("> All VulnChain flags correspond to packages with their own CVEs in this lockfile.")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("## Methodology Notes")
    lines.append("")
    lines.append("- **VulnChain model:** VulnGAT-HR (frozen 2-layer GAT encoder trained on 51-repo graph, refit linear head)")
    lines.append("- **Knowledge base:** 51-repo heterogeneous graph (12,405 packages, 883 CVEs, 2,632 hasVulnerability edges)")
    lines.append("- **Risk score:** Sigmoid output [0, 1]; threshold at 0.40 for 'critical' classification")
    lines.append("- **Propagation paths:** BFS upstream from each CVE-bearing package to direct dependencies")
    lines.append("- **npm audit:** Standard `npm audit --json` with no registry modifications")
    lines.append("- **Post-hoc calibration:** Packages with no CVE and no vulnerable descendant capped at 0.08")
    lines.append("")
    lines.append("> [!NOTE]")
    lines.append("> The 100% NodeTestBench precision claim from Phase 4 is **retracted** (D4).")
    lines.append("> VulnGAT-HR precision on NodeTestBench is 75.6% (41 flagged, 10 FP) with recall 40.3%.")
    lines.append("> The model's strength is in ranking and propagation-aware risk assessment, not binary detection.")

    return "\n".join(lines)


def main():
    print("=" * 70)
    print("  Phase 5 Demo -- VulnChain vs npm audit")
    print("=" * 70)

    comparisons = []

    for name, lockfile in LOCKFILES.items():
        print(f"\n{'-' * 50}")
        print(f"  Lockfile: {name}")
        print(f"  Path: {lockfile}")
        print(f"{'-' * 50}")

        if not lockfile.exists():
            print(f"  [SKIP] File not found: {lockfile}")
            continue

        # 1. Run VulnChain
        print("  [1/2] Running VulnChain (VulnGAT-HR)...")
        vc_output = DEMO_DIR / f"vc_{name}.json"
        vc_raw = run_vulnchain(lockfile, vc_output)
        vc_summary = extract_vulnchain_summary(vc_raw)
        print(f"        -> {vc_summary.get('total_packages', '?')} packages, "
              f"{vc_summary.get('flagged_count', '?')} flagged, "
              f"{vc_summary.get('attack_paths_found', '?')} attack paths")

        # 2. Run npm audit
        print("  [2/2] Running npm audit --json...")
        npm_raw = run_npm_audit(lockfile)
        npm_summary = extract_npm_audit_summary(npm_raw)

        npm_vuln_count = npm_summary.get("total_vulnerabilities",
                                         npm_summary.get("total_advisories", "?"))
        print(f"        -> {npm_vuln_count} vulnerabilities reported")

        # Save raw npm output
        npm_output = DEMO_DIR / f"npm_{name}.json"
        with open(npm_output, "w", encoding="utf-8") as f:
            json.dump(npm_raw, f, indent=2)

        comparisons.append({
            "lockfile_name": name,
            "lockfile_path": str(lockfile),
            "vulnchain": vc_summary,
            "npm_audit": npm_summary
        })

    # Save comparison JSON
    comp_path = DEMO_DIR / "demo_comparison.json"
    with open(comp_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated": datetime.now().isoformat(),
            "model": "VulnGAT-HR (phase5/models/vulngat_hr_full.pt)",
            "comparisons": comparisons
        }, f, indent=2)
    print(f"\n[OK] Comparison JSON saved to: {comp_path}")

    # Generate markdown report
    report = generate_report(comparisons)
    report_path = DEMO_DIR / "DEMO_REPORT.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[OK] Demo report saved to: {report_path}")


if __name__ == "__main__":
    main()
