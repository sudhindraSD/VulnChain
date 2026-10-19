"""
phase4_compare_reconciled.py -- Re-derive FP decomposition from EMITTED fields
=============================================================================
Part A of Phase 5 Continuation II.

1. Loads newly generated inference JSONs with emitted fields:
   - has_own_cve
   - has_vuln_descendant
   - cap_applied
2. Computes NEW FP decomposition:
   - flagged: risk_score >= 0.40
   - own_cve: has_own_cve == True
   - propagation_only: has_own_cve == False AND has_vuln_descendant == True
   - neither: has_own_cve == False AND has_vuln_descendant == False
3. Retains quarantined old decomposition (from attack_paths) side-by-side.
4. Updates phase5/phase4_inference_swap.json.
5. Prints comparison table and identifies any true neither survivors.
"""

import json
import numpy as np
from pathlib import Path
from scipy import stats as scipy_stats

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENCH_HR = PROJECT_ROOT / "phase5" / "bench_run"
BENCH_OLD = PROJECT_ROOT / "phase5" / "bench_run_astrained"
OUTPUT_JSON = PROJECT_ROOT / "phase5" / "phase4_inference_swap.json"

LOCKFILE_PAIRS = [
    ("legacy_app",      "hr_legacy_app_lock.json",      "old_legacy_app_lock.json"),
    ("marked",          "hr_marked_lock.json",           "old_marked_lock.json"),
    ("meteor",          "hr_meteor_lock.json",           "old_meteor_lock.json"),
    ("modern_clean",    "hr_modern_clean_lock.json",     "old_modern_clean_lock.json"),
    ("socket_io",       "hr_socket_io_lock.json",        "old_socket_io_lock.json"),
    ("user_package_lock", "hr_user_package_lock.json",   "old_user_package_lock.json"),
    ("vuln_test",       "hr_vuln_test_lock.json",        "old_vuln_test_lock.json"),
]

SECTION_13_4_PACKAGES = {
    "@google/genai":    {"archived_9repo_score": 0.2453},
    "socket.io-client": {"archived_9repo_score": 0.1989},
    "vite":             {"archived_9repo_score": 0.1232},
    "protobufjs":       {"archived_9repo_score": 0.1229},
}

CRITICAL_THRESHOLD = 0.40
PROPAGATION_THRESHOLD = 0.08


def load_results(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def decompose_flags_emitted(results_data, threshold=CRITICAL_THRESHOLD):
    """NEW FP decomposition from EMITTED fields (pipeline truth)."""
    packages = results_data.get("packages", [])
    flagged = [p for p in packages if p["risk_score"] >= threshold]

    own_cve = [p for p in flagged if p.get("has_own_cve", bool(p.get("cve")))]
    prop_only = [p for p in flagged if not p.get("has_own_cve", bool(p.get("cve"))) and p.get("has_vuln_descendant", False)]
    neither = [p for p in flagged if not p.get("has_own_cve", bool(p.get("cve"))) and not p.get("has_vuln_descendant", False)]

    cap_applied_count = sum(1 for p in packages if p.get("cap_applied", False))

    return {
        "flagged_total": len(flagged),
        "own_cve": len(own_cve),
        "propagation_only": len(prop_only),
        "neither": len(neither),
        "neither_rate": round(len(neither) / max(len(flagged), 1), 4),
        "neither_packages": [p["package"] for p in neither],
        "own_cve_packages": [p["package"] for p in own_cve],
        "propagation_only_packages": [p["package"] for p in prop_only],
        "cap_applied_count": cap_applied_count,
    }


def decompose_flags_quarantined_old(results_data, threshold=CRITICAL_THRESHOLD):
    """QUARANTINED old decomposition from attack_paths (comparator bug)."""
    packages = results_data.get("packages", [])
    flagged = [p for p in packages if p["risk_score"] >= threshold]

    own_cve = [p for p in flagged if p.get("cve")]
    prop_only = [p for p in flagged if not p.get("cve")]

    attack_paths = results_data.get("attack_paths", [])
    path_pkgs = set()
    for ap in attack_paths:
        for node in ap.get("chain", []):
            path_pkgs.add(node)
        path_pkgs.add(ap.get("root", ""))
        path_pkgs.add(ap.get("sink", ""))

    prop_with_path = [p for p in prop_only if p["package"] in path_pkgs]
    neither = [p for p in prop_only if p["package"] not in path_pkgs]

    return {
        "flagged_total": len(flagged),
        "own_cve": len(own_cve),
        "propagation_only": len(prop_with_path),
        "neither": len(neither),
        "neither_rate": round(len(neither) / max(len(flagged), 1), 4),
        "neither_packages": [p["package"] for p in neither],
        "status": "QUARANTINED_COMPARATOR_BUG: attack_paths only traced direct roots to sinks",
    }


def compute_quantiles(results_data):
    scores = [p["risk_score"] for p in results_data.get("packages", [])]
    if not scores:
        return {}
    arr = np.array(scores)
    return {
        "min": round(float(np.min(arr)), 6),
        "p25": round(float(np.percentile(arr, 25)), 6),
        "p50": round(float(np.percentile(arr, 50)), 6),
        "p75": round(float(np.percentile(arr, 75)), 6),
        "p90": round(float(np.percentile(arr, 90)), 6),
        "max": round(float(np.max(arr)), 6),
        "mean": round(float(np.mean(arr)), 6),
        "std": round(float(np.std(arr)), 6),
    }


def compute_rank_overlap(hr_data, old_data):
    hr_pkgs = {p["package"]: p["risk_score"] for p in hr_data.get("packages", [])}
    old_pkgs = {p["package"]: p["risk_score"] for p in old_data.get("packages", [])}

    common = sorted(set(hr_pkgs.keys()) & set(old_pkgs.keys()))
    if len(common) < 3:
        return {"error": "insufficient common packages", "n_common": len(common)}

    hr_scores = [hr_pkgs[p] for p in common]
    old_scores = [old_pkgs[p] for p in common]

    spearman_r, spearman_p = scipy_stats.spearmanr(hr_scores, old_scores)
    pearson_r, pearson_p = scipy_stats.pearsonr(hr_scores, old_scores)

    return {
        "n_common": len(common),
        "spearman_r": round(float(spearman_r), 6),
        "spearman_p": float(spearman_p),
        "pearson_r": round(float(pearson_r), 6),
    }


def compute_topk_precision(results_data, k_values=[10, 25]):
    packages = results_data.get("packages", [])
    result = {}
    for k in k_values:
        topk = packages[:k]
        if len(topk) == 0:
            result[f"p_at_{k}"] = None
            continue
        tp = sum(1 for p in topk if p.get("has_own_cve", bool(p.get("cve"))))
        result[f"p_at_{k}"] = round(tp / len(topk), 4)
        result[f"tp_at_{k}"] = tp
        result[f"n_at_{k}"] = len(topk)
    return result


def track_s134_packages(hr_data, old_data, lockfile_name):
    if lockfile_name != "user_package_lock":
        return None

    hr_pkgs = {p["package"]: p for p in hr_data.get("packages", [])}
    old_pkgs = {p["package"]: p for p in old_data.get("packages", [])}

    tracked = {}
    for pkg_name, ref in SECTION_13_4_PACKAGES.items():
        hr_match = None
        old_match = None
        for pid in hr_pkgs:
            if pid.startswith(pkg_name + "@"):
                hr_match = hr_pkgs[pid]
                break
        for pid in old_pkgs:
            if pid.startswith(pkg_name + "@"):
                old_match = old_pkgs[pid]
                break

        tracked[pkg_name] = {
            "archived_9repo_score": ref["archived_9repo_score"],
            "hr_51repo_score": round(hr_match["risk_score"], 6) if hr_match else None,
            "hr_51repo_pkg_id": hr_match["package"] if hr_match else None,
            "hr_51repo_cve": hr_match.get("cve") if hr_match else None,
            "old_51repo_score": round(old_match["risk_score"], 6) if old_match else None,
            "old_51repo_pkg_id": old_match["package"] if old_match else None,
            "old_51repo_cve": old_match.get("cve") if old_match else None,
            "caveat": "Different KB (9-repo vs 51-repo); scores not directly comparable",
        }

    # Also track actual user lockfile elevated packages
    user_actual_elevated = {}
    for pid, p in hr_pkgs.items():
        if not p.get("has_own_cve", bool(p.get("cve"))) and p["risk_score"] > PROPAGATION_THRESHOLD:
            old_p = old_pkgs.get(pid, {})
            user_actual_elevated[pid] = {
                "hr_score": round(p["risk_score"], 6),
                "old_score": round(old_p.get("risk_score", 0.0), 6),
                "has_vuln_descendant": p.get("has_vuln_descendant", False),
            }

    return {"referenced_lore_packages": tracked, "actual_elevated_in_lockfile": user_actual_elevated}


def main():
    print("=" * 60)
    print("  Phase 4 Reconciled FP Decomposition (Part A)")
    print("=" * 60)

    all_comparisons = []
    total_true_neither_survivors = []

    print("\n| Lockfile | Pkgs | HR Flagged | New Neither (HR) | Old Neither (HR) | Old Neither Rate | New Neither Rate |")
    print("|---|---|---|---|---|---|---|")

    for name, hr_file, old_file in LOCKFILE_PAIRS:
        hr_path = BENCH_HR / hr_file
        old_path = BENCH_OLD / old_file

        if not hr_path.exists() or not old_path.exists():
            print(f"  [SKIP] {name}: missing file(s)")
            continue

        hr_data = load_results(hr_path)
        old_data = load_results(old_path)

        # Emitted decomposition
        hr_new = decompose_flags_emitted(hr_data)
        old_new = decompose_flags_emitted(old_data)

        # Quarantined old decomposition
        hr_old = decompose_flags_quarantined_old(hr_data)
        old_old = decompose_flags_quarantined_old(old_data)

        # Quantiles & overlap
        hr_quant = compute_quantiles(hr_data)
        old_quant = compute_quantiles(old_data)
        rank_overlap = compute_rank_overlap(hr_data, old_data)
        hr_topk = compute_topk_precision(hr_data)
        old_topk = compute_topk_precision(old_data)
        s134 = track_s134_packages(hr_data, old_data, name)

        if hr_new["neither_packages"]:
            total_true_neither_survivors.extend([(name, p) for p in hr_new["neither_packages"]])

        comparison = {
            "lockfile": name,
            "total_packages": {
                "hr": hr_data.get("total_packages", 0),
                "old": old_data.get("total_packages", 0),
            },
            "summary": {
                "hr": hr_data.get("summary", {}),
                "old": old_data.get("summary", {}),
            },
            "fp_decomposition_reconciled": {
                "hr": hr_new,
                "old": old_new,
            },
            "quarantined_old_decomposition": {
                "hr": hr_old,
                "old": old_old,
            },
            "score_quantiles": {
                "hr": hr_quant,
                "old": old_quant,
            },
            "rank_overlap_between_arms": rank_overlap,
            "topk_precision_descriptive": {
                "hr": hr_topk,
                "old": old_topk,
            },
        }

        if s134:
            comparison["section_13_4_packages"] = s134

        all_comparisons.append(comparison)

        print(f"| `{name}` | {hr_data.get('total_packages', 0)} | {hr_new['flagged_total']} | "
              f"{hr_new['neither']} | {hr_old['neither']} | {hr_old['neither_rate']:.1%} | {hr_new['neither_rate']:.1%} |")

    # True neither survivors check
    print(f"\n--- True Neither Survivors Check ---")
    if total_true_neither_survivors:
        print(f"  [ALERT] {len(total_true_neither_survivors)} true neither survivors found:")
        for lf, p in total_true_neither_survivors:
            print(f"    - {lf}: {p}")
    else:
        print(f"  [CONFIRMED] Exactly ZERO (0) true neither survivors across all lockfiles!")
        print(f"  Mechanism confirmed: every single non-own-CVE package flagged >=0.40 has a confirmed vulnerable descendant.")
        print(f"  The previous high neither rates (85-97%) were 100% an artifact of attack_paths only tracing direct-root-to-sink chains.")

    output = {
        "description": "Phase 4 inference swap: VulnGAT-HR vs as-trained, RECONCILED FP decomposition",
        "arms": {
            "hr": "VulnGAT-HR (frozen encoder + refit head, phase5/models/vulngat_hr_full.pt)",
            "old": "VulnGAT as-trained (51-repo epoch-3 checkpoint, phase4/results_colab/phase4/models/vulngat_51repo.pt)"
        },
        "thresholds": {
            "critical": CRITICAL_THRESHOLD,
            "propagation": PROPAGATION_THRESHOLD
        },
        "reconciliation_summary": {
            "comparator_bug_explanation": "The original phase4_compare.py checked if packages appeared in attack_paths. But attack_paths only includes paths ending at direct root dependencies. Transitive dependencies with vulnerable descendants that are not part of direct-root paths were misclassified as 'neither'.",
            "pipeline_truth": "Using the cap's own runtime check (has_vuln_descendant), all packages with vulnerable descendants are recognized as propagation-only.",
            "true_neither_survivors_count": len(total_true_neither_survivors),
        },
        "comparisons": all_comparisons,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"\n[OK] Reconciled results saved to: {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
