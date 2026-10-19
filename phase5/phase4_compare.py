"""
phase4_compare.py -- Phase 4 inference swap comparison (D2)
===========================================================
For each lockfile x arm (HR vs as-trained), produces:
  - FP decomposition: own-CVE / propagation-only / neither
  - Per-lockfile score quantiles + Spearman rank-overlap between arms
  - Top-K (K=10,25) precision as descriptive only
  - Four s13.4 packages across arms + archived 9-repo scores

Saves phase5/phase4_inference_swap.json.
"""

import json
import os
import sys
import numpy as np
from pathlib import Path
from scipy import stats as scipy_stats

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENCH_HR = PROJECT_ROOT / "phase5" / "bench_run"
BENCH_OLD = PROJECT_ROOT / "phase5" / "bench_run_astrained"
OUTPUT_JSON = PROJECT_ROOT / "phase5" / "phase4_inference_swap.json"

# Lockfile pairs: (name, hr_file, old_file)
LOCKFILE_PAIRS = [
    ("legacy_app",      "hr_legacy_app_lock.json",      "old_legacy_app_lock.json"),
    ("marked",          "hr_marked_lock.json",           "old_marked_lock.json"),
    ("meteor",          "hr_meteor_lock.json",           "old_meteor_lock.json"),
    ("modern_clean",    "hr_modern_clean_lock.json",     "old_modern_clean_lock.json"),
    ("socket_io",       "hr_socket_io_lock.json",        "old_socket_io_lock.json"),
    ("user_package_lock", "hr_user_package_lock.json",   "old_user_package_lock.json"),
    ("vuln_test",       "hr_vuln_test_lock.json",        "old_vuln_test_lock.json"),
]

# s13.4 packages to track across arms (from the personal lockfile)
SECTION_13_4_PACKAGES = {
    "@google/genai":    {"archived_9repo_score": 0.2453},
    "socket.io-client": {"archived_9repo_score": 0.1989},
    "vite":             {"archived_9repo_score": 0.1232},
    "protobufjs":       {"archived_9repo_score": 0.1229},
}

CRITICAL_THRESHOLD = 0.40
PROPAGATION_THRESHOLD = 0.08


def load_results(filepath):
    """Load an analyze_project.py JSON output."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def decompose_flags(results_data, threshold=CRITICAL_THRESHOLD):
    """FP decomposition: own-CVE / propagation-only / neither.

    Flagged = risk_score >= threshold
    own-CVE: has a cve field
    propagation-only: no cve, but risk_score > PROPAGATION_THRESHOLD (elevated by blast radius)
    neither: flagged >= threshold, no cve, no clear propagation reason
    """
    packages = results_data.get("packages", [])
    flagged = [p for p in packages if p["risk_score"] >= threshold]

    own_cve = [p for p in flagged if p.get("cve")]
    prop_only = [p for p in flagged if not p.get("cve")]

    # Further decompose prop_only: check if they have propagation paths
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
        "own_cve_packages": [p["package"] for p in own_cve],
        "propagation_only_packages": [p["package"] for p in prop_with_path],
    }


def compute_quantiles(results_data):
    """Per-lockfile score quantiles."""
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
    """Spearman rank-overlap between HR and as-trained arms."""
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
    """Top-K precision (descriptive only, no claims).

    Ground truth: packages with a non-null cve field.
    Precision@K = fraction of top-K packages that have a CVE.
    """
    packages = results_data.get("packages", [])
    result = {}
    for k in k_values:
        topk = packages[:k]
        if len(topk) == 0:
            result[f"p_at_{k}"] = None
            continue
        tp = sum(1 for p in topk if p.get("cve"))
        result[f"p_at_{k}"] = round(tp / len(topk), 4)
        result[f"tp_at_{k}"] = tp
        result[f"n_at_{k}"] = len(topk)
    return result


def track_s134_packages(hr_data, old_data, lockfile_name):
    """Track the four s13.4 packages across arms."""
    if lockfile_name != "user_package_lock":
        return None

    hr_pkgs = {p["package"]: p for p in hr_data.get("packages", [])}
    old_pkgs = {p["package"]: p for p in old_data.get("packages", [])}

    tracked = {}
    for pkg_name, ref in SECTION_13_4_PACKAGES.items():
        # Find the package in results (may have version suffix)
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

    return tracked


def main():
    print("=" * 60)
    print("  Phase 4 Inference Swap Comparison (D2)")
    print("=" * 60)

    all_comparisons = []

    for name, hr_file, old_file in LOCKFILE_PAIRS:
        hr_path = BENCH_HR / hr_file
        old_path = BENCH_OLD / old_file

        if not hr_path.exists() or not old_path.exists():
            print(f"  [SKIP] {name}: missing file(s)")
            continue

        print(f"\n  Processing: {name}")
        hr_data = load_results(hr_path)
        old_data = load_results(old_path)

        # Summary counts
        hr_summary = hr_data.get("summary", {})
        old_summary = old_data.get("summary", {})

        # FP decomposition
        hr_decomp = decompose_flags(hr_data)
        old_decomp = decompose_flags(old_data)

        # Quantiles
        hr_quant = compute_quantiles(hr_data)
        old_quant = compute_quantiles(old_data)

        # Rank overlap between arms
        rank_overlap = compute_rank_overlap(hr_data, old_data)

        # Top-K precision
        hr_topk = compute_topk_precision(hr_data)
        old_topk = compute_topk_precision(old_data)

        # s13.4 tracking
        s134 = track_s134_packages(hr_data, old_data, name)

        comparison = {
            "lockfile": name,
            "total_packages": {
                "hr": hr_data.get("total_packages", 0),
                "old": old_data.get("total_packages", 0),
            },
            "summary": {
                "hr": hr_summary,
                "old": old_summary,
            },
            "fp_decomposition": {
                "hr": hr_decomp,
                "old": old_decomp,
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

        # Print summary
        print(f"    HR:  {hr_decomp['flagged_total']} flagged "
              f"({hr_decomp['own_cve']} own-CVE, "
              f"{hr_decomp['propagation_only']} prop-only, "
              f"{hr_decomp['neither']} NEITHER [{hr_decomp['neither_rate']:.1%}])")
        print(f"    Old: {old_decomp['flagged_total']} flagged "
              f"({old_decomp['own_cve']} own-CVE, "
              f"{old_decomp['propagation_only']} prop-only, "
              f"{old_decomp['neither']} NEITHER [{old_decomp['neither_rate']:.1%}])")
        print(f"    Rank overlap: Spearman r={rank_overlap.get('spearman_r', '?')}")

    # Save output
    output = {
        "description": "Phase 4 inference swap: VulnGAT-HR vs as-trained, per-lockfile comparison",
        "arms": {
            "hr": "VulnGAT-HR (frozen encoder + refit head, phase5/models/vulngat_hr_full.pt)",
            "old": "VulnGAT as-trained (51-repo epoch-3 checkpoint, phase4/results_colab/phase4/models/vulngat_51repo.pt)",
        },
        "thresholds": {
            "critical": CRITICAL_THRESHOLD,
            "propagation": PROPAGATION_THRESHOLD,
        },
        "comparisons": all_comparisons,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"\n[OK] Saved to: {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
