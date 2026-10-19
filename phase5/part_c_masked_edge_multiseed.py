"""
part_c_masked_edge_multiseed.py -- 5-Seed Masked-Edge Audit (50% Mask ONLY)
===========================================================================
Part C Step 4 of Phase 5 Continuation II.

Runs masked-edge audit at 50% mask across seeds {42, 123, 456, 789, 1024} for:
1. label-prop baseline
2. VulnGAT-HR (v1-HR)

Reports:
- AUC mean +- std for label-prop
- AUC mean +- std for VulnGAT-HR
- margin = max(0.02, 2 * std(label-prop))
- pre-registered success threshold = mean(label-prop) + margin
"""

import os
import sys
import json
import torch
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "TrainModel"))

# Import functions directly from the proven masked_edge_audit.py
from masked_edge_audit import (
    compute_own_vpss,
    select_eligible_packages,
    apply_edge_mask,
    run_model_inference,
    run_label_prop_baseline,
    compute_auc,
    compute_auc_stratified,
    get_never_vuln_indices,
)
from training.dataset import load_vulnchain_dataset
from core.model.vulngat import VulnGAT

SEEDS = [42, 123, 456, 789, 1024]
MASK_RATIO = 0.50
OWN_VPSS_THRESHOLD = 0.70

GRAPH_FILE = str(PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json")
LABELS_FILE = str(PROJECT_ROOT / "phase4" / "vpss_labels_51repo.json")
SPLIT_FILE = str(PROJECT_ROOT / "phase4" / "repo_split_mapping_51repo.json")
MODEL_FILE = str(PROJECT_ROOT / "phase5" / "models" / "vulngat_hr_full.pt")
OUTPUT_JSON = PROJECT_ROOT / "phase5" / "part_c_masked_edge_audit_5seeds.json"


def main():
    print("=" * 70)
    print("  PART C: 5-Seed Masked-Edge Audit (50% Mask ONLY)")
    print("=" * 70)

    device = torch.device("cpu")

    # 1. Load data
    print("Loading audit data...")
    with open(GRAPH_FILE, "r", encoding="utf-8") as f:
        graph_json = json.load(f)
    with open(LABELS_FILE, "r", encoding="utf-8") as f:
        vpss_labels = json.load(f)

    data, mappings, masks = load_vulnchain_dataset(
        graph_path=GRAPH_FILE, labels_path=LABELS_FILE, repo_split_path=SPLIT_FILE
    )
    pkg_id_to_idx = mappings["pkg_id_to_idx"]
    idx_to_pkg_id = mappings["idx_to_pkg_id"]
    cve_id_to_idx = mappings["cve_id_to_idx"]
    num_packages = data["Package"].num_nodes

    # 2. Decompose own-VPSS and filter eligible packages
    print("Filtering eligible packages (own/VPSS >= 0.70)...")
    own_vpss_data = compute_own_vpss(graph_json, vpss_labels)
    eligible_pkg_ids = select_eligible_packages(own_vpss_data, OWN_VPSS_THRESHOLD)
    never_vuln_indices = get_never_vuln_indices(vpss_labels, pkg_id_to_idx, num_packages)
    print(f"  Eligible packages: {len(eligible_pkg_ids)}")
    print(f"  Never-vulnerable negatives: {len(never_vuln_indices)}")

    # 3. Load VulnGAT-HR model
    print(f"Loading VulnGAT-HR from {MODEL_FILE}...")
    model = VulnGAT()
    model.load_state_dict(torch.load(MODEL_FILE, map_location=device))
    model.to(device)
    model.eval()

    results_by_seed = []
    model_aucs_overall = []
    lp_aucs_overall = []

    model_aucs_shared = []
    lp_aucs_shared = []

    model_aucs_orphaned = []
    lp_aucs_orphaned = []

    print(f"\nRunning 50% mask audit across seeds {SEEDS}...")
    for seed in SEEDS:
        print(f"\n--- Seed {seed} ---")
        # Apply 50% mask
        masked_data, masked_pkg_indices, masked_pkg_to_cves, stratum_labels = apply_edge_mask(
            data, eligible_pkg_ids, pkg_id_to_idx, graph_json, cve_id_to_idx,
            MASK_RATIO, seed,
        )

        n_shared = sum(1 for s in stratum_labels.values() if s == "shared")
        n_orphaned = sum(1 for s in stratum_labels.values() if s == "orphaned")
        print(f"  Masked packages: {len(masked_pkg_indices)} (shared: {n_shared}, orphaned: {n_orphaned})")

        # Model inference
        model_scores = run_model_inference(model, masked_data, device)

        # Label-prop baseline
        lp_scores = run_label_prop_baseline(
            masked_data, vpss_labels, pkg_id_to_idx, idx_to_pkg_id, num_packages
        )

        # Stratified AUCs
        model_auc_strat = compute_auc_stratified(model_scores, masked_pkg_indices, never_vuln_indices, stratum_labels)
        lp_auc_strat = compute_auc_stratified(lp_scores, masked_pkg_indices, never_vuln_indices, stratum_labels)

        print(f"  Model AUC (overall):      {model_auc_strat['overall']:.4f} (shared: {model_auc_strat['shared']:.4f}, orphaned: {model_auc_strat['orphaned']:.4f})")
        print(f"  Label-Prop AUC (overall): {lp_auc_strat['overall']:.4f} (shared: {lp_auc_strat['shared']:.4f}, orphaned: {lp_auc_strat['orphaned']:.4f})")

        model_aucs_overall.append(model_auc_strat["overall"])
        lp_aucs_overall.append(lp_auc_strat["overall"])
        model_aucs_shared.append(model_auc_strat["shared"])
        lp_aucs_shared.append(lp_auc_strat["shared"])
        model_aucs_orphaned.append(model_auc_strat["orphaned"])
        lp_aucs_orphaned.append(lp_auc_strat["orphaned"])

        results_by_seed.append({
            "seed": seed,
            "model_auc": model_auc_strat,
            "label_prop_auc": lp_auc_strat,
        })

    # Summary statistics
    lp_mean = float(np.mean(lp_aucs_overall))
    lp_std = float(np.std(lp_aucs_overall))
    model_mean = float(np.mean(model_aucs_overall))
    model_std = float(np.std(model_aucs_overall))

    margin = max(0.02, 2.0 * lp_std)
    success_threshold = lp_mean + margin

    print("\n" + "=" * 70)
    print("  MASKED-EDGE AUDIT SUMMARY (50% Mask, 5 Seeds)")
    print("=" * 70)
    print(f"  VulnGAT-HR AUC (overall):    {model_mean:.4f} +- {model_std:.4f}")
    print(f"  Label-Prop AUC (overall):    {lp_mean:.4f} +- {lp_std:.4f}")
    print(f"  Label-Prop std:              {lp_std:.4f}")
    print(f"  Margin = max(0.02, 2*std):   {margin:.4f}")
    print(f"  Pre-registered Success Bar:  {success_threshold:.4f} (label-prop + margin)")
    print(f"  Current VulnGAT-HR vs Bar:   {model_mean:.4f} vs {success_threshold:.4f} (Diff: {model_mean - success_threshold:+.4f})")
    print(f"  Shared stratum:   Model = {np.mean(model_aucs_shared):.4f} +- {np.std(model_aucs_shared):.4f} | LP = {np.mean(lp_aucs_shared):.4f} +- {np.std(lp_aucs_shared):.4f}")
    print(f"  Orphaned stratum: Model = {np.mean(model_aucs_orphaned):.4f} +- {np.std(model_aucs_orphaned):.4f} | LP = {np.mean(lp_aucs_orphaned):.4f} +- {np.std(lp_aucs_orphaned):.4f}")

    output_payload = {
        "mask_ratio": MASK_RATIO,
        "seeds": SEEDS,
        "overall_summary": {
            "model_auc_mean": model_mean,
            "model_auc_std": model_std,
            "label_prop_auc_mean": lp_mean,
            "label_prop_auc_std": lp_std,
            "margin": margin,
            "success_threshold": success_threshold,
            "model_passes_criterion": model_mean >= success_threshold,
        },
        "shared_stratum": {
            "model_auc_mean": float(np.mean(model_aucs_shared)),
            "model_auc_std": float(np.std(model_aucs_shared)),
            "label_prop_auc_mean": float(np.mean(lp_aucs_shared)),
            "label_prop_auc_std": float(np.std(lp_aucs_shared)),
        },
        "orphaned_stratum": {
            "model_auc_mean": float(np.mean(model_aucs_orphaned)),
            "model_auc_std": float(np.std(model_aucs_orphaned)),
            "label_prop_auc_mean": float(np.mean(lp_aucs_orphaned)),
            "label_prop_auc_std": float(np.std(lp_aucs_orphaned)),
        },
        "by_seed": results_by_seed,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)
    print(f"\n[OK] Results saved to: {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
