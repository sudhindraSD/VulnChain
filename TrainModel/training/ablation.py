"""
training/ablation.py — Ablation Studies for VulnChain (Section 11.3)

Evaluates the contribution of each architectural component by training variants:
  - Full VulnGAT (Baseline)
  - A1: No Author Nodes (removes Author nodes + maintainedBy / introducedBy edges)
  - A2: No Contrastive Loss (sets InfoNCE weight = 0.0)
  - A4: Raw CVSS Only (replaces 768-dim SentenceBERT embedding with 1 CVSS scalar)
"""

import os
import sys
import copy
import torch
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.model.vulngat import VulnGAT
from core.model.loss import VulnChainLoss
from training.dataset import load_vulnchain_dataset
from training.evaluate import evaluate_model


def run_ablation_experiment(
    variant_name: str,
    data,
    masks,
    mappings,
    device: torch.device,
    infonce_weight: float = 0.1,
    cve_dim: int = 769,
    remove_author: bool = False,
    max_epochs: int = 40,
    patience: int = 8
) -> dict:
    """
    Trains a model variant under specified ablation conditions and evaluates on the test split.
    """
    print(f"\n{'=' * 60}")
    print(f"Running Ablation Variant: {variant_name}")
    print(f"{'=' * 60}")

    # Prepare data copy
    exp_data = copy.deepcopy(data)
    pkg_ids = [mappings["idx_to_pkg_id"][i] for i in range(len(mappings["idx_to_pkg_id"]))]

    if remove_author:
        # A1: Drop Author nodes & edges
        del exp_data["Author"]
        del exp_data["Package", "maintainedBy", "Author"]
        del exp_data["CVE", "introducedBy", "Author"]

    if cve_dim == 1:
        # A4: Use only CVSS score (1-dim)
        exp_data["CVE"].x = exp_data["CVE"].x[:, :1]

    # Initialize model
    model = VulnGAT(
        hidden_dim=128,
        num_layers=3,
        num_heads=4,
        dropout=0.3
    )
    if cve_dim != 769:
        model.projections["CVE"] = torch.nn.Linear(cve_dim, 128)
    if remove_author:
        del model.projections["Author"]
        for layer in model.layers:
            del layer.layer_norms["Author"]
            for key in list(layer.convs.keys()):
                if "Author" in key:
                    del layer.convs[key]

    model = model.to(device)
    criterion = VulnChainLoss(infonce_weight=infonce_weight, edge_drop_rate=0.2)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)

    train_mask = masks["train_mask"].to(device)
    val_mask = masks["val_mask"].to(device)
    test_mask = masks["test_mask"].to(device)

    best_val_loss = float("inf")
    best_state = None
    patience_cnt = 0

    x_dict = {ntype: exp_data[ntype].x.to(device) for ntype in exp_data.node_types}
    edge_index_dict = {
        (src, rel, tgt): exp_data[src, rel, tgt].edge_index.to(device)
        for src, rel, tgt in exp_data.edge_types
    }
    train_labels = exp_data["Package"].y.to(device)

    for epoch in range(1, max_epochs + 1):
        model.train()
        optimizer.zero_grad()

        preds = model(x_dict, edge_index_dict)
        loss, mse, _ = criterion(model, preds, train_labels, x_dict, edge_index_dict, train_mask)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_preds = model(x_dict, edge_index_dict)
            val_mse = torch.nn.functional.mse_loss(val_preds[val_mask], train_labels[val_mask]).item()

        if val_mse < best_val_loss:
            best_val_loss = val_mse
            patience_cnt = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_cnt += 1
            if patience_cnt >= patience:
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    eval_res = evaluate_model(model, exp_data, test_mask, pkg_ids, device)
    print(f"[{variant_name}] Test MAE: {eval_res['mae']:.4f} | Spearman rho: {eval_res['spearman_rho']:.4f} | Ranking Acc: {eval_res['ranking_accuracy']*100:.2f}%")
    return eval_res


def main():
    print("=" * 70)
    print("VulnChain -- Ablation Suite (Section 11.3)")
    print("=" * 70)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    data, mappings, masks = load_vulnchain_dataset()

    results = {}

    # 1. Full Baseline
    results["Full VulnGAT"] = run_ablation_experiment(
        "Full VulnGAT (Baseline)", data, masks, mappings, device, infonce_weight=0.1, cve_dim=769
    )

    # 2. A1: No Author Nodes
    results["A1 (No Author Nodes)"] = run_ablation_experiment(
        "A1: No Author Nodes", data, masks, mappings, device, remove_author=True
    )

    # 3. A2: No InfoNCE Contrastive Loss
    results["A2 (No InfoNCE)"] = run_ablation_experiment(
        "A2: No Contrastive Loss", data, masks, mappings, device, infonce_weight=0.0
    )

    # 4. A4: Raw CVSS vs SentenceBERT
    results["A4 (Raw CVSS Only)"] = run_ablation_experiment(
        "A4: Raw CVSS Only (No SentenceBERT)", data, masks, mappings, device, cve_dim=1
    )

    print("\n" + "=" * 70)
    print("Ablation Study Summary Table (Test Set)")
    print("=" * 70)
    print(f"{'Variant':<32}{'Test MAE':<12}{'Spearman rho':<15}{'Ranking Acc':<15}")
    print("-" * 70)
    for name, res in results.items():
        print(f"{name:<32}{res['mae']:<12.4f}{res['spearman_rho']:<15.4f}{res['ranking_accuracy']*100:<14.2f}%")
    print("=" * 70)


if __name__ == "__main__":
    main()
