"""
mlp_baseline.py — Phase 4 C4: Feature-Only MLP Baseline (NO graph input)

Answers the VPSS-circularity question (WORKER_ORDERS_PHASE4.md Section 4.C4):
VPSS labels are a deterministic function of (CVSS, depth, exposure), and depth
( dim 3) + directness (dims 0/1) are readable straight off the 10-dim Package
feature vector. If a feature-only MLP matches VulnGAT on the same split, the
GNN's headline evidence must come from the masked-edge audit / OOD benchmark,
not from VPSS correlation.

Protocol (matches training/train.py exactly):
  - Same graph/labels/split files (env: GRAPH_FILE, LABELS_FILE, REPO_SPLIT_FILE)
  - Same feature preprocessing (loads via training.dataset.load_vulnchain_dataset)
  - Same optimizer (Adam lr=1e-3, weight_decay=1e-5), MSE loss, same early
    stopping (patience 10 on val MSE)
  - Architecture: 10 -> 64 -> 64 -> 1 (two hidden layers) -> Sigmoid
  - ZERO graph structure touched: no edge_index, no message passing

Usage (from phase4/, Colab or local):
    GRAPH_FILE=vulnchain_graph.json \
    LABELS_FILE=vpss_labels_51repo.json \
    REPO_SPLIT_FILE=repo_split_mapping_51repo.json \
    python mlp_baseline.py
"""

import json
import os
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "TrainModel"))

from training.dataset import load_vulnchain_dataset
from training.evaluate import compute_mae, compute_spearman_rho, compute_ranking_accuracy

SEED = 42
MAX_EPOCHS = 200
PATIENCE = 10
RESULTS_OUT = os.environ.get("MLP_OUT", "mlp_baseline_results.json")


class FeatureMLP(nn.Module):
    """Feature-only regressor: identical I/O contract to VulnGAT's head."""

    def __init__(self, in_dim: int = 10, hidden: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, hidden),
            nn.ReLU(),
            nn.Linear(hidden, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x).squeeze(-1)


def pearson(pred: np.ndarray, targ: np.ndarray) -> float:
    if len(pred) < 2 or np.std(pred) == 0 or np.std(targ) == 0:
        return 0.0
    return float(np.corrcoef(pred, targ)[0, 1])


def eval_split(preds: np.ndarray, targs: np.ndarray) -> dict:
    nz = targs > 1e-9
    return {
        "n": int(len(targs)),
        "n_nonzero": int(nz.sum()),
        "mae": round(compute_mae(preds, targs), 6),
        "mse": round(float(np.mean((preds - targs) ** 2)), 6),
        "spearman_all": round(compute_spearman_rho(preds, targs), 4),
        "pearson_nonzero": round(pearson(preds[nz], targs[nz]), 4),
        "spearman_nonzero": round(compute_spearman_rho(preds[nz], targs[nz]), 4),
        "ranking_accuracy": round(compute_ranking_accuracy(preds, targs), 4),
    }


def main():
    torch.manual_seed(SEED)
    np.random.seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    data, mappings, masks = load_vulnchain_dataset()  # env-var paths

    x = data["Package"].x.to(device)          # [N, 10] normalized features
    y = data["Package"].y.to(device)          # [N] continuous VPSS
    train_mask, val_mask, test_mask = (masks["train_mask"].to(device),
                                       masks["val_mask"].to(device),
                                       masks["test_mask"].to(device))
    print(f"Packages: {x.shape[0]} | train {train_mask.sum().item()}, "
          f"val {val_mask.sum().item()}, test {test_mask.sum().item()} "
          f"(test non-zero: {(y[test_mask] > 0).sum().item()})")

    model = FeatureMLP(in_dim=x.shape[1]).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)

    best_val, patience_ctr, best_state = float("inf"), 0, None
    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        optimizer.zero_grad()
        preds = model(x)
        loss = torch.nn.functional.mse_loss(preds[train_mask], y[train_mask])
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_mse = torch.nn.functional.mse_loss(model(x)[val_mask], y[val_mask]).item()
        if val_mse < best_val:
            best_val, patience_ctr = val_mse, 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_ctr += 1
            if patience_ctr >= PATIENCE:
                print(f"Early stopping at epoch {epoch} (best val MSE {best_val:.5f})")
                break
        if epoch % 20 == 0:
            print(f"  epoch {epoch:>3} | train MSE {loss.item():.5f} | val MSE {val_mse:.5f}")

    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        all_preds = model(x).cpu().numpy()
    all_targs = data["Package"].y.cpu().numpy()

    results = {"model": "FeatureMLP (no graph)", "seed": SEED,
               "best_val_mse": round(best_val, 6),
               "train": eval_split(all_preds[train_mask.cpu().numpy()], all_targs[train_mask.cpu().numpy()]),
               "val": eval_split(all_preds[val_mask.cpu().numpy()], all_targs[val_mask.cpu().numpy()]),
               "test": eval_split(all_preds[test_mask.cpu().numpy()], all_targs[test_mask.cpu().numpy()])}

    print("\n=== Feature-Only MLP Baseline Results ===")
    for split in ("train", "val", "test"):
        r = results[split]
        print(f"{split:>5}: MAE {r['mae']:.4f} | MSE {r['mse']:.4f} | "
              f"Spearman(all) {r['spearman_all']:.4f} | "
              f"Pearson(nz) {r['pearson_nonzero']:.4f} (n={r['n_nonzero']}) | "
              f"RankAcc {r['ranking_accuracy']:.2%}")

    with open(RESULTS_OUT, "w") as f:
        json.dump(results, f, indent=2)
    torch.save(best_state, RESULTS_OUT.replace(".json", ".pt"))
    print(f"\nwrote {RESULTS_OUT}")


if __name__ == "__main__":
    main()
