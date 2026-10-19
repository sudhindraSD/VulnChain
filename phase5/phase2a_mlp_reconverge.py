"""
phase5/phase2a_mlp_reconverge.py — Phase 2a: fix the under-converged MLP
baseline and produce the final baseline table.

Archived Phase-4 MLP (full-batch, 200 epochs, val-MSE selection, stopped at
cap while val MSE still improving): test RankAcc 72.2% — it loses to ridge on
the raw 10 features (77.1%). Orders: "Either reconverge it properly or replace
it with the ridge as the reported floor. Final table: ridge-raw / MLP /
VulnGAT-HR."

Fix applied (training-budget only; architecture/preprocessing/split frozen):
  - minibatch Adam (bs=256) instead of 1-step-per-epoch full batch — the same
    under-convergence disease identified and fixed in Phase 1
  - checkpoint selection on val Spearman (non-zero) instead of val MSE — the
    protocol fix, so all three models in the final table are selected the
    same way
  - max 500 epochs, patience 50, seed 42 (mirrors the Phase-1 protocol)

Also recomputes the ridge-raw floor with the archived diagnostic's exact
recipe (alpha selected on val MSE) for a consistent side-by-side table.

Run:  python phase5/phase2a_mlp_reconverge.py   (CPU, ~1 min)
"""

import json
import os
import sys

import numpy as np
import torch
import torch.nn as nn
from sklearn.linear_model import Ridge

ROOT = r"C:/Users/Admin/Desktop/Major VulnChain"
RESULTS = os.path.join(ROOT, "phase4", "results_colab", "phase4")
OUT_DIR = os.path.join(ROOT, "phase5")
sys.path.insert(0, os.path.join(ROOT, "TrainModel"))
os.chdir(OUT_DIR)

from training.dataset import load_vulnchain_dataset
from training.evaluate import compute_mae, compute_ranking_accuracy, compute_spearman_rho

SEED = 42
MAX_EPOCHS = 500
PATIENCE = 50
BATCH_SIZE = 256
LR = 1e-3
WD = 1e-5  # mirrors archived mlp_baseline.py optimizer

torch.manual_seed(SEED)
np.random.seed(SEED)

print("=" * 78)
print("PHASE 2a — MLP baseline reconvergence + final baseline table")
print("=" * 78)


def pearson(a, b):
    return float(np.corrcoef(a, b)[0, 1])


def eval_split(p, t):
    nz = t > 1e-9
    return {
        "n": int(len(t)), "n_nonzero": int(nz.sum()),
        "mse": float(np.mean((p - t) ** 2)), "mae": float(np.mean(np.abs(p - t))),
        "pearson_nonzero": pearson(p[nz], t[nz]),
        "spearman_nonzero": compute_spearman_rho(p[nz], t[nz]),
        "spearman_all": compute_spearman_rho(p, t),
        "ranking_accuracy": compute_ranking_accuracy(p, t),
        "ranking_accuracy_nonzero": compute_ranking_accuracy(p[nz], t[nz]),
    }


data, mappings, masks = load_vulnchain_dataset(
    graph_path=os.path.join(RESULTS, "vulnchain_graph.json"),
    labels_path=os.path.join(RESULTS, "vpss_labels_51repo.json"),
    repo_split_path=os.path.join(RESULTS, "repo_split_mapping_51repo.json"),
)
X = data["Package"].x
y = data["Package"].y
tr_m, va_m, te_m = masks["train_mask"], masks["val_mask"], masks["test_mask"]
y_np = y.numpy()
tr, va, te = tr_m.numpy(), va_m.numpy(), te_m.numpy()
va_nz = y_np[va] > 0

# ---------------------------------------------------------------------------
# 1. Ridge on raw 10-d features (the reported floor) — archived recipe
# ---------------------------------------------------------------------------
best = None
for alpha in [1e-3, 1e-2, 1e-1, 1.0, 10.0, 100.0]:
    r = Ridge(alpha=alpha).fit(X[tr_m].numpy(), y_np[tr])
    vmse = float(np.mean((r.predict(X[va_m].numpy()) - y_np[va]) ** 2))
    if best is None or vmse < best[0]:
        best = (vmse, alpha, r)
_, ridge_alpha, ridge = best
ridge_all = 1.0 / (1.0 + np.exp(-ridge.predict(X.numpy())))
ridge_res = {s: eval_split(ridge_all[m], y_np[m]) for s, m in [("train", tr), ("val", va), ("test", te)]}

# ---------------------------------------------------------------------------
# 2. Reconverged MLP (architecture identical to archived mlp_baseline.py)
# ---------------------------------------------------------------------------
class FeatureMLP(nn.Module):
    def __init__(self, in_dim: int = 10, hidden: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden), nn.ReLU(),
            nn.Linear(hidden, hidden), nn.ReLU(),
            nn.Linear(hidden, 1), nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x).squeeze(-1)


mlp = FeatureMLP(in_dim=X.shape[1])
opt = torch.optim.Adam(mlp.parameters(), lr=LR, weight_decay=WD)
loss_fn = nn.MSELoss()
n_tr = int(tr.sum())
g = torch.Generator().manual_seed(SEED)
best = {"epoch": -1, "vs": -np.inf, "state": None}
no_improve = 0
steps_per_epoch = (n_tr + BATCH_SIZE - 1) // BATCH_SIZE

for epoch in range(MAX_EPOCHS):
    mlp.train()
    perm = torch.randperm(n_tr, generator=g)
    tr_idx = torch.where(tr_m)[0]
    for b in range(steps_per_epoch):
        idx = tr_idx[perm[b * BATCH_SIZE:(b + 1) * BATCH_SIZE]]
        opt.zero_grad()
        loss = loss_fn(mlp(X[idx]), y[idx])
        loss.backward()
        opt.step()
    mlp.eval()
    with torch.no_grad():
        vp = mlp(X[va_m]).numpy()
    vs = compute_spearman_rho(vp[va_nz], y_np[va][va_nz])
    if vs > best["vs"] + 1e-12:
        best = {"epoch": epoch, "vs": float(vs), "state": {k: v.clone() for k, v in mlp.state_dict().items()}}
        no_improve = 0
    else:
        no_improve += 1
        if no_improve >= PATIENCE:
            break

mlp.load_state_dict(best["state"])
mlp.eval()
with torch.no_grad():
    mlp_all = mlp(X).numpy()
mlp_res = {s: eval_split(mlp_all[m], y_np[m]) for s, m in [("train", tr), ("val", va), ("test", te)]}
print(f"\nMLP reconverged: {epoch + 1} epochs run (max {MAX_EPOCHS}), selected epoch {best['epoch']} "
      f"(val Spearman-nz {best['vs']:.4f}), bs={BATCH_SIZE}, lr={LR}, wd={WD}")

# ---------------------------------------------------------------------------
# 3. Final table: ridge-raw / MLP / VulnGAT-HR (+ archived references)
# ---------------------------------------------------------------------------
with open(os.path.join(OUT_DIR, "phase1_head_refit.json")) as f:
    hr = json.load(f)
with open(os.path.join(RESULTS, "mlp_baseline_results_51repo.json")) as f:
    mlp_archived = json.load(f)
with open(os.path.join(RESULTS, "vulngat_51repo_metrics.json")) as f:
    gnn_archived = json.load(f)

rows = [
    ("ridge-raw (floor)", ridge_res, f"alpha={ridge_alpha}"),
    ("MLP reconverged", mlp_res, f"epoch {best['epoch']}"),
    ("VulnGAT-HR", {
        "train": None, "val": hr["val"], "test": {
            **{k: v for k, v in hr["test_all"].items() if k != "n"},
            "ranking_accuracy_nonzero": hr["test_nonzero"]["ranking_accuracy"],
        }
    }, "frozen encoder + fresh head"),
]

print("\n--- FINAL TABLE (test split, saleor-storefront) ---")
hdr = f"{'model':<22}{'MSE':>8}{'MAE':>8}{'Pear_nz':>9}{'Spear_nz':>10}{'Spear_all':>11}{'RankAcc':>9}{'RankAcc_nz':>11}"
print(hdr)
print("-" * len(hdr))
for name, res, note in rows:
    t = res["test"]
    print(f"{name:<22}{t['mse']:>8.4f}{t['mae']:>8.4f}{t['pearson_nonzero']:>9.4f}"
          f"{t['spearman_nonzero']:>10.4f}{t['spearman_all']:>11.4f}{t['ranking_accuracy']*100:>8.2f}%"
          f"{t['ranking_accuracy_nonzero']*100:>10.2f}%   [{note}]")
print(f"{'MLP archived (P4)':<22}{mlp_archived['test']['mse']:>8.4f}{mlp_archived['test']['mae']:>8.4f}"
      f"{mlp_archived['test']['pearson_nonzero']:>9.4f}{mlp_archived['test']['spearman_nonzero']:>10.4f}"
      f"{mlp_archived['test']['spearman_all']:>11.4f}{mlp_archived['test']['ranking_accuracy']*100:>8.2f}%"
      f"{'—':>11}   [under-converged, reference]")
print(f"{'VulnGAT archived (P4)':<22}{gnn_archived['test']['mse']:>8.4f}{gnn_archived['test']['mae']:>8.4f}"
      f"{gnn_archived['test']['pearson_nonzero']:>9.4f}{gnn_archived['test']['spearman_nonzero']:>10.4f}"
      f"{gnn_archived['test']['spearman_all']:>11.4f}{gnn_archived['test']['ranking_accuracy']*100:>8.2f}%"
      f"{'—':>11}   [anti-aligned head, reference]")

out = {
    "phase": "2a — baseline fix",
    "protocol": {
        "mlp": {"arch": "10-64-64-1-Sigmoid (identical to archived)", "seed": SEED, "bs": BATCH_SIZE,
                "lr": LR, "wd": WD, "max_epochs": MAX_EPOCHS, "patience": PATIENCE,
                "selection": "val Spearman-nz (protocol fix; archived used val MSE full-batch 200 ep)"},
        "ridge_raw": {"alpha_selected_on": "val MSE (archived diagnostic recipe)", "alpha": ridge_alpha},
    },
    "ridge_raw": ridge_res,
    "mlp_reconverged": {"selected_epoch": best["epoch"], "val_spearman_nz": best["vs"],
                        "epochs_run": epoch + 1, **mlp_res},
    "references": {
        "mlp_archived_phase4": mlp_archived,
        "vulngat_archived_phase4_test": gnn_archived["test"],
        "vulngat_hr_phase1": hr["test_all"],
    },
}
with open(os.path.join(OUT_DIR, "phase2a_baselines.json"), "w") as f:
    json.dump(out, f, indent=2)
torch.save(best["state"], os.path.join(OUT_DIR, "mlp_reconverged.pt"))
print(f"\nSaved phase5/phase2a_baselines.json + phase5/mlp_reconverged.pt")
