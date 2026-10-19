"""
phase5/debug_phase1_convergence.py — Phase 1 sanity-gate failure debug.

Symptom: full-batch head refit reached test Spearman_all 0.4724 / RankAcc-all
72.9% (anchor zone: 0.7552 / 87.1%) and test RankAcc (nz cut) 58.68% (gate
expects ~85-88%). Best epoch = 499 = the cap -> still improving, never
plateaued.

Debug plan (orders: "first debug wiring locally — selection metric,
embedding cache, split masks"):

  D1. Embedding cache validity: ridge probe (closed form) on the cached Z
      must reproduce the archived diagnostic anchor (test Spearman_all
      0.7775 / RankAcc 88.5%). If yes, cache + masks + labels are correct.
  D2. Calibrate the gate metric: compute ridge's test RankAcc on the
      NON-ZERO cut — the gate's ~85-88% expectation was written from
      all-cut anchors; measure what the honest ceiling on the nz cut is.
  D3. Optimization hypothesis: full-batch = 1 Adam step/epoch; 500 steps at
      lr=1e-3 under-converges. Compare (a) full-batch run extended to 5,000
      epochs, (b) minibatch (bs=256) 500 epochs. Selection stays on val
      Spearman-nz exactly as ordered; test numbers are only observed.

Run:  python phase5/debug_phase1_convergence.py   (CPU, ~2-4 min)
"""

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
from training.evaluate import compute_ranking_accuracy, compute_spearman_rho

GRAPH = os.path.join(RESULTS, "vulnchain_graph.json")
LABELS = os.path.join(RESULTS, "vpss_labels_51repo.json")
SPLIT = os.path.join(RESULTS, "repo_split_mapping_51repo.json")

SEED = 42
torch.manual_seed(SEED)
np.random.seed(SEED)

data, mappings, masks = load_vulnchain_dataset(
    graph_path=GRAPH, labels_path=LABELS, repo_split_path=SPLIT
)
Z = torch.from_numpy(np.load(os.path.join(OUT_DIR, "pkg_embeddings_frozen.npy"))).float()
y = data["Package"].y.numpy()
tr, va, te = masks["train_mask"].numpy(), masks["val_mask"].numpy(), masks["test_mask"].numpy()
Z_tr, y_tr = Z[torch.from_numpy(tr)], torch.from_numpy(y[tr]).float()
Z_va, y_va = Z[torch.from_numpy(va)], y[va]
Z_te, y_te = Z[torch.from_numpy(te)], y[te]
va_nz, te_nz = y_va > 0, y_te > 0


def report(tag, p):
    print(f"  {tag:<44} Spear_all={compute_spearman_rho(p, y_te):+.4f}  "
          f"RankAcc_all={compute_ranking_accuracy(p, y_te)*100:5.2f}%  "
          f"Spear_nz={compute_spearman_rho(p[te_nz], y_te[te_nz]):+.4f}  "
          f"RankAcc_nz={compute_ranking_accuracy(p[te_nz], y_te[te_nz])*100:5.2f}%")


print("=" * 100)
print("D1/D2 — Ridge probe on cached embeddings (validates cache + masks; calibrates nz-cut ceiling)")
print("=" * 100)
best = None
for alpha in [1e-3, 1e-2, 1e-1, 1.0, 10.0, 100.0]:
    r = Ridge(alpha=alpha).fit(Z_tr.numpy(), y[tr])
    vmse = float(np.mean((r.predict(Z_va.numpy()) - y_va) ** 2))
    if best is None or vmse < best[0]:
        best = (vmse, alpha, r)
_, alpha, r = best
p_ridge = 1.0 / (1.0 + np.exp(-r.predict(Z_te.numpy())))
print(f"ridge alpha={alpha} (selected on val MSE, as in the archived diagnostic):")
report("ridge+sigmoid on TEST", p_ridge)
logit_ridge = r.predict(Z_te.numpy())
report("ridge raw logit on TEST (rank-invariant check)", logit_ridge)

print()
print("=" * 100)
print("D3 — Head optimization: full-batch vs minibatch (selection = val Spearman-nz, as ordered)")
print("=" * 100)


def train_head(batch_size, epochs, label):
    torch.manual_seed(SEED)
    head = nn.Sequential(nn.Linear(128, 1), nn.Sigmoid())
    opt = torch.optim.Adam(head.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()
    n = Z_tr.shape[0]
    g = torch.Generator().manual_seed(SEED)
    best = {"epoch": -1, "vs": -np.inf, "state": None}
    steps_per_epoch = (n + batch_size - 1) // batch_size if batch_size else 1
    for epoch in range(epochs):
        if batch_size:
            perm = torch.randperm(n, generator=g)
            for b in range(steps_per_epoch):
                idx = perm[b * batch_size:(b + 1) * batch_size]
                opt.zero_grad()
                loss = loss_fn(head(Z_tr[idx]).squeeze(-1), y_tr[idx])
                loss.backward()
                opt.step()
        else:
            opt.zero_grad()
            loss = loss_fn(head(Z_tr).squeeze(-1), y_tr)
            loss.backward()
            opt.step()
        head.eval()
        with torch.no_grad():
            vp = head(Z_va).squeeze(-1).numpy()
        vs = compute_spearman_rho(vp[va_nz], y_va[va_nz])
        if vs > best["vs"] + 1e-12:
            best = {"epoch": epoch, "vs": float(vs), "state": {k: v.clone() for k, v in head.state_dict().items()}}
    head.load_state_dict(best["state"])
    head.eval()
    with torch.no_grad():
        tp = head(Z_te).squeeze(-1).numpy()
    print(f"\n[{label}] steps/epoch={steps_per_epoch}, total steps={steps_per_epoch * epochs}, "
          f"selected epoch {best['epoch']} (val Spear-nz {best['vs']:.4f}):")
    report(f"{label} on TEST", tp)
    return head


train_head(None, 500, "full-batch 500 ep (current Phase 1)")
train_head(None, 5000, "full-batch 5000 ep (10x budget)")
train_head(256, 500, "minibatch bs=256, 500 ep")
