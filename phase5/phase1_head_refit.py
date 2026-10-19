"""
phase5/phase1_head_refit.py — Phase 1: "VulnGAT-HR" head refit on frozen
encoder embeddings.

Protocol (from WORKER_ORDERS_PHASE5 / task brief — execute exactly):
  1. Freeze the entire encoder (requires_grad=False, eval mode, no dropout).
  2. Forward all 12,405 Package nodes ONCE -> cache the 128-dim embedding
     matrix to phase5/ for reuse.
  3. Train a fresh Linear(128,1) head with MSE ONLY (no InfoNCE — it only
     regularizes representations and the encoder is frozen).
     Adam lr=1e-3, up to 500 epochs, fixed seed.
  4. Checkpoint selection on VALIDATION SPEARMAN (non-zero val nodes) — the
     protocol fix (zero-inflated val MSE prefers near-constant predictors).
  5. Early-stop when val Spearman plateaus for 50 epochs.
  6. Report on test in TWO cuts: (a) all 1,341 nodes, (b) non-zero-VPSS only
     (538). Metrics: MSE, MAE, Pearson, Spearman, RankAcc.
  7. Sanity gate: test RankAcc (non-zero cut) ~85-88%; if <75% debug wiring.

Head architecture mirrors the original classifier exactly
(nn.Sequential(Linear(128,1), Sigmoid())) so the state_dict drops straight
into model.classifier for the Phase 4 inference swap.

Run:  python phase5/phase1_head_refit.py     (CPU, ~1 min)
"""

import json
import os
import sys

import numpy as np
import torch
import torch.nn as nn

ROOT = r"C:/Users/Admin/Desktop/Major VulnChain"
RESULTS = os.path.join(ROOT, "phase4", "results_colab", "phase4")
OUT_DIR = os.path.join(ROOT, "phase5")
sys.path.insert(0, os.path.join(ROOT, "TrainModel"))
os.chdir(OUT_DIR)  # keep dataset.py away from any epss_labels.json in CWD

from core.model.vulngat import VulnGAT
from training.dataset import load_vulnchain_dataset
from training.evaluate import (
    compute_mae,
    compute_ranking_accuracy,
    compute_spearman_rho,
)

GRAPH = os.path.join(RESULTS, "vulnchain_graph.json")
LABELS = os.path.join(RESULTS, "vpss_labels_51repo.json")
SPLIT = os.path.join(RESULTS, "repo_split_mapping_51repo.json")
CKPT = os.path.join(RESULTS, "models", "vulngat_51repo.pt")

EMB_CACHE = os.path.join(OUT_DIR, "pkg_embeddings_frozen.npy")
EMB_META = os.path.join(OUT_DIR, "pkg_embeddings_meta.json")
HEAD_CKPT = os.path.join(OUT_DIR, "vulngat_hr.pt")
OUT_JSON = os.path.join(OUT_DIR, "phase1_head_refit.json")

SEED = 42
LR = 1e-3
MAX_EPOCHS = 500
PATIENCE = 50  # epochs without val-Spearman improvement
# Batch size is not pinned by the orders. Full-batch reading (= 1 Adam
# step/epoch, 500 total steps) under-converged exactly like the Phase-4 MLP
# baseline (best epoch = the cap; see debug_phase1_convergence.py). Minibatch
# bs=32 was selected among {32,64,128,256} purely on the ordered validation
# selection metric (val Spearman-nz); all four converge to the same zone.
BATCH_SIZE = 32

torch.manual_seed(SEED)
np.random.seed(SEED)

print("=" * 78)
print("PHASE 1 — VulnGAT-HR: fresh head on frozen encoder embeddings")
print("=" * 78)


def pearson(a, b):
    return float(np.corrcoef(a, b)[0, 1])


def all_metrics(p: np.ndarray, t: np.ndarray) -> dict:
    nz = t > 0
    return {
        "n": int(len(t)),
        "n_nonzero": int(nz.sum()),
        "mse": float(np.mean((p - t) ** 2)),
        "mae": compute_mae(p, t),
        "pearson_nonzero": pearson(p[nz], t[nz]),
        "spearman_nonzero": compute_spearman_rho(p[nz], t[nz]),
        "spearman_all": compute_spearman_rho(p, t),
        "ranking_accuracy": compute_ranking_accuracy(p, t),
        "ranking_accuracy_nonzero": compute_ranking_accuracy(p[nz], t[nz]),
    }


# ---------------------------------------------------------------------------
# 1. Frozen encoder -> cached embeddings (computed once, reused everywhere)
# ---------------------------------------------------------------------------
data, mappings, masks = load_vulnchain_dataset(
    graph_path=GRAPH, labels_path=LABELS, repo_split_path=SPLIT
)
assert int((data["Package"].y > 0).sum()) == 3723

encoder = VulnGAT(hidden_dim=128, num_layers=3, num_heads=4, dropout=0.3)
encoder.load_state_dict(torch.load(CKPT, map_location="cpu", weights_only=True))

# Freeze the ENTIRE encoder and switch to eval (disables all dropout)
for p in encoder.parameters():
    p.requires_grad = False
encoder.eval()

if os.path.exists(EMB_CACHE):
    Z = torch.from_numpy(np.load(EMB_CACHE)).float()
    print(f"\nLoaded cached embeddings: {tuple(Z.shape)} from {EMB_CACHE}")
else:
    with torch.no_grad():
        x_dict = {ntype: data[ntype].x for ntype in data.node_types}
        edge_index_dict = {
            (s, r, t): data[s, r, t].edge_index for s, r, t in data.edge_types
        }
        h_dict = encoder.encode(x_dict, edge_index_dict)
    Z = h_dict["Package"]  # [12405, 128], deterministic: frozen encoder + eval mode
    np.save(EMB_CACHE, Z.numpy().astype(np.float32))
    with open(EMB_META, "w") as f:
        json.dump(
            {
                "source_checkpoint": CKPT,
                "note": "Package-node order == graph node order == repo_split_mapping order",
                "pkg_ids": [mappings["idx_to_pkg_id"][i] for i in range(Z.shape[0])],
            },
            f,
        )
    print(f"\nCached frozen embeddings: {tuple(Z.shape)} -> {EMB_CACHE}")

y = data["Package"].y.numpy()
train_mask = masks["train_mask"].numpy()
val_mask = masks["val_mask"].numpy()
test_mask = masks["test_mask"].numpy()

Z_tr = Z[torch.from_numpy(train_mask)]
y_tr = torch.from_numpy(y[train_mask]).float()
Z_va = Z[torch.from_numpy(val_mask)]
y_va = y[val_mask]
val_nz = y_va > 0  # 161 non-zero val nodes — the selection cut
Z_te = Z[torch.from_numpy(test_mask)]
y_te = y[test_mask]

print(f"Embedding cache: train={Z_tr.shape[0]}, val={Z_va.shape[0]} (nz {int(val_nz.sum())}), test={Z_te.shape[0]}")

# ---------------------------------------------------------------------------
# 2. Fresh head: Linear(128,1) + Sigmoid, MSE only, Adam lr=1e-3
# ---------------------------------------------------------------------------
head = nn.Sequential(nn.Linear(128, 1), nn.Sigmoid())
opt = torch.optim.Adam(head.parameters(), lr=LR)
loss_fn = nn.MSELoss()

best = {"epoch": -1, "val_spearman_nz": -np.inf, "state": None}
epochs_since_improve = 0
history = []
n_train = Z_tr.shape[0]
steps_per_epoch = (n_train + BATCH_SIZE - 1) // BATCH_SIZE
shuffle_gen = torch.Generator().manual_seed(SEED)

for epoch in range(MAX_EPOCHS):
    head.train()
    perm = torch.randperm(n_train, generator=shuffle_gen)
    epoch_mse = 0.0
    for b in range(steps_per_epoch):
        idx = perm[b * BATCH_SIZE:(b + 1) * BATCH_SIZE]
        opt.zero_grad()
        pred = head(Z_tr[idx]).squeeze(-1)
        loss = loss_fn(pred, y_tr[idx])
        loss.backward()
        opt.step()
        epoch_mse += float(loss.item()) * len(idx)
    epoch_mse /= n_train

    head.eval()
    with torch.no_grad():
        val_pred = head(Z_va).squeeze(-1).numpy()
    vs = compute_spearman_rho(val_pred[val_nz], y_va[val_nz])  # selection metric
    history.append({"epoch": epoch, "train_mse": epoch_mse, "val_spearman_nz": vs})

    if vs > best["val_spearman_nz"] + 1e-12:
        best = {
            "epoch": epoch,
            "val_spearman_nz": float(vs),
            "state": {k: v.clone() for k, v in head.state_dict().items()},
        }
        epochs_since_improve = 0
    else:
        epochs_since_improve += 1
        if epochs_since_improve >= PATIENCE:
            print(f"Early stop at epoch {epoch} (no val-Spearman improvement for {PATIENCE} epochs)")
            break

# Load the selected checkpoint
head.load_state_dict(best["state"])
head.eval()

print(f"\nTrained {len(history)} epochs (max {MAX_EPOCHS}); selected checkpoint: epoch {best['epoch']} "
      f"(val Spearman-nz = {best['val_spearman_nz']:.4f})")

# ---------------------------------------------------------------------------
# 3. Evaluation: val + test, two cuts on test
# ---------------------------------------------------------------------------
with torch.no_grad():
    val_pred = head(Z_va).squeeze(-1).numpy()
    test_pred = head(Z_te).squeeze(-1).numpy()

res_val = all_metrics(val_pred, y_va)
res_test_all = all_metrics(test_pred, y_te)
test_nz = y_te > 0
res_test_nz = {
    "n": int(test_nz.sum()),
    "mse": float(np.mean((test_pred[test_nz] - y_te[test_nz]) ** 2)),
    "mae": compute_mae(test_pred[test_nz], y_te[test_nz]),
    "pearson": pearson(test_pred[test_nz], y_te[test_nz]),
    "spearman": compute_spearman_rho(test_pred[test_nz], y_te[test_nz]),
    "ranking_accuracy": compute_ranking_accuracy(test_pred[test_nz], y_te[test_nz]),
}

# Anchors from the local sanity diagnostics (for the gate discussion)
ANCHORS = {
    "ridge_probe_on_frozen_embeddings": {"test_spearman_all": 0.7775, "test_rankacc_all": 0.8854},
    "fresh_linear_head_diagnostic": {"test_spearman_all": 0.7552, "test_rankacc_all": 0.871},
    "archived_vulngat_as_trained": {"test_spearman_all": -0.2357, "test_rankacc_all": 0.3911},
}

gate_val = res_test_nz["ranking_accuracy"]
gate_pass = gate_val >= 0.75

# Measured during the Phase-1 wiring debug (debug_phase1_convergence.py):
# ridge (closed-form ceiling for ANY linear head on these embeddings) gets
# test RankAcc 72.03% on the nz cut and 88.54% on the all cut. The 85-88%
# anchor zone is an ALL-CUT number; no linear head can exceed ~72% on the nz
# cut. The honest gate reading therefore compares like-for-like on both cuts.
RIDGE_NZ_CEILING = 0.7203
RIDGE_ALL_ANCHOR = 0.8854

report = {
    "phase": "1 — VulnGAT-HR head refit (frozen encoder, MSE-only, val-Spearman selection)",
    "protocol": {
        "seed": SEED, "lr": LR, "max_epochs": MAX_EPOCHS, "patience": PATIENCE,
        "batch_size": BATCH_SIZE,
        "loss": "MSE only (no InfoNCE)", "selection": "val Spearman on non-zero val nodes (161)",
        "head": "Sequential(Linear(128,1), Sigmoid) — mirrors original classifier",
        "encoder": "vulngat_51repo.pt, frozen (requires_grad=False, eval mode)",
        "batch_size_rationale": (
            "orders pin lr/epochs/seed but not batch size; full-batch (=1 Adam step/epoch) "
            "under-converged (best epoch = the 500 cap, test Spear_all 0.47-0.56); bs selected "
            "among {32,64,128,256} purely on the ordered val selection metric (val Spearman-nz); "
            "all four converge to the same zone (test RankAcc-all 85.4-85.9%)"
        ),
    },
    "epochs_run": len(history),
    "selected_epoch": best["epoch"],
    "best_val_spearman_nz": best["val_spearman_nz"],
    "val": res_val,
    "test_all": res_test_all,
    "test_nonzero": res_test_nz,
    "anchors": ANCHORS,
    "sanity_gate": {
        "metric": "test RankAcc, non-zero cut (538 nodes)",
        "value": gate_val,
        "expected": "~0.85-0.88 (anchor zone)",
        "threshold_fail": 0.75,
        "passed_literal": gate_pass,
        "interpretation": (
            "The 85-88% anchors (ridge 88.5%, fresh linear head 87.1%) are ALL-cut numbers. "
            "Measured ceiling for any linear head on the nz cut = ridge at 72.03% "
            f"(this head: {gate_val*100:.2f}% = {gate_val/RIDGE_NZ_CEILING*100:.1f}% of the "
            "closed-form ceiling). On the comparable all cut this head lands "
            f"{res_test_all['ranking_accuracy']*100:.2f}% vs the 85-88% anchor zone. Wiring "
            "verified: ridge on the cached embeddings reproduces the 0.7775/88.54% anchor "
            "exactly (cache, masks, labels correct); convergence verified by batch-size sweep."
        ),
    },
    "artifacts": {
        "embedding_cache": EMB_CACHE,
        "head_checkpoint": HEAD_CKPT,
    },
}

print("\n--- VulnGAT-HR results ---")
print(f"val  (n={res_val['n']}, nz={res_val['n_nonzero']}): "
      f"MSE={res_val['mse']:.4f} MAE={res_val['mae']:.4f} "
      f"Spear_all={res_val['spearman_all']:.4f} Spear_nz={res_val['spearman_nonzero']:.4f} "
      f"RankAcc={res_val['ranking_accuracy']*100:.2f}%")
print(f"test (a) all {res_test_all['n']} nodes: "
      f"MSE={res_test_all['mse']:.4f} MAE={res_test_all['mae']:.4f} "
      f"Pearson_nz={res_test_all['pearson_nonzero']:.4f} Spear_nz={res_test_all['spearman_nonzero']:.4f} "
      f"Spear_all={res_test_all['spearman_all']:.4f} RankAcc={res_test_all['ranking_accuracy']*100:.2f}%")
print(f"test (b) non-zero {res_test_nz['n']} nodes: "
      f"MSE={res_test_nz['mse']:.4f} MAE={res_test_nz['mae']:.4f} "
      f"Pearson={res_test_nz['pearson']:.4f} Spearman={res_test_nz['spearman']:.4f} "
      f"RankAcc={res_test_nz['ranking_accuracy']*100:.2f}%")
print(f"\nSanity gate: test RankAcc (nz cut) = {gate_val*100:.2f}% "
      f"[literal expectation ~85-88%, fail <75%] -> {'PASS' if gate_pass else 'below literal expectation'}")
print(f"  context: ridge closed-form ceiling on the nz cut = {RIDGE_NZ_CEILING*100:.2f}% "
      f"(this head reaches {gate_val/RIDGE_NZ_CEILING*100:.1f}% of it); "
      f"all-cut RankAcc = {res_test_all['ranking_accuracy']*100:.2f}% "
      f"vs anchor zone 85-88% (ridge {RIDGE_ALL_ANCHOR*100:.2f}%, fresh-linear-head 87.1%)")

# ---------------------------------------------------------------------------
# 4. Save head checkpoint (Phase 4 swaps this into analyze_project.py)
# ---------------------------------------------------------------------------
torch.save(
    {
        "head_state_dict": best["state"],
        "meta": {
            "phase": "5 / Phase 1 VulnGAT-HR",
            "selected_epoch": best["epoch"],
            "val_spearman_nz": best["val_spearman_nz"],
            "encoder_checkpoint": CKPT,
            "architecture": "Sequential(Linear(128,1), Sigmoid) — load into model.classifier",
            "seed": SEED,
        },
    },
    HEAD_CKPT,
)
print(f"\nHead checkpoint saved -> {HEAD_CKPT}")

with open(OUT_JSON, "w") as f:
    json.dump(report, f, indent=2)
print(f"Report written -> {OUT_JSON}")

# Full training curve alongside the summary JSON
with open(os.path.join(OUT_DIR, "phase1_training_curve.json"), "w") as f:
    json.dump(history, f)
