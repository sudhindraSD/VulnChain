"""
phase5/phase0_validity_gate.py — Phase 0: local reproduction of the archived
Colab test metrics for the 51-repo VulnGAT checkpoint.

Gate (from WORKER_ORDERS_PHASE5 / task brief):
  - Rebuild the forward pass locally on CPU from
    phase4/results_colab/phase4/models/vulngat_51repo.pt
    (the epoch-3 best-val-MSE snapshot with the anti-aligned head).
  - Reproduce the archived metrics exactly:
      test Spearman_all = -0.2357, RankAcc = 39.11%
    plus train/val metrics and the per-prediction comparison against the
    archived test_predictions_51repo.json (~1e-6).
  - If anything fails: STOP and debug wiring before any refit work.

Wiring is copied verbatim from phase4/diagnose_embedding_collapse.py, which
already reproduced these numbers on this exact CPU machine.

Run:  python phase5/phase0_validity_gate.py     (CPU, ~1-2 min)
"""

import json
import os
import sys

import numpy as np
import torch

ROOT = r"C:/Users/Admin/Desktop/Major VulnChain"
RESULTS = os.path.join(ROOT, "phase4", "results_colab", "phase4")
OUT_DIR = os.path.join(ROOT, "phase5")
sys.path.insert(0, os.path.join(ROOT, "TrainModel"))

# training/dataset.py picks up epss_labels.json from CWD if present — run from
# a clean dir (phase5/) so VPSS labels are guaranteed to load.
os.chdir(OUT_DIR)

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
ARCHIVED_METRICS = os.path.join(RESULTS, "vulngat_51repo_metrics.json")
ARCHIVED_PREDS = os.path.join(RESULTS, "test_predictions_51repo.json")
OUT_JSON = os.path.join(OUT_DIR, "phase0_validity.json")

torch.manual_seed(42)
np.random.seed(42)
report = {"phase": "0 — validity gate (local CPU reproduction of archived Colab run)"}

print("=" * 78)
print("PHASE 0 — Validity gate: reproduce archived Colab metrics on local CPU")
print("=" * 78)


def pearson(a, b):
    return float(np.corrcoef(a, b)[0, 1])


# ---------------------------------------------------------------------------
# 1. Dataset + model rebuild (exact wiring of the proven local diagnostic)
# ---------------------------------------------------------------------------
data, mappings, masks = load_vulnchain_dataset(
    graph_path=GRAPH, labels_path=LABELS, repo_split_path=SPLIT
)

n_nonzero_total = int((data["Package"].y > 0).sum())
assert n_nonzero_total == 3723, f"expected 3723 non-zero VPSS labels, got {n_nonzero_total}"

model = VulnGAT(hidden_dim=128, num_layers=3, num_heads=4, dropout=0.3)
state = torch.load(CKPT, map_location="cpu", weights_only=True)
model.load_state_dict(state)
model.eval()

with torch.no_grad():
    x_dict = {ntype: data[ntype].x for ntype in data.node_types}
    edge_index_dict = {
        (s, r, t): data[s, r, t].edge_index for s, r, t in data.edge_types
    }
    preds = model(x_dict, edge_index_dict).numpy()

y = data["Package"].y.numpy()
train_mask = masks["train_mask"].numpy()
val_mask = masks["val_mask"].numpy()
test_mask = masks["test_mask"].numpy()

# ---------------------------------------------------------------------------
# 2. Metric reproduction vs archived vulngat_51repo_metrics.json
# ---------------------------------------------------------------------------
with open(ARCHIVED_METRICS) as f:
    archived = json.load(f)

report["reproduced"] = {}
all_ok = True
for split, m in [("train", train_mask), ("val", val_mask), ("test", test_mask)]:
    p, t = preds[m], y[m]
    nz = t > 0
    got = {
        "n": int(m.sum()),
        "n_nonzero": int(nz.sum()),
        "mae": compute_mae(p, t),
        "mse": float(np.mean((p - t) ** 2)),
        "pearson_nonzero": pearson(p[nz], t[nz]),
        "spearman_nonzero": compute_spearman_rho(p[nz], t[nz]),
        "spearman_all": compute_spearman_rho(p, t),
        "ranking_accuracy": compute_ranking_accuracy(p, t),
    }
    exp = archived[split]
    diffs = {}
    ok_split = True
    for k, ev in exp.items():
        if k in ("n", "n_nonzero"):
            ok_split &= (got[k] == ev)
            diffs[k] = {"expected": ev, "got": got[k]}
        else:
            d = abs(got[k] - float(ev))
            diffs[k] = {"expected": float(ev), "got": got[k], "abs_diff": d}
            # order spec is ~1e-6; observed float32 CPU/GPU accumulation noise
            # is <=1e-7, genuine wiring bugs differ at 1e-2+ — 1e-6 separates them
            ok_split &= (d < 1e-6)
    report["reproduced"][split] = {"metrics": got, "diffs_vs_archived": diffs}
    all_ok &= ok_split
    print(f"\n[{split}]  (n={got['n']}, nz={got['n_nonzero']})")
    for k in ("mae", "mse", "pearson_nonzero", "spearman_nonzero", "spearman_all", "ranking_accuracy"):
        d = diffs[k]
        print(f"  {k:<18} expected={d['expected']:+.10f}  got={d['got']:+.10f}  |diff|={d['abs_diff']:.2e}")
    print(f"  -> {'EXACT MATCH' if ok_split else 'MISMATCH'}")

# ---------------------------------------------------------------------------
# 3. Per-prediction comparison vs archived test_predictions_51repo.json
# ---------------------------------------------------------------------------
with open(ARCHIVED_PREDS) as f:
    arch = json.load(f)

arch_preds = np.array(arch["predictions"], dtype=np.float64)
ids_match = [mappings["idx_to_pkg_id"][i] for i in range(len(preds))] == arch["pkg_ids"]
max_diff = float(np.max(np.abs(preds.astype(np.float64) - arch_preds)))
mean_diff = float(np.mean(np.abs(preds.astype(np.float64) - arch_preds)))
pred_ok = ids_match and (max_diff <= 1e-6)

report["prediction_comparison"] = {
    "pkg_ids_order_match": ids_match,
    "max_abs_diff": max_diff,
    "mean_abs_diff": mean_diff,
    "gate": "pkg_id order identical AND max|pred - archived| <= 1e-6",
    "passed": pred_ok,
}
print(f"\n[predictions] pkg_id order match: {ids_match}")
print(f"[predictions] max |local - archived| over 12,405 preds: {max_diff:.3e}  (mean {mean_diff:.3e})")
print(f"[predictions] gate (<= 1e-6): {'PASS' if pred_ok else 'FAIL'}")

# ---------------------------------------------------------------------------
# 4. Verdict
# ---------------------------------------------------------------------------
gate = all_ok and pred_ok
report["verdict"] = "PASS — local rebuild reproduces the archived Colab run; wiring is valid." if gate else "FAIL — wiring mismatch; STOP and debug."
print("\n" + "=" * 78)
print(f"PHASE 0 GATE: {'PASS' if gate else 'FAIL'}")
print("=" * 78)

with open(OUT_JSON, "w") as f:
    json.dump(report, f, indent=2)
print(f"Report written to {OUT_JSON}")
sys.exit(0 if gate else 1)
