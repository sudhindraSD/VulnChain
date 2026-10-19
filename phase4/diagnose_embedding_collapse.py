"""
diagnose_embedding_collapse.py — Empirical verification of the InfoNCE-collapse
diagnosis behind the proposed VulnGAT-v2 reweight.

The claim under test (WORKER_REPORT_PHASE4.md §C1/brain-diagnosis):
  InfoNCE dominates the weighted loss (~93%) and sat at chance (~7.9) for the
  whole run → package embeddings collapsed → the VPSS head cannot use them.

Checkable sub-claims, tested directly against the phase-4 checkpoint
(models/vulngat_51repo.pt, best-val = epoch 3):

  G1. Geometry: do the 128-d Package embeddings have collapsed variance /
      pairwise cosine ≈ 1 / PCA effective rank ≈ 1?
  M1. Mechanism: is the failure "embeddings useless" or "head not using them"?
      - Ridge probe (fit on train embeddings -> VPSS, eval on test) vs the
        same probe on raw 10-d features. If the embedding probe recovers
        MLP-level ranking signal, embeddings are NOT the bottleneck.
  H1. Head: is the trained Linear(128,1) itself degenerate?
  O1. Output level: prediction distribution / tie rate from the checkpoint and
      the archived test_predictions_51repo.json.

Pre-registered verdict rule (decided before running):
  - COLLAPSE CONFIRMED   if effective rank < 8 AND mean pairwise cosine > 0.95
                         AND the embedding ridge probe fails to reach even
                         raw-feature-probe ranking accuracy.
  - COLLAPSE REFUTED     if embeddings show healthy spread AND the probe
                         recovers ranking signal near/above the raw-feature
                         probe (=> the reweight alone is not the fix).
  - Anything else lands in between and is reported as-is.

Run:  python phase4/diagnose_embedding_collapse.py   (CPU, ~1-2 min)
"""

import json
import os
import sys

import numpy as np
import torch

# ---------------------------------------------------------------------------
# Paths & imports (TrainModel package + phase-4 artifacts)
# ---------------------------------------------------------------------------
ROOT = r"C:/Users/Admin/Desktop/Major VulnChain"
RESULTS = os.path.join(ROOT, "phase4", "results_colab", "phase4")
sys.path.insert(0, os.path.join(ROOT, "TrainModel"))

# dataset.py picks up epss_labels.json from CWD if present — run from RESULTS
os.chdir(RESULTS)

from core.model.vulngat import VulnGAT
from core.model.loss import compute_infonce_loss
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
OUT_JSON = os.path.join(ROOT, "phase4", "embedding_collapse_diagnosis.json")

torch.manual_seed(42)
np.random.seed(42)
report = {}

print("=" * 72)
print("VulnChain — InfoNCE-collapse verification (checkpoint: vulngat_51repo.pt)")
print("=" * 72)

# ---------------------------------------------------------------------------
# 1. Rebuild dataset + model, reproduce archived metrics (validity gate)
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
    h_dict = model.encode(x_dict, edge_index_dict)
    preds = model.classifier(h_dict["Package"]).squeeze(-1).numpy()

h_pkg = h_dict["Package"].numpy()          # [12405, 128] penultimate embeddings
y = data["Package"].y.numpy()
test_mask = masks["test_mask"].numpy()
train_mask = masks["train_mask"].numpy()
val_mask = masks["val_mask"].numpy()

# Validity gate: checkpoint must reproduce archived vulngat_51repo_metrics.json
for split, m in [("train", train_mask), ("val", val_mask), ("test", test_mask)]:
    mae = compute_mae(preds[m], y[m])
    rho = compute_spearman_rho(preds[m], y[m])
    racc = compute_ranking_accuracy(preds[m], y[m])
    report[f"repro_{split}"] = {"mae": mae, "spearman_all": rho, "ranking_accuracy": racc}
    print(f"[repro] {split:<5} MAE={mae:.4f}  Spearman_all={rho:.4f}  RankAcc={racc*100:.2f}%")

expected = {"train": (-0.2036, 38.75), "val": (-0.0445, 48.68), "test": (-0.2357, 39.11)}
ok = all(
    abs(report[f"repro_{s}"]["spearman_all"] - e[0]) < 0.01
    and abs(report[f"repro_{s}"]["ranking_accuracy"] * 100 - e[1]) < 0.5
    for s, e in expected.items()
)
print(f"[repro] matches archived metrics: {ok}")
assert ok, "Pipeline rebuild failed to reproduce archived numbers — aborting."

# ---------------------------------------------------------------------------
# 2. G1 — Embedding geometry
# ---------------------------------------------------------------------------
def geometry(tag: str, X: np.ndarray, cos_sample: int = 4096) -> dict:
    """Variance / PCA / cosine-similarity collapse metrics for a node matrix."""
    out = {}
    Xc = X - X.mean(axis=0, keepdims=True)
    dim = Xc.shape[1]

    # per-dimension std
    stds = Xc.std(axis=0)
    out["dim"] = dim
    out["per_dim_std_min"] = float(stds.min())
    out["per_dim_std_median"] = float(np.median(stds))
    out["per_dim_std_max"] = float(stds.max())
    out["n_dims_std_lt_1e-3"] = int((stds < 1e-3).sum())

    # PCA spectrum
    U, S, Vt = np.linalg.svd(Xc, full_matrices=False)
    lam = S**2
    evr = lam / lam.sum()
    cum = np.cumsum(evr)
    out["pca_evr_top10"] = [round(float(v), 5) for v in evr[:10]]
    out["pca_cum_top10"] = [round(float(v), 5) for v in cum[:10]]
    out["n comps for 95% var"] = int(np.searchsorted(cum, 0.95) + 1)
    out["n comps for 99% var"] = int(np.searchsorted(cum, 0.99) + 1)
    # participation ratio (spectral entropy-ish effective rank)
    out["participation_ratio"] = float(lam.sum() ** 2 / (lam**2).sum())

    # pairwise cosine on a sample
    rng = np.random.default_rng(42)
    idx = rng.choice(X.shape[0], size=min(cos_sample, X.shape[0]), replace=False)
    Z = X[idx] / (np.linalg.norm(X[idx], axis=1, keepdims=True) + 1e-12)
    sims = (Z @ Z.T).ravel()
    sims = sims[np.abs(sims - 1.0) > 1e-9]  # drop self-pairs
    out["cos_mean"] = float(sims.mean())
    out["cos_std"] = float(sims.std())
    for q in (1, 5, 25, 50, 75, 95, 99):
        out[f"cos_q{q}"] = float(np.percentile(sims, q))
    out["frac_cos_gt_0.99"] = float((sims > 0.99).mean())

    out["norm_mean"] = float(np.linalg.norm(X, axis=1).mean())
    out["norm_std"] = float(np.linalg.norm(X, axis=1).std())
    return out

geo_emb = geometry("penultimate Package embeddings", h_pkg)
report["geometry_embeddings"] = geo_emb

# Context: the projected inputs (pre-HAN) and the raw 10-d features
with torch.no_grad():
    proj = model.projections["Package"](x_dict["Package"]).numpy()
geo_proj = geometry("projected inputs (pre-HAN)", proj)
geo_raw = geometry("raw 10-d package features", data["Package"].x.numpy())
report["geometry_projected_input"] = geo_proj
report["geometry_raw_features"] = geo_raw

print("\n--- G1 · Geometry (128-d Package embeddings, eval mode, full graph) ---")
print(f"  per-dim std: min={geo_emb['per_dim_std_min']:.4g}  median={geo_emb['per_dim_std_median']:.4g}  max={geo_emb['per_dim_std_max']:.4g}  (dims<1e-3: {geo_emb['n_dims_std_lt_1e-3']}/128)")
print(f"  PCA EVR top-5: {geo_emb['pca_evr_top10'][:5]}  → comps for 95%: {geo_emb['n comps for 95% var']}, 99%: {geo_emb['n comps for 99% var']}")
print(f"  participation ratio: {geo_emb['participation_ratio']:.1f} / 128")
print(f"  pairwise cosine: mean={geo_emb['cos_mean']:.4f}  std={geo_emb['cos_std']:.4f}  q01={geo_emb['cos_q1']:.4f}  q50={geo_emb['cos_q50']:.4f}  q99={geo_emb['cos_q99']:.4f}")
print(f"  fraction of pairs with cos>0.99: {geo_emb['frac_cos_gt_0.99']*100:.2f}%")
print(f"  [context] projected-input PR={geo_proj['participation_ratio']:.1f}, cos mean={geo_proj['cos_mean']:.3f} | raw-feature PR={geo_raw['participation_ratio']:.1f}, cos mean={geo_raw['cos_mean']:.3f}")

# ---------------------------------------------------------------------------
# 3. M1 — Ridge probes: embeddings vs raw features (fit train, select on val)
# ---------------------------------------------------------------------------
from sklearn.linear_model import Ridge
from sklearn.metrics import roc_auc_score

def pearson(a, b):
    return float(np.corrcoef(a, b)[0, 1])

def run_probe(tag: str, X_full: np.ndarray):
    res = {"tag": tag}
    best = None
    for alpha in [1e-3, 1e-2, 1e-1, 1.0, 10.0, 100.0]:
        r = Ridge(alpha=alpha)
        r.fit(X_full[train_mask], y[train_mask])
        val_mse = float(np.mean((r.predict(X_full[val_mask]) - y[val_mask]) ** 2))
        if best is None or val_mse < best[0]:
            best = (val_mse, alpha, r)
    _, alpha, r = best
    res["alpha"] = alpha

    def sig(v):
        return 1.0 / (1.0 + np.exp(-v))

    for split, m in [("train", train_mask), ("test", test_mask)]:
        p = sig(r.predict(X_full[m]))
        t = y[m]
        nz = t > 0
        res[split] = {
            "mae": compute_mae(p, t),
            "spearman_all": compute_spearman_rho(p, t),
            "spearman_nonzero": compute_spearman_rho(p[nz], t[nz]),
            "pearson_nonzero": pearson(p[nz], t[nz]),
            "ranking_accuracy": compute_ranking_accuracy(p, t),
            "auc_zero_vs_nonzero": roc_auc_score(nz.astype(int), p),
        }
    return res

probe_emb = run_probe("ridge on 128-d penultimate embeddings", h_pkg)
probe_raw = run_probe("ridge on 10-d raw features", data["Package"].x.numpy())
report["probe_embeddings"] = probe_emb
report["probe_raw_features"] = probe_raw

print("\n--- M1 · Ridge probes (fit train, alpha on val, eval on test) ---")
hdr = f"  {'':<38}{'Spear_all':>10}{'Spear_nz':>10}{'Pear_nz':>9}{'RankAcc':>9}{'AUC nz':>8}"
print(hdr)
print(f"  {'trained VulnGAT (archived checkpoint)':<38}{report['repro_test']['spearman_all']:>10.4f}{'0.2227':>10}{'0.4263':>9}{'39.11%':>9}{'—':>8}")
print(f"  {'MLP on raw feats (archived, 200 ep)':<38}{'0.4426':>10}{'0.4944':>10}{'0.5716':>9}{'72.18%':>9}{'—':>8}")
for pr in (probe_raw, probe_emb):
    t = pr["test"]
    print(f"  {pr['tag'] + ' (a=' + str(pr['alpha']) + ')':<38}{t['spearman_all']:>10.4f}{t['spearman_nonzero']:>10.4f}{t['pearson_nonzero']:>9.4f}{t['ranking_accuracy']*100:>8.2f}%{t['auc_zero_vs_nonzero']:>8.3f}")

# ---------------------------------------------------------------------------
# 4. H1 — Is the trained head itself degenerate?
# ---------------------------------------------------------------------------
W = model.classifier[0].weight.detach().numpy().ravel()
b = model.classifier[0].bias.detach().item()
logit = h_pkg @ W + b
r_best = Ridge(alpha=probe_emb["alpha"]).fit(h_pkg[train_mask], y[train_mask])
ridge_logit_test = r_best.predict(h_pkg[test_mask])
report["head"] = {
    "weight_l2": float(np.linalg.norm(W)),
    "bias": float(b),
    "logit_std": float(logit.std()),
    "corr_logit_vs_ridge_emb_score": float(
        np.corrcoef(logit[test_mask], ridge_logit_test)[0, 1]
    ),
}
print("\n--- H1 · Trained classifier head ---")
print(f"  ||W||={report['head']['weight_l2']:.4f}  bias={report['head']['bias']:.4f}  logit std over packages={report['head']['logit_std']:.4f}")
print(f"  corr(head logit, ridge-on-embedding score) on test: r={report['head']['corr_logit_vs_ridge_emb_score']:.4f}")

# ---------------------------------------------------------------------------
# 5. InfoNCE value of the checkpoint (eval-mode, edge-dropout views, 3 seeds)
# ---------------------------------------------------------------------------
inf_vals = []
for seed in (0, 1, 2):
    torch.manual_seed(seed)
    with torch.no_grad():
        # keep dropout modules in eval; only augment_edge_index randomness active
        inf_vals.append(compute_infonce_loss(model, x_dict, edge_index_dict, 0.2, 0.5).item())
report["infonce_evalmode_seeds"] = inf_vals
print(f"\n  InfoNCE of checkpoint (eval mode, edge-drop views, seeds 0/1/2): {[round(v,3) for v in inf_vals]}  (train log: 7.90–7.93; chance ln(4095)=8.32)")

# ---------------------------------------------------------------------------
# 6. O1 — Output-level collapse: archived predictions & checkpoint preds
# ---------------------------------------------------------------------------
with open(os.path.join(RESULTS, "test_predictions_51repo.json")) as f:
    arch = json.load(f)
arch_test = [p for p, m in zip(arch["predictions"], test_mask) if m]

def pred_stats(tag, arr):
    arr = np.asarray(arr, dtype=float)
    st = {
        "n": len(arr),
        "std": float(arr.std()),
        "min": float(arr.min()),
        "max": float(arr.max()),
        "p01": float(np.percentile(arr, 1)),
        "p50": float(np.percentile(arr, 50)),
        "p99": float(np.percentile(arr, 99)),
        "frac_within_0.01_of_median": float((np.abs(arr - np.median(arr)) < 0.01).mean()),
        "n_unique_4dp": int(len(np.unique(np.round(arr, 4)))),
    }
    print(f"  {tag}: std={st['std']:.4f} range=[{st['min']:.4f},{st['max']:.4f}] "
          f"p01–p99=[{st['p01']:.4f},{st['p99']:.4f}] "
          f"within±0.01 of median: {st['frac_within_0.01_of_median']*100:.1f}% "
          f"unique@4dp: {st['n_unique_4dp']}/{st['n']}")
    return st

print("\n--- O1 · Prediction distributions (test split) ---")
report["pred_stats_archived"] = pred_stats("archived Colab preds ", arch_test)
report["pred_stats_checkpoint"] = pred_stats("local rebuild preds ", preds[test_mask])
print(f"  max |local - archived| on test: {float(np.max(np.abs(preds[test_mask] - np.array(arch_test)))):.2e}")

# ---------------------------------------------------------------------------
# 7. Verdict
# ---------------------------------------------------------------------------
pr_emb, pr_raw_ = geo_emb["participation_ratio"], geo_raw["participation_ratio"]
cos_mean = geo_emb["cos_mean"]
emb_racc = probe_emb["test"]["ranking_accuracy"]
raw_racc = probe_raw["test"]["ranking_accuracy"]

collapsed_geom = (pr_emb < 8) and (cos_mean > 0.95)
probe_fails = emb_racc < raw_racc - 0.05  # embeddings clearly worse than raw feats

if collapsed_geom and probe_fails:
    verdict = "COLLAPSE CONFIRMED — reweight InfoNCE + longer training is the right fix."
elif (not collapsed_geom) and (emb_racc >= raw_racc - 0.05):
    verdict = ("COLLAPSE REFUTED — embeddings retain comparable signal to raw features; "
               "the failure is head/optimization, not embedding geometry. "
               "InfoNCE reweighting alone is not the identified fix.")
else:
    verdict = ("MIXED — geometry and probe disagree; report numbers as-is and decide "
               "v2 scope from the tables above.")

report["verdict"] = verdict
print("\n" + "=" * 72)
print(f"VERDICT: {verdict}")
print("=" * 72)

with open(OUT_JSON, "w") as f:
    json.dump(report, f, indent=2)
print(f"\nFull numbers written to: {OUT_JSON}")
