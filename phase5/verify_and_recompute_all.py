"""
phase5/verify_and_recompute_all.py -- Comprehensive verification and recomputation script
Executes Steps 1, 2, 3, and 4 strictly without model re-training (only inference forward passes
plus the fast CPU baseline refits for Step 2b and exploratory head refit for Step 2d).
"""

import os
import sys
import json
import copy
import zipfile
from pathlib import Path
from collections import defaultdict, deque

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from scipy import stats as scipy_stats
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import Ridge

PROJECT_ROOT = Path(r"C:\Users\Admin\Desktop\Major VulnChain")
sys.path.insert(0, str(PROJECT_ROOT / "TrainModel"))

from core.model.vulngat import VulnGAT
from training.dataset import load_vulnchain_dataset
from training.evaluate import compute_ranking_accuracy, compute_spearman_rho, compute_mae
import masked_edge_audit as mea

device = torch.device("cpu")
print(f"Device: {device}")

# Paths
GRAPH_FILE = str(PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json")
LABELS_VPSS = str(PROJECT_ROOT / "phase4" / "vpss_labels_51repo.json")
LABELS_EPSS = str(PROJECT_ROOT / "phase5" / "epss_labels_51repo.json")
SPLIT_FILE = str(PROJECT_ROOT / "phase4" / "repo_split_mapping_51repo.json")
OSV_CACHE = str(PROJECT_ROOT / ".osv_records_cache.json")
HR_MODEL_FILE = str(PROJECT_ROOT / "phase5" / "models" / "vulngat_hr_full.pt")
MLP_MODEL_FILE = str(PROJECT_ROOT / "phase5" / "mlp_reconverged.pt")
V2DC_RESULTS_FILE = str(PROJECT_ROOT / "phase5" / "v2dc_final_results.json")
V2DC_ZIP = str(PROJECT_ROOT / "phase5" / "v2dc_checkpoints.zip")

print("=" * 80)
print("STEP 1: Trace HR Test Spearman & Recompute on Temporal Cut")
print("=" * 80)

# Load graph and labels
with open(GRAPH_FILE, "r", encoding="utf-8") as f:
    graph_json = json.load(f)
with open(LABELS_VPSS, "r", encoding="utf-8") as f:
    vpss_labels = json.load(f)
with open(LABELS_EPSS, "r", encoding="utf-8") as f:
    epss_labels = json.load(f)
with open(OSV_CACHE, "r", encoding="utf-8") as f:
    osv_data = json.load(f)

# 1.1 Temporal non-zero test cut (N=1,433 and N=1,430)
pkg_nodes = graph_json["nodes"]["Package"]
pkg_id_to_idx = {n["id"]: i for i, n in enumerate(pkg_nodes)}
cve_id_to_idx = {n["id"]: i for i, n in enumerate(graph_json["nodes"]["CVE"])}

pkg_to_cves = defaultdict(list)
for edge in graph_json["edges"]["hasVulnerability"]:
    pkg_to_cves[edge["source"]].append(edge["target"])

cve_dates = {c["id"]: osv_data[c["id"]]["published"][:10] for c in graph_json["nodes"]["CVE"] if c["id"] in osv_data and osv_data[c["id"]].get("published")}
deps_of = defaultdict(list)
for e in graph_json["edges"]["dependsOn"]:
    deps_of[e["source"]].append(e["target"])

pkg_newest_date = {}
for pid in pkg_id_to_idx:
    visited = {pid: 0}
    q = deque([pid])
    contrib_dates = []
    while q:
        cur = q.popleft()
        d = visited[cur]
        if cur in pkg_to_cves:
            for cve in pkg_to_cves[cur]:
                if cve in cve_dates:
                    contrib_dates.append(cve_dates[cve])
        if d < 5:
            for nxt in deps_of.get(cur, ()):
                if nxt not in visited and nxt in pkg_id_to_idx:
                    visited[nxt] = d + 1
                    q.append(nxt)
    if contrib_dates:
        pkg_newest_date[pid] = max(contrib_dates)

nz_pkgs = [pid for pid in pkg_id_to_idx if epss_labels[pid]["epss_risk"] > 0]
test_pkgs_1433 = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, "2000-01-01") >= "2026-08-01"]
test_idx_1433 = [pkg_id_to_idx[pid] for pid in test_pkgs_1433]

# Load VulnGAT-HR
data_hr, mappings, masks_phase4 = load_vulnchain_dataset(
    graph_path=GRAPH_FILE, labels_path=LABELS_VPSS, repo_split_path=SPLIT_FILE
)
hr_model = VulnGAT()
hr_model.load_state_dict(torch.load(HR_MODEL_FILE, map_location=device))
hr_model.to(device)
hr_model.eval()

# Forward pass on clean graph with dim 6 LIVE
with torch.no_grad():
    x_dict_live = {ntype: data_hr[ntype].x.to(device) for ntype in data_hr.node_types}
    edge_index_dict = {k: data_hr[k].edge_index.to(device) for k in data_hr.edge_types}
    preds_hr_live = hr_model(x_dict_live, edge_index_dict).cpu().numpy()

# Forward pass on clean graph with dim 6 ZEROED
with torch.no_grad():
    x_dict_zeroed = copy.copy(x_dict_live)
    pkg_x_z = x_dict_live["Package"].clone()
    pkg_x_z[:, 6] = 0.0
    x_dict_zeroed["Package"] = pkg_x_z
    preds_hr_zeroed = hr_model(x_dict_zeroed, edge_index_dict).cpu().numpy()

# Ground truth EPSS targets for temporal test cut
targets_epss = np.array([epss_labels[n["id"]]["epss_risk"] for n in pkg_nodes], dtype=np.float32)

sp_temporal_1433_live, _ = scipy_stats.spearmanr(targets_epss[test_idx_1433], preds_hr_live[test_idx_1433])
sp_temporal_1433_zeroed, _ = scipy_stats.spearmanr(targets_epss[test_idx_1433], preds_hr_zeroed[test_idx_1433])

print(f"VulnGAT-HR on Temporal Nonzero Test Cut (N=1,433, EPSS targets):")
print(f"  Dim 6 LIVE:   Spearman = {sp_temporal_1433_live:.4f}")
print(f"  Dim 6 ZEROED: Spearman = {sp_temporal_1433_zeroed:.4f}")

# Ground truth VPSS targets for Phase 4 repo-split test cut (N=1,341 all, N=538 nonzero)
test_mask_p4 = masks_phase4["test_mask"].cpu().numpy()
targets_vpss = data_hr["Package"].y.cpu().numpy()
test_idx_p4 = np.where(test_mask_p4)[0]
test_idx_p4_nz = np.where(test_mask_p4 & (targets_vpss > 0))[0]

sp_p4_all_live, _ = scipy_stats.spearmanr(targets_vpss[test_idx_p4], preds_hr_live[test_idx_p4])
sp_p4_all_zeroed, _ = scipy_stats.spearmanr(targets_vpss[test_idx_p4], preds_hr_zeroed[test_idx_p4])
sp_p4_nz_live, _ = scipy_stats.spearmanr(targets_vpss[test_idx_p4_nz], preds_hr_live[test_idx_p4_nz])
sp_p4_nz_zeroed, _ = scipy_stats.spearmanr(targets_vpss[test_idx_p4_nz], preds_hr_zeroed[test_idx_p4_nz])

print(f"\nVulnGAT-HR on Phase 4 Repo-Split Test Cut (N=1,341 all, N=538 nonzero, VPSS targets):")
print(f"  Dim 6 LIVE:   Spearman_all = {sp_p4_all_live:.4f} | Spearman_nz = {sp_p4_nz_live:.4f}")
print(f"  Dim 6 ZEROED: Spearman_all = {sp_p4_all_zeroed:.4f} | Spearman_nz = {sp_p4_nz_zeroed:.4f}")

print("\n" + "=" * 80)
print("STEP 2: Dim 6 Confound on Headline Metrics (Phase 4 Test Population: N=1,341)")
print("=" * 80)

# (a) VulnGAT-HR RankAcc
rankacc_hr_live = compute_ranking_accuracy(preds_hr_live[test_idx_p4], targets_vpss[test_idx_p4])
rankacc_hr_zeroed = compute_ranking_accuracy(preds_hr_zeroed[test_idx_p4], targets_vpss[test_idx_p4])
rankacc_hr_nz_live = compute_ranking_accuracy(preds_hr_live[test_idx_p4_nz], targets_vpss[test_idx_p4_nz])
rankacc_hr_nz_zeroed = compute_ranking_accuracy(preds_hr_zeroed[test_idx_p4_nz], targets_vpss[test_idx_p4_nz])

print("2(a) VulnGAT-HR on Test (N=1,341):")
print(f"  LIVE:   RankAcc = {rankacc_hr_live*100:.2f}% | Spearman_all = {sp_p4_all_live:.4f} | Spearman_nz = {sp_p4_nz_live:.4f}")
print(f"  ZEROED: RankAcc = {rankacc_hr_zeroed*100:.2f}% | Spearman_all = {sp_p4_all_zeroed:.4f} | Spearman_nz = {sp_p4_nz_zeroed:.4f}")

# (b) Ridge-raw and Reconverged MLP
train_mask_p4 = masks_phase4["train_mask"].cpu().numpy()
val_mask_p4 = masks_phase4["val_mask"].cpu().numpy()

X_all = data_hr["Package"].x.cpu().numpy()  # 10 features normalized
y_all = targets_vpss

X_train = X_all[train_mask_p4]
y_train = y_all[train_mask_p4]
X_val = X_all[val_mask_p4]
y_val = y_all[val_mask_p4]
X_test = X_all[test_mask_p4]
y_test = y_all[test_mask_p4]

# Ridge with dim 6 LIVE
ridge_live = Ridge(alpha=1.0)
ridge_live.fit(X_train, y_train)
preds_ridge_live = ridge_live.predict(X_test)

# Ridge evaluated with dim 6 ZEROED at inference
X_test_z = X_test.copy()
X_test_z[:, 6] = 0.0
preds_ridge_zeroed_inf = ridge_live.predict(X_test_z)

# Ridge refit WITHOUT dim 6 (train on 9 features)
cols_no_dim6 = [0, 1, 2, 3, 4, 5, 7, 8, 9]
ridge_no_dim6 = Ridge(alpha=1.0)
ridge_no_dim6.fit(X_train[:, cols_no_dim6], y_train)
preds_ridge_no_dim6 = ridge_no_dim6.predict(X_test[:, cols_no_dim6])

# MLP reconverged
class FeatureMLP(nn.Module):
    def __init__(self, in_dim=10):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    def forward(self, x):
        return self.net(x).squeeze(-1)

mlp_reconv = FeatureMLP(10)
mlp_reconv.load_state_dict(torch.load(MLP_MODEL_FILE, map_location=device))
mlp_reconv.eval()

with torch.no_grad():
    preds_mlp_live = mlp_reconv(torch.tensor(X_test, dtype=torch.float32)).numpy()
    preds_mlp_zeroed_inf = mlp_reconv(torch.tensor(X_test_z, dtype=torch.float32)).numpy()

# Train fresh MLP without dim 6 (in_dim=9)
print("\nTraining fresh MLP without dim 6 (in_dim=9, CPU)...")
torch.manual_seed(42)
mlp_no_dim6 = FeatureMLP(9)
opt_mlp = torch.optim.AdamW(mlp_no_dim6.parameters(), lr=1e-3, weight_decay=1e-5)

X_tr_9 = torch.tensor(X_train[:, cols_no_dim6], dtype=torch.float32)
y_tr_t = torch.tensor(y_train, dtype=torch.float32)
X_val_9 = torch.tensor(X_val[:, cols_no_dim6], dtype=torch.float32)
y_val_t = torch.tensor(y_val, dtype=torch.float32)
val_nz_mask = y_val > 0

best_val_sp = -1.0
best_mlp_state = None
patience = 50
patience_cnt = 0

batch_size = 256
n_batches = int(np.ceil(len(X_tr_9) / batch_size))

for epoch in range(500):
    mlp_no_dim6.train()
    perm = torch.randperm(len(X_tr_9))
    for b in range(n_batches):
        idx = perm[b*batch_size:(b+1)*batch_size]
        opt_mlp.zero_grad()
        p = mlp_no_dim6(X_tr_9[idx])
        loss = F.mse_loss(p, y_tr_t[idx])
        loss.backward()
        opt_mlp.step()

    mlp_no_dim6.eval()
    with torch.no_grad():
        vp = mlp_no_dim6(X_val_9).numpy()
        sp_nz, _ = scipy_stats.spearmanr(y_val[val_nz_mask], vp[val_nz_mask])
        if np.isnan(sp_nz): sp_nz = -1.0

    if sp_nz > best_val_sp:
        best_val_sp = sp_nz
        best_mlp_state = copy.deepcopy(mlp_no_dim6.state_dict())
        patience_cnt = 0
    else:
        patience_cnt += 1
        if patience_cnt >= patience:
            break

mlp_no_dim6.load_state_dict(best_mlp_state)
mlp_no_dim6.eval()
with torch.no_grad():
    preds_mlp_no_dim6 = mlp_no_dim6(torch.tensor(X_test[:, cols_no_dim6], dtype=torch.float32)).numpy()

def calc_all_metrics(preds, targets):
    nz = targets > 0
    return {
        "rankacc": compute_ranking_accuracy(preds, targets),
        "rankacc_nz": compute_ranking_accuracy(preds[nz], targets[nz]),
        "spearman_all": compute_spearman_rho(preds, targets),
        "spearman_nz": compute_spearman_rho(preds[nz], targets[nz]),
    }

m_ridge_live = calc_all_metrics(preds_ridge_live, y_test)
m_ridge_z_inf = calc_all_metrics(preds_ridge_zeroed_inf, y_test)
m_ridge_refit = calc_all_metrics(preds_ridge_no_dim6, y_test)

m_mlp_live = calc_all_metrics(preds_mlp_live, y_test)
m_mlp_z_inf = calc_all_metrics(preds_mlp_zeroed_inf, y_test)
m_mlp_refit = calc_all_metrics(preds_mlp_no_dim6, y_test)

print("\n2(b) Baseline Metrics on Test (N=1,341):")
print(f"  Ridge LIVE:        RankAcc = {m_ridge_live['rankacc']*100:.2f}% | Spear_all = {m_ridge_live['spearman_all']:.4f} | Spear_nz = {m_ridge_live['spearman_nz']:.4f}")
print(f"  Ridge ZEROED inf:  RankAcc = {m_ridge_z_inf['rankacc']*100:.2f}% | Spear_all = {m_ridge_z_inf['spearman_all']:.4f} | Spear_nz = {m_ridge_z_inf['spearman_nz']:.4f}")
print(f"  Ridge REFIT (9-d): RankAcc = {m_ridge_refit['rankacc']*100:.2f}% | Spear_all = {m_ridge_refit['spearman_all']:.4f} | Spear_nz = {m_ridge_refit['spearman_nz']:.4f}")
print(f"  MLP LIVE:          RankAcc = {m_mlp_live['rankacc']*100:.2f}% | Spear_all = {m_mlp_live['spearman_all']:.4f} | Spear_nz = {m_mlp_live['spearman_nz']:.4f}")
print(f"  MLP ZEROED inf:    RankAcc = {m_mlp_z_inf['rankacc']*100:.2f}% | Spear_all = {m_mlp_z_inf['spearman_all']:.4f} | Spear_nz = {m_mlp_z_inf['spearman_nz']:.4f}")
print(f"  MLP REFIT (9-d):   RankAcc = {m_mlp_refit['rankacc']*100:.2f}% | Spear_all = {m_mlp_refit['spearman_all']:.4f} | Spear_nz = {m_mlp_refit['spearman_nz']:.4f}")

# (c) Report Margins
print("\n2(c) HR Margins vs Baselines:")
print(f"  [LIVE] HR (85.55%) vs Ridge ({m_ridge_live['rankacc']*100:.2f}%): +{(85.55 - m_ridge_live['rankacc']*100):.2f} pp")
print(f"  [LIVE] HR (85.55%) vs MLP ({m_mlp_live['rankacc']*100:.2f}%):   +{(85.55 - m_mlp_live['rankacc']*100):.2f} pp")
print(f"  [ZEROED inf] HR ({rankacc_hr_zeroed*100:.2f}%) vs Ridge ({m_ridge_z_inf['rankacc']*100:.2f}%): +{(rankacc_hr_zeroed*100 - m_ridge_z_inf['rankacc']*100):.2f} pp")
print(f"  [ZEROED inf] HR ({rankacc_hr_zeroed*100:.2f}%) vs MLP ({m_mlp_z_inf['rankacc']*100:.2f}%):   +{(rankacc_hr_zeroed*100 - m_mlp_z_inf['rankacc']*100):.2f} pp")
print(f"  [HR zeroed vs REFIT 9d] HR ({rankacc_hr_zeroed*100:.2f}%) vs Ridge refit ({m_ridge_refit['rankacc']*100:.2f}%): +{(rankacc_hr_zeroed*100 - m_ridge_refit['rankacc']*100):.2f} pp")
print(f"  [HR zeroed vs REFIT 9d] HR ({rankacc_hr_zeroed*100:.2f}%) vs MLP refit ({m_mlp_refit['rankacc']*100:.2f}%):   +{(rankacc_hr_zeroed*100 - m_mlp_refit['rankacc']*100):.2f} pp")

# (d) EXPLORATORY: Refit only the HR head on embeddings recomputed with dim 6 zeroed
print("\n2(d) EXPLORATORY: Refit HR head on embeddings recomputed with dim 6 ZEROED...")
# Recompute embeddings with encoder forward where Package.x[:, 6] = 0
with torch.no_grad():
    Z_zeroed = hr_model.encode(x_dict_zeroed, edge_index_dict)["Package"].cpu()  # [12405, 128]

# Train fresh Linear(128,1) -> Sigmoid head on Z_zeroed
torch.manual_seed(42)
head_refit_z = nn.Sequential(nn.Linear(128, 1), nn.Sigmoid())
opt_head_z = torch.optim.Adam(head_refit_z.parameters(), lr=1e-3)

Z_tr = Z_zeroed[train_mask_p4]
y_tr_t = torch.tensor(y_train, dtype=torch.float32)
Z_val = Z_zeroed[val_mask_p4]
y_val_nz_mask = torch.tensor(y_val > 0)
Z_test = Z_zeroed[test_mask_p4]

best_val_sp_hz = -1.0
best_hz_state = None
patience_hz = 50
patience_cnt_hz = 0
batch_size_hz = 32
n_batches_hz = int(np.ceil(len(Z_tr) / batch_size_hz))

for epoch in range(500):
    head_refit_z.train()
    perm = torch.randperm(len(Z_tr))
    for b in range(n_batches_hz):
        idx = perm[b*batch_size_hz:(b+1)*batch_size_hz]
        opt_head_z.zero_grad()
        p = head_refit_z(Z_tr[idx]).squeeze(-1)
        loss = F.mse_loss(p, y_tr_t[idx])
        loss.backward()
        opt_head_z.step()

    head_refit_z.eval()
    with torch.no_grad():
        vp = head_refit_z(Z_val).squeeze(-1).numpy()
        sp_nz, _ = scipy_stats.spearmanr(y_val[val_nz_mask], vp[val_nz_mask])
        if np.isnan(sp_nz): sp_nz = -1.0

    if sp_nz > best_val_sp_hz:
        best_val_sp_hz = sp_nz
        best_hz_state = copy.deepcopy(head_refit_z.state_dict())
        patience_cnt_hz = 0
    else:
        patience_cnt_hz += 1
        if patience_cnt_hz >= patience_hz:
            break

head_refit_z.load_state_dict(best_hz_state)
head_refit_z.eval()
with torch.no_grad():
    preds_hr_head_refit_z = head_refit_z(Z_test).squeeze(-1).numpy()

m_hr_head_refit_z = calc_all_metrics(preds_hr_head_refit_z, y_test)
print(f"  EXPLORATORY Refit HR Head on Zeroed Embeddings:")
print(f"    RankAcc = {m_hr_head_refit_z['rankacc']*100:.2f}% | Spearman_all = {m_hr_head_refit_z['spearman_all']:.4f} | Spearman_nz = {m_hr_head_refit_z['spearman_nz']:.4f}")
print(f"    Margin vs Ridge Refit ({m_ridge_refit['rankacc']*100:.2f}%): +{(m_hr_head_refit_z['rankacc']*100 - m_ridge_refit['rankacc']*100):.2f} pp")
print(f"    Margin vs MLP Refit ({m_mlp_refit['rankacc']*100:.2f}%):   +{(m_hr_head_refit_z['rankacc']*100 - m_mlp_refit['rankacc']*100):.2f} pp")

print("\n" + "=" * 80)
print("STEP 3: NodeTestBench Dim 6 Check")
print("=" * 80)

# Load NodeTestBench results
with open(PROJECT_ROOT / "phase5" / "bench_run" / "bench_results_hr.json", "r", encoding="utf-8") as f:
    bench_data = json.load(f)

# Re-score bench_results_hr.json at threshold >= 0.40
bench_pkgs = bench_data["packages"]
print(f"Total packages in NodeTestBench: {len(bench_pkgs)}")

# Live results from bench_results_hr.json
tp_live = sum(1 for p in bench_pkgs if p["risk_score"] >= 0.40 and p.get("cve"))
fp_live = sum(1 for p in bench_pkgs if p["risk_score"] >= 0.40 and not p.get("cve"))
fn_live = sum(1 for p in bench_pkgs if p["risk_score"] < 0.40 and p.get("cve"))
tn_live = sum(1 for p in bench_pkgs if p["risk_score"] < 0.40 and not p.get("cve"))

prec_live = tp_live / (tp_live + fp_live) if (tp_live + fp_live) > 0 else 0.0
rec_live = tp_live / (tp_live + fn_live) if (tp_live + fn_live) > 0 else 0.0

print(f"NodeTestBench LIVE (threshold >= 0.40):")
print(f"  Flagged: {tp_live + fp_live} | TP={tp_live}, FP={fp_live}, FN={fn_live}, TN={tn_live}")
print(f"  Precision = {prec_live*100:.1f}% | Recall = {rec_live*100:.1f}%")

# Now re-run inference on NodeTestBench with dim 6 ZEROED
# Parse NodeTestBench package-lock.json
sys.path.insert(0, str(PROJECT_ROOT / "phase5" / "bench_run"))
from analyze_project import parse_package_lock, build_analysis_tensors

bench_lock = str(PROJECT_ROOT / "phase5" / "NodeTestBench" / "package-lock.json")
packages_ntb, edges_ntb = parse_package_lock(bench_lock)
x_dict_ntb, edge_index_dict_ntb, pkg_list_ntb, all_has_vuln_ntb, has_vuln_subtree_ntb = build_analysis_tensors(
    packages_ntb, edges_ntb, cached_graph_path=GRAPH_FILE
)

# 1. LIVE check with exact analyze_project pipeline (with calibration cap)
with torch.no_grad():
    x_dict_ntb_live = {k: v.to(device) for k, v in x_dict_ntb.items()}
    edge_index_ntb_live = {k: v.to(device) for k, v in edge_index_dict_ntb.items()}
    scores_ntb_live_raw = hr_model(x_dict_ntb_live, edge_index_ntb_live).cpu().numpy()

scores_ntb_live_capped = scores_ntb_live_raw.copy()
for idx, pkg_id in enumerate(pkg_list_ntb):
    has_own = pkg_id in all_has_vuln_ntb
    if not has_own and not (pkg_id in has_vuln_subtree_ntb):
        scores_ntb_live_capped[idx] = min(scores_ntb_live_capped[idx], 0.08)

gt_cve_map = {p["package"]: p.get("cve") for p in bench_pkgs}

# 2. ZEROED check (dim 6 zeroed before inference)
x_dict_ntb_zeroed = copy.deepcopy(x_dict_ntb_live)
x_dict_ntb_zeroed["Package"][:, 6] = 0.0

with torch.no_grad():
    scores_ntb_zeroed_raw = hr_model(x_dict_ntb_zeroed, edge_index_ntb_live).cpu().numpy()

scores_ntb_zeroed_capped = scores_ntb_zeroed_raw.copy()
for idx, pkg_id in enumerate(pkg_list_ntb):
    has_own = pkg_id in all_has_vuln_ntb
    if not has_own and not (pkg_id in has_vuln_subtree_ntb):
        scores_ntb_zeroed_capped[idx] = min(scores_ntb_zeroed_capped[idx], 0.08)

def eval_ntb_scores(scores, label):
    tp = sum(1 for i, pid in enumerate(pkg_list_ntb) if scores[i] >= 0.40 and bool(gt_cve_map.get(pid)))
    fp = sum(1 for i, pid in enumerate(pkg_list_ntb) if scores[i] >= 0.40 and not bool(gt_cve_map.get(pid)))
    fn = sum(1 for i, pid in enumerate(pkg_list_ntb) if scores[i] < 0.40 and bool(gt_cve_map.get(pid)))
    tn = sum(1 for i, pid in enumerate(pkg_list_ntb) if scores[i] < 0.40 and not bool(gt_cve_map.get(pid)))
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    print(f"  {label:<30}: Flagged={tp+fp:<3} | TP={tp:<2}, FP={fp:<2}, FN={fn:<2}, TN={tn:<3} | Prec={prec*100:.1f}% | Rec={rec*100:.1f}%")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "prec": prec, "rec": rec}

print("\nNodeTestBench Re-Score (threshold >= 0.40):")
ntb_live_capped = eval_ntb_scores(scores_ntb_live_capped, "Dim 6 LIVE (capped)")
ntb_live_raw = eval_ntb_scores(scores_ntb_live_raw, "Dim 6 LIVE (raw)")
ntb_zeroed_capped = eval_ntb_scores(scores_ntb_zeroed_capped, "Dim 6 ZEROED (capped)")
ntb_zeroed_raw = eval_ntb_scores(scores_ntb_zeroed_raw, "Dim 6 ZEROED (raw)")

print("\n" + "=" * 80)
print("STEP 4: v2.1 Row Corrections & Verification")
print("=" * 80)

with open(V2DC_RESULTS_FILE, "r", encoding="utf-8") as f:
    v2dc_data = json.load(f)

summary = v2dc_data["summary"]
print("v2.1 Pre-registered ARM Means across 5 seeds:")
for arm_name, s in summary.items():
    print(f"  {arm_name:<22}: Masked-50 AUC = {s['auc_mean']:.4f} +/- {s['auc_std']:.4f} | Spearman = {s['spearman_mean']:.4f} +/- {s['spearman_std']:.4f}")

# Re-run the 5 checkpoints of full_v2 (p=0.3) on the official zeroed path
print("\nRe-running v2.1 full_v2 (p=0.3) 5 checkpoints on OFFICIAL ZEROED audit path...")
SEEDS = [42, 123, 456, 789, 1024]
ckpt_zip = zipfile.ZipFile(V2DC_ZIP)

# Prepare graph data for v2 architecture
# Port v2 data loading
pkg_features_v2 = np.array([n["features"] for n in pkg_nodes], dtype=np.float32)
def norm_feats(tensor, continuous_indices):
    norm_tensor = tensor.clone()
    for idx in continuous_indices:
        col = norm_tensor[:, idx]
        min_val = col.min()
        max_val = col.max()
        norm_tensor[:, idx] = (col - min_val) / (max_val - min_val) if max_val > min_val else 0.0
    return norm_tensor

pkg_feat_v2 = norm_feats(torch.tensor(pkg_features_v2, dtype=torch.float32), [2, 3, 4, 5, 7])
cve_feat_v2 = []
for n in graph_json["nodes"]["CVE"]:
    emb = n.get("embedding") or [0.0]*768
    cvss = float(n.get("cvss_score", 0.0) if n.get("cvss_score") is not None else 0.0) / 10.0
    cve_feat_v2.append(emb + [cvss])
cve_feat_v2 = torch.tensor(cve_feat_v2, dtype=torch.float32)
auth_feat_v2 = norm_feats(torch.tensor([n["features"] for n in graph_json["nodes"]["Author"]], dtype=torch.float32), [0, 1, 2, 3, 6])

from torch_geometric.data import HeteroData
from torch_geometric.nn import GATConv, HeteroConv

def build_coo(edge_list, src_map, dst_map):
    src, dst = [], []
    for e in edge_list:
        if e["source"] in src_map and e["target"] in dst_map:
            src.append(src_map[e["source"]]); dst.append(dst_map[e["target"]])
    return torch.tensor([src, dst], dtype=torch.long)

auth_id_to_idx = {n["id"]: i for i, n in enumerate(graph_json["nodes"]["Author"])}
cve_id_to_idx = {n["id"]: i for i, n in enumerate(graph_json["nodes"]["CVE"])}

data_v2 = HeteroData()
data_v2["Package"].x = pkg_feat_v2
data_v2["CVE"].x = cve_feat_v2
data_v2["Author"].x = auth_feat_v2
data_v2["Package", "dependsOn", "Package"].edge_index = build_coo(graph_json["edges"]["dependsOn"], pkg_id_to_idx, pkg_id_to_idx)
data_v2["Package", "hasVulnerability", "CVE"].edge_index = build_coo(graph_json["edges"]["hasVulnerability"], pkg_id_to_idx, cve_id_to_idx)
data_v2["Package", "maintainedBy", "Author"].edge_index = build_coo(graph_json["edges"]["maintainedBy"], pkg_id_to_idx, auth_id_to_idx)
data_v2["CVE", "introducedBy", "Author"].edge_index = build_coo(graph_json["edges"]["introducedBy"], cve_id_to_idx, auth_id_to_idx)

FWD = [("Package", "dependsOn", "Package"), ("Package", "hasVulnerability", "CVE"),
       ("Package", "maintainedBy", "Author"), ("CVE", "introducedBy", "Author")]

def with_rev(edge_index_dict):
    full_dict = dict(edge_index_dict)
    for (src, rel, dst) in FWD:
        if (src, rel, dst) in full_dict:
            full_dict[(dst, "rev_" + rel, src)] = full_dict[(src, rel, dst)].flip(0)
    return full_dict

class VulnGATv2Model(nn.Module):
    def __init__(self, pkg_in_dim=10, cve_in_dim=769, author_in_dim=7, hidden_dim=128, heads=4):
        super().__init__()
        self.pkg_proj = nn.Linear(pkg_in_dim, hidden_dim)
        self.cve_proj = nn.Linear(cve_in_dim, hidden_dim)
        self.author_proj = nn.Linear(author_in_dim, hidden_dim)
        convspec = lambda a, b: GATConv(a, b, heads=heads, add_self_loops=False)
        both = {
            ("Package", "dependsOn", "Package"): convspec(hidden_dim, hidden_dim // heads),
            ("Package", "hasVulnerability", "CVE"): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Package", "maintainedBy", "Author"): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("CVE", "introducedBy", "Author"): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Package", "rev_dependsOn", "Package"): convspec(hidden_dim, hidden_dim // heads),
            ("CVE", "rev_hasVulnerability", "Package"): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Author", "rev_maintainedBy", "Package"): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Author", "rev_introducedBy", "CVE"): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
        }
        self.conv1 = HeteroConv(both, aggr="sum")
        self.conv2 = HeteroConv(both, aggr="sum")
        self.classifier = nn.Sequential(nn.Linear(hidden_dim, 64), nn.GELU(), nn.Dropout(0.1), nn.Linear(64, 1), nn.Sigmoid())
    def forward(self, x_dict, edge_index_dict):
        h = {"Package": F.relu(self.pkg_proj(x_dict["Package"])),
             "CVE": F.relu(self.cve_proj(x_dict["CVE"])),
             "Author": F.relu(self.author_proj(x_dict["Author"]))}
        ef = with_rev(edge_index_dict)
        h1 = self.conv1(h, ef); h1 = {k: F.relu(v) for k, v in h1.items()}
        h2 = self.conv2(h1, ef)
        return self.classifier(h2["Package"]).squeeze(-1), h2["Package"]

own_vpss = mea.compute_own_vpss(graph_json, vpss_labels)
eligible_645 = mea.select_eligible_packages(own_vpss, 0.70)
never_8682 = mea.get_never_vuln_indices(vpss_labels, pkg_id_to_idx, len(pkg_nodes))

aucs_v21_official_zeroed = []

for s in SEEDS:
    ckpt_name = f"v2dc_full_v2_p30_s{s}.pt"
    ckpt_bytes = ckpt_zip.open(ckpt_name)
    m = VulnGATv2Model()
    m.load_state_dict(torch.load(ckpt_bytes, map_location=device))
    m.eval()

    # Official masked audit (with dim 6 zeroed for masked packages per Commandment 2)
    masked_data, masked_indices, _, _ = mea.apply_edge_mask(
        data_v2, eligible_645, pkg_id_to_idx, graph_json, cve_id_to_idx, 0.50, s
    )
    with torch.no_grad():
        x_d = {k: masked_data[k].x for k in masked_data.node_types}
        e_d = {k: masked_data[k].edge_index for k in masked_data.edge_types}
        scores, _ = m(x_d, e_d)
        scores = scores.cpu().numpy()

    pos = scores[list(masked_indices)]
    neg = scores[never_8682]
    y_ev = np.concatenate([np.ones(len(pos)), np.zeros(len(neg))])
    auc_val = float(roc_auc_score(y_ev, np.concatenate([pos, neg])))
    aucs_v21_official_zeroed.append(auc_val)
    print(f"  v2.1 full_v2 p=0.3 s={s:<4}: Official zeroed masked-50 AUC = {auc_val:.4f}")

mean_v21_off = np.mean(aucs_v21_official_zeroed)
std_v21_off = np.std(aucs_v21_official_zeroed)
print(f"  => v2.1 full_v2 p=0.3 (5-seed mean +/- std on Official Zeroed Path): {mean_v21_off:.4f} +/- {std_v21_off:.4f}")
