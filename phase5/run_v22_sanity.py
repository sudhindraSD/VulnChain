"""
phase5/run_v22_sanity.py -- VulnGAT v2.2 Sanity Diagnostic & Exploratory Script
CPU execution, fixed seed 42, arm full_v2 (p=0.3).
Authorized changes only:
1. Zero-label packages included in train_mask (train = train_fit + all zeros; val/test nonzero temporal cuts).
2. No early stopping: 100 full epochs, final checkpoint used.
Exploratory arm: 300 epochs with same spec.
"""

import os
import sys
import json
import copy
import random
import time
from pathlib import Path
from collections import defaultdict, deque

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from scipy import stats as scipy_stats
from sklearn.metrics import roc_auc_score
from torch_geometric.data import HeteroData
from torch_geometric.nn import GATConv, HeteroConv

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# File paths
GRAPH_FILE = PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json"
EPSS_LABELS_FILE = PROJECT_ROOT / "phase5" / "epss_labels_51repo.json"
VPSS_LABELS_FILE = PROJECT_ROOT / "phase4" / "vpss_labels_51repo.json"
OSV_CACHE = PROJECT_ROOT / ".osv_records_cache.json"
RESULTS_OUT = PROJECT_ROOT / "phase5" / "v22_sanity_results.json"
CKPT_DIR = PROJECT_ROOT / "phase5" / "v22_checkpoints"
CKPT_DIR.mkdir(exist_ok=True)

device = torch.device("cpu")
print(f"Using device: {device}")

# 1. Pre-registered constants
SEED = 42
P_MASK = 0.30
LR = 5e-4
WEIGHT_DECAY = 1e-4
LAMBDA_RANK = 0.20
LAMBDA_AUX = 0.30
TEMPORAL_CUTOFF = "2026-08-01"

PRIMARY_GATE_THRESHOLD = 0.7391
SECONDARY_GATE_THRESHOLD = 0.6571

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

set_seed(SEED)

# 2. Load dataset
print("Loading raw files...")
with open(GRAPH_FILE, "r", encoding="utf-8") as f:
    graph_json = json.load(f)
with open(EPSS_LABELS_FILE, "r", encoding="utf-8") as f:
    epss_labels = json.load(f)
with open(VPSS_LABELS_FILE, "r", encoding="utf-8") as f:
    vpss_labels = json.load(f)
with open(OSV_CACHE, "r", encoding="utf-8") as f:
    osv_data = json.load(f)

pkg_nodes = graph_json["nodes"]["Package"]
cve_nodes = graph_json["nodes"]["CVE"]
author_nodes = graph_json["nodes"]["Author"]

pkg_id_to_idx = {n["id"]: i for i, n in enumerate(pkg_nodes)}
idx_to_pkg_id = {i: n["id"] for i, n in enumerate(pkg_nodes)}
cve_id_to_idx = {n["id"]: i for i, n in enumerate(cve_nodes)}
author_id_to_idx = {n["id"]: i for i, n in enumerate(author_nodes)}

num_packages = len(pkg_nodes)
num_cves = len(cve_nodes)
num_authors = len(author_nodes)

pkg_features = np.array([n["features"] for n in pkg_nodes], dtype=np.float32)
pkg_targets = np.array([epss_labels[n["id"]]["epss_risk"] for n in pkg_nodes], dtype=np.float32)

def normalize_features(features_tensor, continuous_indices):
    norm_tensor = features_tensor.clone()
    for idx in continuous_indices:
        col = norm_tensor[:, idx]
        min_val = col.min()
        max_val = col.max()
        if max_val > min_val:
            norm_tensor[:, idx] = (col - min_val) / (max_val - min_val)
        else:
            norm_tensor[:, idx] = 0.0
    return norm_tensor

# Normalization [FIX A3]
pkg_feat_tensor = normalize_features(torch.tensor(pkg_features, dtype=torch.float32), [2, 3, 4, 5, 7])

cve_features = []
for n in cve_nodes:
    emb = n.get("embedding")
    if emb is None:
        emb = [0.0] * 768
    cvss = n.get("cvss_score")
    cvss_val = (float(cvss) if cvss is not None else 0.0) / 10.0
    cve_features.append(emb + [cvss_val])
cve_features = np.array(cve_features, dtype=np.float32)

author_features = np.array([n["features"] for n in author_nodes], dtype=np.float32)
author_feat_tensor = normalize_features(torch.tensor(author_features, dtype=torch.float32), [0, 1, 2, 3, 6])

def build_edge_index(edge_list, src_map, dst_map):
    src, dst = [], []
    for e in edge_list:
        if e["source"] in src_map and e["target"] in dst_map:
            src.append(src_map[e["source"]])
            dst.append(dst_map[e["target"]])
    return torch.tensor([src, dst], dtype=torch.long)

edges_dependsOn = build_edge_index(graph_json["edges"]["dependsOn"], pkg_id_to_idx, pkg_id_to_idx)
edges_hasVuln = build_edge_index(graph_json["edges"]["hasVulnerability"], pkg_id_to_idx, cve_id_to_idx)
edges_maintainedBy = build_edge_index(graph_json["edges"]["maintainedBy"], pkg_id_to_idx, author_id_to_idx)
edges_introducedBy = build_edge_index(graph_json["edges"]["introducedBy"], cve_id_to_idx, author_id_to_idx)

data = HeteroData()
data["Package"].x = pkg_feat_tensor
data["Package"].y = torch.tensor(pkg_targets, dtype=torch.float32)
data["CVE"].x = torch.tensor(cve_features, dtype=torch.float32)
data["Author"].x = author_feat_tensor

data["Package", "dependsOn", "Package"].edge_index = edges_dependsOn
data["Package", "hasVulnerability", "CVE"].edge_index = edges_hasVuln
data["Package", "maintainedBy", "Author"].edge_index = edges_maintainedBy
data["CVE", "introducedBy", "Author"].edge_index = edges_introducedBy

# Package -> direct-CVE adjacency
pkg_to_cves = defaultdict(list)
for edge in graph_json["edges"]["hasVulnerability"]:
    pkg_to_cves[edge["source"]].append(edge["target"])

# Official eligibility computation [FIX A1]
OWN_VPSS_THRESHOLD = 0.70

def compute_own_vpss(graph_json, vpss_labels):
    pkg_to_cves_official = defaultdict(list)
    for edge in graph_json["edges"]["hasVulnerability"]:
        pkg_to_cves_official[edge["source"]].append(edge["target"])

    cve_cvss = {}
    for cve_node in graph_json["nodes"]["CVE"]:
        cvss_raw = cve_node.get("cvss_score")
        cvss_val = float(cvss_raw) if cvss_raw is not None else 0.0
        cve_cvss[cve_node["id"]] = cvss_val

    result = {}
    for pkg_id, cve_list in pkg_to_cves_official.items():
        label_entry = vpss_labels.get(pkg_id, {})
        full_vpss = float(label_entry.get("vpss", 0.0))
        raw_sum = float(label_entry.get("raw_sum", 0.0))
        own_raw = sum(cve_cvss.get(cve_id, 0.0) / 10.0 for cve_id in cve_list)

        if raw_sum > 1e-9:
            own_ratio = min(own_raw / raw_sum, 1.0)
        elif own_raw > 0:
            own_ratio = 1.0
        else:
            own_ratio = 0.0

        own_vpss = own_ratio * full_vpss
        result[pkg_id] = {
            "own_vpss": own_vpss,
            "own_ratio": own_ratio,
            "own_raw": own_raw,
            "direct_cves": cve_list,
            "full_vpss": full_vpss,
        }
    return result

def select_eligible_packages(own_vpss_data, threshold=OWN_VPSS_THRESHOLD):
    eligible = [
        pkg_id for pkg_id, data_ in own_vpss_data.items()
        if data_["own_ratio"] >= threshold and data_["full_vpss"] > 1e-6
    ]
    if len(eligible) < 15:
        eligible = [
            pkg_id for pkg_id, data_ in own_vpss_data.items()
            if data_["own_ratio"] >= 0.30 and data_["full_vpss"] > 1e-6
        ]
    return eligible

def get_never_vuln_indices(vpss_labels, pkg_id_to_idx, num_packages):
    never_vuln = []
    for pkg_id in pkg_id_to_idx.keys():
        entry = vpss_labels.get(pkg_id, {})
        vpss = float(entry.get("vpss", 0.0))
        if vpss < 1e-9:
            never_vuln.append(pkg_id_to_idx[pkg_id])
    return never_vuln

own_vpss_data = compute_own_vpss(graph_json, vpss_labels)
eligible_pkg_ids = select_eligible_packages(own_vpss_data)
never_vuln_indices = get_never_vuln_indices(vpss_labels, pkg_id_to_idx, num_packages)
eligible_indices = [pkg_id_to_idx[pid] for pid in eligible_pkg_ids]

assert len(eligible_pkg_ids) == 645, f"Expected 645 eligible, got {len(eligible_pkg_ids)}"
assert len(never_vuln_indices) == 8682, f"Expected 8682 never_vuln, got {len(never_vuln_indices)}"
print(f"Primary Gate Pinned Population: {len(eligible_pkg_ids)} eligible vs {len(never_vuln_indices)} never-vuln negatives.")

# Temporal split
cve_dates = {c["id"]: osv_data[c["id"]]["published"][:10] for c in cve_nodes if c["id"] in osv_data and osv_data[c["id"]].get("published")}
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
zero_pkgs = [pid for pid in pkg_id_to_idx if epss_labels[pid]["epss_risk"] <= 0]

train_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, "2000-01-01") < TEMPORAL_CUTOFF]
test_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, "2000-01-01") >= TEMPORAL_CUTOFF]

random.seed(42)
shuffled_train = list(train_pkgs)
random.shuffle(shuffled_train)
val_cut = int(0.20 * len(shuffled_train))
val_pkgs = shuffled_train[:val_cut]
train_fit_pkgs = shuffled_train[val_cut:]

# Authorized Change 1: Zero-label packages go into training loss (train_mask)
train_mask = torch.zeros(num_packages, dtype=torch.bool)
val_mask = torch.zeros(num_packages, dtype=torch.bool)
test_mask = torch.zeros(num_packages, dtype=torch.bool)

# Nonzero split
for pid in train_fit_pkgs:
    train_mask[pkg_id_to_idx[pid]] = True
for pid in val_pkgs:
    val_mask[pkg_id_to_idx[pid]] = True
for pid in test_pkgs:
    test_mask[pkg_id_to_idx[pid]] = True

# All zero packages added to train_mask
for pid in zero_pkgs:
    train_mask[pkg_id_to_idx[pid]] = True

data["Package"].train_mask = train_mask
data["Package"].val_mask = val_mask
data["Package"].test_mask = test_mask

print(f"Dataset Masks: Train={train_mask.sum().item()} (train_fit={len(train_fit_pkgs)} nz + {len(zero_pkgs)} zero) | Val={val_mask.sum().item()} nz | Test={test_mask.sum().item()} nz")
print(f"Total accounted: {train_mask.sum().item() + val_mask.sum().item() + test_mask.sum().item()} / {num_packages}")

# 3. Model architecture
FWD_EDGES = [
    ("Package", "dependsOn", "Package"),
    ("Package", "hasVulnerability", "CVE"),
    ("Package", "maintainedBy", "Author"),
    ("CVE", "introducedBy", "Author"),
]

def with_reverse_edges(edge_index_dict):
    full_dict = dict(edge_index_dict)
    for (src, rel, dst) in FWD_EDGES:
        key = (src, rel, dst)
        if key in full_dict:
            rev_key = (dst, "rev_" + rel, src)
            full_dict[rev_key] = full_dict[key].flip(0)
    return full_dict

class VulnGATv2(nn.Module):
    def __init__(self, pkg_in_dim=10, cve_in_dim=769, author_in_dim=7, hidden_dim=128, heads=4):
        super().__init__()
        self.pkg_proj = nn.Linear(pkg_in_dim, hidden_dim)
        self.cve_proj = nn.Linear(cve_in_dim, hidden_dim)
        self.author_proj = nn.Linear(author_in_dim, hidden_dim)

        conv_spec = lambda in_d, out_d: GATConv(in_d, out_d, heads=heads, add_self_loops=False)
        self.conv1 = HeteroConv({
            ("Package", "dependsOn", "Package"): conv_spec(hidden_dim, hidden_dim // heads),
            ("Package", "hasVulnerability", "CVE"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Package", "maintainedBy", "Author"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("CVE", "introducedBy", "Author"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Package", "rev_dependsOn", "Package"): conv_spec(hidden_dim, hidden_dim // heads),
            ("CVE", "rev_hasVulnerability", "Package"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Author", "rev_maintainedBy", "Package"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Author", "rev_introducedBy", "CVE"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
        }, aggr="sum")

        self.conv2 = HeteroConv({
            ("Package", "dependsOn", "Package"): conv_spec(hidden_dim, hidden_dim // heads),
            ("Package", "hasVulnerability", "CVE"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Package", "maintainedBy", "Author"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("CVE", "introducedBy", "Author"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Package", "rev_dependsOn", "Package"): conv_spec(hidden_dim, hidden_dim // heads),
            ("CVE", "rev_hasVulnerability", "Package"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Author", "rev_maintainedBy", "Package"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
            ("Author", "rev_introducedBy", "CVE"): conv_spec((hidden_dim, hidden_dim), hidden_dim // heads),
        }, aggr="sum")

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x_dict, edge_index_dict):
        h_dict = {
            "Package": F.relu(self.pkg_proj(x_dict["Package"])),
            "CVE": F.relu(self.cve_proj(x_dict["CVE"])),
            "Author": F.relu(self.author_proj(x_dict["Author"])),
        }
        edge_dict_full = with_reverse_edges(edge_index_dict)
        h1 = self.conv1(h_dict, edge_dict_full)
        h1 = {k: F.relu(v) for k, v in h1.items()}
        h2 = self.conv2(h1, edge_dict_full)
        pkg_emb = h2["Package"]
        risk_preds = self.classifier(pkg_emb).squeeze(-1)
        return risk_preds, pkg_emb

def compute_pairwise_ranking_loss(preds, targets, mask, max_pairs=5000):
    p = preds[mask]
    t = targets[mask]
    n = len(p)
    if n < 2:
        return torch.tensor(0.0, device=preds.device)
    idx_i = torch.randint(0, n, (max_pairs,), device=preds.device)
    idx_j = torch.randint(0, n, (max_pairs,), device=preds.device)
    diff_t = t[idx_i] - t[idx_j]
    valid = torch.abs(diff_t) > 0.05
    if not valid.any():
        return torch.tensor(0.0, device=preds.device)
    sign = torch.sign(diff_t[valid])
    diff_p = p[idx_i[valid]] - p[idx_j[valid]]
    return F.soft_margin_loss(diff_p, sign)

def apply_dynamic_edge_dropout(edge_index_dict, p_mask=0.30):
    new_edges = copy.copy(edge_index_dict)
    cve_edge_key = ("Package", "hasVulnerability", "CVE")
    if cve_edge_key in new_edges:
        edges = new_edges[cve_edge_key]
        mask = torch.rand(edges.size(1), device=edges.device) > p_mask
        new_edges[cve_edge_key] = edges[:, mask]
    return new_edges

# Evaluation helper
def evaluate_model(model, data, seed=42):
    model.eval()
    with torch.no_grad():
        # 1. Clean graph forward -- dim 6 LIVE
        preds_clean_live, _ = model(data.x_dict, data.edge_index_dict)
        preds_live = preds_clean_live.cpu().numpy()

        pos_clean_live = preds_live[eligible_indices]
        neg_clean_live = preds_live[never_vuln_indices]
        y_clean = np.concatenate([np.ones(len(pos_clean_live)), np.zeros(len(neg_clean_live))])
        clean_auc_live = float(roc_auc_score(y_clean, np.concatenate([pos_clean_live, neg_clean_live])))

        # 2. Clean graph forward -- dim 6 ZEROED (global)
        x_dict_zeroed_glob = copy.copy(data.x_dict)
        pkg_x_zg = data["Package"].x.clone()
        pkg_x_zg[:, 6] = 0.0
        x_dict_zeroed_glob["Package"] = pkg_x_zg
        preds_clean_zg, _ = model(x_dict_zeroed_glob, data.edge_index_dict)
        preds_zg = preds_clean_zg.cpu().numpy()
        clean_auc_zeroed_global = float(roc_auc_score(y_clean, np.concatenate([preds_zg[eligible_indices], preds_zg[never_vuln_indices]])))

        # 3. Clean graph forward -- dim 6 ZEROED (eligible only)
        x_dict_zeroed_elig = copy.copy(data.x_dict)
        pkg_x_ze = data["Package"].x.clone()
        for idx in eligible_indices:
            pkg_x_ze[idx, 6] = 0.0
        x_dict_zeroed_elig["Package"] = pkg_x_ze
        preds_clean_ze, _ = model(x_dict_zeroed_elig, data.edge_index_dict)
        preds_ze = preds_clean_ze.cpu().numpy()
        clean_auc_zeroed_elig = float(roc_auc_score(y_clean, np.concatenate([preds_ze[eligible_indices], preds_ze[never_vuln_indices]])))

        # 4. Masked-50 evaluation
        rng = np.random.RandomState(seed)
        mask_flags = rng.random(len(eligible_pkg_ids)) < 0.50
        masked_pkg_ids = {eligible_pkg_ids[i] for i in range(len(eligible_pkg_ids)) if mask_flags[i]}
        masked_pkg_indices = [pkg_id_to_idx[pid] for pid in masked_pkg_ids if pid in pkg_id_to_idx]

        edges = data["Package", "hasVulnerability", "CVE"].edge_index
        src_nodes = edges[0].cpu().numpy()
        keep_mask = ~np.isin(src_nodes, masked_pkg_indices)

        masked_edge_index = copy.copy(data.edge_index_dict)
        masked_edge_index[("Package", "hasVulnerability", "CVE")] = edges[:, keep_mask].to(device)

        # 4a. Official / Notebook path: Dim 6 LIVE
        scores_m_live, _ = model(data.x_dict, masked_edge_index)
        scores_m_live = scores_m_live.cpu().numpy()
        pos_m_live = scores_m_live[masked_pkg_indices]
        neg_m_live = scores_m_live[never_vuln_indices]
        y_m = np.concatenate([np.ones(len(pos_m_live)), np.zeros(len(neg_m_live))])
        masked_auc_live = float(roc_auc_score(y_m, np.concatenate([pos_m_live, neg_m_live])))

        # 4b. Commandment 2 path: Dim 6 ZEROED for masked packages only
        x_dict_m_c2 = copy.copy(data.x_dict)
        pkg_x_c2 = data["Package"].x.clone()
        for idx in masked_pkg_indices:
            pkg_x_c2[idx, 6] = 0.0
        x_dict_m_c2["Package"] = pkg_x_c2
        scores_m_c2, _ = model(x_dict_m_c2, masked_edge_index)
        scores_m_c2 = scores_m_c2.cpu().numpy()
        masked_auc_c2 = float(roc_auc_score(y_m, np.concatenate([scores_m_c2[masked_pkg_indices], scores_m_c2[never_vuln_indices]])))

        # 4c. Dim 6 ZEROED globally
        x_dict_m_zg = copy.copy(data.x_dict)
        pkg_x_mzg = data["Package"].x.clone()
        pkg_x_mzg[:, 6] = 0.0
        x_dict_m_zg["Package"] = pkg_x_mzg
        scores_m_zg, _ = model(x_dict_m_zg, masked_edge_index)
        scores_m_zg = scores_m_zg.cpu().numpy()
        masked_auc_zg = float(roc_auc_score(y_m, np.concatenate([scores_m_zg[masked_pkg_indices], scores_m_zg[never_vuln_indices]])))

        # Spearman correlations on nonzero temporal cuts
        val_p = preds_live[data["Package"].val_mask.cpu().numpy()]
        val_t = data["Package"].y[data["Package"].val_mask].cpu().numpy()
        val_sp, _ = scipy_stats.spearmanr(val_t, val_p)

        test_p = preds_live[data["Package"].test_mask.cpu().numpy()]
        test_t = data["Package"].y[data["Package"].test_mask].cpu().numpy()
        test_sp, _ = scipy_stats.spearmanr(test_t, test_p)

    return {
        "clean_auc_live": clean_auc_live,
        "clean_auc_zeroed_global": clean_auc_zeroed_global,
        "clean_auc_zeroed_elig": clean_auc_zeroed_elig,
        "eligible_mean_live": float(pos_clean_live.mean()),
        "eligible_std_live": float(pos_clean_live.std()),
        "never_vuln_mean_live": float(neg_clean_live.mean()),
        "never_vuln_std_live": float(neg_clean_live.std()),
        "eligible_mean_zg": float(preds_zg[eligible_indices].mean()),
        "eligible_std_zg": float(preds_zg[eligible_indices].std()),
        "never_vuln_mean_zg": float(preds_zg[never_vuln_indices].mean()),
        "never_vuln_std_zg": float(preds_zg[never_vuln_indices].std()),
        "masked_auc_live": masked_auc_live,
        "masked_auc_c2": masked_auc_c2,
        "masked_auc_zg": masked_auc_zg,
        "val_spearman": float(val_sp),
        "test_spearman": float(test_sp),
    }

# 4. Training function
def train_run(total_epochs=100, run_name="v2.2_seed42_100ep"):
    print(f"\n=======================================================")
    print(f"  Starting Run: {run_name} ({total_epochs} epochs, CPU)")
    print(f"=======================================================")
    set_seed(SEED)
    model = VulnGATv2().to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)

    train_m = data["Package"].train_mask.to(device)
    val_m = data["Package"].val_mask.to(device)
    y_true = data["Package"].y.to(device)

    trajectory = []
    t_start = time.time()

    for epoch in range(total_epochs):
        model.train()
        optimizer.zero_grad()

        preds_clean, _ = model(data.x_dict, data.edge_index_dict)
        loss_mse = F.mse_loss(preds_clean[train_m], y_true[train_m])

        loss_rank = compute_pairwise_ranking_loss(preds_clean, y_true, train_m)
        loss_total = loss_mse + LAMBDA_RANK * loss_rank

        masked_edges = apply_dynamic_edge_dropout(data.edge_index_dict, P_MASK)
        preds_masked, _ = model(data.x_dict, masked_edges)
        loss_aux = F.mse_loss(preds_masked[train_m], preds_clean[train_m].detach())
        loss_total = loss_total + LAMBDA_AUX * loss_aux

        loss_total.backward()
        optimizer.step()

        # Validation on nonzero val cut
        model.eval()
        with torch.no_grad():
            vp, _ = model(data.x_dict, data.edge_index_dict)
            val_p = vp[val_m].cpu().numpy()
            val_t = y_true[val_m].cpu().numpy()
            val_sp, _ = scipy_stats.spearmanr(val_t, val_p)
            if np.isnan(val_sp):
                val_sp = -1.0

        entry = {
            "epoch": epoch,
            "loss_mse": float(loss_mse.item()),
            "loss_rank": float(loss_rank.item()),
            "loss_aux": float(loss_aux.item()),
            "loss_total": float(loss_total.item()),
            "val_spearman": float(val_sp),
        }
        trajectory.append(entry)

        if epoch in [0, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99, 149, 199, 249, 299] or epoch == total_epochs - 1:
            print(f"  ep {epoch:3d} ({time.time()-t_start:5.1f}s): mse={entry['loss_mse']:.4f} rank={entry['loss_rank']:.4f} aux={entry['loss_aux']:.4f} tot={entry['loss_total']:.4f} val_sp={entry['val_spearman']:.4f}")

    wall_time = time.time() - t_start
    print(f"\nTraining completed in {wall_time:.1f}s ({wall_time/60:.2f} min).")

    # Save FINAL checkpoint
    ckpt_path = CKPT_DIR / f"{run_name}_final.pt"
    torch.save(model.state_dict(), ckpt_path)
    print(f"Saved final checkpoint to {ckpt_path}")

    # Evaluate final checkpoint
    eval_metrics = evaluate_model(model, data, seed=SEED)
    eval_metrics["wall_time_sec"] = wall_time
    eval_metrics["total_epochs"] = total_epochs
    eval_metrics["checkpoint"] = str(ckpt_path)

    print("\n--- Evaluation Results ---")
    print(f"  Clean AUC (dim 6 LIVE):           {eval_metrics['clean_auc_live']:.4f}")
    print(f"  Clean AUC (dim 6 ZEROED global):  {eval_metrics['clean_auc_zeroed_global']:.4f}")
    print(f"  Clean AUC (dim 6 ZEROED elig):    {eval_metrics['clean_auc_zeroed_elig']:.4f}")
    print(f"  Eligible mean (live):             {eval_metrics['eligible_mean_live']:.4f} +/- {eval_metrics['eligible_std_live']:.4f}")
    print(f"  Never-vuln mean (live):           {eval_metrics['never_vuln_mean_live']:.4f} +/- {eval_metrics['never_vuln_std_live']:.4f}")
    print(f"  Eligible mean (zeroed global):    {eval_metrics['eligible_mean_zg']:.4f} +/- {eval_metrics['eligible_std_zg']:.4f}")
    print(f"  Never-vuln mean (zeroed global):  {eval_metrics['never_vuln_mean_zg']:.4f} +/- {eval_metrics['never_vuln_std_zg']:.4f}")
    print(f"  Masked-50 AUC (LIVE / official):  {eval_metrics['masked_auc_live']:.4f}")
    print(f"  Masked-50 AUC (C2 zeroed masked): {eval_metrics['masked_auc_c2']:.4f}")
    print(f"  Masked-50 AUC (ZEROED global):    {eval_metrics['masked_auc_zg']:.4f}")
    print(f"  Val Spearman (nonzero cut):       {eval_metrics['val_spearman']:.4f}")
    print(f"  Test Spearman (nonzero cut):      {eval_metrics['test_spearman']:.4f}")

    return {
        "run_name": run_name,
        "metrics": eval_metrics,
        "trajectory": trajectory,
    }

def main():
    results = {}

    # Step 3 & 4: 100-epoch population-fixed run
    res_100 = train_run(total_epochs=100, run_name="v22_full_v2_p30_s42_100ep")
    results["run_100ep"] = res_100

    # Step 5: Optional exploratory 300-epoch run
    res_300 = train_run(total_epochs=300, run_name="v22_exploratory_p30_s42_300ep")
    results["run_300ep_exploratory"] = res_300

    with open(RESULTS_OUT, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[COMPLETE] All diagnostic runs finished. Results saved to {RESULTS_OUT}")

if __name__ == "__main__":
    main()
