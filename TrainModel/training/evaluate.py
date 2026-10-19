"""
training/evaluate.py — Evaluation Metrics & CISA KEV Benchmark for VulnChain

Implements the evaluation metrics defined in Section 11 of VULNCHAIN_DESIGN_v1.0.md:
1. MAE (Mean Absolute Error) against continuous VPSS labels
2. Spearman's rho (Rank correlation with VPSS labels)
3. Ranking Accuracy (% of pairs correctly ordered by risk)
4. Precision@K on CISA KEV Ground Truth catalog (confirmed exploited in the wild)
"""

import torch
import numpy as np

# Curated CISA KEV / Confirmed in-the-wild supply chain attack targets (Section 11.2)
CISA_KEV_GROUND_TRUTH = {
    "log4j-core",
    "event-stream",
    "ua-parser-js",
    "node-ipc",
    "minimist",
    "lodash",
    "handlebars",
    "colors",
    "faker",
    "flatmap-stream",
    "axios",
    "express"
}


def compute_mae(predictions: np.ndarray, targets: np.ndarray) -> float:
    """Mean Absolute Error."""
    return float(np.mean(np.abs(predictions - targets)))


def _rank_data(a: np.ndarray) -> np.ndarray:
    """
    Computes fractional ranks (matching scipy.stats.rankdata) using pure NumPy.
    Handles ties by assigning the average rank.
    """
    sorter = np.argsort(a, kind="mergesort")
    inv = np.empty_like(sorter)
    inv[sorter] = np.arange(len(a))

    a_sorted = a[sorter]
    obs = np.r_[True, a_sorted[1:] != a_sorted[:-1]]
    dense = obs.cumsum()[inv]

    count = np.r_[np.nonzero(obs)[0], len(a)]
    return 0.5 * (count[dense] + count[dense - 1] + 1)


def compute_spearman_rho(predictions: np.ndarray, targets: np.ndarray) -> float:
    """
    Spearman rank correlation coefficient (rho) using pure NumPy.
    Returns rho in [-1.0, 1.0].
    """
    if len(np.unique(predictions)) <= 1 or len(np.unique(targets)) <= 1:
        return 0.0
    rx = _rank_data(predictions)
    ry = _rank_data(targets)
    corr_matrix = np.corrcoef(rx, ry)
    return float(corr_matrix[0, 1])


def compute_ranking_accuracy(predictions: np.ndarray, targets: np.ndarray, 
                             max_samples: int = 20000, seed: int = 42) -> float:
    """
    Computes the percentage of discordant target pairs (y_i > y_j)
    that are correctly ordered by the model (pred_i > pred_j).
    """
    np.random.seed(seed)
    n = len(targets)
    if n < 2:
        return 1.0

    # Sample random pairs
    i_idx = np.random.randint(0, n, size=max_samples)
    j_idx = np.random.randint(0, n, size=max_samples)

    # Filter out same indices
    valid = (i_idx != j_idx) & (np.abs(targets[i_idx] - targets[j_idx]) > 1e-4)
    i_valid = i_idx[valid]
    j_valid = j_idx[valid]

    if len(i_valid) == 0:
        return 1.0

    # True ordering: target_i > target_j
    swap = targets[i_valid] < targets[j_valid]
    i_valid[swap], j_valid[swap] = j_valid[swap], i_valid[swap]

    # Model concordance: pred_i > pred_j
    correct = (predictions[i_valid] > predictions[j_valid])
    # Give half credit for ties
    ties = (np.abs(predictions[i_valid] - predictions[j_valid]) < 1e-6)
    
    acc = (np.sum(correct) + 0.5 * np.sum(ties)) / len(i_valid)
    return float(acc)


def compute_precision_at_k(pkg_ids: list[str], predictions: np.ndarray, k: int = 10) -> tuple[float, list[dict]]:
    """
    Precision@K against CISA KEV catalog (Section 11.1).
    Checks how many of the top-K highest-scored packages match confirmed exploited vulnerabilities.
    """
    sorted_indices = np.argsort(-predictions)
    top_k_indices = sorted_indices[:k]

    hits = 0
    top_k_results = []
    for rank, idx in enumerate(top_k_indices, 1):
        pkg_id = pkg_ids[idx]
        base_name = pkg_id.rsplit("@", 1)[0]
        is_kev = any(base_name == kev_name or base_name.endswith("/" + kev_name) for kev_name in CISA_KEV_GROUND_TRUTH)
        if is_kev:
            hits += 1
        top_k_results.append({
            "rank": rank,
            "package": pkg_id,
            "risk_score": float(predictions[idx]),
            "in_cisa_kev": is_kev
        })

    precision = hits / k if k > 0 else 0.0
    return precision, top_k_results


def evaluate_model(model, data, mask, pkg_ids: list[str], device: torch.device, k: int = 10) -> dict:
    """
    Evaluates VulnGAT on a given split mask (train, val, or test).
    
    Returns:
        dict of computed metrics and top-K inspection list
    """
    model.eval()
    with torch.no_grad():
        x_dict = {ntype: data[ntype].x.to(device) for ntype in data.node_types}
        edge_index_dict = {
            (src, rel, tgt): data[src, rel, tgt].edge_index.to(device)
            for src, rel, tgt in data.edge_types
        }

        # Predict risk scores
        all_preds = model(x_dict, edge_index_dict).cpu().numpy()
        all_targets = data["Package"].y.numpy()

        split_mask_np = mask.cpu().numpy() if isinstance(mask, torch.Tensor) else mask
        split_preds = all_preds[split_mask_np]
        split_targets = all_targets[split_mask_np]
        split_pkg_ids = [pkg_ids[i] for i in range(len(pkg_ids)) if split_mask_np[i]]

        mae = compute_mae(split_preds, split_targets)
        spearman_rho = compute_spearman_rho(split_preds, split_targets)
        rank_acc = compute_ranking_accuracy(split_preds, split_targets)
        prec_at_k, top_k = compute_precision_at_k(split_pkg_ids, split_preds, k=k)

        return {
            "mae": mae,
            "spearman_rho": spearman_rho,
            "ranking_accuracy": rank_acc,
            "precision_at_k": prec_at_k,
            "top_k_packages": top_k,
            "predictions": split_preds,
            "targets": split_targets
        }
