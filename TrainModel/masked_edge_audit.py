
"""
masked_edge_audit.py -- Masked-Edge Model-Contribution Audit for VulnGAT

Rigorously measures whether VulnGAT contributes anything beyond BFS traversal
or label propagation by:
  1. Masking fractions of hasVulnerability edges from the graph
  2. Re-running inference on the masked graph
  3. Comparing against three baselines (BFS-masked, label-prop, feature-shuffle)
  4. Reporting AUC, Hits@10, MRR with bootstrap CIs, stratified by shared/orphaned CVEs

Critical design decisions (each fixing a specific flaw in the naive version):
  - Scores against own(P) VPSS component only, not full VPSS (avoids descendant leakage)
  - Three-baseline ladder, not random (BFS is the real floor, not chance)
  - Stratifies by shared/orphaned CVEs (orphaned = no path for any mechanism)
  - Bypasses analyze_project.py's calibration cap (would clamp masked = clean)
  - Uses repo-level split, not random node split
  - Pre-registered seeds, mask ratios, metrics, and eligibility filters
"""

import os
import sys
import json
import copy
import time
import warnings
from collections import defaultdict, deque

import numpy as np
import torch

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.model.vulngat import VulnGAT
from training.dataset import load_vulnchain_dataset

# ===============================================================================
# PRE-REGISTRATION CONFIG -- locked before first run, do not tune after results
# ===============================================================================

SEED = 42
MASK_RATIOS = [0.10, 0.30, 0.50]
OWN_VPSS_THRESHOLD = 0.70       # own(P) / VPSS(P) >= 0.7 to be eligible
BOOTSTRAP_ITERS = 1000
BOOTSTRAP_ALPHA = 0.05          # 95% confidence intervals
HITS_K = 10
# Env-var overrides mirror training/dataset.py so this one script audits
# either the 9-repo pilot or the Phase-4 51-repo artifacts without edits.
MODEL_PATH = os.environ.get("MODEL_PATH", "models/vulngat_trained.pt")
GRAPH_PATH = os.environ.get("GRAPH_FILE", "vulnchain_graph.json")
LABELS_PATH = os.environ.get("LABELS_FILE", "vpss_labels.json")
SPLIT_PATH = os.environ.get("REPO_SPLIT_FILE", "repo_split_mapping.json")
OUTPUT_JSON = os.environ.get("AUDIT_OUT", "masked_edge_audit_results.json")


# ===============================================================================
# 1. OWN-VPSS DECOMPOSITION
# ===============================================================================

def compute_own_vpss(graph_json: dict, vpss_labels: dict) -> dict:
    """
    Reconstructs the own(P) component of VPSS for each package.

    own(P) captures the risk contribution from P's *direct* hasVulnerability
    edges. The deterministic formula is:
        own(P) = sum over direct CVEs of (CVSS/10 * 0.7^0 * exposure)
    where depth=0 for own CVEs, so decay factor = 1.0.

    Since the labels store normalized VPSS but not the own/descendant split,
    we approximate:
        own_raw(P) = sum of CVSS/10 for each of P's direct CVE edges
        own_ratio(P) = own_raw(P) / raw_sum(P)  [from labels]
        own_vpss(P) = own_ratio(P) * VPSS(P)

    For packages with raw_sum == 0 or no CVEs, own_vpss = 0.

    Returns:
        dict: {pkg_id: {"own_vpss": float, "own_ratio": float, "own_raw": float,
                         "direct_cves": [cve_ids], "full_vpss": float}}
    """
    # Map package -> list of direct CVE edges
    pkg_to_cves = defaultdict(list)
    for edge in graph_json["edges"]["hasVulnerability"]:
        pkg_to_cves[edge["source"]].append(edge["target"])

    # Map CVE id -> CVSS score
    cve_cvss = {}
    for cve_node in graph_json["nodes"]["CVE"]:
        cvss_raw = cve_node.get("cvss_score")
        cvss_val = float(cvss_raw) if cvss_raw is not None else 0.0
        cve_cvss[cve_node["id"]] = cvss_val

    result = {}
    for pkg_id, cve_list in pkg_to_cves.items():
        label_entry = vpss_labels.get(pkg_id, {})
        full_vpss = float(label_entry.get("vpss", 0.0))
        raw_sum = float(label_entry.get("raw_sum", 0.0))

        # Own raw contribution: sum of CVSS/10 for direct CVEs (depth=0, decay=1.0)
        own_raw = sum(cve_cvss.get(cve_id, 0.0) / 10.0 for cve_id in cve_list)

        if raw_sum > 1e-9:
            own_ratio = min(own_raw / raw_sum, 1.0)
        elif own_raw > 0:
            own_ratio = 1.0  # Package has own CVEs but raw_sum is zero/missing
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


# ===============================================================================
# 2. ELIGIBLE PACKAGE SELECTION
# ===============================================================================

def select_eligible_packages(own_vpss_data: dict, threshold: float = OWN_VPSS_THRESHOLD) -> list:
    """
    Filters to packages where own-CVE contribution dominates VPSS.

    Only packages with own_ratio >= threshold are eligible for masking eval,
    ensuring the masked signal (own CVE) is the dominant component of the
    package's label, not the descendant term which survives masking.

    If threshold filtering leaves fewer than 15 packages, relaxes to 0.3
    with a printed warning.

    Returns:
        list of pkg_ids that pass the eligibility filter
    """
    eligible = [
        pkg_id for pkg_id, data in own_vpss_data.items()
        if data["own_ratio"] >= threshold and data["full_vpss"] > 1e-6
    ]

    if len(eligible) < 15:
        warnings.warn(
            f"Only {len(eligible)} packages pass own_ratio >= {threshold:.2f}. "
            f"Relaxing threshold to 0.30 for statistical power."
        )
        eligible = [
            pkg_id for pkg_id, data in own_vpss_data.items()
            if data["own_ratio"] >= 0.30 and data["full_vpss"] > 1e-6
        ]

    return eligible


# ===============================================================================
# 3. EDGE MASKING
# ===============================================================================

def apply_edge_mask(
    data,
    eligible_pkg_ids: list,
    pkg_id_to_idx: dict,
    graph_json: dict,
    cve_id_to_idx: dict,
    mask_ratio: float,
    seed: int,
) -> tuple:
    """
    Removes mask_ratio fraction of hasVulnerability edges for eligible packages.

    For each eligible package, independently decides (with probability mask_ratio)
    whether to mask ALL of that package's hasVulnerability edges. This simulates
    a package having no known CVE association.

    Also classifies each masked package's CVEs as:
      - 'shared': CVE still attached to at least one other package after masking
      - 'orphaned': CVE has no remaining hasVulnerability edges after masking

    Returns:
        masked_data: deep-copied HeteroData with edges removed
        masked_pkg_indices: set of masked package node indices
        masked_pkg_to_cves: dict {pkg_idx: [cve_idx, ...]} -- deleted CVE edges
        stratum_labels: dict {pkg_idx: 'shared' | 'orphaned'}
    """
    rng = np.random.RandomState(seed)

    # Decide which eligible packages to mask
    mask_flags = rng.random(len(eligible_pkg_ids)) < mask_ratio
    masked_pkg_ids = set()
    for i, pkg_id in enumerate(eligible_pkg_ids):
        if mask_flags[i]:
            masked_pkg_ids.add(pkg_id)

    # Ensure at least 3 packages are masked for any meaningful eval
    if len(masked_pkg_ids) < 3 and len(eligible_pkg_ids) >= 3:
        forced = rng.choice(len(eligible_pkg_ids), size=3, replace=False)
        for idx in forced:
            masked_pkg_ids.add(eligible_pkg_ids[idx])

    # Build set of masked package indices and their CVE connections
    masked_pkg_indices = set()
    masked_pkg_to_cves = {}  # pkg_idx -> [cve_idx]

    pkg_to_cves_graph = defaultdict(list)
    for edge in graph_json["edges"]["hasVulnerability"]:
        pkg_to_cves_graph[edge["source"]].append(edge["target"])

    for pkg_id in masked_pkg_ids:
        if pkg_id not in pkg_id_to_idx:
            continue
        pkg_idx = pkg_id_to_idx[pkg_id]
        masked_pkg_indices.add(pkg_idx)
        cve_indices = []
        for cve_id in pkg_to_cves_graph.get(pkg_id, []):
            if cve_id in cve_id_to_idx:
                cve_indices.append(cve_id_to_idx[cve_id])
        masked_pkg_to_cves[pkg_idx] = cve_indices

    # Now filter the edge_index tensor
    has_vuln_key = ("Package", "hasVulnerability", "CVE")
    original_edge_index = data[has_vuln_key].edge_index  # [2, E]

    # Build mask: keep edges NOT from masked packages
    num_edges = original_edge_index.size(1)
    keep_mask = torch.ones(num_edges, dtype=torch.bool)
    for col_idx in range(num_edges):
        src_idx = original_edge_index[0, col_idx].item()
        if src_idx in masked_pkg_indices:
            keep_mask[col_idx] = False

    # Deep copy data and apply mask
    masked_data = copy.deepcopy(data)
    masked_data[has_vuln_key].edge_index = original_edge_index[:, keep_mask].clone()

    # Commandment 2 (VULNCHAIN_LESSONS_LEARNED): zero Package feature dim 6
    # (has_known_cve_history) for masked packages. Otherwise the model reads
    # CVE history straight from its features while the edges are hidden --
    # the exact backdoor that invalidated the first audit attempt.
    pkg_x = masked_data["Package"].x.clone()
    for pkg_idx in masked_pkg_indices:
        pkg_x[pkg_idx, 6] = 0.0
    masked_data["Package"].x = pkg_x

    # Classify strata: shared vs orphaned
    # After masking, which CVE nodes still have at least one hasVulnerability edge?
    surviving_edge_index = masked_data[has_vuln_key].edge_index
    surviving_cve_indices = set(surviving_edge_index[1].tolist()) if surviving_edge_index.size(1) > 0 else set()

    stratum_labels = {}
    for pkg_idx, cve_list in masked_pkg_to_cves.items():
        # If ANY of this package's deleted CVEs still appear in surviving edges -> shared
        any_shared = any(cve_idx in surviving_cve_indices for cve_idx in cve_list)
        stratum_labels[pkg_idx] = "shared" if any_shared else "orphaned"

    return masked_data, masked_pkg_indices, masked_pkg_to_cves, stratum_labels


# ===============================================================================
# 4. MODEL INFERENCE (raw, no calibration cap)
# ===============================================================================

def run_model_inference(model: VulnGAT, data, device: torch.device) -> np.ndarray:
    """
    Raw model forward pass on the given graph data.
    Returns uncapped sigmoid scores -- deliberately bypasses the
    analyze_project.py min(score, 0.08) calibration cap.
    """
    model.eval()
    x_dict = {ntype: data[ntype].x.to(device) for ntype in data.node_types}
    edge_index_dict = {
        (src, rel, tgt): data[src, rel, tgt].edge_index.to(device)
        for src, rel, tgt in data.edge_types
    }
    with torch.no_grad():
        scores = model(x_dict, edge_index_dict).cpu().numpy()
    return scores


# ===============================================================================
# 5. BFS BASELINE
# ===============================================================================

def run_bfs_baseline(
    graph_json: dict,
    masked_pkg_ids: set,
    vpss_labels: dict,
    pkg_id_to_idx: dict,
    num_packages: int,
) -> np.ndarray:
    """
    Re-computes the deterministic VPSS formula on the masked graph.

    The VPSS formula is: VPSS(P) = normalize(sum over reachable CVEs of
        CVSS/10 * 0.7^depth * exposure)

    For masked packages, their own CVE edges are deleted, so own(P) = 0;
    but descendant contributions via dependsOn edges are still intact.

    This is the minimum baseline the model must beat -- it exactly replicates
    what a BFS script can recover from the masked graph.
    """
    # Build adjacency: package -> packages it depends on
    depends_on = defaultdict(set)
    for edge in graph_json["edges"]["dependsOn"]:
        depends_on[edge["source"]].add(edge["target"])

    # Build surviving hasVulnerability map (excluding masked packages)
    pkg_to_cves_surviving = defaultdict(list)
    cve_cvss = {}
    for cve_node in graph_json["nodes"]["CVE"]:
        cvss_raw = cve_node.get("cvss_score")
        cve_cvss[cve_node["id"]] = float(cvss_raw) if cvss_raw is not None else 0.0

    for edge in graph_json["edges"]["hasVulnerability"]:
        pkg_id = edge["source"]
        if pkg_id not in masked_pkg_ids:
            pkg_to_cves_surviving[pkg_id].append(edge["target"])

    # For each package, BFS through dependsOn to find reachable CVEs
    all_pkg_ids = [node["id"] for node in graph_json["nodes"]["Package"]]
    bfs_scores = np.zeros(num_packages, dtype=np.float32)

    for pkg_id in all_pkg_ids:
        if pkg_id not in pkg_id_to_idx:
            continue
        idx = pkg_id_to_idx[pkg_id]

        # BFS from this package through dependsOn edges
        visited = set()
        queue = deque()
        queue.append((pkg_id, 0))  # (node, depth from this package)
        visited.add(pkg_id)
        raw_sum = 0.0

        while queue:
            current, depth = queue.popleft()

            # Collect CVEs from current node (if it has surviving edges)
            for cve_id in pkg_to_cves_surviving.get(current, []):
                cvss = cve_cvss.get(cve_id, 0.0) / 10.0
                decay = 0.7 ** depth
                raw_sum += cvss * decay

            # Traverse dependsOn edges
            for dep in depends_on.get(current, set()):
                if dep not in visited:
                    visited.add(dep)
                    queue.append((dep, depth + 1))

        # Normalize: clamp to [0, 1] using same approach as labels
        # The labels use: vpss = raw_sum / normalization_constant
        # We use a reasonable cap -- max raw_sum in the dataset
        bfs_scores[idx] = raw_sum

    # Normalize to [0, 1] range using max observed raw_sum from labels
    max_raw = max(
        (float(v.get("raw_sum", 0.0)) for v in vpss_labels.values()),
        default=1.0
    )
    if max_raw > 0:
        bfs_scores = np.clip(bfs_scores / max_raw, 0.0, 1.0)

    return bfs_scores


# ===============================================================================
# 6. LABEL PROPAGATION BASELINE
# ===============================================================================

def run_label_prop_baseline(
    data,
    vpss_labels: dict,
    pkg_id_to_idx: dict,
    idx_to_pkg_id: dict,
    num_packages: int,
) -> np.ndarray:
    """
    Simple label-propagation baseline: each package's score = mean VPSS
    of its immediate graph neighbors (connected by any edge type).

    For packages with no neighbors, falls back to the global mean VPSS.
    This tests "does VulnGAT beat simple structural averaging?"
    """
    # Build adjacency from all edge types
    neighbors = defaultdict(set)

    for edge_type_key in data.edge_types:
        edge_index = data[edge_type_key].edge_index
        src_type = edge_type_key[0]
        tgt_type = edge_type_key[2]

        # Only count edges where both endpoints are Package nodes
        if src_type == "Package" and tgt_type == "Package":
            for col in range(edge_index.size(1)):
                s = edge_index[0, col].item()
                t = edge_index[1, col].item()
                neighbors[s].add(t)
                neighbors[t].add(s)  # undirected for label prop
        elif src_type == "Package":
            # Package -> X edge: package has this as a neighbor characteristic
            # For label prop, we only propagate VPSS, which is defined on Package nodes
            # So cross-type edges don't directly contribute label values
            # But we use dependsOn edges (Package->Package) above
            pass

    # Also add Package<->Package edges from hasVulnerability via shared CVEs
    # (two packages sharing a CVE are structurally linked)
    cve_to_pkgs = defaultdict(set)
    has_vuln_key = ("Package", "hasVulnerability", "CVE")
    if has_vuln_key in data.edge_types:
        ei = data[has_vuln_key].edge_index
        for col in range(ei.size(1)):
            pkg_idx = ei[0, col].item()
            cve_idx = ei[1, col].item()
            cve_to_pkgs[cve_idx].add(pkg_idx)
    for cve_idx, pkg_set in cve_to_pkgs.items():
        pkg_list = list(pkg_set)
        for i in range(len(pkg_list)):
            for j in range(i + 1, len(pkg_list)):
                neighbors[pkg_list[i]].add(pkg_list[j])
                neighbors[pkg_list[j]].add(pkg_list[i])

    # Get VPSS labels as array
    vpss_array = np.zeros(num_packages, dtype=np.float32)
    for pkg_id, entry in vpss_labels.items():
        if pkg_id in pkg_id_to_idx:
            vpss_array[pkg_id_to_idx[pkg_id]] = float(entry.get("vpss", 0.0))

    global_mean = vpss_array.mean()

    # Compute label-prop scores
    lp_scores = np.zeros(num_packages, dtype=np.float32)
    for idx in range(num_packages):
        nbrs = neighbors.get(idx, set())
        if len(nbrs) > 0:
            lp_scores[idx] = np.mean([vpss_array[n] for n in nbrs])
        else:
            lp_scores[idx] = global_mean

    return lp_scores


# ===============================================================================
# 7. FEATURE-SHUFFLE ABLATION
# ===============================================================================

def run_feature_shuffle_ablation(
    model: VulnGAT, data, device: torch.device, seed: int
) -> np.ndarray:
    """
    Randomly permutes the 768-dim CVE embeddings across CVE nodes, then
    re-runs model inference on the (masked) graph.

    If model scores for masked packages don't drop relative to the
    unshuffled run, the CVE embeddings were not the mechanism producing
    the score -- the model was relying on structural features only.

    Only shuffles the embedding portion (dims 1:769), preserves the CVSS
    score (dim 0) to isolate semantic embedding contribution.
    """
    rng = np.random.RandomState(seed)

    # Deep copy to avoid modifying the input
    shuffled_data = copy.deepcopy(data)
    cve_features = shuffled_data["CVE"].x.clone()

    num_cves = cve_features.size(0)
    if num_cves > 1:
        # Shuffle embedding portion (columns 1:) across CVE nodes
        perm = rng.permutation(num_cves)
        cve_features[:, 1:] = cve_features[perm, 1:]

    shuffled_data["CVE"].x = cve_features

    return run_model_inference(model, shuffled_data, device)


# ===============================================================================
# 8. AUC COMPUTATION (stratified)
# ===============================================================================

def compute_auc(
    scores: np.ndarray,
    positive_indices: list,
    negative_indices: list,
) -> float:
    """
    Computes AUC (area under ROC) for a binary classification:
      positive = masked-vulnerable packages
      negative = never-vulnerable packages

    Uses the Wilcoxon-Mann-Whitney statistic (equivalent to AUC):
      AUC = P(score(positive) > score(negative))

    Returns 0.5 if either class is empty.
    """
    if len(positive_indices) == 0 or len(negative_indices) == 0:
        return 0.5

    pos_scores = scores[positive_indices]
    neg_scores = scores[negative_indices]

    # Wilcoxon-Mann-Whitney
    n_pos = len(pos_scores)
    n_neg = len(neg_scores)

    count = 0.0
    for ps in pos_scores:
        count += np.sum(ps > neg_scores) + 0.5 * np.sum(ps == neg_scores)

    auc = count / (n_pos * n_neg)
    return float(auc)


def compute_auc_stratified(
    scores: np.ndarray,
    masked_pkg_indices: set,
    never_vuln_indices: list,
    stratum_labels: dict,
) -> dict:
    """
    AUC stratified by shared vs orphaned CVEs.
    Returns dict: {
        "overall": float, "shared": float, "orphaned": float,
        "n_shared": int, "n_orphaned": int
    }
    """
    shared_indices = [idx for idx in masked_pkg_indices if stratum_labels.get(idx) == "shared"]
    orphaned_indices = [idx for idx in masked_pkg_indices if stratum_labels.get(idx) == "orphaned"]

    result = {
        "overall": compute_auc(scores, list(masked_pkg_indices), never_vuln_indices),
        "shared": compute_auc(scores, shared_indices, never_vuln_indices),
        "orphaned": compute_auc(scores, orphaned_indices, never_vuln_indices),
        "n_shared": len(shared_indices),
        "n_orphaned": len(orphaned_indices),
        "n_never_vuln": len(never_vuln_indices),
    }
    return result


# ===============================================================================
# 9. HITS@K / MRR
# ===============================================================================

def compute_hits_at_k_mrr(
    model: VulnGAT,
    data,
    masked_pkg_to_cves: dict,
    device: torch.device,
    k: int = HITS_K,
) -> dict:
    """
    For each masked package P, uses the model's embedding space to rank all
    CVE nodes by cosine similarity to P's post-masking representation.

    Checks whether the true (deleted) CVE appears in top-K (Hits@K) and at
    what rank (MRR = mean reciprocal rank).

    Also computes random-ranking MRR as a sanity floor.
    """
    if len(masked_pkg_to_cves) == 0:
        return {"hits_at_k": 0.0, "mrr": 0.0, "random_mrr": 0.0, "n_queries": 0}

    model.eval()
    x_dict = {ntype: data[ntype].x.to(device) for ntype in data.node_types}
    edge_index_dict = {
        (src, rel, tgt): data[src, rel, tgt].edge_index.to(device)
        for src, rel, tgt in data.edge_types
    }

    with torch.no_grad():
        h_dict = model.encode(x_dict, edge_index_dict)

    pkg_embeddings = h_dict["Package"].cpu()   # [N_pkg, 128]
    cve_embeddings = h_dict["CVE"].cpu()       # [N_cve, 128]

    # L2 normalize for cosine similarity
    pkg_norm = torch.nn.functional.normalize(pkg_embeddings, dim=1)
    cve_norm = torch.nn.functional.normalize(cve_embeddings, dim=1)

    num_cves = cve_norm.size(0)
    random_mrr = 1.0 / num_cves if num_cves > 0 else 0.0

    hits = 0
    reciprocal_ranks = []
    n_queries = 0

    for pkg_idx, cve_indices in masked_pkg_to_cves.items():
        if len(cve_indices) == 0:
            continue

        # Cosine similarity between this package and all CVEs
        pkg_vec = pkg_norm[pkg_idx].unsqueeze(0)  # [1, 128]
        sims = torch.mm(pkg_vec, cve_norm.t()).squeeze(0)  # [N_cve]

        # Rank CVEs by descending similarity
        ranked = torch.argsort(sims, descending=True).tolist()

        # Check each true CVE
        for true_cve_idx in cve_indices:
            n_queries += 1
            if true_cve_idx in ranked[:k]:
                hits += 1
            rank_pos = ranked.index(true_cve_idx) + 1  # 1-indexed
            reciprocal_ranks.append(1.0 / rank_pos)

    hits_at_k = hits / n_queries if n_queries > 0 else 0.0
    mrr = float(np.mean(reciprocal_ranks)) if reciprocal_ranks else 0.0

    return {
        "hits_at_k": hits_at_k,
        "mrr": mrr,
        "random_mrr": random_mrr,
        "n_queries": n_queries,
    }


# ===============================================================================
# 10. BOOTSTRAP CONFIDENCE INTERVALS
# ===============================================================================

def bootstrap_ci(
    scores: np.ndarray,
    positive_indices: list,
    negative_indices: list,
    metric_fn,
    n_iters: int = BOOTSTRAP_ITERS,
    alpha: float = BOOTSTRAP_ALPHA,
    seed: int = SEED,
) -> tuple:
    """
    Bootstrap confidence interval for AUC (or any metric computed on
    positive vs negative index sets).

    Resamples with replacement from both positive and negative index sets,
    computes metric on each resample, returns (CI_low, CI_high).
    """
    rng = np.random.RandomState(seed + 7)  # offset seed to avoid correlation
    pos_arr = np.array(positive_indices)
    neg_arr = np.array(negative_indices)

    if len(pos_arr) == 0 or len(neg_arr) == 0:
        return (0.0, 0.0)

    values = []
    for _ in range(n_iters):
        pos_sample = rng.choice(pos_arr, size=len(pos_arr), replace=True).tolist()
        neg_sample = rng.choice(neg_arr, size=len(neg_arr), replace=True).tolist()
        val = metric_fn(scores, pos_sample, neg_sample)
        values.append(val)

    values = sorted(values)
    lo = values[int(n_iters * alpha / 2)]
    hi = values[int(n_iters * (1 - alpha / 2))]
    return (float(lo), float(hi))


def bootstrap_ci_mrr(
    reciprocal_ranks: list,
    n_iters: int = BOOTSTRAP_ITERS,
    alpha: float = BOOTSTRAP_ALPHA,
    seed: int = SEED,
) -> tuple:
    """Bootstrap CI for MRR (a simple mean of reciprocal ranks)."""
    if len(reciprocal_ranks) == 0:
        return (0.0, 0.0)
    rng = np.random.RandomState(seed + 13)
    arr = np.array(reciprocal_ranks)
    values = []
    for _ in range(n_iters):
        sample = rng.choice(arr, size=len(arr), replace=True)
        values.append(float(np.mean(sample)))
    values = sorted(values)
    lo = values[int(n_iters * alpha / 2)]
    hi = values[int(n_iters * (1 - alpha / 2))]
    return (float(lo), float(hi))


# ===============================================================================
# 11. FULL HITS@K/MRR WITH RECIPROCAL RANKS (for bootstrap)
# ===============================================================================

def compute_hits_mrr_detailed(
    model: VulnGAT,
    data,
    masked_pkg_to_cves: dict,
    device: torch.device,
    k: int = HITS_K,
) -> dict:
    """
    Like compute_hits_at_k_mrr but also returns the raw reciprocal ranks
    list for bootstrap CI computation.
    """
    if len(masked_pkg_to_cves) == 0:
        return {"hits_at_k": 0.0, "mrr": 0.0, "random_mrr": 0.0,
                "n_queries": 0, "reciprocal_ranks": [], "hit_flags": []}

    model.eval()
    x_dict = {ntype: data[ntype].x.to(device) for ntype in data.node_types}
    edge_index_dict = {
        (src, rel, tgt): data[src, rel, tgt].edge_index.to(device)
        for src, rel, tgt in data.edge_types
    }

    with torch.no_grad():
        h_dict = model.encode(x_dict, edge_index_dict)

    pkg_embeddings = h_dict["Package"].cpu()
    cve_embeddings = h_dict["CVE"].cpu()
    pkg_norm = torch.nn.functional.normalize(pkg_embeddings, dim=1)
    cve_norm = torch.nn.functional.normalize(cve_embeddings, dim=1)

    num_cves = cve_norm.size(0)
    random_mrr = 1.0 / num_cves if num_cves > 0 else 0.0

    reciprocal_ranks = []
    hit_flags = []
    n_queries = 0

    for pkg_idx, cve_indices in masked_pkg_to_cves.items():
        if len(cve_indices) == 0:
            continue
        pkg_vec = pkg_norm[pkg_idx].unsqueeze(0)
        sims = torch.mm(pkg_vec, cve_norm.t()).squeeze(0)
        ranked = torch.argsort(sims, descending=True).tolist()

        for true_cve_idx in cve_indices:
            n_queries += 1
            in_top_k = true_cve_idx in ranked[:k]
            hit_flags.append(1 if in_top_k else 0)
            rank_pos = ranked.index(true_cve_idx) + 1
            reciprocal_ranks.append(1.0 / rank_pos)

    hits_at_k = float(np.mean(hit_flags)) if hit_flags else 0.0
    mrr = float(np.mean(reciprocal_ranks)) if reciprocal_ranks else 0.0

    return {
        "hits_at_k": hits_at_k,
        "mrr": mrr,
        "random_mrr": random_mrr,
        "n_queries": n_queries,
        "reciprocal_ranks": reciprocal_ranks,
        "hit_flags": hit_flags,
    }


# ===============================================================================
# 12. IDENTIFY NEVER-VULNERABLE PACKAGES
# ===============================================================================

def get_never_vuln_indices(
    vpss_labels: dict,
    pkg_id_to_idx: dict,
    num_packages: int,
) -> list:
    """
    Returns indices of packages that have VPSS = 0 (never had any CVE,
    neither own nor descendant). These form the negative class for AUC.
    """
    never_vuln = []
    all_pkg_ids = set(pkg_id_to_idx.keys())
    for pkg_id in all_pkg_ids:
        entry = vpss_labels.get(pkg_id, {})
        vpss = float(entry.get("vpss", 0.0))
        if vpss < 1e-9:
            never_vuln.append(pkg_id_to_idx[pkg_id])
    return never_vuln


# ===============================================================================
# 13. MAIN ORCHESTRATION
# ===============================================================================

def main():
    start_time = time.time()

    print("=" * 90)
    print("  VulnChain -- Masked-Edge Model-Contribution Audit")
    print("=" * 90)
    print()
    print("  PRE-REGISTERED CONFIGURATION:")
    print(f"    Random seed:          {SEED}")
    print(f"    Mask ratios:          {MASK_RATIOS}")
    print(f"    Own/VPSS threshold:   {OWN_VPSS_THRESHOLD}")
    print(f"    Bootstrap iterations: {BOOTSTRAP_ITERS}")
    print(f"    Hits@K:               {HITS_K}")
    print(f"    Metrics:              AUC (masked-vuln vs never-vuln), Hits@{HITS_K}, MRR")
    print()

    # -- Load data ---------------------------------------------------------
    print("[1/7] Loading graph, labels, and model...")
    with open(GRAPH_PATH, "r", encoding="utf-8") as f:
        graph_json = json.load(f)
    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        vpss_labels = json.load(f)

    data, mappings, masks = load_vulnchain_dataset(
        graph_path=GRAPH_PATH, labels_path=LABELS_PATH, repo_split_path=SPLIT_PATH
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = VulnGAT()
    model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu", weights_only=True))
    model = model.to(device)
    model.eval()

    pkg_id_to_idx = mappings["pkg_id_to_idx"]
    idx_to_pkg_id = mappings["idx_to_pkg_id"]
    cve_id_to_idx = mappings["cve_id_to_idx"]
    num_packages = data["Package"].num_nodes

    print(f"  Device: {device}")
    print(f"  Packages: {num_packages}, CVEs: {data['CVE'].num_nodes}")
    print()

    # -- Compute own-VPSS decomposition ------------------------------------
    print("[2/7] Computing own-VPSS decomposition...")
    own_vpss_data = compute_own_vpss(graph_json, vpss_labels)
    print(f"  Packages with direct CVEs: {len(own_vpss_data)}")

    # Distribution of own_ratio
    ratios = [d["own_ratio"] for d in own_vpss_data.values()]
    if ratios:
        print(f"  Own-ratio distribution: mean={np.mean(ratios):.3f}, "
              f"median={np.median(ratios):.3f}, "
              f"p25={np.percentile(ratios, 25):.3f}, "
              f"p75={np.percentile(ratios, 75):.3f}")

    # -- Select eligible packages ------------------------------------------
    print("[3/7] Selecting eligible packages (own/VPSS >= {:.2f})...".format(OWN_VPSS_THRESHOLD))
    eligible_pkg_ids = select_eligible_packages(own_vpss_data, OWN_VPSS_THRESHOLD)
    print(f"  Eligible packages: {len(eligible_pkg_ids)}")

    # Classify by split
    train_eligible = [p for p in eligible_pkg_ids if pkg_id_to_idx.get(p, -1) in
                      set(torch.where(masks["train_mask"])[0].tolist())]
    val_eligible = [p for p in eligible_pkg_ids if pkg_id_to_idx.get(p, -1) in
                    set(torch.where(masks["val_mask"])[0].tolist())]
    test_eligible = [p for p in eligible_pkg_ids if pkg_id_to_idx.get(p, -1) in
                     set(torch.where(masks["test_mask"])[0].tolist())]
    print(f"    Train: {len(train_eligible)}, Val: {len(val_eligible)}, Test: {len(test_eligible)}")

    # -- Identify never-vulnerable packages --------------------------------
    never_vuln_indices = get_never_vuln_indices(vpss_labels, pkg_id_to_idx, num_packages)
    print(f"  Never-vulnerable packages (VPSS=0): {len(never_vuln_indices)}")

    # -- Full-graph baseline scores (unmasked) -----------------------------
    print("[4/7] Running full-graph model inference (unmasked baseline)...")
    full_scores = run_model_inference(model, data, device)
    print(f"  Score range: [{full_scores.min():.5f}, {full_scores.max():.5f}]")
    print()

    # -- Sweep mask ratios -------------------------------------------------
    all_results = []

    for mask_ratio in MASK_RATIOS:
        print("-" * 90)
        print(f"[5/7] MASK RATIO = {mask_ratio:.0%}")
        print("-" * 90)

        # Apply edge mask
        ratio_seed = SEED + int(mask_ratio * 100)
        masked_data, masked_pkg_indices, masked_pkg_to_cves, stratum_labels = apply_edge_mask(
            data, eligible_pkg_ids, pkg_id_to_idx, graph_json, cve_id_to_idx,
            mask_ratio, ratio_seed,
        )

        n_shared = sum(1 for s in stratum_labels.values() if s == "shared")
        n_orphaned = sum(1 for s in stratum_labels.values() if s == "orphaned")
        masked_edges_remaining = masked_data["Package", "hasVulnerability", "CVE"].edge_index.size(1)
        original_edges = data["Package", "hasVulnerability", "CVE"].edge_index.size(1)

        print(f"  Masked packages: {len(masked_pkg_indices)} "
              f"(shared: {n_shared}, orphaned: {n_orphaned})")
        print(f"  hasVulnerability edges: {original_edges} -> {masked_edges_remaining} "
              f"(removed {original_edges - masked_edges_remaining})")

        # Get masked package IDs for BFS baseline
        masked_pkg_ids_set = set()
        for pkg_idx in masked_pkg_indices:
            if pkg_idx in idx_to_pkg_id:
                masked_pkg_ids_set.add(idx_to_pkg_id[pkg_idx])

        # -- Run all four methods ------------------------------------------
        print("  Running model inference on masked graph...")
        model_scores = run_model_inference(model, masked_data, device)

        print("  Running BFS baseline on masked graph...")
        bfs_scores = run_bfs_baseline(
            graph_json, masked_pkg_ids_set, vpss_labels, pkg_id_to_idx, num_packages
        )

        print("  Running label-propagation baseline on masked graph...")
        lp_scores = run_label_prop_baseline(
            masked_data, vpss_labels, pkg_id_to_idx, idx_to_pkg_id, num_packages
        )

        print("  Running feature-shuffle ablation on masked graph...")
        shuffle_scores = run_feature_shuffle_ablation(
            model, masked_data, device, ratio_seed + 999
        )

        # -- Compute AUC (stratified) --------------------------------------
        print("  Computing AUC (masked-vulnerable vs never-vulnerable)...")
        masked_indices_list = list(masked_pkg_indices)

        methods = {
            "model": model_scores,
            "bfs_baseline": bfs_scores,
            "label_prop": lp_scores,
            "feat_shuffle": shuffle_scores,
        }

        for stratum_name in ["overall", "shared", "orphaned"]:
            if stratum_name == "overall":
                pos_indices = masked_indices_list
            elif stratum_name == "shared":
                pos_indices = [i for i in masked_indices_list if stratum_labels.get(i) == "shared"]
            else:
                pos_indices = [i for i in masked_indices_list if stratum_labels.get(i) == "orphaned"]

            if len(pos_indices) == 0:
                for method_name in methods:
                    all_results.append({
                        "mask_ratio": mask_ratio,
                        "stratum": stratum_name,
                        "metric": "AUC",
                        "method": method_name,
                        "value": None,
                        "CI_low": None,
                        "CI_high": None,
                        "n_positive": 0,
                        "n_negative": len(never_vuln_indices),
                    })
                continue

            for method_name, method_scores in methods.items():
                auc_val = compute_auc(method_scores, pos_indices, never_vuln_indices)
                ci_low, ci_high = bootstrap_ci(
                    method_scores, pos_indices, never_vuln_indices, compute_auc,
                    n_iters=BOOTSTRAP_ITERS, seed=ratio_seed + hash(method_name) % 10000,
                )
                all_results.append({
                    "mask_ratio": mask_ratio,
                    "stratum": stratum_name,
                    "metric": "AUC",
                    "method": method_name,
                    "value": round(auc_val, 4),
                    "CI_low": round(ci_low, 4),
                    "CI_high": round(ci_high, 4),
                    "n_positive": len(pos_indices),
                    "n_negative": len(never_vuln_indices),
                })

        # -- Compute Hits@K / MRR ------------------------------------------
        print(f"  Computing Hits@{HITS_K} and MRR (embedding-space CVE re-ranking)...")
        hmrr = compute_hits_mrr_detailed(model, masked_data, masked_pkg_to_cves, device, k=HITS_K)

        mrr_ci = bootstrap_ci_mrr(
            hmrr["reciprocal_ranks"], seed=ratio_seed + 777
        )

        all_results.append({
            "mask_ratio": mask_ratio,
            "stratum": "overall",
            "metric": f"Hits@{HITS_K}",
            "method": "model",
            "value": round(hmrr["hits_at_k"], 4),
            "CI_low": None,
            "CI_high": None,
            "n_queries": hmrr["n_queries"],
        })
        all_results.append({
            "mask_ratio": mask_ratio,
            "stratum": "overall",
            "metric": "MRR",
            "method": "model",
            "value": round(hmrr["mrr"], 4),
            "CI_low": round(mrr_ci[0], 4),
            "CI_high": round(mrr_ci[1], 4),
            "n_queries": hmrr["n_queries"],
        })
        all_results.append({
            "mask_ratio": mask_ratio,
            "stratum": "overall",
            "metric": "MRR",
            "method": "random_floor",
            "value": round(hmrr["random_mrr"], 4),
            "CI_low": None,
            "CI_high": None,
            "n_queries": hmrr["n_queries"],
        })

        # -- Score drop analysis (model vs feature-shuffle) ----------------
        masked_model_mean = float(np.mean([model_scores[i] for i in masked_pkg_indices]))
        masked_shuffle_mean = float(np.mean([shuffle_scores[i] for i in masked_pkg_indices]))
        score_drop = masked_model_mean - masked_shuffle_mean

        all_results.append({
            "mask_ratio": mask_ratio,
            "stratum": "overall",
            "metric": "mean_score_drop_shuffle",
            "method": "model_vs_shuffle",
            "value": round(score_drop, 6),
            "model_mean": round(masked_model_mean, 6),
            "shuffle_mean": round(masked_shuffle_mean, 6),
        })

        print(f"  Done. Model mean on masked: {masked_model_mean:.4f}, "
              f"Shuffle mean: {masked_shuffle_mean:.4f}, "
              f"Drop: {score_drop:+.4f}")
        print()

    # =====================================================================
    # OUTPUT: Markdown Table + JSON
    # =====================================================================
    print("=" * 90)
    print("[6/7] RESULTS TABLE")
    print("=" * 90)
    print()

    # Print AUC table
    print("### AUC: Masked-Vulnerable vs Never-Vulnerable Packages")
    print()
    header = f"{'Mask%':<8}{'Stratum':<12}{'Model':<16}{'BFS-Masked':<16}{'Label-Prop':<16}{'Feat-Shuffle':<16}{'N_pos':<8}"
    print(header)
    print("-" * len(header))

    for mask_ratio in MASK_RATIOS:
        for stratum in ["overall", "shared", "orphaned"]:
            row_results = {r["method"]: r for r in all_results
                          if r["mask_ratio"] == mask_ratio
                          and r["stratum"] == stratum
                          and r["metric"] == "AUC"}

            def fmt_auc(r):
                if r is None or r.get("value") is None:
                    return "N/A"
                v = r["value"]
                ci_l = r.get("CI_low")
                ci_h = r.get("CI_high")
                if ci_l is not None and ci_h is not None:
                    return f"{v:.3f}[{ci_l:.2f},{ci_h:.2f}]"
                return f"{v:.3f}"

            model_r = row_results.get("model")
            bfs_r = row_results.get("bfs_baseline")
            lp_r = row_results.get("label_prop")
            fs_r = row_results.get("feat_shuffle")

            n_pos = model_r.get("n_positive", 0) if model_r else 0

            print(f"{mask_ratio:<8.0%}{stratum:<12}"
                  f"{fmt_auc(model_r):<16}{fmt_auc(bfs_r):<16}"
                  f"{fmt_auc(lp_r):<16}{fmt_auc(fs_r):<16}{n_pos:<8}")

    print()

    # Print Hits@K / MRR table
    print(f"### Hits@{HITS_K} / MRR: Embedding-Space CVE Re-Ranking")
    print()
    header2 = f"{'Mask%':<8}{'Metric':<12}{'Model':<20}{'Random Floor':<16}{'N_queries':<10}"
    print(header2)
    print("-" * len(header2))

    for mask_ratio in MASK_RATIOS:
        for metric_name in [f"Hits@{HITS_K}", "MRR"]:
            model_r = next((r for r in all_results
                            if r["mask_ratio"] == mask_ratio
                            and r["metric"] == metric_name
                            and r["method"] in ("model",)), None)
            rand_r = next((r for r in all_results
                           if r["mask_ratio"] == mask_ratio
                           and r["metric"] == metric_name
                           and r["method"] == "random_floor"), None)

            def fmt_val(r):
                if r is None or r.get("value") is None:
                    return "N/A"
                v = r["value"]
                ci_l = r.get("CI_low")
                ci_h = r.get("CI_high")
                if ci_l is not None and ci_h is not None:
                    return f"{v:.4f} [{ci_l:.3f},{ci_h:.3f}]"
                return f"{v:.4f}"

            n_q = model_r.get("n_queries", 0) if model_r else 0
            print(f"{mask_ratio:<8.0%}{metric_name:<12}"
                  f"{fmt_val(model_r):<20}{fmt_val(rand_r):<16}{n_q:<10}")

    print()

    # Print score-drop table
    print("### Feature-Shuffle Score Drop (semantic embedding signal)")
    print()
    header3 = f"{'Mask%':<8}{'Model Mean':<14}{'Shuffle Mean':<14}{'Drop':<12}{'Interpretation':<40}"
    print(header3)
    print("-" * len(header3))

    for mask_ratio in MASK_RATIOS:
        drop_r = next((r for r in all_results
                       if r["mask_ratio"] == mask_ratio
                       and r["metric"] == "mean_score_drop_shuffle"), None)
        if drop_r:
            drop = drop_r["value"]
            model_m = drop_r.get("model_mean", 0)
            shuf_m = drop_r.get("shuffle_mean", 0)
            if abs(drop) < 0.005:
                interp = "No evidence of embedding use"
            elif drop > 0.02:
                interp = "Embeddings contribute to scores"
            else:
                interp = "Weak/marginal embedding signal"
            print(f"{mask_ratio:<8.0%}{model_m:<14.4f}{shuf_m:<14.4f}{drop:<+12.4f}{interp:<40}")

    # =====================================================================
    # INTERPRETATION
    # =====================================================================
    print()
    print("=" * 90)
    print("[7/7] INTERPRETATION")
    print("=" * 90)
    print()

    # Determine outcome based on 50% mask ratio (harshest test)
    target_ratio = 0.50

    model_auc = None
    bfs_auc = None
    lp_auc = None
    fs_auc = None
    score_drop = None

    for r in all_results:
        if r["mask_ratio"] != target_ratio or r["stratum"] != "shared":
            continue
        if r["metric"] == "AUC":
            if r["method"] == "model":
                model_auc = r.get("value")
            elif r["method"] == "bfs_baseline":
                bfs_auc = r.get("value")
            elif r["method"] == "label_prop":
                lp_auc = r.get("value")
            elif r["method"] == "feat_shuffle":
                fs_auc = r.get("value")

    for r in all_results:
        if r["mask_ratio"] == target_ratio and r["metric"] == "mean_score_drop_shuffle":
            score_drop = r.get("value")

    # Fallback to overall stratum if shared had no data
    if model_auc is None:
        for r in all_results:
            if r["mask_ratio"] != target_ratio or r["stratum"] != "overall":
                continue
            if r["metric"] == "AUC":
                if r["method"] == "model":
                    model_auc = r.get("value")
                elif r["method"] == "bfs_baseline":
                    bfs_auc = r.get("value")
                elif r["method"] == "label_prop":
                    lp_auc = r.get("value")
                elif r["method"] == "feat_shuffle":
                    fs_auc = r.get("value")

    beats_bfs = model_auc is not None and bfs_auc is not None and model_auc > bfs_auc + 0.02
    beats_lp = model_auc is not None and lp_auc is not None and model_auc > lp_auc + 0.02
    embedding_signal = score_drop is not None and score_drop > 0.01

    if beats_bfs and beats_lp and embedding_signal:
        outcome = 1
        print("  OUTCOME 1: SEMANTIC / ZERO-DAY GENERALIZATION (STRONGEST)")
        print()
        print("  The model beats both BFS-masked and label-prop baselines,")
        print("  AND feature-shuffle ablation drops scores, indicating the")
        print("  768-dim CVE embeddings are an active mechanism for risk inference.")
        print()
        print("  Claim supported: 'VulnGAT performs learned semantic generalization")
        print("  beyond scripted traversal -- it can infer risk for packages with")
        print("  no observed CVE edge using CVE-text embeddings from neighbors.'")
        print()
        print("  NOTE: This is rare at this data volume. Verify the shared-CVE")
        print("  stratum carefully -- the mechanism requires a CVE to be reachable")
        print("  via another package's edge.")

    elif beats_bfs and beats_lp:
        outcome = 2
        print("  OUTCOME 2: STRUCTURAL PROPAGATION (MODERATE)")
        print()
        print("  The model beats BFS-masked and label-prop baselines, but the")
        print("  feature-shuffle ablation does NOT drop scores. The GNN is using")
        print("  learned nonlinear risk propagation through dependency structure,")
        print("  but NOT the CVE-text embeddings.")
        print()
        print("  Claim supported: 'VulnGAT performs learned nonlinear risk")
        print("  propagation through dependency structure under edge sparsity,")
        print("  beyond scripted traversal or label propagation.'")
        print()
        print("  This is narrower than semantic generalization but still a real,")
        print("  non-BFS-replicable contribution. Upgrades the prior 30/70 credit")
        print("  split with evidence.")

    else:
        outcome = 3
        print("  OUTCOME 3: NO CLEAR ADVANTAGE OVER BASELINES")
        print()
        if model_auc is not None:
            print(f"  Model AUC:     {model_auc:.4f}")
        if bfs_auc is not None:
            print(f"  BFS AUC:       {bfs_auc:.4f}")
        if lp_auc is not None:
            print(f"  Label-Prop:    {lp_auc:.4f}")
        print()
        print("  The model does not clearly beat BFS or label-propagation baselines")
        print("  on the masked-edge evaluation. This is a sharper, more honest")
        print("  characterization than the prior '30/70 split' -- it identifies")
        if not beats_bfs:
            print("  that structural propagation does not exceed what BFS recovers,")
        if not beats_lp:
            print("  that learned representations do not exceed neighbor averaging,")
        print("  under this specific edge-masking evaluation protocol.")

    print()
    print("  +-------------------------------------------------------------+")
    print("  | DISTRIBUTION-SHIFT CAVEAT                                  |")
    print("  |                                                            |")
    print("  | The model was NEVER trained with hasVulnerability edges     |")
    print("  | deliberately deleted. A collapse under masking could mean:  |")
    print("  |                                                            |")
    print("  |   (a) The model cannot do this (architecture limitation)   |")
    print("  |   (b) The model was never trained for this input (OOD)     |")
    print("  |                                                            |")
    print("  | These are DIFFERENT findings. This audit reports the       |")
    print("  | current, as-trained model's behavior. If collapse is       |")
    print("  | observed, it motivates (but does not itself justify) a     |")
    print("  | follow-up: extending the existing edge-dropout             |")
    print("  | augmentation (p=0.2 for InfoNCE) to also require VPSS     |")
    print("  | prediction under hasVulnerability masking during training. |")
    print("  |                                                            |")
    print("  | Do NOT build this training-side fix in this script --       |")
    print("  | it is a separate follow-up, only worth doing if this      |")
    print("  | audit shows collapse.                                      |")
    print("  +-------------------------------------------------------------+")

    # -- Save JSON ---------------------------------------------------------
    output = {
        "config": {
            "seed": SEED,
            "mask_ratios": MASK_RATIOS,
            "own_vpss_threshold": OWN_VPSS_THRESHOLD,
            "bootstrap_iters": BOOTSTRAP_ITERS,
            "hits_k": HITS_K,
        },
        "summary": {
            "eligible_packages": len(eligible_pkg_ids),
            "never_vuln_packages": len(never_vuln_indices),
            "outcome": outcome,
        },
        "results": all_results,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    elapsed = time.time() - start_time
    print()
    print(f"  Results saved to: {OUTPUT_JSON}")
    print(f"  Total runtime:    {elapsed:.1f}s")
    print()
    print("=" * 90)
    print("  Audit Complete.")
    print("=" * 90)


if __name__ == "__main__":
    main()