"""
training/dataset.py — Graph Loader and PyG HeteroData Conversion for VulnChain

Loads vulnchain_graph.json and vpss_labels.json, converts to PyTorch Geometric
HeteroData format with:
- Feature tensor extraction & normalization for Package (10-dim), CVE (769-dim), Author (7-dim)
- Edge index construction (COO format) for all 4 edge types
- Continuous VPSS regression labels tensor [5578]
- Stratified train / validation / test masks (80% / 10% / 10%)
"""

import json
import os
import torch
import numpy as np
from torch_geometric.data import HeteroData


def normalize_features(features_tensor: torch.Tensor, continuous_indices: list) -> torch.Tensor:
    """
    Min-max normalize continuous features to [0, 1] range to ensure stable gradient flow.
    """
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


def load_vulnchain_dataset(
    graph_path: str = None,
    labels_path: str = None,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42,
    repo_split_path: str = None
) -> tuple[HeteroData, dict, dict]:
    """
    Loads the graph and labels, converts to HeteroData, and generates split masks.

    Paths default to env-var overrides (GRAPH_FILE / LABELS_FILE / REPO_SPLIT_FILE)
    so alternate graphs/splits can be selected without editing code; explicit
    arguments still take precedence.

    Returns:
        data (HeteroData): PyG heterogeneous graph object
        mappings (dict): Mapping dicts from node IDs to integer indices
        masks (dict): Boolean masks {'train_mask', 'val_mask', 'test_mask'} for Package nodes
    """
    graph_path = graph_path or os.environ.get("GRAPH_FILE", "vulnchain_graph.json")
    labels_path = labels_path or os.environ.get("LABELS_FILE", "vpss_labels.json")
    repo_split_path = repo_split_path or os.environ.get("REPO_SPLIT_FILE", "repo_split_mapping.json")

    if not os.path.exists(graph_path):
        raise FileNotFoundError(f"Graph file not found at: {graph_path}")
    if not os.path.exists(labels_path):
        raise FileNotFoundError(f"Labels file not found at: {labels_path}")

    print(f"Loading graph from {graph_path}...")
    with open(graph_path, "r", encoding="utf-8") as f:
        graph_json = json.load(f)

    print(f"Loading labels from {labels_path}...")
    with open(labels_path, "r", encoding="utf-8") as f:
        labels_json = json.load(f)

    # 1. Build Node ID -> Index mappings
    pkg_nodes = graph_json["nodes"]["Package"]
    cve_nodes = graph_json["nodes"]["CVE"]
    auth_nodes = graph_json["nodes"]["Author"]

    pkg_id_to_idx = {node["id"]: idx for idx, node in enumerate(pkg_nodes)}
    cve_id_to_idx = {node["id"]: idx for idx, node in enumerate(cve_nodes)}
    auth_id_to_idx = {node["id"]: idx for idx, node in enumerate(auth_nodes)}

    # 2. Extract & stack node features
    # Package features: 10 dimensions
    pkg_feat_list = [node["features"] for node in pkg_nodes]
    pkg_feat_tensor = torch.tensor(pkg_feat_list, dtype=torch.float32)
    # Continuous dimensions: 2(out_degree), 3(depth_in_tree), 4(version_recency_days), 5(versions_behind_latest), 7(weekly_downloads_log)
    pkg_feat_tensor = normalize_features(pkg_feat_tensor, [2, 3, 4, 5, 7])

    # CVE features: 768-dim SentenceBERT embedding + 1 CVSS score = 769 dimensions
    cve_feat_list = []
    for node in cve_nodes:
        cvss = float(node.get("cvss_score", 0.0) if node.get("cvss_score") is not None else 0.0) / 10.0  # Normalize 0-10 to 0-1
        emb = node["embedding"]
        cve_feat_list.append([cvss] + emb)
    cve_feat_tensor = torch.tensor(cve_feat_list, dtype=torch.float32)

    # Author features: 7 dimensions
    auth_feat_list = [node["features"] for node in auth_nodes]
    auth_feat_tensor = torch.tensor(auth_feat_list, dtype=torch.float32)
    # Continuous dimensions: 0(account_age_days), 1(total_packages_maintained), 2(packages_with_known_cves), 3(days_since_last_commit), 6(reputation_score)
    auth_feat_tensor = normalize_features(auth_feat_tensor, [0, 1, 2, 3, 6])

    # 3. Construct Edge Index Tensors (COO format)
    def build_edge_index(edge_list, src_mapping, tgt_mapping):
        src_indices = []
        tgt_indices = []
        for edge in edge_list:
            src = edge["source"]
            tgt = edge["target"]
            if src in src_mapping and tgt in tgt_mapping:
                src_indices.append(src_mapping[src])
                tgt_indices.append(tgt_mapping[tgt])
        if len(src_indices) == 0:
            return torch.empty((2, 0), dtype=torch.long)
        return torch.tensor([src_indices, tgt_indices], dtype=torch.long)

    edges_json = graph_json["edges"]
    edge_index_dependsOn = build_edge_index(edges_json["dependsOn"], pkg_id_to_idx, pkg_id_to_idx)
    edge_index_hasVuln = build_edge_index(edges_json["hasVulnerability"], pkg_id_to_idx, cve_id_to_idx)
    edge_index_maintainedBy = build_edge_index(edges_json["maintainedBy"], pkg_id_to_idx, auth_id_to_idx)
    edge_index_introducedBy = build_edge_index(edges_json["introducedBy"], cve_id_to_idx, auth_id_to_idx)

    # 4. Extract Labels (prefer EPSS over VPSS)
    epss_labels_path = labels_path.replace("vpss_labels", "epss_labels")
    if os.path.exists("epss_labels.json"):
        print(f"Loading EPSS-based labels from epss_labels.json...")
        with open("epss_labels.json", "r", encoding="utf-8") as f:
            alt_labels = json.load(f)
        labels_list = []
        for node in pkg_nodes:
            pkg_id = node["id"]
            entry = alt_labels.get(pkg_id, {})
            score = float(entry.get("epss_risk", 0.0))
            labels_list.append(score)
        labels_tensor = torch.tensor(labels_list, dtype=torch.float32)
        print(f"  Using EPSS labels: {(labels_tensor > 0).sum().item()} non-zero out of {len(labels_list)}")
    else:
        labels_list = []
        for node in pkg_nodes:
            pkg_id = node["id"]
            vpss_entry = labels_json.get(pkg_id, {})
            vpss_score = float(vpss_entry.get("vpss", 0.0))
            labels_list.append(vpss_score)
        labels_tensor = torch.tensor(labels_list, dtype=torch.float32)

    # 5. Populate PyG HeteroData Object
    data = HeteroData()
    data["Package"].x = pkg_feat_tensor
    data["CVE"].x = cve_feat_tensor
    data["Author"].x = auth_feat_tensor
    data["Package"].y = labels_tensor

    data["Package", "dependsOn", "Package"].edge_index = edge_index_dependsOn
    data["Package", "hasVulnerability", "CVE"].edge_index = edge_index_hasVuln
    data["Package", "maintainedBy", "Author"].edge_index = edge_index_maintainedBy
    data["CVE", "introducedBy", "Author"].edge_index = edge_index_introducedBy

    # 6. Repository-Level Split (train / val / test)
    num_packages = len(pkg_nodes)

    if os.path.exists(repo_split_path):
        print(f"Loading true repository-level split from {repo_split_path}...")
        with open(repo_split_path, "r", encoding="utf-8") as f:
            repo_split = json.load(f)

        train_ids = repo_split["train_pkg_ids"]
        val_ids = repo_split["val_pkg_ids"]
        test_ids = repo_split["test_pkg_ids"]

        train_indices = [pkg_id_to_idx[pid] for pid in train_ids if pid in pkg_id_to_idx]
        val_indices = [pkg_id_to_idx[pid] for pid in val_ids if pid in pkg_id_to_idx]
        test_indices = [pkg_id_to_idx[pid] for pid in test_ids if pid in pkg_id_to_idx]

        dropped = {
            "train": len(train_ids) - len(train_indices),
            "val": len(val_ids) - len(val_indices),
            "test": len(test_ids) - len(test_indices),
        }
        if any(dropped.values()):
            print(f"  WARNING: split IDs missing from graph (silently skipped): {dropped}")
        else:
            print(f"  Split ID check: 0 dropped (train={len(train_ids)}, val={len(val_ids)}, test={len(test_ids)})")

        train_mask = torch.zeros(num_packages, dtype=torch.bool)
        val_mask = torch.zeros(num_packages, dtype=torch.bool)
        test_mask = torch.zeros(num_packages, dtype=torch.bool)

        train_mask[train_indices] = True
        val_mask[val_indices] = True
        test_mask[test_indices] = True
    else:
        # Fallback Stratified Node Split
        np.random.seed(seed)
        torch.manual_seed(seed)

        is_vuln = (labels_tensor > 0).numpy()
        vuln_indices = np.where(is_vuln)[0]
        clean_indices = np.where(~is_vuln)[0]

        np.random.shuffle(vuln_indices)
        np.random.shuffle(clean_indices)

        def split_indices(indices):
            n = len(indices)
            n_train = int(n * train_ratio)
            n_val = int(n * val_ratio)
            train_idx = indices[:n_train]
            val_idx = indices[n_train:n_train + n_val]
            test_idx = indices[n_train + n_val:]
            return train_idx, val_idx, test_idx

        v_train, v_val, v_test = split_indices(vuln_indices)
        c_train, c_val, c_test = split_indices(clean_indices)

        train_indices = np.concatenate([v_train, c_train])
        val_indices = np.concatenate([v_val, c_val])
        test_indices = np.concatenate([v_test, c_test])

        train_mask = torch.zeros(num_packages, dtype=torch.bool)
        val_mask = torch.zeros(num_packages, dtype=torch.bool)
        test_mask = torch.zeros(num_packages, dtype=torch.bool)

        train_mask[train_indices] = True
        val_mask[val_indices] = True
        test_mask[test_indices] = True

    data["Package"].train_mask = train_mask
    data["Package"].val_mask = val_mask
    data["Package"].test_mask = test_mask

    mappings = {
        "pkg_id_to_idx": pkg_id_to_idx,
        "cve_id_to_idx": cve_id_to_idx,
        "auth_id_to_idx": auth_id_to_idx,
        "idx_to_pkg_id": {idx: node_id for node_id, idx in pkg_id_to_idx.items()}
    }

    masks = {
        "train_mask": train_mask,
        "val_mask": val_mask,
        "test_mask": test_mask
    }

    print(f"HeteroData constructed successfully:")
    print(f"  Package nodes: {data['Package'].num_nodes}, features: {data['Package'].x.shape}")
    print(f"  CVE nodes:     {data['CVE'].num_nodes}, features: {data['CVE'].x.shape}")
    print(f"  Author nodes:  {data['Author'].num_nodes}, features: {data['Author'].x.shape}")
    print(f"  Edges:")
    print(f"    Package -> dependsOn -> Package:    {data['Package', 'dependsOn', 'Package'].num_edges}")
    print(f"    Package -> hasVulnerability -> CVE: {data['Package', 'hasVulnerability', 'CVE'].num_edges}")
    print(f"    Package -> maintainedBy -> Author:  {data['Package', 'maintainedBy', 'Author'].num_edges}")
    print(f"    CVE -> introducedBy -> Author:      {data['CVE', 'introducedBy', 'Author'].num_edges}")
    is_vuln_tensor = (data["Package"].y > 0)
    train_vuln_cnt = (train_mask & is_vuln_tensor).sum().item()
    val_vuln_cnt = (val_mask & is_vuln_tensor).sum().item()
    test_vuln_cnt = (test_mask & is_vuln_tensor).sum().item()

    print(f"  Splits (Package nodes):")
    print(f"    Train: {train_mask.sum().item()} (Vulnerable: {train_vuln_cnt})")
    print(f"    Val:   {val_mask.sum().item()} (Vulnerable: {val_vuln_cnt})")
    print(f"    Test:  {test_mask.sum().item()} (Vulnerable: {test_vuln_cnt})")

    return data, mappings, masks


if __name__ == "__main__":
    data, mappings, masks = load_vulnchain_dataset()
