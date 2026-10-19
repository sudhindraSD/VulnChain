import json
import random
from collections import defaultdict, deque
from pathlib import Path

import numpy as np
from sklearn.linear_model import RidgeClassifier, RidgeCV
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent

GRAPH_PATH = ROOT / "phase4" / "vulnchain_graph.json"
CACHE_PATH = ROOT / ".osv_records_cache.json"
SPLIT_PATH = ROOT / "phase4" / "repo_split_mapping_51repo.json"
PACKAGE_GRAPH_PATH = ROOT / "data_pipeline" / "package_graph.json"

T = "2024-07-01"


def run_full_baseline_suite():
    print("=" * 80)
    print(f"TEMPORAL LABEL FEASIBILITY & BASELINE SUITE (T = {T})")
    print("=" * 80)

    # 1. Load data
    with open(GRAPH_PATH, encoding="utf-8") as f:
        graph = json.load(f)
    with open(CACHE_PATH, encoding="utf-8") as f:
        osv = json.load(f)
    with open(SPLIT_PATH, encoding="utf-8") as f:
        split_mapping = json.load(f)
    with open(PACKAGE_GRAPH_PATH, encoding="utf-8") as f:
        pg = json.load(f)

    cve_dates = {
        cid: rec["published"][:10]
        for cid, rec in osv.items()
        if rec.get("published")
    }

    # Lockfile topology / Package repo_sources
    repo_sources = {n["id"]: n.get("repo_sources", []) for n in pg["nodes"]}
    pkg_dict = {n["id"]: n for n in graph["nodes"]["Package"]}

    # Pre-T and Post-T CVE sets
    pre_t_cves = set(cid for cid, d in cve_dates.items() if d <= T)
    post_t_cves = set(cid for cid, d in cve_dates.items() if d > T)

    # hasVulnerability edges
    hv_edges = graph["edges"]["hasVulnerability"]
    pre_t_hv = [e for e in hv_edges if e["target"] in pre_t_cves]
    pre_t_vuln_pkgs = set(e["source"] for e in pre_t_hv)
    post_t_vuln_pkgs = set(
        e["source"] for e in hv_edges if e["target"] in post_t_cves
    )

    # Pre-T dependsOn graph
    deps_of = defaultdict(list)
    for e in graph["edges"]["dependsOn"]:
        deps_of[e["source"]].append(e["target"])

    # Splits
    train_ids = split_mapping["train_pkg_ids"]
    val_ids = split_mapping["val_pkg_ids"]
    test_ids = split_mapping["test_pkg_ids"]
    val_test_ids = val_ids + test_ids

    # At-risk populations (no pre-T vulnerability history)
    train_at_risk = [pid for pid in train_ids if pid not in pre_t_vuln_pkgs]
    val_at_risk = [pid for pid in val_ids if pid not in pre_t_vuln_pkgs]
    test_at_risk = [pid for pid in test_ids if pid not in pre_t_vuln_pkgs]
    val_test_at_risk = val_at_risk + test_at_risk

    y_train = np.array(
        [1 if pid in post_t_vuln_pkgs else 0 for pid in train_at_risk]
    )
    y_val = np.array(
        [1 if pid in post_t_vuln_pkgs else 0 for pid in val_at_risk]
    )
    y_test = np.array(
        [1 if pid in post_t_vuln_pkgs else 0 for pid in test_at_risk]
    )
    y_val_test = np.array(
        [1 if pid in post_t_vuln_pkgs else 0 for pid in val_test_at_risk]
    )

    print("\n--- AT-RISK POPULATION SUMMARY ---")
    print(
        f"Train:    {len(train_at_risk):5} nodes, {y_train.sum():3} positives"
        f" ({y_train.mean()*100:.3f}% base rate)"
    )
    print(
        f"Val:      {len(val_at_risk):5} nodes, {y_val.sum():3} positives"
        f" ({y_val.mean()*100:.3f}% base rate)"
    )
    print(
        f"Test:     {len(test_at_risk):5} nodes, {y_test.sum():3} positives"
        f" ({y_test.mean()*100:.3f}% base rate)"
    )
    print(
        f"Val+Test: {len(val_test_at_risk):5} nodes, {y_val_test.sum():3}"
        f" positives ({y_val_test.mean()*100:.3f}% base rate)"
    )

    # Precompute topological features for all packages
    # 1. Transitive descendants count
    descendants = {}
    dep_pre_t_count = {}
    for pid in pkg_dict:
        visited = set()
        q = deque(deps_of.get(pid, []))
        pre_t_deps = 0
        while q:
            curr = q.popleft()
            if curr not in visited:
                visited.add(curr)
                if curr in pre_t_vuln_pkgs:
                    pre_t_deps += 1
                for nxt in deps_of.get(curr, []):
                    if nxt not in visited:
                        q.append(nxt)
        descendants[pid] = len(visited)
        dep_pre_t_count[pid] = pre_t_deps

    # 2. Number of repos using package
    num_repos = {pid: len(repo_sources.get(pid, [])) for pid in pkg_dict}

    # Baseline 1: dependency-has-pre-T-history (continuous count and binary indicator)
    score_dep_hist_count = np.array(
        [dep_pre_t_count[pid] for pid in val_test_at_risk]
    )
    score_dep_hist_binary = np.array(
        [1.0 if dep_pre_t_count[pid] > 0 else 0.0 for pid in val_test_at_risk]
    )

    # Baseline 2: descendant count
    score_descendants = np.array(
        [float(descendants[pid]) for pid in val_test_at_risk]
    )

    # Baseline 3: number of repos using the package
    score_num_repos = np.array(
        [float(num_repos[pid]) for pid in val_test_at_risk]
    )

    # Baseline 4: Ridge on time-safe features
    # Time-safe features:
    # 0: is_direct_dependency
    # 1: is_dev_dependency
    # 2: out_degree
    # 3: depth_in_tree
    # plus lockfile topological features: descendants, num_repos
    def get_time_safe_feats(pid):
        f = pkg_dict[pid]["features"]
        # dims 0, 1, 2, 3
        return [
            float(f[0]),
            float(f[1]),
            float(f[2]),
            float(f[3]),
            float(descendants[pid]),
            float(num_repos[pid]),
        ]

    X_train = np.array([get_time_safe_feats(pid) for pid in train_at_risk])
    X_val_test = np.array(
        [get_time_safe_feats(pid) for pid in val_test_at_risk]
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_test_scaled = scaler.transform(X_val_test)

    ridge = RidgeCV(alphas=[0.01, 0.1, 1.0, 10.0, 100.0, 1000.0])
    ridge.fit(X_train_scaled, y_train)
    score_ridge = ridge.predict(X_val_test_scaled)

    # Baseline 5: Label propagation on graph
    # Propagate training labels y_train along dependsOn edges (bidirectional)
    # Package id to index
    all_pids = list(pkg_dict.keys())
    pid_to_i = {pid: i for i, pid in enumerate(all_pids)}
    N_all = len(all_pids)

    # Build symmetric normalized adjacency for label propagation
    adj = defaultdict(set)
    for e in graph["edges"]["dependsOn"]:
        u, v = pid_to_i[e["source"]], pid_to_i[e["target"]]
        adj[u].add(v)
        adj[v].add(u)

    # Label vector: training at-risk nodes have known labels; val/test/pre-T initialized to 0
    y_init = np.zeros(N_all, dtype=np.float32)
    labeled_mask = np.zeros(N_all, dtype=bool)
    for pid, y_val_item in zip(train_at_risk, y_train):
        idx = pid_to_i[pid]
        y_init[idx] = float(y_val_item)
        labeled_mask[idx] = True

    # 10 iterations of label propagation with clamping
    alpha = 0.5
    y_prop = y_init.copy()
    degrees = np.array([len(adj[i]) for i in range(N_all)], dtype=np.float32)
    degrees[degrees == 0] = 1.0

    for step in range(15):
        y_next = np.zeros(N_all, dtype=np.float32)
        for i in range(N_all):
            if adj[i]:
                # average of neighbors
                y_next[i] = sum(y_prop[j] for j in adj[i]) / len(adj[i])
            else:
                y_next[i] = y_prop[i]
        # Convex combination with initial labels on labeled set
        y_prop = alpha * y_next + (1.0 - alpha) * y_init
        y_prop[labeled_mask] = y_init[labeled_mask]

    score_label_prop = np.array(
        [y_prop[pid_to_i[pid]] for pid in val_test_at_risk]
    )

    # Baseline 6: Random baseline
    np.random.seed(42)
    score_random = np.random.uniform(0.0, 1.0, size=len(val_test_at_risk))

    # Evaluate all baselines
    baselines = {
        "dependency-has-pre-T-history (count)": score_dep_hist_count,
        "dependency-has-pre-T-history (binary)": score_dep_hist_binary,
        "descendant count": score_descendants,
        "number of repos using the package": score_num_repos,
        "ridge on time-safe features": score_ridge,
        "label propagation": score_label_prop,
        "random": score_random,
    }

    # Grouped bootstrap by package name (without @version)
    names_val_test = np.array(
        [pid.rsplit("@", 1)[0] for pid in val_test_at_risk]
    )
    unique_names = np.unique(names_val_test)
    n_unique = len(unique_names)
    print(f"\nUnique package names in pooled val+test: {n_unique}")

    # Pre-map names to indices
    name_to_indices = defaultdict(list)
    for idx, name in enumerate(names_val_test):
        name_to_indices[name].append(idx)

    # Bootstrap
    N_BOOT = 2000
    np.random.seed(42)

    boot_results = {k: {"pr_auc": [], "roc_auc": []} for k in baselines}

    for b in range(N_BOOT):
        sampled_names = np.random.choice(unique_names, size=n_unique, replace=True)
        sampled_indices = []
        for sname in sampled_names:
            sampled_indices.extend(name_to_indices[sname])

        sampled_indices = np.array(sampled_indices)
        y_b = y_val_test[sampled_indices]
        if y_b.sum() == 0 or y_b.sum() == len(y_b):
            continue

        for bname, scores in baselines.items():
            s_b = scores[sampled_indices]
            # PR-AUC
            pr = average_precision_score(y_b, s_b)
            # ROC-AUC
            roc = roc_auc_score(y_b, s_b)
            boot_results[bname]["pr_auc"].append(pr)
            boot_results[bname]["roc_auc"].append(roc)

    base_rate = y_val_test.mean()

    print("\n" + "=" * 105)
    print(
        f"{'Baseline':<38} | {'PR-AUC':<8} | {'PR-AUC 95% CI':<19} | {'ROC-AUC':<8} | {'ROC-AUC 95% CI':<19}"
    )
    print("-" * 105)

    summary_table = []
    for bname, scores in baselines.items():
        pr_point = average_precision_score(y_val_test, scores)
        roc_point = roc_auc_score(y_val_test, scores)

        pr_ci_low = np.percentile(boot_results[bname]["pr_auc"], 2.5)
        pr_ci_high = np.percentile(boot_results[bname]["pr_auc"], 97.5)

        roc_ci_low = np.percentile(boot_results[bname]["roc_auc"], 2.5)
        roc_ci_high = np.percentile(boot_results[bname]["roc_auc"], 97.5)

        print(
            f"{bname:<38} | {pr_point:.4f}   | [{pr_ci_low:.4f}, {pr_ci_high:.4f}]   "
            f"| {roc_point:.4f}   | [{roc_ci_low:.4f}, {roc_ci_high:.4f}]"
        )
        summary_table.append({
            "name": bname,
            "pr_point": pr_point,
            "pr_ci": (pr_ci_low, pr_ci_high),
            "roc_point": roc_point,
            "roc_ci": (roc_ci_low, roc_ci_high),
        })

    print("-" * 105)
    print(
        f"Base rate (prevalence): {base_rate:.4f} ({base_rate*100:.2f}%"
        f" positive)"
    )

    return summary_table, base_rate


if __name__ == "__main__":
    run_full_baseline_suite()
