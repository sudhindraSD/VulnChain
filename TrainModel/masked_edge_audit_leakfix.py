"""
masked_edge_audit_leakfix.py -- LP leak check for the 50% masked-edge audit
==========================================================================
NEW FILE. Created for the LP_LEAKCHECK investigation only.

It does NOT modify, overwrite, or re-run any existing audit script or result.
It imports the official functions verbatim from TrainModel/masked_edge_audit.py
and adds exactly one new baseline:

    LP_clean = the SAME run_label_prop_baseline() averaging, but fed VPSS labels
               recomputed from the MASKED graph (masked hasVulnerability edges
               removed) using the bit-exact VPSS labeler in data_pipeline/.

Everything else (eligibility, mask, model, BFS, AUC, 5 seeds) is unchanged and
is called through the official implementations. No parameter is tuned.

Run:  python TrainModel/masked_edge_audit_leakfix.py
Out:  phase5/LP_LEAKCHECK.md   (new file)
"""

import sys
sys.dont_write_bytecode = True  # do not leave __pycache__ in existing folders

import json
from pathlib import Path
from collections import defaultdict

import numpy as np
import torch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "TrainModel"))
sys.path.insert(0, str(PROJECT_ROOT / "data_pipeline"))

from masked_edge_audit import (                       # noqa: E402
    compute_own_vpss,
    select_eligible_packages,
    apply_edge_mask,
    run_model_inference,
    run_label_prop_baseline,
    run_bfs_baseline,
    compute_auc,
    get_never_vuln_indices,
)
from training.dataset import load_vulnchain_dataset   # noqa: E402
from core.model.vulngat import VulnGAT                # noqa: E402
import vpss_labeler as vl                            # noqa: E402

# --- Pre-registered / official settings (copied verbatim, NOT tuned) ---------
SEEDS = [42, 123, 456, 789, 1024]          # phase5/part_c_masked_edge_multiseed.py
MASK_RATIO = 0.50
OWN_VPSS_THRESHOLD = 0.70                  # official; auto-relaxes to 0.30 -> N=645
EXPECTED_ELIGIBLE = 645
EXPECTED_NEVER_VULN = 8682

GRAPH_FILE = PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json"
LABELS_FILE = PROJECT_ROOT / "phase4" / "vpss_labels_51repo.json"
SPLIT_FILE = PROJECT_ROOT / "phase4" / "repo_split_mapping_51repo.json"
MODEL_FILE = PROJECT_ROOT / "phase5" / "models" / "vulngat_hr_full.pt"
OUT_MD = PROJECT_ROOT / "phase5" / "LP_LEAKCHECK.md"

HAS_VULN_KEY = ("Package", "hasVulnerability", "CVE")


# ---------------------------------------------------------------------------
# 1. Build the masked graph (structure only) and recompute VPSS on it
# ---------------------------------------------------------------------------
def build_masked_graph(graph_json: dict, masked_pkg_ids: set) -> dict:
    """Return a graph identical to graph_json except that every
    hasVulnerability edge whose source is a masked package is removed.
    dependsOn, nodes, and all other edges are untouched. The input is not
    mutated."""
    edges = dict(graph_json["edges"])           # shallow copy of the edge lists
    edges["hasVulnerability"] = [
        e for e in graph_json["edges"]["hasVulnerability"]
        if e["source"] not in masked_pkg_ids
    ]
    return {"nodes": graph_json["nodes"], "edges": edges}


def recompute_vpss_labels(graph_json: dict, masked_pkg_ids: set):
    """Bit-exact VPSS labels recomputed from the masked graph.

    Uses data_pipeline/vpss_labeler.label_all, the verified reconstruction of
    the original formula:
        raw(P) = sum_d [ sum CVSS(C) over (V,C) at depth d ] * 0.7^d * exposure(P)
        vpss(P) = round(raw / (raw + 10), 6)
    BFS runs outward through dependsOn (source=dependent, target=dependency).
    The only changed input is the surviving hasVulnerability edge set.
    """
    masked_graph = build_masked_graph(graph_json, masked_pkg_ids)
    labels, stats = vl.label_all(masked_graph)
    return labels, stats


# ---------------------------------------------------------------------------
# 2. LP neighbor pool (mirrors run_label_prop_baseline lines 387-424 exactly)
# ---------------------------------------------------------------------------
def build_lp_neighbors(data) -> dict:
    """Same adjacency used by the official LP: undirected Package<->Package
    dependsOn edges, plus Package<->Package links for packages sharing a
    surviving CVE. Returned as {idx: set(neighbor_idx)}."""
    neighbors = defaultdict(set)
    for edge_type_key in data.edge_types:
        ei = data[edge_type_key].edge_index
        if edge_type_key[0] == "Package" and edge_type_key[2] == "Package":
            for col in range(ei.size(1)):
                s = ei[0, col].item()
                t = ei[1, col].item()
                neighbors[s].add(t)
                neighbors[t].add(s)

    cve_to_pkgs = defaultdict(set)
    if HAS_VULN_KEY in data.edge_types:
        ei = data[HAS_VULN_KEY].edge_index
        for col in range(ei.size(1)):
            cve_to_pkgs[ei[1, col].item()].add(ei[0, col].item())
    for pkg_set in cve_to_pkgs.values():
        pkg_list = list(pkg_set)
        for i in range(len(pkg_list)):
            for j in range(i + 1, len(pkg_list)):
                neighbors[pkg_list[i]].add(pkg_list[j])
                neighbors[pkg_list[j]].add(pkg_list[i])
    return neighbors


def vpss_array_from(labels: dict, pkg_id_to_idx: dict, n: int) -> np.ndarray:
    arr = np.zeros(n, dtype=np.float32)
    for pkg_id, entry in labels.items():
        if pkg_id in pkg_id_to_idx:
            arr[pkg_id_to_idx[pkg_id]] = float(entry.get("vpss", 0.0))
    return arr


def pearson(a: np.ndarray, b: np.ndarray) -> float:
    if a.std() == 0 or b.std() == 0:
        return float("nan")
    return float(np.corrcoef(a, b)[0, 1])


def spearman(a: np.ndarray, b: np.ndarray) -> float:
    ra = np.argsort(np.argsort(a)).astype(np.float64)
    rb = np.argsort(np.argsort(b)).astype(np.float64)
    return pearson(ra, rb)


# ---------------------------------------------------------------------------
# 3. Main
# ---------------------------------------------------------------------------
def main():
    device = torch.device("cpu")

    print("Loading graph / labels / dataset / model ...")
    with open(GRAPH_FILE, "r", encoding="utf-8") as f:
        graph_json = json.load(f)
    with open(LABELS_FILE, "r", encoding="utf-8") as f:
        vpss_labels_original = json.load(f)

    data, mappings, _masks = load_vulnchain_dataset(
        graph_path=str(GRAPH_FILE),
        labels_path=str(LABELS_FILE),
        repo_split_path=str(SPLIT_FILE),
    )
    pkg_id_to_idx = mappings["pkg_id_to_idx"]
    idx_to_pkg_id = mappings["idx_to_pkg_id"]
    cve_id_to_idx = mappings["cve_id_to_idx"]
    num_packages = data["Package"].num_nodes

    # --- Validation 0: labeler is bit-exact on the UNMASKED 51-repo graph ---
    unmasked_labels, unmasked_stats = recompute_vpss_labels(graph_json, set())
    fields = ("vpss", "raw_sum", "num_contributing_vulns", "min_depth_to_vuln")
    mismatches = sum(
        1 for pid, v in unmasked_labels.items()
        for k in fields if v[k] != vpss_labels_original[pid][k]
    )
    print(f"  labeler validation: {len(unmasked_labels)} packages, "
          f"{mismatches} field mismatches vs shipped labels")
    assert mismatches == 0, "VPSS labeler did not reproduce shipped labels"
    assert set(unmasked_labels) == set(vpss_labels_original)

    # --- Official eligibility + negatives, with the hard population assertion -
    own_vpss_data = compute_own_vpss(graph_json, vpss_labels_original)
    eligible_pkg_ids = select_eligible_packages(own_vpss_data, OWN_VPSS_THRESHOLD)
    never_vuln_indices = get_never_vuln_indices(
        vpss_labels_original, pkg_id_to_idx, num_packages
    )
    print(f"  eligible={len(eligible_pkg_ids)}  never_vuln={len(never_vuln_indices)}")
    assert len(eligible_pkg_ids) == EXPECTED_ELIGIBLE, (
        f"ELIGIBILITY ASSERTION FAILED: expected {EXPECTED_ELIGIBLE}, "
        f"got {len(eligible_pkg_ids)}"
    )
    assert len(never_vuln_indices) == EXPECTED_NEVER_VULN, (
        f"NEGATIVE-POPULATION ASSERTION FAILED: expected {EXPECTED_NEVER_VULN}, "
        f"got {len(never_vuln_indices)}"
    )

    model = VulnGAT()
    model.load_state_dict(torch.load(MODEL_FILE, map_location=device, weights_only=True))
    model = model.to(device)
    model.eval()

    rows = []
    sklearn_checked = False
    sklearn_max_abs_diff = None

    for seed in SEEDS:
        print(f"\n--- seed {seed} ---")

        masked_data, masked_pkg_indices, _masked_cves, _strata = apply_edge_mask(
            data, eligible_pkg_ids, pkg_id_to_idx, graph_json, cve_id_to_idx,
            MASK_RATIO, seed,
        )
        masked_pkg_ids = {
            idx_to_pkg_id[i] for i in masked_pkg_indices if i in idx_to_pkg_id
        }
        pos = list(masked_pkg_indices)

        # ---- LP_original: official LP on ORIGINAL (unmasked) closure labels ---
        lp_orig = run_label_prop_baseline(
            masked_data, vpss_labels_original,
            pkg_id_to_idx, idx_to_pkg_id, num_packages,
        )

        # ---- LP_clean: identical LP, labels recomputed on the MASKED graph ----
        masked_labels, _masked_stats = recompute_vpss_labels(graph_json, masked_pkg_ids)
        lp_clean = run_label_prop_baseline(
            masked_data, masked_labels,
            pkg_id_to_idx, idx_to_pkg_id, num_packages,
        )

        # ---- VulnGAT-HR on masked graph (dim 6 zeroed by apply_edge_mask) ----
        model_scores = run_model_inference(model, masked_data, device)

        # ---- BFS baseline (official implementation, masked graph) ------------
        bfs_scores = run_bfs_baseline(
            graph_json, masked_pkg_ids, vpss_labels_original,
            pkg_id_to_idx, num_packages,
        )

        # ---- AUC (official Wilcoxon-Mann-Whitney ROC-AUC) ---------------------
        aucs = {
            "LP_original": compute_auc(lp_orig, pos, never_vuln_indices),
            "LP_clean": compute_auc(lp_clean, pos, never_vuln_indices),
            "VulnGAT-HR": compute_auc(model_scores, pos, never_vuln_indices),
            "BFS": compute_auc(bfs_scores, pos, never_vuln_indices),
        }

        # One-off cross-check that compute_auc really is ROC-AUC (no tuning).
        if not sklearn_checked:
            try:
                from sklearn.metrics import roc_auc_score
                y = np.concatenate(
                    [np.ones(len(pos)), np.zeros(len(never_vuln_indices))]
                )
                s = np.concatenate([lp_orig[pos], lp_orig[never_vuln_indices]])
                sklearn_max_abs_diff = abs(
                    float(roc_auc_score(y, s)) - aucs["LP_original"]
                )
            except Exception as exc:                     # pragma: no cover
                sklearn_max_abs_diff = f"sklearn check unavailable: {exc}"
            sklearn_checked = True

        # ---- Changed neighbor labels -----------------------------------------
        orig_arr = vpss_array_from(vpss_labels_original, pkg_id_to_idx, num_packages)
        clean_arr = vpss_array_from(masked_labels, pkg_id_to_idx, num_packages)
        changed_mask = orig_arr != clean_arr
        changed_all = int(changed_mask.sum())

        neighbors = build_lp_neighbors(masked_data)
        pool = sorted({n for nbrs in neighbors.values() for n in nbrs})
        changed_pool = int(changed_mask[pool].sum()) if pool else 0

        row = {
            "seed": seed,
            "n_masked": len(masked_pkg_indices),
            "n_removed_edges": (
                len(graph_json["edges"]["hasVulnerability"])
                - masked_data[HAS_VULN_KEY].edge_index.size(1)
            ),
            **{f"auc_{k}": float(v) for k, v in aucs.items()},
            "changed_labels_all": changed_all,
            "changed_labels_lp_pool": changed_pool,
            "lp_pool_size": len(pool),
            "nonzero_labels_original": int((orig_arr > 0).sum()),
            "nonzero_labels_clean": int((clean_arr > 0).sum()),
            "pearson": pearson(lp_orig, lp_clean),
            "spearman": spearman(lp_orig, lp_clean),
        }
        rows.append(row)
        print("  " + "  ".join(f"{k}={aucs[k]:.6f}" for k in aucs))
        print(f"  changed labels: all={changed_all}, in LP pool={changed_pool}/"
              f"{len(pool)};  pearson(LP_orig,LP_clean)={row['pearson']:.6f}")

    # ---------------------------------------------------------------- summary
    methods = ["LP_original", "LP_clean", "VulnGAT-HR", "BFS"]
    summary = {}
    for m in methods:
        vals = np.array([r[f"auc_{m}"] for r in rows], dtype=np.float64)
        summary[m] = (float(vals.mean()), float(vals.std()))

    write_report(rows, summary, sklearn_max_abs_diff, unmasked_stats,
                 len(eligible_pkg_ids), len(never_vuln_indices), num_packages)
    print(f"\n[OK] Report written to {OUT_MD}")


# ---------------------------------------------------------------------------
# 4. Report
# ---------------------------------------------------------------------------
def write_report(rows, summary, sklearn_diff, unmasked_stats,
                 n_eligible, n_neg, num_packages):
    methods = ["LP_original", "LP_clean", "VulnGAT-HR", "BFS"]
    L = []
    A = L.append

    A("# LP Leak Check — 50% Masked-Edge Audit")
    A("")
    A("Generated by `TrainModel/masked_edge_audit_leakfix.py` (new file). "
      "No existing script, result, or data file was modified or overwritten.")
    A("")

    # ---- Step 1 verdict ----------------------------------------------------
    A("## 1. Which labels does LP use? — VERDICT: the leak is real")
    A("")
    A("`TrainModel/masked_edge_audit.py::run_label_prop_baseline` (lines 373-443) "
      "takes two inputs:")
    A("")
    A("- `data` = the **masked** `HeteroData` from `apply_edge_mask`. Its "
      "`hasVulnerability` edge_index has every edge of the masked packages "
      "removed, and `Package.x[:, 6]` is zeroed for those packages.")
    A("- `vpss_labels` = the **original** `phase4/vpss_labels_51repo.json`, "
      "loaded once in `phase5/part_c_masked_edge_multiseed.py` (line 64) and "
      "**never recomputed after masking**. `run_label_prop_baseline` builds "
      "`vpss_array` from this dict (lines 426-430).")
    A("")
    A("Neighbourhoods come from the masked graph: undirected `dependsOn` "
      "Package<->Package edges (unchanged by the mask), plus Package<->Package "
      "links for packages sharing a **surviving** CVE. The score is the plain "
      "mean of `vpss_array[n]` over those neighbours (line 439); the no-neighbour "
      "fallback is the global mean of the original labels (line 432).")
    A("")
    A("VPSS is a **closure** label. `data_pipeline/vpss_labeler.py` was verified "
      f"bit-exact against the shipped label file on all "
      f"{unmasked_stats['total_packages']:,} packages (0 field mismatches on "
      "`vpss`, `raw_sum`, `num_contributing_vulns`, `min_depth_to_vuln`):")
    A("")
    A("```text")
    A("raw(P)  = sum_d [ sum CVSS(C) over (V,C) pairs at BFS depth d ] "
      "* 0.7^d * exposure(P)")
    A("vpss(P) = round(raw(P) / (raw(P) + 10), 6)")
    A("BFS goes outward through dependsOn (source = dependent, target = dependency)")
    A("```")
    A("")
    A("**Therefore:** for a masked package P, its parents (packages that depend "
      "on P) still carry P's own CVE contribution in their VPSS at depth d, "
      "scaled by `0.7^d`. LP makes `dependsOn` undirected, so P's score is the "
      "mean of neighbour labels that include exactly the vulnerability the mask "
      "was supposed to hide. LP is partly reading the answer. The same applies "
      "to any ancestor of any masked package. `apply_edge_mask`'s dim-6 zeroing "
      "does not help: `run_label_prop_baseline` never reads `data['Package'].x`.")
    A("")
    A("The suspicion is **not** wrong, so the audit proceeds.")
    A("")

    # ---- Step 2 method -----------------------------------------------------
    A("## 2. LP_clean")
    A("")
    A("`LP_clean` is the **same** `run_label_prop_baseline()` function, called on "
      "the **same** masked `HeteroData` (identical neighbour sets), but with VPSS "
      "labels recomputed from the masked graph:")
    A("")
    A("1. `build_masked_graph()` removes every `hasVulnerability` edge whose "
      "source is a masked package. `dependsOn`, all node features, CVE nodes, "
      "and all other edges are untouched.")
    A("2. `data_pipeline/vpss_labeler.label_all()` recomputes VPSS for **all** "
      f"{num_packages:,} packages on that graph — same BFS, same `0.7^d` decay, "
      "same exposure tiers, same CVSS median-imputation, same `raw/(raw+10)` "
      "normalization, same 6-decimal rounding. Recomputing all packages (a "
      "superset of the neighbour nodes) is required because the official LP also "
      "uses the global mean over all labels for its no-neighbour fallback.")
    A("3. The official `run_label_prop_baseline()` is called with these labels. "
      "No new averaging code was written, so the only difference between "
      "`LP_original` and `LP_clean` is the label dictionary.")
    A("")
    A("The original LP is kept untouched and reported side by side.")
    A("")

    # ---- Protocol ----------------------------------------------------------
    A("## 3. Protocol (unchanged settings, no tuning)")
    A("")
    A("| Item | Value |")
    A("|---|---|")
    A(f"| Graph | `phase5/bench_run/vulnchain_graph.json` ({num_packages:,} packages, 883 CVEs, 60,789 dependsOn, 2,632 hasVulnerability) |")
    A("| Labels | `phase4/vpss_labels_51repo.json` |")
    A("| Split | `phase4/repo_split_mapping_51repo.json` |")
    A(f"| Model | `phase5/models/vulngat_hr_full.pt` (VulnGAT-HR), dim 6 zeroed for masked packages by `apply_edge_mask` |")
    A(f"| Mask | 50% at seeds {SEEDS} — `apply_edge_mask(..., 0.50, seed)` |")
    A(f"| Eligibility | official `compute_own_vpss` + `select_eligible_packages(0.70)` → **{n_eligible}** |")
    A(f"| Negatives | official `get_never_vuln_indices` → **{n_neg:,}** |")
    A("| AUC | official `compute_auc` (Wilcoxon-Mann-Whitney ROC-AUC, ties = 0.5) |")
    A("| std | population `np.std` (ddof=0), matching the published 5-seed script |")
    A("")
    A(f"Hard assertions `N_eligible == 645` and `N_never_vuln == 8682` are in the "
      f"script and **passed** ({n_eligible} / {n_neg:,}).")
    A("")

    # ---- Step 4 main table -------------------------------------------------
    A("## 4. ROC-AUC over 5 seeds (the requested table)")
    A("")
    A("| Method | Mean ± Std ROC-AUC |")
    A("|---|---|")
    for m in methods:
        mu, sd = summary[m]
        A(f"| {m} | {mu:.6f} ± {sd:.6f} |")
    A("")
    A("All numbers are exactly as produced; nothing was rounded in a favourable "
      "direction and no setting was adjusted after seeing a result.")
    A("")

    # ---- Per seed ----------------------------------------------------------
    A("### Per-seed detail")
    A("")
    A("| Seed | N masked | LP_original | LP_clean | VulnGAT-HR | BFS |")
    A("|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        A(f"| {r['seed']} | {r['n_masked']} | {r['auc_LP_original']:.6f} | "
          f"{r['auc_LP_clean']:.6f} | {r['auc_VulnGAT-HR']:.6f} | "
          f"{r['auc_BFS']:.6f} |")
    A("")

    # ---- Step 5 changed labels + correlation --------------------------------
    A("## 5. How many neighbour labels changed, and score correlation")
    A("")
    A("`changed_labels_all` = number of the 12,405 packages whose `vpss` differs "
      "between the original label file and the masked-graph recomputation. "
      "`changed_labels_lp_pool` = the same count restricted to the set of nodes "
      "that LP ever reads as a neighbour (the union of all neighbour sets built "
      "by the official adjacency). Correlation is over all 12,405 package scores.")
    A("")
    A("| Seed | Removed edges | Changed labels (all) | Changed labels (LP neighbour pool) | Pool size | Non-zero labels orig → clean | Pearson r | Spearman ρ |")
    A("|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        A(f"| {r['seed']} | {r['n_removed_edges']} | {r['changed_labels_all']:,} | "
          f"{r['changed_labels_lp_pool']:,} | {r['lp_pool_size']:,} | "
          f"{r['nonzero_labels_original']:,} → {r['nonzero_labels_clean']:,} | "
          f"{r['pearson']:.6f} | {r['spearman']:.6f} |")
    A("")
    mean_changed_all = float(np.mean([r["changed_labels_all"] for r in rows]))
    mean_changed_pool = float(np.mean([r["changed_labels_lp_pool"] for r in rows]))
    mean_pearson = float(np.mean([r["pearson"] for r in rows]))
    mean_spearman = float(np.mean([r["spearman"] for r in rows]))
    A(f"**Means across 5 seeds:** changed labels (all) = {mean_changed_all:,.1f}; "
      f"changed labels inside the LP neighbour pool = {mean_changed_pool:,.1f}; "
      f"Pearson r(LP_original, LP_clean) = {mean_pearson:.6f}; "
      f"Spearman ρ = {mean_spearman:.6f}.")
    A("")

    # ---- Validation --------------------------------------------------------
    A("## 6. Validation / cross-checks")
    A("")
    A(f"- VPSS labeler reproduces the shipped 51-repo labels **bit-exactly** on "
      f"all {unmasked_stats['total_packages']:,} packages (0 mismatches), so the "
      f"masked-graph recomputation is a formula-identical intervention, not a "
      f"different scoring scheme.")
    A(f"- `compute_auc` vs `sklearn.metrics.roc_auc_score` on seed 42 "
      f"LP_original: |Δ| = {sklearn_diff} (sanity check only; all reported "
      f"numbers use the official `compute_auc`).")
    A("- Published `phase5/part_c_masked_edge_audit_5seeds.json` reports "
      "LP_original 0.719099 ± 0.006897 and VulnGAT-HR 0.631473 ± 0.004468 on "
      "this same 5-seed protocol; the LP_original / VulnGAT-HR columns above "
      "should match it (read as a reproduction check, not used to alter anything).")
    A("")

    # ---- Discrepancies -----------------------------------------------------
    A("## 7. Where the code differs from the task description")
    A("")
    A("These are reported rather than guessed around; everything below was kept "
      "exactly as the repository does it.")
    A("")
    A("1. **Mask semantics.** `apply_edge_mask` does not remove 50% of "
      "`hasVulnerability` *edges*. It draws a Bernoulli(`mask_ratio`) per "
      "**eligible package** and removes **all** of that package's edges "
      "(plus a forced floor of 3 masked packages). So ~50% of eligible "
      "packages lose all their CVE edges; the number of edges removed is in "
      "the per-seed table above.")
    A("2. **The 5-seed 50% protocol** lives in "
      "`phase5/part_c_masked_edge_multiseed.py`, not in "
      "`TrainModel/masked_edge_audit.py::main` (which sweeps three ratios "
      "0.10/0.30/0.50 with seeds 52/72/92). The hard N=645 / N=8,682 "
      "assertions come from `phase5/run_v22_sanity.py` lines 209-210. "
      "This script combines those three official pieces without changing them.")
    A("3. **`compute_own_vpss` unit mismatch (pre-existing).** It computes "
      "`own_raw = Σ CVSS/10` but divides by `raw_sum`, which the labeler stores "
      "as `Σ CVSS` (unscaled). `own_ratio` is therefore ~10x too small, so "
      "nothing passes 0.70 and `select_eligible_packages` takes its documented "
      "auto-relaxation to 0.30 — which is exactly what produces N=645 "
      "(confirmed in `phase5/preflight_v2_rerun.py:293`). Preserved verbatim.")
    A("4. **LP docstring vs code.** The docstring says 'connected by any edge "
      "type', but the code only uses Package<->Package `dependsOn` edges plus "
      "shared-CVE Package<->Package links; all cross-type edges are skipped. "
      "`idx_to_pkg_id` is an unused parameter. `LP_original` and `LP_clean` "
      "both go through this exact code path.")
    A("5. **BFS normalization.** `run_bfs_baseline` recomputes raw risk on the "
      "masked graph but divides by `max(raw_sum)` from the **original** label "
      "file instead of the labeler's `raw/(raw+10)`. That is a single positive "
      "constant scale factor, which cannot change a rank-based ROC-AUC; it was "
      "left untouched. BFS therefore uses the masked CVE set and does not "
      "inherit the LP label leak.")
    A("6. **Negatives are shared.** `never_vuln_indices` comes from the original "
      "labels for every method (including LP_clean), matching the official "
      "protocol and keeping the comparison fair. It is not recomputed on the "
      "masked graph.")
    A("")

    # ---- Interpretation ----------------------------------------------------
    A("## 8. What the numbers mean")
    A("")
    mu_o, sd_o = summary["LP_original"]
    mu_c, sd_c = summary["LP_clean"]
    mu_m, sd_m = summary["VulnGAT-HR"]
    mu_b, sd_b = summary["BFS"]
    A(f"`LP_original` = {mu_o:.6f} ± {sd_o:.6f}; `LP_clean` = "
      f"{mu_c:.6f} ± {sd_c:.6f}; change = {mu_c - mu_o:+.6f}. "
      f"VulnGAT-HR = {mu_m:.6f} ± {sd_m:.6f}; BFS = {mu_b:.6f} ± {sd_b:.6f}.")
    A("")
    A("The gap between `LP_original` and `LP_clean` is the part of the label-"
      "propagation baseline's score that came from unmasked closure labels — "
      "i.e. leaked information — as opposed to structure the masked graph "
      "genuinely supports (surviving shared-CVE links). Note that the "
      "pre-registered success bar in `phase5/part_c_masked_edge_multiseed.py` "
      "is `mean(LP_original) + max(0.02, 2*std(LP_original))`; this report "
      "does not recompute or re-adjudicate that gate, it only quantifies the leak.")
    A("")
    A("## 9. Reproduce")
    A("")
    A("```bash")
    A("cd C:/Users/soumy/Desktop/VulnChain")
    A("python TrainModel/masked_edge_audit_leakfix.py")
    A("```")
    A("")
    A("Writes only `phase5/LP_LEAKCHECK.md`. Reads all existing files; changes none.")

    OUT_MD.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
