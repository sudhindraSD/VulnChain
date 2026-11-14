"""
masked_edge_hybrid_cs.py -- Step 3: Correct & Smooth hybrid + controls
======================================================================
NEW FILE, written on branch `hybrid-cs`. No existing script, result, label,
model or data file is modified; the only output is phase5/HYBRID_RESULT.md.

The gate was PRE-REGISTERED in phase5/HYBRID_GATE.md (standalone commit
8989cd4, parent 390d971) before any hybrid code existed. This file is the
first hybrid code. It is not a gate adjudication script by design choices:
the gate rule, comparator and fallback come verbatim from that document.

Protocol is inherited from TrainModel/masked_edge_audit_complement.py /
masked_edge_audit_leakfix.py: identical imports, official apply_edge_mask,
compute_own_vpss, select_eligible_packages(0.70), get_never_vuln_indices,
run_model_inference, run_label_prop_baseline, compute_auc, ddof=0 std, the
hard N=645 / N=8682 assertions, and the LP neighbourhood (undirected
dependsOn + shared-surviving-CVE links).

Method selection is frozen before the gate seeds are touched:
  * grid alpha x n_iter is evaluated ONLY on tuning mask seeds [52, 72, 92];
  * the argmax of mean AUC is frozen and written to the output;
  * the gate seeds [42, 123, 456, 789, 1024] are evaluated ONCE.
No retries, no second grid, no per-seed choices, no post-hoc tuning.

Usage:
  python TrainModel/masked_edge_hybrid_cs.py
  python TrainModel/masked_edge_hybrid_cs.py --base <path/to/no_dim6.pt>

--base exists so this exact script can later be rerun with a no-dim6
checkpoint. That rerun is NOT performed here (only the default
phase5/models/vulngat_hr_full.pt is used).
"""

import argparse
import sys
sys.dont_write_bytecode = True  # do not leave __pycache__ in existing folders

import json
from pathlib import Path

import numpy as np
import torch
from scipy import sparse
from sklearn.linear_model import Ridge

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "TrainModel"))
sys.path.insert(0, str(PROJECT_ROOT / "data_pipeline"))

from masked_edge_audit import (                       # noqa: E402
    compute_own_vpss,
    select_eligible_packages,
    apply_edge_mask,
    run_model_inference,
    run_label_prop_baseline,
    compute_auc,
    get_never_vuln_indices,
)
from masked_edge_audit_leakfix import (              # noqa: E402
    SEEDS as GATE_SEEDS,
    MASK_RATIO,
    OWN_VPSS_THRESHOLD,
    EXPECTED_ELIGIBLE,
    EXPECTED_NEVER_VULN,
    GRAPH_FILE,
    LABELS_FILE,
    SPLIT_FILE,
    MODEL_FILE,
    recompute_vpss_labels,
    build_lp_neighbors,
    vpss_array_from,
)
from masked_edge_audit_complement import (           # noqa: E402
    W_HR,
    W_LP,
    evaluated_indices,
    average_tie_ranks,
    embed,
)
from training.dataset import load_vulnchain_dataset   # noqa: E402
from core.model.vulngat import VulnGAT                # noqa: E402

OUT_MD = PROJECT_ROOT / "phase5" / "HYBRID_RESULT.md"

# ---------------------------------------------------------------------------
# Pre-declared constants. None of these is changed after results are seen.
# ---------------------------------------------------------------------------
TUNING_SEEDS = [52, 72, 92]                  # disjoint from GATE_SEEDS
ALPHA_GRID = [0.5, 0.7, 0.8, 0.9]
ITER_GRID = [10, 25, 50]
GRID = [(a, n) for a in ALPHA_GRID for n in ITER_GRID]   # fixed iteration order
# Tie-break: strict '>' keeps the FIRST combo in GRID order (lowest alpha,
# then lowest n_iter). Declared before the grid is run.

BOOTSTRAP_ITERS = 1000
BOOTSTRAP_SEED = 20261114
PERM_SEED_BASE = 20261114
SANITY_TOL = 0.05                # "near 0.5" = |mean AUC - 0.5| <= 0.05
CI_LOW_PCT, CI_HIGH_PCT = 2.5, 97.5
RIDGE_ALPHA = 1.0                # repo's reported ridge-raw value (val-MSE selected)

EXPECTED_HR_MEAN = 0.6314725216034925   # part_c_masked_edge_audit_5seeds.json
EXPECTED_LP_MEAN = 0.632905             # phase5/LP_LEAKCHECK.md
EXPECTED_RANKAVG_MEAN = 0.692055        # phase5/COMPLEMENT_CHECK.md
REPRO_TOL = 1e-6

METHODS = [
    "HR",
    "LP_clean",
    "RANK_AVG(HR,LP)",
    "C&S hybrid",
    "RIDGE_RAW",
    "RANK_AVG(RIDGE,LP)",
    "C&S RIDGE base",
    "Sanity (permuted)",
]

# Human-readable column headers used in the report / stdout.
HEADERS = [
    "HR", "LP_clean", "rank-avg(HR,LP)", "C&S hybrid",
    "RIDGE_RAW", "rank-avg(RIDGE,LP)", "C&S ridge base", "sanity perm.",
]


# ---------------------------------------------------------------------------
# Correct & Smooth (new code)
# ---------------------------------------------------------------------------
def normalized_adjacency(neighbors: dict, n: int):
    """Symmetrically normalised adjacency with self-loops, over EXACTLY the
    same neighbourhood that run_label_prop_baseline uses (undirected
    dependsOn + shared-surviving-CVE Package<->Package links).

        A = adjacency + I ;  S = D^(-1/2) A D^(-1/2)
    Duplicate (i,j) entries are collapsed to a binary 1 (A.data[:] = 1).
    Declared once; no per-seed choices.
    """
    rows = list(range(n))
    cols = list(range(n))
    for i, nbrs in neighbors.items():
        for j in nbrs:
            rows.append(int(i))
            cols.append(int(j))
    data = np.ones(len(rows), dtype=np.float64)
    A = sparse.coo_matrix((data, (rows, cols)), shape=(n, n)).tocsr()
    A.data[:] = 1.0                       # binary adjacency, no multi-edge weights
    deg = np.asarray(A.sum(axis=1)).ravel()
    inv = np.zeros(n, dtype=np.float64)
    nz = deg > 0
    inv[nz] = 1.0 / np.sqrt(deg[nz])
    D = sparse.diags(inv)
    return (D @ A @ D).tocsr()


def correct_and_smooth(base, labels, known, S, alpha, n_iter, labels_smooth=None):
    """Two-step Correct & Smooth.

    Correct: E0 = (labels - base) on known, 0 on unknown;
             E <- (1-alpha)*E0 + alpha * S @ E   (n_iter);
             corrected = base + E.  No residual scaling (per spec).

    Smooth:  Y0 = corrected, with the known labels FIXED in the anchor
             (Y0[known] = labels_smooth[known]);
             Y  <- (1-alpha)*Y0 + alpha * S @ Y  (n_iter, same alpha/n_iter).
             Known nodes are NOT re-clamped on every iteration: the recurrence
             mirrors the explicitly specified correct-step recurrence and the
             C&S paper's Algorithm 1. 'Fixed' refers to the anchor Y0.

    labels_smooth exists only for the permuted-label sanity control; it is
    passed identically to BOTH steps so that control destroys label signal
    everywhere.
    """
    if labels_smooth is None:
        labels_smooth = labels
    base = np.asarray(base, dtype=np.float64)
    labels = np.asarray(labels, dtype=np.float64)
    labels_smooth = np.asarray(labels_smooth, dtype=np.float64)

    E0 = np.zeros(base.shape[0], dtype=np.float64)
    E0[known] = labels[known] - base[known]
    E = E0.copy()
    for _ in range(n_iter):
        E = (1.0 - alpha) * E0 + alpha * (S @ E)
    corrected = base + E

    Y0 = corrected.copy()
    Y0[known] = labels_smooth[known]
    Y = Y0.copy()
    for _ in range(n_iter):
        Y = (1.0 - alpha) * Y0 + alpha * (S @ Y)
    return Y


def rank_avg_scores(a_full, b_full, eval_idx, n):
    """Equal-weight average of average-tie ranks over the evaluated set,
    embedded back so the OFFICIAL compute_auc can consume it unchanged."""
    fused = W_HR * average_tie_ranks(a_full[eval_idx]) \
        + W_LP * average_tie_ranks(b_full[eval_idx])
    return embed(n, eval_idx, fused)


def ridge_raw_scores(masked_data, labels_clean, train_mask):
    """Ridge on the 10 raw Package features (dim 6 zeroed for masked packages
    by apply_edge_mask), fitted on the train split with the repo's ridge-raw
    recipe: Ridge(alpha=1.0) (the val-MSE-selected value reported in
    phase5/WORKER_REPORT_PHASE5.md and phase5/phase2a_mlp_reconverge.py),
    followed by the archived diagnostic's sigmoid on predictions.

    Target = label_clean (VPSS recomputed on the MASKED graph), NOT the
    original labels, per phase5/HYBRID_GATE.md section 3. See report section
    'Protocol decisions' for this documented deviation.
    """
    X = masked_data["Package"].x.detach().cpu().numpy().astype(np.float64)
    tr = np.asarray(train_mask.detach().cpu().numpy(), dtype=bool)
    ridge = Ridge(alpha=RIDGE_ALPHA).fit(X[tr], labels_clean[tr])
    p = ridge.predict(X)
    return 1.0 / (1.0 + np.exp(-p))


def bootstrap_ci(pairs, iters, seed):
    """Percentile bootstrap over the 5 paired differences (informational)."""
    rng = np.random.RandomState(seed)
    arr = np.asarray(pairs, dtype=np.float64)
    means = np.empty(iters, dtype=np.float64)
    for k in range(iters):
        idx = rng.randint(0, arr.size, size=arr.size)
        means[k] = arr[idx].mean()
    return (float(means.mean()),
            float(np.percentile(means, CI_LOW_PCT)),
            float(np.percentile(means, CI_HIGH_PCT)),
            float(means.std(ddof=0)))


# ---------------------------------------------------------------------------
# Per-seed preparation (one mask instance, shared by every method)
# ---------------------------------------------------------------------------
def parse_args():
    ap = argparse.ArgumentParser(
        description="Step 3: Correct & Smooth hybrid + controls (pre-registered gate)"
    )
    ap.add_argument(
        "--base", default=str(MODEL_FILE),
        help="Path to the base checkpoint. Default: phase5/models/vulngat_hr_full.pt. "
             "A no-dim6 checkpoint can be supplied here later; that rerun is NOT done here.",
    )
    return ap.parse_args()


def prepare_seed(seed, ctx):
    """Compute, for ONE mask instance: masked_data, pos, clean labels, HR,
    LP_clean, RIDGE_RAW, known/unknown masks, normalised adjacency.
    All methods in the report are derived from this single shared object."""
    masked_data, masked_idx_set, _cves, _strata = apply_edge_mask(
        ctx["data"], ctx["eligible"], ctx["pkg_id_to_idx"], ctx["graph_json"],
        ctx["cve_id_to_idx"], MASK_RATIO, seed,
    )
    masked_pkg_ids = {
        ctx["idx_to_pkg_id"][i] for i in masked_idx_set
        if i in ctx["idx_to_pkg_id"]
    }
    pos = list(masked_idx_set)
    neg = ctx["never_vuln_indices"]
    n = ctx["num_packages"]

    masked_labels, _stats = recompute_vpss_labels(ctx["graph_json"], masked_pkg_ids)
    y_clean = vpss_array_from(
        masked_labels, ctx["pkg_id_to_idx"], n
    ).astype(np.float64)

    hr = run_model_inference(ctx["model"], masked_data, ctx["device"]).astype(np.float64)
    lp = run_label_prop_baseline(
        masked_data, masked_labels, ctx["pkg_id_to_idx"], ctx["idx_to_pkg_id"], n
    ).astype(np.float64)
    ridge = ridge_raw_scores(masked_data, y_clean, ctx["train_mask"])

    neighbors = build_lp_neighbors(masked_data)
    S = normalized_adjacency(neighbors, n)

    known = np.ones(n, dtype=bool)
    known[pos] = False                       # masked = unknown; NEVER treated as known

    return {
        "seed": seed,
        "pos": pos,
        "neg": neg,
        "eval_idx": evaluated_indices(pos, neg),
        "y_clean": y_clean,
        "hr": hr,
        "lp": lp,
        "ridge": ridge,
        "known": known,
        "S": S,
        "n": n,
        "n_known": int(known.sum()),
        "n_unknown": int((~known).sum()),
    }


def evaluate_gate_seed(sd, alpha, n_iter):
    """All 8 reported columns for one gate seed, with the FROZEN parameters."""
    pos, neg, n = sd["pos"], sd["neg"], sd["n"]

    cs_hr = correct_and_smooth(
        sd["hr"], sd["y_clean"], sd["known"], sd["S"], alpha, n_iter
    )
    cs_ridge = correct_and_smooth(
        sd["ridge"], sd["y_clean"], sd["known"], sd["S"], alpha, n_iter
    )

    # Sanity control: permute label_clean AMONG KNOWN NODES ONLY; use the
    # permuted vector in BOTH C&S steps. Deterministic, declared seed.
    rng = np.random.RandomState(PERM_SEED_BASE + sd["seed"])
    k_idx = np.flatnonzero(sd["known"])
    y_perm = sd["y_clean"].copy()
    y_perm[k_idx] = sd["y_clean"][k_idx][rng.permutation(k_idx.size)]
    cs_perm = correct_and_smooth(
        sd["hr"], y_perm, sd["known"], sd["S"], alpha, n_iter,
        labels_smooth=y_perm,
    )

    rank_hr_lp = rank_avg_scores(sd["hr"], sd["lp"], sd["eval_idx"], n)
    rank_ridge_lp = rank_avg_scores(sd["ridge"], sd["lp"], sd["eval_idx"], n)

    return {
        "seed": sd["seed"],
        "HR": compute_auc(sd["hr"], pos, neg),
        "LP_clean": compute_auc(sd["lp"], pos, neg),
        "RANK_AVG(HR,LP)": compute_auc(rank_hr_lp, pos, neg),
        "C&S hybrid": compute_auc(cs_hr, pos, neg),
        "RIDGE_RAW": compute_auc(sd["ridge"], pos, neg),
        "RANK_AVG(RIDGE,LP)": compute_auc(rank_ridge_lp, pos, neg),
        "C&S RIDGE base": compute_auc(cs_ridge, pos, neg),
        "Sanity (permuted)": compute_auc(cs_perm, pos, neg),
        "n_known": sd["n_known"],
        "n_unknown": sd["n_unknown"],
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def table_line(cells):
    return "| " + " | ".join(str(c) for c in cells) + " |"


def write_report(ctx, tuning, grid_means, grid_per_seed, best, gate_rows,
                 summary, checks, sanity_mean, harness_broken, gate, boot,
                 gap, gap_boot, base_path):
    L = []
    A = L.append
    alpha, n_iter = best
    try:
        base_disp = base_path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        base_disp = str(base_path)

    A("# Step 3 — Correct & Smooth Hybrid + Controls")
    A("")
    A(f"Branch `hybrid-cs` · generated by `TrainModel/masked_edge_hybrid_cs.py` "
      f"(new file) · base checkpoint `{base_disp}`.")
    A("")
    A("Pre-registration: `phase5/HYBRID_GATE.md` was committed **on its own** in "
      "`8989cd4` (parent `390d971`) before any hybrid code existed. That file is "
      "unchanged. This is the first hybrid evaluation and it uses the gate exactly "
      "as written. No existing script, result, label, model or data file was modified.")
    A("")

    A("## 1. Protocol (inherited, no tuning of protocol)")
    A("")
    A("| Item | Value |")
    A("|---|---|")
    A(f"| Gate (evaluation) seeds | `{GATE_SEEDS}` |")
    A(f"| Tuning (selection) seeds | `{TUNING_SEEDS}` — disjoint from gate seeds |")
    A(f"| Mask | `{MASK_RATIO:.2f}` via official `apply_edge_mask`, identical mask instance per seed for every method |")
    A(f"| Graph / labels / split | `phase5/bench_run/vulnchain_graph.json`, `phase4/vpss_labels_51repo.json`, `phase4/repo_split_mapping_51repo.json` |")
    A(f"| Eligibility | official `compute_own_vpss` + `select_eligible_packages({OWN_VPSS_THRESHOLD:.2f})` → **{ctx['n_eligible']}** |")
    A(f"| Negatives | official `get_never_vuln_indices` → **{len(ctx['never_vuln_indices']):,}** |")
    A("| AUC | official `compute_auc` (Wilcoxon–Mann–Whitney, ties = 0.5) |")
    A("| std | population `np.std` (`ddof=0`) across seeds |")
    A(f"| Hard asserts | `N_eligible == {EXPECTED_ELIGIBLE}`, `N_never_vuln == {EXPECTED_NEVER_VULN}` — **passed** |")
    A("| C&S neighbourhood | identical to `run_label_prop_baseline`: undirected `dependsOn` + shared-surviving-CVE Package↔Package links |")
    A("| Normalised adjacency | `S = D^(-1/2) (A+I) D^(-1/2)`, binary edges |")
    A("| C&S labels | `vpss_labeler.label_all()` on the **MASKED** graph (`label_clean`), never the original labels |")
    A("| Known / unknown | known = every package NOT masked; unknown = masked packages (residual 0, never known) |")
    A(f"| Base model | VulnGAT-HR, `Package.x[:,6]` zeroed for masked packages by `apply_edge_mask` |")
    A(f"| `--base` | `{base_disp}` (default). A no-dim6 rerun is supported but **NOT performed here** |")
    A("")

    A("### Protocol decisions where the specification was underdetermined")
    A("")
    A("These were fixed **before** the run and are reported so nothing is hidden; "
      "they were not changed after seeing any result.")
    A("")
    A("1. **Smooth-step recurrence.** Both steps use the same recurrence form "
      "`X <- (1-alpha)*X0 + alpha*S@X` for `n_iter` iterations, matching the "
      "explicitly specified correct-step formula and 'same alpha / n_iter'. "
      "Known labels are fixed in the anchor `Y0` (`Y0[known] = label_clean[known]`); "
      "known nodes are **not** re-clamped on every iteration. Some C&S "
      "implementations do re-clamp; that variant was not used.")
    A("2. **No residual scaling / no autoscale.** The spec says E is 'added to "
      "base scores'; no learned scale factor is applied.")
    A("3. **Ridge target.** The repo's ridge-raw recipe is "
      "`Ridge(alpha=1.0)` on the 10 raw Package features fitted on "
      "`masks['train_mask']`, with the archived diagnostic's sigmoid applied to "
      "predictions (`phase5/phase2a_mlp_reconverge.py`, "
      "`phase5/WORKER_REPORT_PHASE5.md`, `phase5/part_c_epss_arms.py`). Its "
      "regression target is here `label_clean` (masked-graph VPSS), **not** the "
      "repo's `data['Package'].y`, because `HYBRID_GATE.md` §3 forbids original "
      "labels in label-consuming hybrid components. `alpha=1.0` is used directly "
      "(the repo's reported val-MSE-selected value) so no second grid is run.")
    A("4. **Adjacency normalisation, tie-break, RNG seeds, sanity tolerance** are "
      f"declared as module constants: symmetric normalisation with self-loops; "
      f"strict-`>` grid selection (first combo wins ties); bootstrap seed "
      f"`{BOOTSTRAP_SEED}`, permutation seed `{PERM_SEED_BASE}+seed`, "
      f"`SANITY_TOL = {SANITY_TOL}` ('near 0.5' = |mean − 0.5| ≤ 0.05).")
    A("")

    # ---- Tuning ------------------------------------------------------------
    A("## 2. Hyperparameter selection — tuning seeds only")
    A("")
    A(f"Grid: alpha ∈ `{ALPHA_GRID}`, n_iter ∈ `{ITER_GRID}` → {len(GRID)} combos. "
      "Selection statistic = mean C&S hybrid AUC over tuning mask seeds "
      f"`{TUNING_SEEDS}`. Both C&S steps share alpha and n_iter. **One grid, no retries.**")
    A("")
    A("| alpha | n_iter | AUC seed 52 | AUC seed 72 | AUC seed 92 | mean | selected |")
    A("|---:|---:|---:|---:|---:|---:|:---:|")
    for key in GRID:
        a, k = key
        vals = grid_per_seed[key]
        A(f"| {a} | {k} | {vals[0]:.6f} | {vals[1]:.6f} | {vals[2]:.6f} | "
          f"{grid_means[key]:.6f} | {'**FROZEN**' if key == best else ''} |")
    A("")
    A(f"**Frozen parameters: alpha = {alpha}, n_iter = {n_iter}** "
      f"(tuning mean AUC = {grid_means[best]:.6f}). Applied unchanged to all "
      "gate seeds and to every C&S variant below.")
    A("")

    # ---- Main results ------------------------------------------------------
    A("## 3. Gate-seed results — per-seed rows and mean ± std")
    A("")
    A("| Seed | " + " | ".join(HEADERS) + " |")
    A("|---:|" + "---:|" * len(METHODS))
    for r in gate_rows:
        A(table_line([r["seed"]] + [f"{r[m]:.6f}" for m in METHODS]))
    A(table_line(["mean ± std"] + [
        f"{summary[m][0]:.6f} ± {summary[m][1]:.6f}" for m in METHODS
    ]))
    A("")
    A("All AUC values use the official `compute_auc`; std is population "
      "(`ddof=0`) across the 5 gate seeds. `Sanity (permuted)` is method 8.")
    A("")

    # ---- Sanity ------------------------------------------------------------
    A("## 4. Sanity control")
    A("")
    A("`label_clean` is randomly permuted **among known nodes only**; the "
      "permuted vector is fed to BOTH C&S steps. Frozen alpha / n_iter, "
      "identical masks. Expectation: near 0.5.")
    A("")
    A("| Seed | C&S hybrid | C&S with permuted labels |")
    A("|---:|---:|---:|")
    for r in gate_rows:
        A(f"| {r['seed']} | {r['C&S hybrid']:.6f} | {r['Sanity (permuted)']:.6f} |")
    A(f"| mean | {summary['C&S hybrid'][0]:.6f} | {sanity_mean:.6f} |")
    A("")
    A(f"|mean(sanity) − 0.5| = {abs(sanity_mean - 0.5):.6f}, tolerance "
      f"{SANITY_TOL} → **{'PASS (harness OK)' if not harness_broken else 'FAIL — HARNESS BROKEN'}**.")
    A("")
    if harness_broken:
        A("> **STOPPED — HARNESS BROKEN.** Per the task instruction, no gate "
          "verdict, no bootstrap interpretation and no ridge-control statement "
          "are produced. The raw tables above are reported as-is; nothing was "
          "fixed by tuning.")
        A("")
        write_md(L)
        return

    # ---- Gate --------------------------------------------------------------
    A("## 5. Gate adjudication (exactly as written in `HYBRID_GATE.md`)")
    A("")
    A("`delta_s = AUC(C&S hybrid) − AUC(LP_clean)`, paired by seed on identical "
      "masks. PASS iff `mean(delta) > max(0.02, 2 * std_pop(LP_clean))`.")
    A("")
    A("| Seed | C&S hybrid | LP_clean | paired delta |")
    A("|---:|---:|---:|---:|")
    for r in gate_rows:
        A(f"| {r['seed']} | {r['C&S hybrid']:.6f} | {r['LP_clean']:.6f} | "
          f"{r['C&S hybrid'] - r['LP_clean']:+.6f} |")
    A("")
    A(f"- `mean(delta)` = **{gate['mean_diff']:+.6f}**")
    A(f"- `std_pop(LP_clean)` = {gate['lp_std']:.6f}; "
      f"`2*std` = {2*gate['lp_std']:.6f}; "
      f"`max(0.02, 2*std)` = **{gate['margin']:.6f}**")
    A(f"- Frozen bar from `HYBRID_GATE.md`: `mean(LP_clean) + margin` = "
      f"{gate['lp_mean']:.6f} + {gate['margin']:.6f} = {gate['bar']:.6f}; "
      f"mean(C&S hybrid) = {gate['hybrid_mean']:.6f}")
    A(f"- **{'PASS' if gate['pass'] else 'FAIL'}** "
      f"(mean delta {gate['mean_diff']:+.6f} vs margin {gate['margin']:.6f}).")
    A("")
    A("Both comparators are reported as required by the amendment: the superseded "
      "leaky gate was `LP_original + 0.02 = 0.739099` (VulnGAT-HR FAILED); the "
      "amended comparator here is `LP_clean`.")
    A("")

    # ---- Bootstrap ---------------------------------------------------------
    A("## 6. Paired difference with / without bootstrap CI (informational)")
    A("")
    A(f"{BOOTSTRAP_ITERS} resamples of the 5 paired differences, "
      f"`RandomState({BOOTSTRAP_SEED})`, percentile CI "
      f"[{CI_LOW_PCT}, {CI_HIGH_PCT}]. Not used for the gate decision.")
    A("")
    A("| Statistic | Value |")
    A("|---|---:|")
    A(f"| mean paired delta (no bootstrap) | {gate['mean_diff']:+.6f} |")
    A(f"| bootstrap mean of resampled means | {boot[0]:+.6f} |")
    A(f"| bootstrap {CI_HIGH_PCT-CI_LOW_PCT:.0f}% percentile CI | "
      f"[{boot[1]:+.6f}, {boot[2]:+.6f}] |")
    A(f"| bootstrap std of resampled means (ddof=0) | {boot[3]:.6f} |")
    A("")

    # ---- Ridge control -----------------------------------------------------
    A("## 7. Ridge control gap")
    A("")
    A("`(C&S with HR base) − (C&S with RIDGE_RAW base)`, paired by seed. "
      "'Within noise' is pre-declared as: the 95% bootstrap percentile CI of "
      "the paired gap contains 0.")
    A("")
    A("| Seed | C&S HR base | C&S ridge base | gap |")
    A("|---:|---:|---:|---:|")
    for r in gate_rows:
        A(f"| {r['seed']} | {r['C&S hybrid']:.6f} | {r['C&S RIDGE base']:.6f} | "
          f"{r['C&S hybrid'] - r['C&S RIDGE base']:+.6f} |")
    A("")
    A(f"- mean gap = {gap['mean']:+.6f} ± {gap['std']:.6f} (population std)")
    A(f"- bootstrap 95% CI = [{gap_boot[1]:+.6f}, {gap_boot[2]:+.6f}] → "
      f"{'within noise (CI contains 0)' if gap['within_noise'] else 'not within noise (CI excludes 0)'}")
    A("")
    if gap["within_noise"]:
        A("The GNN is not contributing beyond raw features.")
    else:
        A("The ridge control gap is not within noise; no interpretation is added.")
    A("")

    # ---- Validation --------------------------------------------------------
    A("## 8. Validation / reproduction checks")
    A("")
    A("| Check | Expected | Observed | Status |")
    A("|---|---:|---:|:---:|")
    for c in checks:
        A(f"| {c['name']} | {c['expected']:.9f} | {c['observed']:.9f} | "
          f"{'OK' if c['ok'] else 'FAILED'} |")
    A("")
    A("The VPSS labeler was revalidated bit-exactly on the unmasked 51-repo "
      f"graph ({ctx['n_packages']:,} packages, 0 field mismatches). "
      f"Known / unknown split per seed: {gate_rows[0]['n_known']:,} / "
      f"{gate_rows[0]['n_unknown']} (varies slightly with the mask).")
    A("")

    # ---- Limitations -------------------------------------------------------
    A("## 9. Limitations carried into the paper (from `HYBRID_GATE.md`)")
    A("")
    A("1. `compute_own_vpss` unit mismatch (`own_raw = Σ CVSS/10` divided by "
      "unscaled `raw_sum`) forces the documented 0.30 auto-relaxation → N=645.")
    A("2. `apply_edge_mask` removes **all** CVE edges of ~50% of eligible "
      "*packages*, not 50% of edges (plus a forced floor of 3).")
    A("3. Negatives are shared from the **original** labels for every method "
      "and are not recomputed on the masked graph.")
    A("")
    A("Additional structural facts of this protocol, stated without interpretation: "
      "the unknown set is exactly the masked positives and the never-vulnerable "
      "negatives are always in the known set; therefore known/unknown status is "
      "aligned with the evaluation class partition, and `label_clean` is 0 for "
      "every negative. The smooth-step anchor `Y0[known] = label_clean[known]` "
      "carries that fact into the final score vector.")
    A("")

    A("## 10. Reproduce")
    A("")
    A("```bash")
    A("cd C:/Users/soumy/Desktop/VulnChain")
    A("git checkout hybrid-cs")
    A("python TrainModel/masked_edge_hybrid_cs.py")
    A("# optional future rerun (NOT performed here):")
    A("# python TrainModel/masked_edge_hybrid_cs.py --base <no-dim6 checkpoint>.pt")
    A("```")
    A("")
    A("Writes only `phase5/HYBRID_RESULT.md`. If the gate is not met, "
      "`HYBRID_GATE.md` §4 pre-declares this as a negative result with no "
      "further tuning on these seeds.")
    write_md(L)


def write_md(lines):
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_failure_report(text, detail):
    write_md([
        "# Step 3 — Correct & Smooth Hybrid + Controls: FAILED",
        "",
        f"**{text}**",
        "",
        detail,
        "",
        "Per the task instruction this is reported, not fixed by tuning. "
        "`phase5/HYBRID_GATE.md` (commit `8989cd4`) is unchanged.",
    ])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()
    base_path = Path(args.base)
    if not base_path.is_absolute():
        base_path = PROJECT_ROOT / base_path
    if not base_path.is_file():
        write_failure_report("BASE CHECKPOINT NOT FOUND", f"`{base_path}`")
        print(f"[FAILED] base checkpoint not found: {base_path}")
        return

    device = torch.device("cpu")
    print("Loading graph / labels / dataset / model ...")
    with open(GRAPH_FILE, "r", encoding="utf-8") as f:
        graph_json = json.load(f)
    with open(LABELS_FILE, "r", encoding="utf-8") as f:
        vpss_labels_original = json.load(f)

    data, mappings, masks = load_vulnchain_dataset(
        graph_path=str(GRAPH_FILE),
        labels_path=str(LABELS_FILE),
        repo_split_path=str(SPLIT_FILE),
    )
    pkg_id_to_idx = mappings["pkg_id_to_idx"]
    idx_to_pkg_id = mappings["idx_to_pkg_id"]
    cve_id_to_idx = mappings["cve_id_to_idx"]
    num_packages = data["Package"].num_nodes
    train_mask = masks["train_mask"]

    # Validation 0: labeler bit-exact on UNMASKED graph.
    unmasked_labels, _ustats = recompute_vpss_labels(graph_json, set())
    fields = ("vpss", "raw_sum", "num_contributing_vulns", "min_depth_to_vuln")
    mismatches = sum(
        1 for pid, v in unmasked_labels.items()
        for k in fields if v[k] != vpss_labels_original[pid][k]
    )
    print(f"  labeler validation: {len(unmasked_labels)} packages, "
          f"{mismatches} field mismatches")
    assert mismatches == 0, "VPSS labeler did not reproduce shipped labels"

    # HARD ASSERTS (required).
    own_vpss_data = compute_own_vpss(graph_json, vpss_labels_original)
    eligible = select_eligible_packages(own_vpss_data, OWN_VPSS_THRESHOLD)
    never_vuln_indices = get_never_vuln_indices(
        vpss_labels_original, pkg_id_to_idx, num_packages
    )
    print(f"  eligible={len(eligible)}  never_vuln={len(never_vuln_indices)}")
    assert len(eligible) == EXPECTED_ELIGIBLE, (
        f"ELIGIBILITY ASSERTION FAILED: expected {EXPECTED_ELIGIBLE}, "
        f"got {len(eligible)}"
    )
    assert len(never_vuln_indices) == EXPECTED_NEVER_VULN, (
        f"NEGATIVE-POPULATION ASSERTION FAILED: expected {EXPECTED_NEVER_VULN}, "
        f"got {len(never_vuln_indices)}"
    )

    model = VulnGAT()
    model.load_state_dict(torch.load(base_path, map_location=device, weights_only=True))
    model = model.to(device)
    model.eval()

    ctx = {
        "data": data,
        "graph_json": graph_json,
        "pkg_id_to_idx": pkg_id_to_idx,
        "idx_to_pkg_id": idx_to_pkg_id,
        "cve_id_to_idx": cve_id_to_idx,
        "num_packages": num_packages,
        "n_packages": num_packages,
        "n_eligible": len(eligible),
        "eligible": eligible,
        "never_vuln_indices": never_vuln_indices,
        "train_mask": train_mask,
        "model": model,
        "device": device,
    }

    # ---------------------------------------------------------------- tuning
    print(f"\n=== TUNING: grid of {len(GRID)} combos on seeds {TUNING_SEEDS} ===")
    tuning_data = []
    for s in TUNING_SEEDS:
        print(f"  preparing tuning seed {s} ...")
        tuning_data.append(prepare_seed(s, ctx))

    grid_per_seed = {}
    grid_means = {}
    for key in GRID:
        a, k = key
        vals = []
        for sd in tuning_data:
            final = correct_and_smooth(
                sd["hr"], sd["y_clean"], sd["known"], sd["S"], a, k
            )
            vals.append(compute_auc(final, sd["pos"], sd["neg"]))
        grid_per_seed[key] = vals
        grid_means[key] = float(np.mean(vals))
        print(f"  alpha={a} n_iter={k:2d}: mean AUC={grid_means[key]:.6f}")

    best = None
    for key in GRID:                     # strict '>' => first combo wins ties
        if best is None or grid_means[key] > grid_means[best]:
            best = key
    alpha_frozen, n_iter_frozen = best
    print(f"  FROZEN: alpha={alpha_frozen}, n_iter={n_iter_frozen} "
          f"(mean={grid_means[best]:.6f})")

    # ------------------------------------------------------------ gate seeds
    print(f"\n=== GATE: ONE evaluation on seeds {list(GATE_SEEDS)} "
          f"with frozen alpha={alpha_frozen}, n_iter={n_iter_frozen} ===")
    gate_rows = []
    for s in GATE_SEEDS:
        sd = prepare_seed(s, ctx)
        row = evaluate_gate_seed(sd, alpha_frozen, n_iter_frozen)
        gate_rows.append(row)
        print(f"  seed {s}: " + "  ".join(
            f"{m}={row[m]:.6f}" for m in METHODS[:4]
        ))

    summary = {}
    for m in METHODS:
        vals = np.array([r[m] for r in gate_rows], dtype=np.float64)
        summary[m] = (float(vals.mean()), float(vals.std(ddof=0)))

    sanity_mean = summary["Sanity (permuted)"][0]
    harness_broken = abs(sanity_mean - 0.5) > SANITY_TOL

    # Reproduction checks (reported, not used to alter anything).
    checks = [
        {"name": "HR mean vs published 5-seed JSON",
         "expected": EXPECTED_HR_MEAN, "observed": summary["HR"][0]},
        {"name": "LP_clean mean vs LP_LEAKCHECK.md",
         "expected": EXPECTED_LP_MEAN, "observed": summary["LP_clean"][0]},
        {"name": "rank-avg(HR,LP) mean vs COMPLEMENT_CHECK.md",
         "expected": EXPECTED_RANKAVG_MEAN,
         "observed": summary["RANK_AVG(HR,LP)"][0]},
    ]
    for c in checks:
        c["ok"] = abs(c["observed"] - c["expected"]) < REPRO_TOL

    # Gate, bootstrap, ridge gap.
    paired = [r["C&S hybrid"] - r["LP_clean"] for r in gate_rows]
    lp_std = summary["LP_clean"][1]
    margin = max(0.02, 2.0 * lp_std)
    gate = {
        "mean_diff": float(np.mean(paired)),
        "lp_std": lp_std,
        "lp_mean": summary["LP_clean"][0],
        "hybrid_mean": summary["C&S hybrid"][0],
        "margin": float(margin),
        "bar": float(summary["LP_clean"][0] + margin),
        "pass": bool(np.mean(paired) > margin),
        "paired": paired,
    }
    boot = bootstrap_ci(paired, BOOTSTRAP_ITERS, BOOTSTRAP_SEED)

    gap_pairs = [r["C&S hybrid"] - r["C&S RIDGE base"] for r in gate_rows]
    gap_boot = bootstrap_ci(gap_pairs, BOOTSTRAP_ITERS, BOOTSTRAP_SEED)
    gap = {
        "mean": float(np.mean(gap_pairs)),
        "std": float(np.std(gap_pairs, ddof=0)),
        "within_noise": bool(gap_boot[1] <= 0.0 <= gap_boot[2]),
    }

    write_report(ctx, tuning_data, grid_means, grid_per_seed, best, gate_rows,
                 summary, checks, sanity_mean, harness_broken, gate, boot,
                 gap, gap_boot, base_path)

    # ---------------------------------------------------------------- stdout
    print("\n" + "=" * 100)
    print("MAIN RESULTS (gate seeds)")
    print("=" * 100)
    print(table_line(["Seed"] + HEADERS))
    print(table_line(["---"] * (len(METHODS) + 1)))
    for r in gate_rows:
        print(table_line([r["seed"]] + [f"{r[m]:.6f}" for m in METHODS]))
    print(table_line(["mean ± std"] + [
        f"{summary[m][0]:.6f} ± {summary[m][1]:.6f}" for m in METHODS
    ]))
    print(f"\nFROZEN: alpha={alpha_frozen}, n_iter={n_iter_frozen}")
    print(f"SANITY: mean={sanity_mean:.6f}, |mean-0.5|="
          f"{abs(sanity_mean - 0.5):.6f}, tol={SANITY_TOL} -> "
          f"{'FAIL: HARNESS BROKEN' if harness_broken else 'PASS'}")
    if not harness_broken:
        print(f"GATE: mean(delta)={gate['mean_diff']:+.6f} vs "
              f"max(0.02, 2*std(LP_clean))={gate['margin']:.6f} -> "
              f"{'PASS' if gate['pass'] else 'FAIL'}")
        print(f"BOOTSTRAP: no-CI mean={gate['mean_diff']:+.6f}; "
              f"with-CI mean={boot[0]:+.6f} "
              f"[{boot[1]:+.6f}, {boot[2]:+.6f}]")
        print(f"RIDGE GAP: mean={gap['mean']:+.6f} ± {gap['std']:.6f}, "
              f"CI=[{gap_boot[1]:+.6f}, {gap_boot[2]:+.6f}], "
              f"within_noise={gap['within_noise']}")
        if gap["within_noise"]:
            print("The GNN is not contributing beyond raw features.")
    else:
        print("STOPPED: harness broken. Gate not adjudicated. See HYBRID_RESULT.md.")
    for c in checks:
        print(f"CHECK: {c['name']}: {c['observed']:.9f} vs "
              f"{c['expected']:.9f} -> {'OK' if c['ok'] else 'FAILED'}")
    print(f"\n[OK] Report written to {OUT_MD}")


if __name__ == "__main__":
    main()
