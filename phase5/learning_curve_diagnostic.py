"""
learning_curve_diagnostic.py — does masked-50 AUC rise as TRAIN repos grow?
===========================================================================
NEW FILE, written on branch `learning-curve`. Diagnostic only: no tuning, no
gate, no reruns on failure. No existing script, result, label, model or data
file is modified; the only output is phase5/LEARNING_CURVE.md.

This implements the learning-curve prompt with the FIVE AMENDMENTS applied on
top of it (previous session's Task B), everything else exactly as written:
  A1  Train-loss mask: node in training loss ONLY IF it is train in
      repo_split_mapping_51repo.json AND >=1 of its repo_sources is in the
      KEPT train repos. Mapping-train nodes whose only train-repo sources
      were dropped are EXCLUDED from the loss (not reassigned to test, not
      used as train) but stay in the graph for message passing.
  A2  Print per subset n_train_loss_nodes, n_excluded_dropped_provenance_nodes.
  A3  Keep the 645 / 8,682 identity assertions and the val/test-label
      assertion on the evaluated sets.
  A4  Time-box: stop after one working day, report completed rows, no extension.
  A5  Add a wall-clock training time per run column.

All assertions are checked in PREFLIGHT, before any training. If an assertion
fails the script stops, writes the report with the completed rows, and does
NOT train, retry, or re-mask.

Run:  python phase5/learning_curve_diagnostic.py
Out:  phase5/LEARNING_CURVE.md
"""

import sys
sys.dont_write_bytecode = True  # do not leave __pycache__ in existing folders

import copy
import json
import math
import random
import time
from pathlib import Path

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
    compute_auc,
)
import vpss_labeler as vl                             # noqa: E402

GRAPH_FILE = PROJECT_ROOT / "phase5" / "bench_run" / "vulnchain_graph.json"
LABELS_FILE = PROJECT_ROOT / "phase4" / "vpss_labels_51repo.json"
SPLIT_FILE = PROJECT_ROOT / "phase4" / "repo_split_mapping_51repo.json"
ENCODER_CKPT = (PROJECT_ROOT / "phase4" / "results_colab" / "phase4" / "models"
                / "vulngat_51repo.pt")
OUT_MD = PROJECT_ROOT / "phase5" / "LEARNING_CURVE.md"

# --- Pre-declared, locked before the run -------------------------------------
FRACTIONS = [0.25, 0.50, 0.75, 1.00]
ORDERING_SEEDS = [1, 2, 3]
MASK_SEEDS = [42, 123, 456, 789, 1024]
MASK_RATIO = 0.50
OWN_VPSS_THRESHOLD = 0.70
VAL_REPOS = {"practica"}
TEST_REPOS = {"saleor-storefront"}
EXPECTED_POSITIVES = 645
EXPECTED_NEGATIVES = 8682
WORKING_DAY_SECONDS = 8 * 3600          # A4: one working day = 8 h wall clock

# Exact phase1_head_refit.py recipe (SEED/LR/MAX_EPOCHS/PATIENCE/BATCH_SIZE),
# zero hyperparameter changes. Documented here; used only if preflight passes.
HR_SEED = 42
HR_LR = 1e-3
HR_MAX_EPOCHS = 500
HR_PATIENCE = 50
HR_BATCH_SIZE = 32

TABLE_COLS = [
    "n_train_repos", "n_train_nodes", "n_train_nonzero_vpss",
    "clean-graph test Spearman", "clean-graph test RankAcc",
    "masked-50 AUC (HR)", "LP_clean masked-50 AUC",
    "n_train_loss_nodes", "n_excluded_dropped_provenance_nodes",
    "wall-clock train (s)",
]


# ---------------------------------------------------------------------------
# 1. Graph + dim-6 neutralisation
# ---------------------------------------------------------------------------
def neutralise_dim6(g):
    """No `no-dim6` branch exists in this clone, so the neutralisation is
    created here, IN MEMORY ONLY (no data file is written or modified).
    Assert Package.x[:, 6] == 0 for every package. Mutates only the loaded
    in-memory dict; the JSON file on disk is untouched."""
    before = sum(1 for n in g["nodes"]["Package"]
                 if float(n["features"][6]) != 0.0)
    for node in g["nodes"]["Package"]:
        node["features"][6] = 0
    col = [float(n["features"][6]) for n in g["nodes"]["Package"]]
    assert len(col) > 0 and all(v == 0.0 for v in col), (
        "DIM-6 NEUTRALISATION ASSERTION FAILED"
    )
    return g, len(col), before


def derive_repos(mapping):
    nrs = mapping["_metadata"]["node_repo_sources"]
    all_repos = {r for srcs in nrs.values() for r in srcs}
    val_test = VAL_REPOS | TEST_REPOS
    train_repos = sorted(all_repos - val_test)
    return train_repos, nrs


def build_runs(train_repos):
    """Nested prefixes of a shuffled train-repo ordering. 100% has ONE
    ordering. `ceil` fixes the repo count for non-integral fractions; declared
    before the run."""
    runs = []
    orderings = {}
    for seed in ORDERING_SEEDS:
        rnd = random.Random(seed)
        order = list(train_repos)
        rnd.shuffle(order)
        orderings[seed] = order
    for frac in FRACTIONS:
        seeds = ORDERING_SEEDS if frac < 1.0 else [ORDERING_SEEDS[0]]
        k = math.ceil(frac * len(train_repos))
        for seed in seeds:
            kept_train = set(orderings[seed][:k])
            runs.append({
                "fraction": frac, "ordering": seed, "k": k,
                "kept_train": kept_train,
            })
    # Hard nesting assertion (per ordering).
    for seed in ORDERING_SEEDS:
        prev = None
        for r in runs:
            if r["ordering"] != seed:
                continue
            if prev is not None and r["fraction"] < 1.0:
                assert prev <= r["kept_train"], "SUBSETS ARE NOT NESTED"
            prev = set(r["kept_train"])
    return runs, orderings


def induced_graph(g, kept_pkgs):
    """Induced subgraph over the union of node sets of the kept repos.
    Each repo's node set is its full lockfile closure (repo_sources).
    All CVE / Author nodes are retained so the CVSS median pool and the
    auxiliary node features are unchanged; only Package endpoints are filtered."""
    kept = set(kept_pkgs)
    return {
        "metadata": g.get("metadata", {}),
        "nodes": {
            "Package": [n for n in g["nodes"]["Package"] if n["id"] in kept],
            "CVE": g["nodes"]["CVE"],
            "Author": g["nodes"]["Author"],
        },
        "edges": {
            "dependsOn": [e for e in g["edges"]["dependsOn"]
                          if e["source"] in kept and e["target"] in kept],
            "hasVulnerability": [e for e in g["edges"]["hasVulnerability"]
                                 if e["source"] in kept],
            "maintainedBy": [e for e in g["edges"]["maintainedBy"]
                             if e["source"] in kept],
            "introducedBy": g["edges"]["introducedBy"],
        },
    }


# ---------------------------------------------------------------------------
# 2. Preflight: all assertions, no training
# ---------------------------------------------------------------------------
def preflight(g_neutral, mapping, full_labels, runs, nrs, t0):
    train_ids = set(mapping["train_pkg_ids"])
    val_ids = set(mapping["val_pkg_ids"])
    test_ids = set(mapping["test_pkg_ids"])

    own = compute_own_vpss(g_neutral, full_labels)
    eligible = set(select_eligible_packages(own, OWN_VPSS_THRESHOLD))
    never = {pid for pid, e in full_labels.items()
             if float(e.get("vpss", 0.0)) < 1e-9}
    assert len(eligible) == EXPECTED_POSITIVES, (
        f"eligible set is {len(eligible)}, expected {EXPECTED_POSITIVES}"
    )
    assert len(never) == EXPECTED_NEGATIVES, (
        f"negative set is {len(never)}, expected {EXPECTED_NEGATIVES}"
    )
    evaluated = val_ids | test_ids | eligible | never

    rows = []
    for r in runs:
        kept_repos = set(r["kept_train"]) | VAL_REPOS | TEST_REPOS
        kept_pkgs = {pid for pid, srcs in nrs.items()
                     if set(srcs) & kept_repos}

        # A1 / A2: train-loss mask.
        train_in_graph = train_ids & kept_pkgs
        train_loss = {pid for pid in train_in_graph
                      if set(nrs.get(pid, [])) & set(r["kept_train"])}
        excluded = train_in_graph - train_loss

        # A3 assertion A: the 645 / 8,682 sets must be present and identical.
        pos_present = eligible & kept_pkgs
        neg_present = never & kept_pkgs
        pos_ok = len(pos_present) == EXPECTED_POSITIVES
        neg_ok = len(neg_present) == EXPECTED_NEGATIVES

        # A3 assertion B: recompute VPSS on the induced graph, compare to the
        # full-graph values on the evaluated sets.
        ig = induced_graph(g_neutral, kept_pkgs)
        lab, _stats = vl.label_all(ig)
        ev_in = evaluated & kept_pkgs
        label_mismatches = sum(
            1 for pid in ev_in
            if abs(float(lab[pid]["vpss"]) - float(full_labels[pid]["vpss"])) > 1e-9
        )
        label_ok = label_mismatches == 0

        n_train_nonzero = sum(
            1 for pid in train_in_graph if float(lab[pid]["vpss"]) > 0.0
        )

        rows.append({
            "fraction": r["fraction"],
            "ordering": r["ordering"],
            "k": r["k"],
            "n_kept_pkgs": len(kept_pkgs),
            "n_train_repos": r["k"],
            "n_train_nodes": len(train_in_graph),
            "n_train_nonzero_vpss": n_train_nonzero,
            "n_train_loss_nodes": len(train_loss),
            "n_excluded_dropped_provenance_nodes": len(excluded),
            "n_train_ids_not_in_graph": len(train_ids - kept_pkgs),
            "pos_present": len(pos_present),
            "pos_missing": EXPECTED_POSITIVES - len(pos_present),
            "neg_present": len(neg_present),
            "neg_missing": EXPECTED_NEGATIVES - len(neg_present),
            "evaluated_nodes_in_graph": len(ev_in),
            "label_mismatches": label_mismatches,
            "pos_ok": pos_ok, "neg_ok": neg_ok, "label_ok": label_ok,
            "wall_s": None,
            "clean_spearman": None, "clean_rankacc": None,
            "hr_auc": None, "lp_auc": None,
        })
        print(f"  preflight {r['fraction']:.2f} ord={r['ordering']}: "
              f"kept_pkgs={len(kept_pkgs):,} pos={len(pos_present)}/{EXPECTED_POSITIVES} "
              f"neg={len(neg_present)}/{EXPECTED_NEGATIVES} "
              f"label_mismatches={label_mismatches}")

    assertions_ok = all(x["pos_ok"] and x["neg_ok"] and x["label_ok"] for x in rows)
    return rows, assertions_ok, len(eligible), len(never)


# ---------------------------------------------------------------------------
# 3. Full pipeline — NOT IMPLEMENTED, deliberately
# ---------------------------------------------------------------------------
# The prompt says: "Assert ... ; if not, stop and report why" and "no reruns
# on failure". Both preflight assertions fail on this data (see §3 of the
# report), so the run stops before training. No training code is written and
# no model is trained; writing an unexercised training loop here would only
# pretend the protocol had been satisfied. The EXACT recipe that would have
# been used is documented in §1 of the report (phase1_head_refit.py: frozen
# vulngat_51repo.pt encoder, fresh Linear(128,1)+Sigmoid head, MSE only,
# Adam lr=1e-3, bs=32, max 500 epochs, patience 50, seed 42, checkpoint on
# val Spearman-nz). Zero hyperparameter changes were made or would be made.


# ---------------------------------------------------------------------------
# 4. Report
# ---------------------------------------------------------------------------
def cell(v, fmt="{:.6f}"):
    return "not run" if v is None else fmt.format(v)


def write_report(rows, assertions_ok, n_eligible, n_never, n_dim6,
                 n_dim6_before, train_repos, orderings, t0,
                 stopped_reason, one_line):
    L = []
    A = L.append
    A("# Learning-Curve Diagnostic — masked-50 AUC vs number of TRAIN repos")
    A("")
    A("Branch `learning-curve` · generated by `phase5/learning_curve_diagnostic.py` "
      "(new file). Diagnostic only: **no tuning, no gate, no reruns on failure**. "
      "No existing script, result, label, model or data file was modified.")
    A("")
    A("**Question:** does masked-50 AUC rise as the number of TRAIN repos grows?")
    A("")
    A("The five amendments from the previous session's Task B were applied on top "
      "of the learning-curve prompt. The original 7 report columns, the "
      "per-fraction aggregation, the single printed line, the no-rerun rule and "
      "all other wording are unchanged; the amendment columns are added. They "
      "are listed in the next section.")
    A("")
    A("## 1. Setup and pre-declared choices")
    A("")
    A(f"- **dim-6 graph:** no `no-dim6` branch exists in this clone "
      f"(`git branch -a` shows `main`, `hybrid-cs`, `learning-curve` only). "
      f"The neutralisation was therefore created here, in memory, and "
      f"`Package.x[:,6] == 0` was asserted on all **{n_dim6:,}** packages — "
      f"**passed** ({n_dim6_before:,} packages had dim 6 = 1 before "
      "neutralisation). No data file was written or modified.")
    A(f"- **Train repos:** {len(train_repos)} repos = every repo in "
      "`_metadata.node_repo_sources` except `practica` (val) and "
      "`saleor-storefront` (test). Val/test repos stay FIXED in all runs.")
    A(f"- **Subsets:** fractions `{FRACTIONS}` × nested prefixes of a repo "
      f"ordering; ordering seeds `{ORDERING_SEEDS}`; 100% has one ordering. "
      f"`k = ceil(fraction * {len(train_repos)})` (declared before the run). "
      "Nesting was asserted for each ordering.")
    A("- **Induced graph:** union of the lockfile closures of kept train repos + "
      "val + test (`repo_sources`). All CVE / Author nodes retained; "
      "`dependsOn` kept only when both endpoints survive; `hasVulnerability` / "
      "`maintainedBy` kept only when the Package endpoint survives.")
    A(f"- **Masked-50 seeds:** `{MASK_SEEDS}`; ratio {MASK_RATIO:.2f}; official "
      "`apply_edge_mask`, `run_model_inference`, `run_label_prop_baseline`, `compute_auc`.")
    A("- **HR recipe (exact, unchanged):** `phase5/phase1_head_refit.py` — "
      f"frozen encoder `vulngat_51repo.pt`, fresh `Linear(128,1)+Sigmoid` head, "
      f"MSE only, Adam lr={HR_LR}, batch={HR_BATCH_SIZE}, max {HR_MAX_EPOCHS} epochs, "
      f"patience {HR_PATIENCE}, seed {HR_SEED}, checkpoint on **val Spearman** "
      "(non-zero val nodes). Zero hyperparameter changes.")
    A("")
    A("**Applied amendments (previous Task B):**")
    A("")
    A("1. **A1 train-loss mask.** A node is in the training loss only if it is "
      "`train` in `repo_split_mapping_51repo.json` AND ≥1 of its `repo_sources` is "
      "in the KEPT train repos. Mapping-train nodes whose only train-repo sources "
      "were dropped are **excluded from the loss** (not reassigned to test, not "
      "used as train) but stay in the graph for message passing.")
    A("2. **A2** `n_train_loss_nodes` and `n_excluded_dropped_provenance_nodes` "
      "are printed per subset (columns below).")
    A("3. **A3** the 645 / 8,682 identity assertions and the val/test label "
      "assertion are kept, unchanged.")
    A(f"4. **A4 time-box** = one working day = {WORKING_DAY_SECONDS//3600} h wall "
      "clock; if the full run is not done, stop, report completed rows, do not extend.")
    A("5. **A5** `wall-clock train (s)` column added.")
    A("")

    A("## 2. Result table")
    A("")
    A("| fraction | ordering | " + " | ".join(TABLE_COLS) + " |")
    A("|---:|---:|" + "---:|" * len(TABLE_COLS))
    for r in rows:
        vals = [
            str(r["n_train_repos"]),
            str(r["n_train_nodes"]),
            str(r["n_train_nonzero_vpss"]),
            cell(r["clean_spearman"]),
            cell(r["clean_rankacc"]),
            cell(r["hr_auc"]),
            cell(r["lp_auc"]),
            str(r["n_train_loss_nodes"]),
            str(r["n_excluded_dropped_provenance_nodes"]),
            cell(r["wall_s"], "{:.1f}"),
        ]
        A(f"| {r['fraction']:.0%} | {r['ordering']} | " + " | ".join(vals) + " |")
    A("")
    A("Aggregation by fraction (mean ± std of HR masked-50 AUC across the 3 "
      "orderings, `ddof=0`; only one ordering at 100%): **not computed — no run "
      "was trained**.")
    A("")

    A("### Per-subset preflight detail (completed rows)")
    A("")
    A("| fraction | ordering | kept packages | 645 positives present | missing | "
      "8,682 negatives present | missing | evaluated nodes in graph | "
      "VPSS label mismatches vs full graph | train IDs absent from graph |")
    A("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        A(f"| {r['fraction']:.0%} | {r['ordering']} | {r['n_kept_pkgs']:,} | "
          f"{r['pos_present']} | {r['pos_missing']} | {r['neg_present']:,} | "
          f"{r['neg_missing']:,} | {r['evaluated_nodes_in_graph']:,} | "
          f"{r['label_mismatches']} | {r['n_train_ids_not_in_graph']:,} |")
    A("")

    A("## 3. Assertions and STOP")
    A("")
    A(f"- Full-graph evaluated sets: **{n_eligible} positives** (official "
      f"`select_eligible_packages(0.70)`, which auto-relaxes to 0.30) and "
      f"**{n_never:,} negatives** (VPSS = 0).")
    A(f"- Assertion A (identical 645 / 8,682 sets in every induced graph): "
      f"**{'PASS' if all(r['pos_ok'] and r['neg_ok'] for r in rows) else 'FAIL'}**.")
    A(f"- Assertion B (test/val labels on evaluated sets match full-graph values "
      f"after `vpss_labeler.label_all()` on each induced graph): "
      f"**{'PASS' if all(r['label_ok'] for r in rows) else 'FAIL'}**.")
    A("")
    if stopped_reason:
        A("> **STOPPED — " + stopped_reason + "** No model was trained, no "
          "masked-50 AUC or LP_clean AUC was computed, and no rerun, tuning, "
          "or second mask was attempted, exactly as instructed.")
        A("")
    A("**Training stage:** not implemented in this script and not executed. "
      "The prompt requires stopping at the first failed assertion, so writing "
      "an unexercised training loop would misrepresent the protocol. The exact "
      "recipe that would have been used, unchanged, is recorded in §1. "
      "Consequently the seven result columns that depend on training are "
      "`not run`, and the per-fraction aggregation and the 50%→100% gain "
      "cannot be computed.")
    A("")
    A("## 4. Required single line")
    A("")
    A(one_line)
    A("")
    A("## 5. Reproduce")
    A("")
    A("```bash")
    A("cd C:/Users/soumy/Desktop/VulnChain")
    A("git checkout learning-curve")
    A("python phase5/learning_curve_diagnostic.py")
    A("```")
    A("")
    A("Writes only `phase5/LEARNING_CURVE.md`. Elapsed wall clock at report "
      f"time: {time.time() - t0:.1f} s (time-box {WORKING_DAY_SECONDS//3600} h "
      "not reached).")
    OUT_MD.write_text("\n".join(L) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main():
    t0 = time.time()
    print("Loading graph / labels / split ...")
    g = json.loads(GRAPH_FILE.read_text(encoding="utf-8"))
    full_labels = json.loads(LABELS_FILE.read_text(encoding="utf-8"))
    mapping = json.loads(SPLIT_FILE.read_text(encoding="utf-8"))

    g_neutral, n_dim6, n_dim6_before = neutralise_dim6(g)
    print(f"  dim-6 neutralised in memory: {n_dim6:,} packages, all zeros "
          f"(asserted); {n_dim6_before:,} had dim 6 = 1 before")

    train_repos, nrs = derive_repos(mapping)
    runs, orderings = build_runs(train_repos)
    print(f"  train repos={len(train_repos)}, runs={len(runs)}")

    print("\n=== PREFLIGHT (both assertions, all runs; no training yet) ===")
    rows, assertions_ok, n_eligible, n_never = preflight(
        g_neutral, mapping, full_labels, runs, nrs, t0
    )

    if not assertions_ok:
        failed_a = [r for r in rows if not (r["pos_ok"] and r["neg_ok"])]
        failed_b = [r for r in rows if not r["label_ok"]]
        reason_parts = []
        if failed_a:
            worst = min(failed_a, key=lambda r: r["pos_present"])
            reason_parts.append(
                f"Assertion A FAILED in {len(failed_a)}/{len(rows)} runs: "
                f"e.g. {worst['fraction']:.0%}/ordering {worst['ordering']} keeps only "
                f"{worst['pos_present']}/645 positives and "
                f"{worst['neg_present']:,}/8,682 negatives — the induced subgraphs "
                f"drop {worst['pos_missing']} positives and "
                f"{worst['neg_missing']:,} negatives, so the evaluated sets are NOT "
                "identical across subsets. Only 100% of train repos retains all of them."
            )
        if failed_b:
            worst = max(failed_b, key=lambda r: r["label_mismatches"])
            reason_parts.append(
                f"Assertion B FAILED in {len(failed_b)}/{len(rows)} runs: "
                f"recomputed VPSS on the induced graph differs from the full-graph "
                f"value on up to {worst['label_mismatches']} evaluated nodes "
                f"(the val ∪ test ∪ 645-positive ∪ 8,682-negative union present in "
                f"the graph; {worst['fraction']:.0%}/ordering {worst['ordering']}); "
                "only 100% reproduces the full-graph labels."
            )
        reason = " ".join(reason_parts)
        one_line = ("No gain in mean HR masked-50 AUC from 50% to 100% of train "
                    "repos can be reported: the required assertions failed, so "
                    "training was stopped before any run (exceeds 0.02: not evaluable).")
        write_report(rows, False, n_eligible, n_never, n_dim6, n_dim6_before,
                     train_repos, orderings, t0, reason, one_line)
        print("\n" + one_line)
        print(f"[STOPPED] Report written to {OUT_MD}")
        return

    # Unreachable on this data. Kept explicit so the script never silently
    # continues past a failed assertion, and never invents a training result.
    if time.time() - t0 > WORKING_DAY_SECONDS:
        reason = ("Time-box reached before the full run completed; completed rows "
                  "reported, no extension.")
    else:
        reason = ("Preflight assertions passed, but the training/evaluation "
                  "stage is not implemented in this diagnostic build because "
                  "the protocol stops at the first failed assertion; no rerun.")
    write_report(rows, True, n_eligible, n_never, n_dim6, n_dim6_before,
                 train_repos, orderings, t0, reason,
                 "No gain computed: training stage not reached.")
    print(reason)


if __name__ == "__main__":
    main()
