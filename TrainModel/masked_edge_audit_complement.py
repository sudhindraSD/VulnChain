"""
masked_edge_audit_complement.py -- HR / LP_clean complementarity check
======================================================================
NEW FILE. Diagnostic only. NO training, NO tuning, NO weight search, NO
per-seed choices. No existing script, result, label, model, or data file is
modified or overwritten; the only output is phase5/COMPLEMENT_CHECK.md.

The protocol is inherited verbatim from TrainModel/masked_edge_audit_leakfix.py:
its seeds, mask ratio, eligibility threshold, file paths, hard assertions,
masked-graph construction and masked-graph VPSS recomputation are imported
directly from that module rather than re-typed. Scoring goes through the
official TrainModel/masked_edge_audit.py implementations:

    HR        = run_model_inference(VulnGAT-HR, masked_data)   (dim 6 zeroed)
    LP_clean  = run_label_prop_baseline(masked_data, masked_labels)
    AUC       = compute_auc(scores, pos, never_vuln_indices)

For each seed we measure, on ONE identical mask instance, what two fixed,
equal-weight fusions of HR and LP_clean would score, plus the rank agreement
between the two score vectors. Nothing is fitted: both fusion weights were
declared at module import (W_HR = W_LP = 0.5) and are never changed.

Run:  python TrainModel/masked_edge_audit_complement.py
Out:  phase5/COMPLEMENT_CHECK.md   (new file)
"""

import sys
sys.dont_write_bytecode = True  # do not leave __pycache__ in existing folders

import json
from pathlib import Path

import numpy as np
import torch
from scipy.stats import rankdata, spearmanr

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
    SEEDS,
    MASK_RATIO,
    OWN_VPSS_THRESHOLD,
    EXPECTED_ELIGIBLE,
    EXPECTED_NEVER_VULN,
    GRAPH_FILE,
    LABELS_FILE,
    SPLIT_FILE,
    MODEL_FILE,
    recompute_vpss_labels,
)
from training.dataset import load_vulnchain_dataset   # noqa: E402
from core.model.vulngat import VulnGAT                # noqa: E402

OUT_MD = PROJECT_ROOT / "phase5" / "COMPLEMENT_CHECK.md"

# --- Pre-declared fusion weights. Fixed before any score is computed. --------
W_HR = 0.5
W_LP = 0.5
assert W_HR == W_LP == 0.5, "equal weights are pre-registered, do not tune"

# --- Reproduction targets (published values, asserted within 1e-6) ----------
EXPECTED_HR_MEAN = 0.6314725216034925       # part_c_masked_edge_audit_5seeds.json
EXPECTED_LP_CLEAN_MEAN = 0.632905           # phase5/LP_LEAKCHECK.md (6 dp)
ASSERT_TOL = 1e-6

COLUMNS = ["HR", "LP_clean", "rank-avg", "z-avg", "corr(all)", "corr(positives)"]


# ---------------------------------------------------------------------------
# Fixed, declared-in-advance definitions (no free parameters)
# ---------------------------------------------------------------------------
def evaluated_indices(pos, neg):
    """The set that actually enters the official compute_auc: the masked
    positives followed by the shared never-vulnerable negatives. Identical
    index list for every method and every seed."""
    return np.asarray(list(pos) + list(neg), dtype=np.int64)


def average_tie_ranks(x):
    """Ranks over the supplied vector with average ranks for ties (standard
    Spearman convention). Declared once; no per-seed choices."""
    return rankdata(np.asarray(x, dtype=np.float64), method="average")


def spearman_rho(a, b):
    """Spearman rho = Pearson correlation of the average-tie ranks."""
    ra = average_tie_ranks(a)
    rb = average_tie_ranks(b)
    if ra.std() == 0 or rb.std() == 0:
        return float("nan")
    return float(np.corrcoef(ra, rb)[0, 1])


def rank_average(hr_eval, lp_eval):
    """Equal-weight average of the two rank vectors over the evaluated set."""
    return W_HR * average_tie_ranks(hr_eval) + W_LP * average_tie_ranks(lp_eval)


def zscore_average(hr_eval, lp_eval):
    """Equal-weight average of the two z-scored vectors over the evaluated set.
    Standardization uses population std (ddof=0), matching the summary std."""
    def z(x):
        sd = np.asarray(x, dtype=np.float64).std(ddof=0)
        if sd == 0:
            return np.zeros_like(x, dtype=np.float64)
        return (np.asarray(x, dtype=np.float64) - np.asarray(x, dtype=np.float64).mean()) / sd
    return W_HR * z(hr_eval) + W_LP * z(lp_eval)


def embed(num_packages, eval_idx, fused_eval):
    """Place fused scores back into a full-length vector so the OFFICIAL
    compute_auc can be called with the exact same pos / neg index lists."""
    full = np.zeros(num_packages, dtype=np.float64)
    full[eval_idx] = fused_eval
    return full


# ---------------------------------------------------------------------------
# Main
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

    # --- Official eligibility + negatives, with the HARD assertions ---------
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
    max_rank_check_diff = 0.0
    max_spearman_check_diff = 0.0

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
        eval_idx = evaluated_indices(pos, never_vuln_indices)
        assert len(np.unique(eval_idx)) == len(eval_idx), "eval set has duplicates"
        assert len(eval_idx) == len(pos) + len(never_vuln_indices)

        # Both scorers run on the SAME masked_data / SAME mask instance.
        hr_scores = run_model_inference(model, masked_data, device)
        masked_labels, _masked_stats = recompute_vpss_labels(graph_json, masked_pkg_ids)
        lp_scores = run_label_prop_baseline(
            masked_data, masked_labels,
            pkg_id_to_idx, idx_to_pkg_id, num_packages,
        )

        hr_eval = np.asarray(hr_scores[eval_idx], dtype=np.float64)
        lp_eval = np.asarray(lp_scores[eval_idx], dtype=np.float64)

        # 1. Official AUCs (unchanged protocol).
        hr_auc = compute_auc(hr_scores, pos, never_vuln_indices)
        lp_auc = compute_auc(lp_scores, pos, never_vuln_indices)

        # 2/3. Two fixed equal-weight fusions, AUC via the official compute_auc.
        rank_fused = rank_average(hr_eval, lp_eval)
        z_fused = zscore_average(hr_eval, lp_eval)
        rank_auc = compute_auc(
            embed(num_packages, eval_idx, rank_fused), pos, never_vuln_indices
        )
        z_auc = compute_auc(
            embed(num_packages, eval_idx, z_fused), pos, never_vuln_indices
        )

        # 4/5. Spearman agreement: full evaluated set, then positives only.
        corr_all = spearman_rho(hr_eval, lp_eval)
        corr_pos = spearman_rho(
            np.asarray(hr_scores[pos], dtype=np.float64),
            np.asarray(lp_scores[pos], dtype=np.float64),
        )

        # --- Sanity cross-checks (no tuning, do not alter any reported value) -
        rank_check = W_HR * rankdata(hr_eval) + W_LP * rankdata(lp_eval)
        max_rank_check_diff = max(
            max_rank_check_diff, float(np.max(np.abs(rank_check - rank_fused)))
        )
        rho_check = float(spearmanr(hr_eval, lp_eval).statistic)
        max_spearman_check_diff = max(
            max_spearman_check_diff, abs(rho_check - corr_all)
        )

        row = {
            "seed": seed,
            "HR": float(hr_auc),
            "LP_clean": float(lp_auc),
            "rank-avg": float(rank_auc),
            "z-avg": float(z_auc),
            "corr(all)": corr_all,
            "corr(positives)": corr_pos,
            "n_pos": len(pos),
            "n_eval": len(eval_idx),
        }
        rows.append(row)
        print("  " + "  ".join(f"{c}={row[c]:.6f}" for c in COLUMNS))

    # ---------------------------------------------------------------- summary
    summary = {}
    for c in COLUMNS:
        vals = np.array([r[c] for r in rows], dtype=np.float64)
        summary[c] = (float(vals.mean()), float(vals.std(ddof=0)))

    # --- Reproduction assertions (published means, tolerance 1e-6) ----------
    hr_mean = summary["HR"][0]
    lp_mean = summary["LP_clean"][0]
    print(f"\n  HR mean      = {hr_mean:.9f}  (published {EXPECTED_HR_MEAN:.9f})")
    print(f"  LP_clean mean= {lp_mean:.9f}  (published {EXPECTED_LP_CLEAN_MEAN:.6f})")
    assert abs(hr_mean - EXPECTED_HR_MEAN) < ASSERT_TOL, (
        f"HR MEAN REPRODUCTION FAILED: |{hr_mean} - {EXPECTED_HR_MEAN}| "
        f">= {ASSERT_TOL}"
    )
    assert abs(lp_mean - EXPECTED_LP_CLEAN_MEAN) < ASSERT_TOL, (
        f"LP_clean MEAN REPRODUCTION FAILED: "
        f"|{lp_mean} - {EXPECTED_LP_CLEAN_MEAN}| >= {ASSERT_TOL}"
    )
    assert max_rank_check_diff < 1e-9
    assert max_spearman_check_diff < 1e-9
    print(f"  [OK] reproduction assertions passed (tol={ASSERT_TOL}); "
          f"rank-check max |Δ|={max_rank_check_diff:.2e}, "
          f"spearman-check max |Δ|={max_spearman_check_diff:.2e}")

    write_report(rows, summary, num_packages, len(eligible_pkg_ids),
                 len(never_vuln_indices), unmasked_stats,
                 max_rank_check_diff, max_spearman_check_diff)
    print(f"\n[OK] Report written to {OUT_MD}")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def fmt_row(label, values):
    return "| " + label + " | " + " | ".join(f"{v:.6f}" for v in values) + " |"


def fmt_mean_std(summary):
    cells = [f"{summary[c][0]:.6f} ± {summary[c][1]:.6f}" for c in COLUMNS]
    return "| mean ± std | " + " | ".join(cells) + " |"


def write_report(rows, summary, num_packages, n_eligible, n_neg,
                 unmasked_stats, rank_diff, rho_diff):
    L = []
    A = L.append

    A("# HR / LP_clean Complementarity Check — 50% Masked-Edge Audit")
    A("")
    A("Generated by `TrainModel/masked_edge_audit_complement.py` (new file). "
      "Diagnostic only: **no training, no tuning, no weight search, no per-seed "
      "choices**. No existing script, result, label, model, or data file was "
      "modified or overwritten. The only output is this file.")
    A("")

    A("## 1. Protocol (inherited from `masked_edge_audit_leakfix.py`)")
    A("")
    A("All settings below are imported directly from "
      "`TrainModel/masked_edge_audit_leakfix.py`, so they cannot drift from the "
      "leak-check run.")
    A("")
    A("| Item | Value |")
    A("|---|---|")
    A(f"| Seeds | `{SEEDS}` |")
    A(f"| Mask | `{MASK_RATIO:.2f}` via official `apply_edge_mask` |")
    A(f"| Graph | `phase5/bench_run/vulnchain_graph.json` ({num_packages:,} packages) |")
    A("| Labels | `phase4/vpss_labels_51repo.json` |")
    A("| Split | `phase4/repo_split_mapping_51repo.json` |")
    A(f"| HR | `phase5/models/vulngat_hr_full.pt`, official `run_model_inference` on the masked `HeteroData`; `Package.x[:, 6]` zeroed for masked packages by `apply_edge_mask` |")
    A("| LP_clean | official `run_label_prop_baseline` fed VPSS recomputed on the masked graph by `vpss_labeler.label_all()` (never the original labels) |")
    A(f"| Eligibility | official `compute_own_vpss` + `select_eligible_packages({OWN_VPSS_THRESHOLD:.2f})` → **{n_eligible}** |")
    A(f"| Negatives | official `get_never_vuln_indices` → **{n_neg:,}** |")
    A("| AUC | official `compute_auc` (Wilcoxon–Mann–Whitney, ties = 0.5) |")
    A("| std | population `np.std` (`ddof=0`), over the 5 seeds |")
    A("")
    A(f"Hard assertions `N_eligible == {EXPECTED_ELIGIBLE}` and "
      f"`N_never_vuln == {EXPECTED_NEVER_VULN}` are retained and **passed** "
      f"({n_eligible} / {n_neg:,}). The VPSS labeler was revalidated "
      f"bit-exactly on all {unmasked_stats['total_packages']:,} unmasked "
      f"packages (0 field mismatches).")
    A("")

    A("## 2. Definitions fixed before running")
    A("")
    A("- **Evaluated set** = `pos + never_vuln_indices`, i.e. exactly the nodes "
      "that enter the official `compute_auc` for that seed (masked positives "
      "first, then the shared never-vulnerable negatives). The same mask "
      "instance, the same positive set and the same negative set are used for "
      "HR, LP_clean and both fusions.")
    A("- **rank-avg** = `0.5 * rankdata(HR_eval, method='average') + "
      "0.5 * rankdata(LP_clean_eval, method='average')`, ranks taken over the "
      "evaluated set. Average ranks for ties are used so that tie-breaking "
      "cannot favour the positives, which are placed first in the index list.")
    A("- **z-avg** = `0.5 * z(HR_eval) + 0.5 * z(LP_clean_eval)`, each vector "
      "standardized over the evaluated set with population std (`ddof=0`).")
    A("- Both fusion AUCs are obtained by placing the fused values back into a "
      "full-length vector and calling the **official `compute_auc`** with the "
      "unchanged `pos` / `never_vuln_indices` lists.")
    A("- **corr(all)** = Spearman ρ between HR and LP_clean over the evaluated "
      "set. **corr(positives)** = Spearman ρ between HR and LP_clean over the "
      "masked positives only, ranks recomputed within that subset. Spearman ρ "
      "is the Pearson correlation of the average-tie rank vectors.")
    A(f"- Fusion weights were declared at import as `W_HR = W_LP = {W_HR}`. "
      "No weight search, no per-seed choice, no post-hoc selection.")
    A("")

    A("## 3. Results — one table")
    A("")
    A("| Seed | " + " | ".join(COLUMNS) + " |")
    A("|---:|" + "---:|" * len(COLUMNS))
    for r in rows:
        A(fmt_row(str(r["seed"]), [r[c] for c in COLUMNS]))
    A(fmt_mean_std(summary))
    A("")
    A("`mean ± std` is the mean and population std (`ddof=0`) across the 5 "
      "seed rows above. All AUC columns use the official `compute_auc`; "
      "correlation columns are Spearman ρ.")
    A("")

    A("## 4. Validation")
    A("")
    A(f"- HR mean = `{summary['HR'][0]:.9f}` reproduces the published "
      f"`part_c_masked_edge_audit_5seeds.json` mean "
      f"`{EXPECTED_HR_MEAN:.9f}`; LP_clean mean = "
      f"`{summary['LP_clean'][0]:.9f}` reproduces "
      f"`phase5/LP_LEAKCHECK.md` `{EXPECTED_LP_CLEAN_MEAN:.6f}`. Both asserted "
      f"within `{ASSERT_TOL:g}` and **passed**.")
    A(f"- Independent re-computation of the rank-average vector: max |Δ| = "
      f"`{rank_diff:.2e}`.")
    A(f"- Our Spearman (Pearson of average-tie ranks) vs "
      f"`scipy.stats.spearmanr`: max |Δ| = `{rho_diff:.2e}`.")
    A(f"- Evaluated set size = `n_pos + {n_neg:,}` per seed, with no duplicate "
      f"indices (asserted for every seed).")
    A("")

    A("## 5. Interpretation")
    A("")
    best = max(summary["HR"][0], summary["LP_clean"][0])
    delta = summary["rank-avg"][0] - best
    verdict = "does" if delta > 0.02 else "does not"
    A(f"The rank-avg mean {summary['rank-avg'][0]:.6f} {verdict} exceed "
      f"max(HR, LP_clean) mean {best:.6f} by more than 0.02 "
      f"(Δ = {delta:+.6f}).")
    A("")

    A("## 6. Reproduce")
    A("")
    A("```bash")
    A("cd C:/Users/soumy/Desktop/VulnChain")
    A("python TrainModel/masked_edge_audit_complement.py")
    A("```")
    A("")
    A("Reads all existing files; writes only `phase5/COMPLEMENT_CHECK.md`. "
      "This is a complementarity measurement, not a hybrid gate adjudication "
      "(see `phase5/HYBRID_GATE.md`).")

    OUT_MD.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
