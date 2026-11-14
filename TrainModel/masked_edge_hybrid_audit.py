"""
masked_edge_hybrid_audit.py — hybrid leak audit (known-set composition)
=======================================================================
NEW FILE on branch `hybrid-cs`. No existing file is modified; the only output
is phase5/HYBRID_AUDIT.md.

Reuses the FROZEN (alpha, n_iter) = (0.5, 25) that
TrainModel/masked_edge_hybrid_cs.py selected on tuning mask seeds
[52, 72, 92] and recorded in phase5/HYBRID_RESULT.md section 2. NO retuning,
NO grid, NO new hyperparameters.

Reuses the exact frozen implementations by import (no copy-paste divergence):
  - official audit functions from TrainModel/masked_edge_audit.py
  - masked-graph VPSS + LP neighbourhood from masked_edge_audit_leakfix.py
  - C&S code + normalised adjacency + rank average from
    masked_edge_hybrid_cs.py

For each gate seed [42, 123, 456, 789, 1024] on the SAME mask:
  1. Known-set composition of the evaluated set (positives / negatives).
  2. C&S_CURRENT score distributions on evaluated negatives vs positives.
  3. C&S_STRICT: identical code / frozen alpha / frozen n_iter, but the known
     set EXCLUDES every evaluated node (all masked positives AND all 8,682
     negatives). Those nodes get residual 0 and are never clamped.
  4. Label-permuted control under the STRICT known set.
  5. One line only: does C&S_STRICT mean AUC exceed LP_clean mean by > 0.02.

Run:  python TrainModel/masked_edge_hybrid_audit.py
Out:  phase5/HYBRID_AUDIT.md
"""

import sys
sys.dont_write_bytecode = True  # no __pycache__ in existing folders

import json
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
from masked_edge_hybrid_cs import (                  # noqa: E402
    correct_and_smooth,
    normalized_adjacency,
    rank_avg_scores,
    PERM_SEED_BASE,
    SANITY_TOL,
)
from masked_edge_audit_complement import (           # noqa: E402
    evaluated_indices,
)
from training.dataset import load_vulnchain_dataset   # noqa: E402
from core.model.vulngat import VulnGAT                # noqa: E402

OUT_MD = PROJECT_ROOT / "phase5" / "HYBRID_AUDIT.md"
RESULT_MD = PROJECT_ROOT / "phase5" / "HYBRID_RESULT.md"

# --- FROZEN, read from HYBRID_RESULT.md §2. Never recomputed here. -----------
ALPHA_FROZEN = 0.5
N_ITER_FROZEN = 25
FROZEN_TOKEN = "**Frozen parameters: alpha = 0.5, n_iter = 25**"

EXPECTED_MEANS = {          # published gate-seed means, 6 dp (reproduction check)
    "HR": 0.631473,
    "LP_clean": 0.632905,
    "C&S_CURRENT": 0.824964,
    "RANK_AVG(HR,LP_clean)": 0.692055,
}
REPRO_TOL = 1e-5

METHODS = ["HR", "LP_clean", "C&S_CURRENT", "C&S_STRICT", "RANK_AVG(HR,LP_clean)"]


def describe(x):
    x = np.asarray(x, dtype=np.float64)
    return (float(np.mean(x)), float(np.median(x)),
            float(np.min(x)), float(np.max(x)))


def main():
    device = torch.device("cpu")

    # Frozen-parameter provenance check (reads the frozen report; no retuning).
    try:
        frozen_ok = FROZEN_TOKEN in RESULT_MD.read_text(encoding="utf-8")
    except Exception:
        frozen_ok = False
    print(f"Frozen (alpha, n_iter) = ({ALPHA_FROZEN}, {N_ITER_FROZEN}) "
          f"from HYBRID_RESULT.md §2; token check: {frozen_ok}")

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
    n = data["Package"].num_nodes

    # Validation: labeler bit-exact on the unmasked graph.
    unmasked_labels, _stats = recompute_vpss_labels(graph_json, set())
    fields = ("vpss", "raw_sum", "num_contributing_vulns", "min_depth_to_vuln")
    mismatches = sum(
        1 for pid, v in unmasked_labels.items()
        for k in fields if v[k] != vpss_labels_original[pid][k]
    )
    assert mismatches == 0, "VPSS labeler did not reproduce shipped labels"

    # Hard population assertions (unchanged).
    own_vpss_data = compute_own_vpss(graph_json, vpss_labels_original)
    eligible = select_eligible_packages(own_vpss_data, OWN_VPSS_THRESHOLD)
    neg = get_never_vuln_indices(vpss_labels_original, pkg_id_to_idx, n)
    print(f"  eligible={len(eligible)}  never_vuln={len(neg)}")
    assert len(eligible) == EXPECTED_ELIGIBLE
    assert len(neg) == EXPECTED_NEVER_VULN

    model = VulnGAT()
    model.load_state_dict(torch.load(MODEL_FILE, map_location=device, weights_only=True))
    model = model.to(device)
    model.eval()

    rows = []
    for seed in GATE_SEEDS:
        print(f"\n--- seed {seed} ---")

        masked_data, masked_idx_set, _cves, _strata = apply_edge_mask(
            data, eligible, pkg_id_to_idx, graph_json, cve_id_to_idx,
            MASK_RATIO, seed,
        )
        masked_pkg_ids = {
            idx_to_pkg_id[i] for i in masked_idx_set if i in idx_to_pkg_id
        }
        pos = list(masked_idx_set)
        eval_idx = evaluated_indices(pos, neg)
        assert len(np.unique(eval_idx)) == len(eval_idx)

        masked_labels, _mstats = recompute_vpss_labels(graph_json, masked_pkg_ids)
        y_clean = vpss_array_from(
            masked_labels, pkg_id_to_idx, n
        ).astype(np.float64)

        hr = run_model_inference(model, masked_data, device).astype(np.float64)
        lp = run_label_prop_baseline(
            masked_data, masked_labels, pkg_id_to_idx, idx_to_pkg_id, n
        ).astype(np.float64)
        S = normalized_adjacency(build_lp_neighbors(masked_data), n)

        # Known sets.
        known_current = np.ones(n, dtype=bool)
        known_current[pos] = False                    # as in masked_edge_hybrid_cs.py
        known_strict = np.ones(n, dtype=bool)
        known_strict[eval_idx] = False                # excludes positives AND negatives

        # C&S variants: identical code, identical frozen hyperparameters.
        cs_current = correct_and_smooth(
            hr, y_clean, known_current, S, ALPHA_FROZEN, N_ITER_FROZEN
        )
        cs_strict = correct_and_smooth(
            hr, y_clean, known_strict, S, ALPHA_FROZEN, N_ITER_FROZEN
        )

        # Label-permuted control under the STRICT known set.
        rng = np.random.RandomState(PERM_SEED_BASE + seed)
        k_idx = np.flatnonzero(known_strict)
        y_perm = y_clean.copy()
        y_perm[k_idx] = y_clean[k_idx][rng.permutation(k_idx.size)]
        cs_strict_perm = correct_and_smooth(
            hr, y_perm, known_strict, S, ALPHA_FROZEN, N_ITER_FROZEN,
            labels_smooth=y_perm,
        )

        rank_fused = rank_avg_scores(hr, lp, eval_idx, n)

        # 1. Known-set composition.
        comp = {
            "n_pos": len(pos),
            "n_neg": len(neg),
            "pos_in_known_current": int(known_current[pos].sum()),
            "neg_in_known_current": int(known_current[neg].sum()),
            "pos_in_known_strict": int(known_strict[pos].sum()),
            "neg_in_known_strict": int(known_strict[neg].sum()),
            "n_known_current": int(known_current.sum()),
            "n_known_strict": int(known_strict.sum()),
        }

        # 2. C&S_CURRENT score distributions.
        neg_scores = cs_current[neg]
        neg_labels = y_clean[neg]
        pos_scores = cs_current[pos]
        dist = {
            "frac_neg_eq_label": float(
                np.mean(np.abs(neg_scores - neg_labels) <= 1e-6)
            ),
            "n_neg_zero_label": int(np.sum(np.abs(neg_labels) <= 1e-12)),
            "neg": describe(neg_scores),
            "pos": describe(pos_scores),
        }

        # 3/4. AUCs.
        aucs = {
            "HR": compute_auc(hr, pos, neg),
            "LP_clean": compute_auc(lp, pos, neg),
            "C&S_CURRENT": compute_auc(cs_current, pos, neg),
            "C&S_STRICT": compute_auc(cs_strict, pos, neg),
            "RANK_AVG(HR,LP_clean)": compute_auc(rank_fused, pos, neg),
        }
        perm_auc = compute_auc(cs_strict_perm, pos, neg)

        rows.append({
            "seed": seed, **comp, **dist,
            **{f"auc_{m}": aucs[m] for m in METHODS},
            "perm_auc": perm_auc,
        })
        print(f"  known: pos {comp['pos_in_known_current']}/{len(pos)}, "
              f"neg {comp['neg_in_known_current']:,}/{len(neg):,}; "
              f"strict pos {comp['pos_in_known_strict']}, "
              f"neg {comp['neg_in_known_strict']}, "
              f"|known_strict|={comp['n_known_strict']:,}")
        print(f"  frac(neg score == known label) = {dist['frac_neg_eq_label']:.6f}")
        print("  " + "  ".join(f"{m}={aucs[m]:.6f}" for m in METHODS)
              + f"  perm={perm_auc:.6f}")

    summary = {}
    for m in METHODS:
        v = np.array([r[f"auc_{m}"] for r in rows], dtype=np.float64)
        summary[m] = (float(v.mean()), float(v.std(ddof=0)))
    perm_vals = np.array([r["perm_auc"] for r in rows], dtype=np.float64)
    perm_mean = float(perm_vals.mean())
    perm_std = float(perm_vals.std(ddof=0))
    perm_near = abs(perm_mean - 0.5) <= SANITY_TOL

    repro = []
    for m, exp in EXPECTED_MEANS.items():
        obs = summary[m][0]
        repro.append({"name": m, "expected": exp, "observed": obs,
                      "ok": abs(obs - exp) < REPRO_TOL})

    diff = summary["C&S_STRICT"][0] - summary["LP_clean"][0]
    one_line = (
        f"C&S_STRICT mean AUC {summary['C&S_STRICT'][0]:.6f} "
        f"{'does' if diff > 0.02 else 'does not'} exceed LP_clean mean "
        f"{summary['LP_clean'][0]:.6f} by more than 0.02 (Δ = {diff:+.6f})."
    )

    write_report(rows, summary, perm_mean, perm_std, perm_near,
                 repro, frozen_ok, one_line)

    # ------------------------------------------------------------- stdout
    print("\n" + "=" * 96)
    print("TABLE 1 — known-set composition")
    print("| Seed | pos in known | neg in known | pos in STRICT | neg in STRICT | |known| | |STRICT known| |")
    for r in rows:
        print(f"| {r['seed']} | {r['pos_in_known_current']} | "
              f"{r['neg_in_known_current']:,} | {r['pos_in_known_strict']} | "
              f"{r['neg_in_known_strict']} | {r['n_known_current']:,} | "
              f"{r['n_known_strict']:,} |")
    print("\nTABLE 2 — C&S_CURRENT score distributions")
    print("| Seed | class | frac == known label | mean | median | min | max |")
    for r in rows:
        print(f"| {r['seed']} | negatives | {r['frac_neg_eq_label']:.6f} | "
              + " | ".join(f"{v:.6f}" for v in r["neg"]) + " |")
        print(f"| {r['seed']} | positives | — | "
              + " | ".join(f"{v:.6f}" for v in r["pos"]) + " |")
    print("\nTABLE 3 — AUC per seed and mean ± std")
    print("| Seed | " + " | ".join(METHODS) + " |")
    for r in rows:
        print("| " + str(r["seed"]) + " | "
              + " | ".join(f"{r[f'auc_{m}']:.6f}" for m in METHODS) + " |")
    print("| mean ± std | " + " | ".join(
        f"{summary[m][0]:.6f} ± {summary[m][1]:.6f}" for m in METHODS) + " |")
    print("\nTABLE 4 — STRICT label-permuted control")
    print("| Seed | permuted AUC |")
    for r in rows:
        print(f"| {r['seed']} | {r['perm_auc']:.6f} |")
    print(f"| mean ± std | {perm_mean:.6f} ± {perm_std:.6f} "
          f"(|mean−0.5|={abs(perm_mean-0.5):.6f}, tol {SANITY_TOL}) |")
    print("\n" + one_line)
    print(f"[OK] Report written to {OUT_MD}")


def write_report(rows, summary, perm_mean, perm_std, perm_near,
                 repro, frozen_ok, one_line):
    L = []
    A = L.append
    A("# Hybrid Leak Audit — known-set composition and C&S_STRICT")
    A("")
    A("Branch `hybrid-cs` · generated by `TrainModel/masked_edge_hybrid_audit.py` "
      "(new file). No existing file was modified. No tuning, no grid, no reruns.")
    A("")
    A(f"**Frozen hyperparameters reused verbatim:** alpha = {ALPHA_FROZEN}, "
      f"n_iter = {N_ITER_FROZEN}, selected by `TrainModel/masked_edge_hybrid_cs.py` "
      f"on tuning mask seeds `[52, 72, 92]` and recorded in "
      f"`phase5/HYBRID_RESULT.md` §2. Frozen-token check against that file: "
      f"**{'OK' if frozen_ok else 'NOT FOUND'}**. No retuning was performed.")
    A("")
    A("All C&S calls go through the frozen `correct_and_smooth()` and "
      "`normalized_adjacency()` implementations imported from "
      "`TrainModel/masked_edge_hybrid_cs.py`; the strict variant changes **only** "
      "the known-set mask. Labels are `label_clean` = `vpss_labeler.label_all()` "
      "on the masked graph. The same mask instance / positives / negatives are "
      "used for every method of a seed. Official `compute_auc`, population std "
      "(`ddof=0`).")
    A("")
    A("Definitions:")
    A("")
    A("- `known_CURRENT` = every package NOT masked (the frozen hybrid's known "
      "set). `Y0[known] = label_clean[known]`; masked positives are unknown.")
    A("- `known_STRICT` = every package except ALL evaluated nodes (masked "
      "positives ∪ 8,682 never-vulnerable negatives). Excluded nodes get "
      "residual 0 and are never clamped.")
    A("")

    A("## 1. Known-set composition (per seed)")
    A("")
    A("| Seed | masked positives | positives in known_CURRENT | 8,682 negatives "
      "in known_CURRENT | positives in known_STRICT | negatives in known_STRICT "
      "| known_CURRENT size | known_STRICT size |")
    A("|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        A(f"| {r['seed']} | {r['n_pos']} | {r['pos_in_known_current']} | "
          f"{r['neg_in_known_current']:,} | {r['pos_in_known_strict']} | "
          f"{r['neg_in_known_strict']} | {r['n_known_current']:,} | "
          f"{r['n_known_strict']:,} |")
    A("")

    A("## 2. C&S_CURRENT score distributions on the evaluated set")
    A("")
    A(f"`frac == known label` = fraction of evaluated negatives whose final "
      f"C&S_CURRENT score equals its clamped/known label within 1e-6 "
      f"(`label_clean` is 0 for all {rows[0]['n_neg_zero_label']:,} of them). "
      "Statistics are over final scores, not ranks.")
    A("")
    A("| Seed | class | frac == known label | mean | median | min | max |")
    A("|---:|---|---:|---:|---:|---:|---:|")
    for r in rows:
        A(f"| {r['seed']} | negatives | {r['frac_neg_eq_label']:.6f} | "
          + " | ".join(f"{v:.6f}" for v in r["neg"]) + " |")
        A(f"| {r['seed']} | positives | — | "
          + " | ".join(f"{v:.6f}" for v in r["pos"]) + " |")
    A("")

    A("## 3. AUC per seed, and mean ± std (ddof=0)")
    A("")
    A("| Seed | " + " | ".join(METHODS) + " |")
    A("|---:|" + "---:|" * len(METHODS))
    for r in rows:
        A("| " + str(r["seed"]) + " | "
          + " | ".join(f"{r[f'auc_{m}']:.6f}" for m in METHODS) + " |")
    A("| mean ± std | " + " | ".join(
        f"{summary[m][0]:.6f} ± {summary[m][1]:.6f}" for m in METHODS) + " |")
    A("")

    A("## 4. Label-permuted control under the STRICT known set")
    A("")
    A(f"`label_clean` is permuted among `known_STRICT` nodes only "
      f"(`RandomState({PERM_SEED_BASE}+seed)`), the permuted vector is fed to "
      f"BOTH C&S steps, frozen alpha/n_iter, identical masks. Expectation: "
      f"near 0.5 (`SANITY_TOL = {SANITY_TOL}`).")
    A("")
    A("| Seed | permuted AUC |")
    A("|---:|---:|")
    for r in rows:
        A(f"| {r['seed']} | {r['perm_auc']:.6f} |")
    A(f"| mean ± std | {perm_mean:.6f} ± {perm_std:.6f} |")
    A("")
    A(f"|mean − 0.5| = {abs(perm_mean-0.5):.6f} → "
      f"**{'near 0.5 (PASS)' if perm_near else 'NOT near 0.5 (FAIL — reported, not rerun)'}**.")
    A("")

    A("## 5. Reproduction checks (harness fidelity, no retuning)")
    A("")
    A("| Method | Published mean | This audit | Status |")
    A("|---|---:|---:|:---:|")
    for c in repro:
        A(f"| {c['name']} | {c['expected']:.6f} | {c['observed']:.6f} | "
          f"{'OK' if c['ok'] else 'FAILED'} |")
    A("")

    A("## 6. Required single line")
    A("")
    A(one_line)
    A("")
    A("## 7. Reproduce")
    A("")
    A("```bash")
    A("cd C:/Users/soumy/Desktop/VulnChain")
    A("git checkout hybrid-cs")
    A("python TrainModel/masked_edge_hybrid_audit.py")
    A("```")
    A("")
    A("Writes only `phase5/HYBRID_AUDIT.md`.")
    OUT_MD.write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
