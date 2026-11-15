"""
confirm_gate_run.py - Task D confirmatory run (PHASE 3)
======================================================
Implements phase5/CONFIRM_GATE.md verbatim. Run ONCE.

Fresh mask seeds [2001, 2002, 2003, 2004, 2005]; 50% edge mask; official
eligible/negative construction; official compute_auc; frozen VulnGAT-HR
inference (NO retraining); VPSS and all graph-derived features recomputed on
the masked graph; equal-weight rank-average of HR and LP_clean over the
evaluated set with average ranks for ties. No tuning, no weights, no GNN
training.

Outputs phase5/CONFIRM_RESULT.md plus phase5/confirm_metrics.json (the
"any metric seen once" marker). Reads phase5/CONFIRM_CRASHLOG.txt if present.

Run:  C:/Python313/python.exe -B phase5/confirm_gate_run.py
"""

import sys
sys.dont_write_bytecode = True

import json
import traceback
from datetime import datetime
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
    rank_avg_scores,
    ridge_raw_scores,
)
from masked_edge_audit_complement import (           # noqa: E402
    evaluated_indices,
)
from training.dataset import load_vulnchain_dataset   # noqa: E402
from core.model.vulngat import VulnGAT                # noqa: E402

SEEDS = [2001, 2002, 2003, 2004, 2005]
PERM_SEED_BASE = 20261114

RESULT_MD = PROJECT_ROOT / "phase5" / "CONFIRM_RESULT.md"
METRICS_JSON = PROJECT_ROOT / "phase5" / "confirm_metrics.json"
CRASHLOG = PROJECT_ROOT / "phase5" / "CONFIRM_CRASHLOG.txt"

METHODS = [
    "LP_clean", "HR", "RIDGE_RAW", "CANDIDATE",
    "RANK_AVG(RIDGE,LP_clean)", "CANDIDATE_perm",
    "PERM_ALL", "BINARISED_LP", "DEGREE", "NONZERO_NBR",
]
DELTAS = ["CANDIDATE-LP_clean", "CANDIDATE-HR",
          "CANDIDATE-RANK_AVG(RIDGE,LP_clean)"]


def labels_from_array(y, pkg_id_to_idx):
    return {pkg_id: {"vpss": float(y[idx])}
            for pkg_id, idx in pkg_id_to_idx.items()}


def run():
    if METRICS_JSON.exists():
        print("ABORT: metrics already written once; any metric seen once means "
              "the run is final", flush=True)
        raise SystemExit(3)

    device = torch.device("cpu")
    print("Loading graph / labels / dataset / model ...", flush=True)
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
    n = data["Package"].num_nodes
    train_mask = masks["train_mask"]

    own_vpss_data = compute_own_vpss(graph_json, vpss_labels_original)
    eligible = select_eligible_packages(own_vpss_data, OWN_VPSS_THRESHOLD)
    neg = get_never_vuln_indices(vpss_labels_original, pkg_id_to_idx, n)
    print(f"  eligible={len(eligible)}  never_vuln={len(neg)}  n={n}",
          flush=True)
    assert len(eligible) == EXPECTED_ELIGIBLE, "ELIGIBILITY ASSERTION FAILED"
    assert len(neg) == EXPECTED_NEVER_VULN, "NEGATIVE ASSERTION FAILED"

    model = VulnGAT()
    model.load_state_dict(torch.load(MODEL_FILE, map_location=device,
                                     weights_only=True))
    model = model.to(device)
    model.eval()

    rows = []
    for seed in SEEDS:
        print(f"\n--- seed {seed} ---", flush=True)
        masked_data, masked_idx_set, _cves, _strata = apply_edge_mask(
            data, eligible, pkg_id_to_idx, graph_json, cve_id_to_idx,
            MASK_RATIO, seed,
        )
        masked_pkg_ids = {idx_to_pkg_id[i] for i in masked_idx_set
                          if i in idx_to_pkg_id}
        pos = list(masked_idx_set)
        eval_idx = evaluated_indices(pos, neg)
        assert len(np.unique(eval_idx)) == len(eval_idx), "EVAL SET OVERLAP"

        # Leak fix: VPSS recomputed on the MASKED graph.
        masked_labels, _stats = recompute_vpss_labels(graph_json, masked_pkg_ids)
        y_clean = vpss_array_from(masked_labels, pkg_id_to_idx, n).astype(np.float64)

        # HR: frozen checkpoint, inference only, NO retraining.
        hr = run_model_inference(model, masked_data, device).astype(np.float64)
        lp = run_label_prop_baseline(
            masked_data, masked_labels, pkg_id_to_idx, idx_to_pkg_id, n
        ).astype(np.float64)
        ridge = ridge_raw_scores(masked_data, y_clean, train_mask)
        neighbors = build_lp_neighbors(masked_data)

        candidate = rank_avg_scores(hr, lp, eval_idx, n)
        rank_ridge_lp = rank_avg_scores(ridge, lp, eval_idx, n)

        # (a) labels permuted over ALL n packages
        rng = np.random.RandomState(PERM_SEED_BASE + seed)
        y_perm = y_clean[rng.permutation(n)]
        lp_perm = run_label_prop_baseline(
            masked_data, labels_from_array(y_perm, pkg_id_to_idx),
            pkg_id_to_idx, idx_to_pkg_id, n
        ).astype(np.float64)
        candidate_perm = rank_avg_scores(hr, lp_perm, eval_idx, n)

        # (b) binarised-label LP
        labels_bin = {
            pid: {"vpss": 1.0 if float(e.get("vpss", 0.0)) > 0 else 0.0}
            for pid, e in masked_labels.items()
        }
        lp_bin = run_label_prop_baseline(
            masked_data, labels_bin, pkg_id_to_idx, idx_to_pkg_id, n
        ).astype(np.float64)

        # (c) degree / (d) nonzero-neighbour-count on masked-graph LP adjacency
        degree = np.zeros(n, dtype=np.float64)
        nonzero = np.zeros(n, dtype=np.float64)
        for i in range(n):
            nbrs = neighbors.get(i, set())
            degree[i] = len(nbrs)
            nonzero[i] = sum(1 for j in nbrs if y_clean[j] > 0)

        scores = {
            "LP_clean": lp, "HR": hr, "RIDGE_RAW": ridge,
            "CANDIDATE": candidate,
            "RANK_AVG(RIDGE,LP_clean)": rank_ridge_lp,
            "CANDIDATE_perm": candidate_perm,
            "PERM_ALL": lp_perm, "BINARISED_LP": lp_bin,
            "DEGREE": degree, "NONZERO_NBR": nonzero,
        }
        row = {"seed": seed, "n": n, "n_eligible": len(eligible),
               "n_neg": len(neg), "n_pos": len(pos),
               "len_eval_idx": int(len(eval_idx))}
        for m in METHODS:
            row[m] = float(compute_auc(scores[m], pos, neg))
        row["CANDIDATE-LP_clean"] = row["CANDIDATE"] - row["LP_clean"]
        row["CANDIDATE-HR"] = row["CANDIDATE"] - row["HR"]
        row["CANDIDATE-RANK_AVG(RIDGE,LP_clean)"] = (
            row["CANDIDATE"] - row["RANK_AVG(RIDGE,LP_clean)"])
        rows.append(row)
        print("  " + "  ".join(f"{m}={row[m]:.6f}" for m in METHODS),
              flush=True)
        # Written after each seed: any metric seen once makes the run final.
        METRICS_JSON.write_text(json.dumps({"partial": rows}, indent=2) + "\n",
                                encoding="utf-8")

    return rows, n, len(eligible), len(neg)


def summarise(rows):
    out = {}
    for k in METHODS + DELTAS:
        v = np.asarray([r[k] for r in rows], dtype=np.float64)
        out[k] = (float(v.mean()), float(v.std(ddof=1)))
    return out


def write_result(rows, n, n_eligible, n_neg, crashes):
    summ = summarise(rows)
    deltas = np.asarray([r["CANDIDATE-LP_clean"] for r in rows], float)
    mean_delta = float(deltas.mean())
    sd_delta = float(deltas.std(ddof=1))
    threshold = max(0.02, 2.0 * sd_delta)
    primary_pass = bool(mean_delta > threshold)

    sec_hr = summ["CANDIDATE-HR"][0]
    sec_rank = summ["CANDIDATE-RANK_AVG(RIDGE,LP_clean)"][0]
    perm_mean = summ["PERM_ALL"][0]
    perm_out = bool(perm_mean < 0.45 or perm_mean > 0.55)

    L = []
    A = L.append
    A("# Task D - confirmatory run result")
    A("")
    A("Pre-registered in `phase5/CONFIRM_GATE.md` (commit `ddcb442`). "
      "Mask seeds [2001, 2002, 2003, 2004, 2005], 50% edge mask, official "
      "eligible/negative construction, official `compute_auc`. "
      "Frozen VulnGAT-HR inference only (no retraining). VPSS and all "
      "graph-derived features recomputed on the masked graph. Equal-weight "
      "rank-average with average ranks for ties, no tuning, no weights. "
      "std = sample (ddof=1) throughout.")
    A("")
    if perm_out:
        A("## NULL CONTROL OUTSIDE 0.45-0.55")
        A("")
        A(f"**PERM_ALL mean = {perm_mean:.6f} - OUTSIDE 0.45-0.55.**")
        A("")
    A("## 1. Set sizes per seed")
    A("")
    A("| Seed | n | n_eligible | n_neg | n_pos | len_eval_idx |")
    A("|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        A(f"| {r['seed']} | {r['n']} | {r['n_eligible']} | {r['n_neg']} | "
          f"{r['n_pos']} | {r['len_eval_idx']} |")
    A("")
    A(f"Hard assertions: n_eligible == {EXPECTED_ELIGIBLE} PASS; "
      f"n_neg == {EXPECTED_NEVER_VULN} PASS. n = {n}.")
    A("")
    A("## 2. Per-seed ROC-AUC (all methods and controls)")
    A("")
    A("| Seed | " + " | ".join(METHODS) + " |")
    A("|---:|" + "---:|" * len(METHODS))
    for r in rows:
        A(f"| {r['seed']} | " + " | ".join(f"{r[m]:.6f}" for m in METHODS)
          + " |")
    A("")
    A("| mean | " + " | ".join(f"{summ[m][0]:.6f}" for m in METHODS) + " |")
    A("| std (ddof=1) | " + " | ".join(f"{summ[m][1]:.6f}" for m in METHODS)
      + " |")
    A("")
    A("## 3. Per-seed paired deltas")
    A("")
    A("| Seed | " + " | ".join(DELTAS) + " |")
    A("|---:|" + "---:|" * len(DELTAS))
    for r in rows:
        A(f"| {r['seed']} | " + " | ".join(f"{r[d]:+.6f}" for d in DELTAS)
          + " |")
    A("")
    A("| mean | " + " | ".join(f"{summ[d][0]:+.6f}" for d in DELTAS) + " |")
    A("| std (ddof=1) | " + " | ".join(f"{summ[d][1]:.6f}" for d in DELTAS)
      + " |")
    A("")
    A("## 4. Primary gate (verdict only on this)")
    A("")
    A(f"- deltas = [{', '.join(f'{d:+.6f}' for d in deltas)}]")
    A(f"- mean_delta = {mean_delta:.6f}")
    A(f"- sd_delta (ddof=1) = {sd_delta:.6f}")
    A(f"- 2 * sd_delta = {2.0 * sd_delta:.6f}")
    A(f"- threshold = max(0.02, 2 * sd_delta) = {threshold:.6f}")
    A(f"- mean_delta - threshold = {mean_delta - threshold:+.6f}")
    A(f"- PRIMARY: {'PASS' if primary_pass else 'FAIL'}")
    A("")
    A("## 5. Secondary (reported, verdict unchanged)")
    A("")
    A("| Secondary | mean paired delta | bar | outcome |")
    A("|---|---:|---:|---|")
    A(f"| CANDIDATE - HR | {sec_hr:+.6f} | > 0.02 | "
      f"{'YES' if sec_hr > 0.02 else 'NO'} |")
    A(f"| CANDIDATE - RANK_AVG(RIDGE,LP_clean) | {sec_rank:+.6f} | > 0 | "
      f"{'YES' if sec_rank > 0 else 'NO'} |")
    A("")
    A("## 6. Null control")
    A("")
    A(f"- PERM_ALL = LP with y_clean permuted over ALL {n} packages, "
      f"RandomState({PERM_SEED_BASE}+seed).")
    A(f"- mean = {perm_mean:.6f}; std (ddof=1) = {summ['PERM_ALL'][1]:.6f}; "
      f"outside 0.45-0.55 = {perm_out}.")
    A(f"- CANDIDATE_perm mean = {summ['CANDIDATE_perm'][0]:.6f} "
      f"(HR unchanged by permutation).")
    A("")
    A("## 7. Crash log")
    A("")
    if crashes:
        for c in crashes.splitlines():
            if c.strip():
                A(f"- {c}")
    else:
        A("- none.")
    A("")
    RESULT_MD.write_text("\n".join(L) + "\n", encoding="utf-8")
    return {"primary_pass": primary_pass, "mean_delta": mean_delta,
            "sd_delta": sd_delta, "threshold": threshold,
            "perm_mean": perm_mean, "perm_out": perm_out}


def main():
    rows, n, n_eligible, n_neg = run()
    crashes = CRASHLOG.read_text(encoding="utf-8") if CRASHLOG.exists() else ""
    verdict = write_result(rows, n, n_eligible, n_neg, crashes)
    METRICS_JSON.write_text(
        json.dumps({"rows": rows, "verdict": verdict}, indent=2) + "\n",
        encoding="utf-8")
    print(f"\nPRIMARY: {'PASS' if verdict['primary_pass'] else 'FAIL'} "
          f"mean_delta={verdict['mean_delta']:.6f} "
          f"threshold={verdict['threshold']:.6f}", flush=True)
    print(f"[OK] wrote {RESULT_MD.name}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        with open(CRASHLOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {type(exc).__name__}: {exc}\n")
            f.write(traceback.format_exc() + "\n")
        raise
