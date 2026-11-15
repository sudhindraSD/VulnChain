# Task D — confirmatory pre-registration: HR + LP_clean rank-average

**PRE-REGISTRATION. Written and committed ALONE before any run script exists.**
No edit to this file after its commit. Branch `hybrid-cs`. T = 2024-07-01 is not
used by this audit; this file governs only the five-seed masked-edge
confirmatory run below.

Provenance: gate-rule commit `8989cd4` is valid. `HYBRID_GATE_ADDENDUM2.md`
records that the original C&S "PASS" is invalid, that C&S_STRICT is a negative
result, and that `RANK_AVG(HR, LP_clean) = 0.692055` on seeds
`[42, 123, 456, 789, 1024]` is EXPLORATORY. That number is NOT a result until
confirmed on fresh seeds. PHASE 1 established that `2001-2005` are unused as
mask seeds anywhere in the repo (gate seeds `[42, 123, 456, 789, 1024]`,
tuning seeds `[52, 72, 92]`).

## 1. Setup

- **Mask seeds:** `[2001, 2002, 2003, 2004, 2005]`, fresh and disjoint from the
  gate and tuning seeds. No substitution.
- **Mask:** 50% edge mask, the official
  `apply_edge_mask(data, eligible, pkg_id_to_idx, graph_json, cve_id_to_idx,
  0.50, seed)` from `TrainModel/masked_edge_audit.py`. Its actual semantics are
  copied, not invented: a Bernoulli(0.50) draw per ELIGIBLE PACKAGE removes
  ALL of that package's `hasVulnerability` edges, zeroes `Package.x[:, 6]` for
  masked packages, and forces at least 3 masked packages. ONE identical mask
  instance per seed is shared by every method.
- **Data:** `phase5/bench_run/vulnchain_graph.json` (12,405 packages),
  `phase4/vpss_labels_51repo.json`, `phase4/repo_split_mapping_51repo.json`,
  `phase5/models/vulngat_hr_full.pt`.
- **Eligible nodes:** official `compute_own_vpss` + `select_eligible_packages(0.70)`
  (with its documented auto-relaxation to 0.30) → **645**; hard assert `== 645`.
- **Negatives:** official `get_never_vuln_indices(vpss_labels_original,
  pkg_id_to_idx, n)` → **8,682**; hard assert `== 8682`. These are shared over
  all seeds and all methods, exactly as in the audit.
- **Positives per seed:** `pos = list(masked_pkg_indices)`. The counts the new
  masks yield are REPORTED per seed; no count is assumed.
- **Evaluated set:** `eval_idx = evaluated_indices(pos, neg)` from
  `TrainModel/masked_edge_audit_complement.py` = `list(pos) + list(neg)`.
  Report `len(pos)`, `len(neg)`, `len(eval_idx)`, `n` per seed.
- **Metric:** ROC-AUC per seed = the official
  `compute_auc(scores, pos, neg)` (Wilcoxon–Mann–Whitney, ties = 0.5), exactly
  the audit's definition.
- **No GNN training, no new GNN, no tuning, no weights, no threshold changes.**

## 2. Leak fix (mandatory)

- VPSS is recomputed on the MASKED graph for all packages by
  `recompute_vpss_labels(graph_json, masked_pkg_ids)` from
  `TrainModel/masked_edge_audit_leakfix.py` (bit-exact labeler). `y_clean =
  vpss_array_from(masked_labels, pkg_id_to_idx, n)`.
- EVERY graph-derived feature is recomputed on `masked_data`: LP neighbour sets
  via `build_lp_neighbors(masked_data)`, RIDGE features
  `masked_data["Package"].x` (dim 6 zeroed by `apply_edge_mask`), HR inference
  on `masked_data`.
- The original label file is used ONLY to define eligibility and the negative
  set; it is never used as a label value by any scoring method.

## 3. HR protocol — copied verbatim from the audit

- `VulnGAT()` is instantiated ONCE and loaded ONCE with
  `torch.load("phase5/models/vulngat_hr_full.pt", map_location=cpu,
  weights_only=True)`, then `.eval()` — before the seed loop.
- Per seed: `hr = run_model_inference(model, masked_data, device)` from
  `TrainModel/masked_edge_audit.py`.
- **HR is NOT retrained, fine-tuned or head-refit on the masked graph.** The
  frozen checkpoint is inference-only; the only per-seed change is the masked
  graph it is run on (`apply_edge_mask` zeroes `Package.x[:, 6]`).
- `LP_clean = run_label_prop_baseline(masked_data, masked_labels,
  pkg_id_to_idx, idx_to_pkg_id, n)` — the official LP, fed masked-graph VPSS.
- `RIDGE_RAW = ridge_raw_scores(masked_data, y_clean, train_mask)` from
  `TrainModel/masked_edge_hybrid_cs.py`: `Ridge(alpha=1.0)` on the 10 raw
  Package features of `masked_data`, fitted on `masks["train_mask"]`, target
  `y_clean`, sigmoid on predictions. Used ONLY to build
  `RANK_AVG(RIDGE, LP_clean)`. No retuning.

## 4. Candidate

- `CANDIDATE = rank_avg_scores(hr, lp_clean, eval_idx, n)` as defined in
  `TrainModel/masked_edge_hybrid_cs.py` / `masked_edge_audit_complement.py`:
  `0.5 * rankdata(hr[eval_idx], method="average") +
  0.5 * rankdata(lp_clean[eval_idx], method="average")`, embedded into a
  length-`n` zero vector (non-evaluated entries 0), so the official
  `compute_auc(CANDIDATE, pos, neg)` consumes it unchanged.
- Equal-weight rank-average over the evaluated set, AVERAGE ranks for ties,
  NO tuning, NO weights, NO per-seed choices.
- `RANK_AVG(RIDGE, LP_clean) = rank_avg_scores(ridge, lp_clean, eval_idx, n)`,
  the same construction.

## 5. Primary gate — verdict depends ONLY on this

For each seed `s`, on the identical mask:
`delta_s = AUC(CANDIDATE_s) - AUC(LP_clean_s)` (paired).

- `mean_delta = mean(delta_s)`
- `sd_delta = np.std(delta_s, ddof=1)` — SAMPLE std over the 5 deltas
- `threshold = max(0.02, 2 * sd_delta)` (computed explicitly in the result)
- **PASS iff `mean_delta > threshold`; otherwise FAIL.** A FAIL is reported as
  a FAIL.

## 6. Secondary — reported, does NOT change the verdict

- `mean_s[AUC(CANDIDATE_s) − AUC(HR_s)] > 0.02` → report the mean paired
  delta and YES/NO.
- `mean_s[AUC(CANDIDATE_s) − AUC(RANK_AVG(RIDGE, LP_clean)_s)] > 0` → report
  the mean paired delta and YES/NO.
- Both are reported as outcomes only; neither can turn a FAIL into a PASS or a
  PASS into a FAIL.

## 7. Controls — all per seed, on the SAME pos / neg eval sets

Definitions are fixed here; none is chosen after seeing a metric.

**(a) Labels permuted over ALL packages.** `y_perm = y_clean` permuted across
ALL `n` packages with `RandomState(20261114 + seed)` (the repo's
`PERM_SEED_BASE + seed`), NOT restricted to known nodes — this is the fix for
the strict permuted-label control that scored 0.662 by permuting only among
`known_STRICT` nodes and therefore preserved locality. `LP_perm =
run_label_prop_baseline(masked_data, labels_from(y_perm), pkg_id_to_idx,
idx_to_pkg_id, n)`, where `labels_from(y_perm)` maps each `pkg_id` to
`{"vpss": y_perm[idx]}`. `PERM_ALL = compute_auc(LP_perm, pos, neg)`.
Null expectation ~0.5; report mean and std. The rank-average recomputed with
`LP_perm` in place of `LP_clean` (`CANDIDATE_perm`) is reported as an extra
column; HR itself is unchanged by the permutation and is not permuted.

**(b) Binarised-label LP.** Identical `run_label_prop_baseline` and identical
neighbour sets, but every masked-graph VPSS label is replaced by
`1.0 if vpss > 0 else 0.0`. `BINARISED_LP = compute_auc(score, pos, neg)`.

**(c) Degree baseline.** `neighbors = build_lp_neighbors(masked_data)`;
`score[i] = len(neighbors.get(i, set()))`, the number of distinct Package
neighbours in the masked-graph LP adjacency.
`DEGREE = compute_auc(score, pos, neg)`.

**(d) Nonzero-neighbour-count baseline.** On the same `neighbors` and the same
`y_clean`: `score[i] = sum(1 for j in neighbors.get(i, set()) if y_clean[j] > 0)`.
`NONZERO_NBR = compute_auc(score, pos, neg)`.

## 8. Reporting (phase5/CONFIRM_RESULT.md)

- Per-seed table: `LP_clean`, `HR`, `RIDGE_RAW`, `CANDIDATE`,
  `RANK_AVG(RIDGE, LP_clean)`, `CANDIDATE_perm`, `PERM_ALL`, `BINARISED_LP`,
  `DEGREE`, `NONZERO_NBR`.
- Per-seed paired deltas: `CANDIDATE − LP_clean`, `CANDIDATE − HR`,
  `CANDIDATE − RANK_AVG(RIDGE, LP_clean)`.
- Mean and std (`ddof=1`) of every column and every delta; the primary
  threshold computed explicitly from the five deltas.
- Set sizes per seed: `n`, `n_eligible`, `n_neg`, `n_pos`, `len(eval_idx)`.
- PASS/FAIL for the primary gate; YES/NO for the two secondary outcomes.
- Any logged crash.
- If the null control `PERM_ALL` mean is outside 0.45–0.55, say so
  prominently.
- No interpretation beyond arithmetic.

## 9. RUN RULES

- Run once. No retries, no threshold changes, no seed changes, no edits to
  this file after its commit.
- A crash BEFORE any metric is written may be fixed (infrastructure only) and
  rerun, and MUST be logged in the result file.
- Any metric seen once means the run is final. A FAIL is reported as a FAIL.
- No further analysis, no new runs, no GNN training, no new ideas after the
  final output.
