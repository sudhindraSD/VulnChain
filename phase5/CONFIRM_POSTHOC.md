# POST-HOC, DESCRIPTIVE, NOT PART OF THE PRE-REGISTERED GATE

Branch `hybrid-cs`. Seeds `[2001, 2002, 2003, 2004, 2005]` only. No frozen file
was edited (`PROOF_PROTOCOL.md`, `PROOF_RESULT.md`, `PROOF_POSTHOC*.md`,
`phase5/CONFIRM_GATE.md`, `phase5/CONFIRM_RESULT.md`, `proof/out/*`). No gate was
re-adjudicated. Arithmetic and lookups only; no verdict wording in sections 2-3.

## 1. Score vectors: reused or recomputed

**Recomputed.** No per-seed score vectors were saved by the Task D run:
`phase5/confirm_gate_run.py` builds a per-seed local `scores` dict inside `run()`
and writes only per-method AUC values to `phase5/confirm_metrics.json`. A search of
`phase5/` for `.npy` / `.npz` / `.pt` / `.pkl` / `*score*` / `*vector*` returned
only model checkpoints (`phase5/models/vulngat_hr_full.pt`,
`phase5/bench_run/models/vulngat_trained.pt`,
`phase5/bench_run_astrained/models/vulngat_trained.pt`,
`phase5/mlp_reconverged.pt`, `phase5/vulngat_hr.pt`,
`phase5/vulngat_epss_head_seed42.pt`, `phase5/v22_checkpoints/*.pt`) and
`phase5/pkg_embeddings_frozen.npy`; no per-seed score vectors.

Recomputation method: imported `phase5/confirm_gate_run.py` (the committed run
script) and used **its own module-level imported functions and constants** —
`apply_edge_mask`, `run_model_inference`, `run_label_prop_baseline`,
`compute_auc`, `get_never_vuln_indices`, `compute_own_vpss`,
`select_eligible_packages` (`TrainModel/masked_edge_audit.py`);
`recompute_vpss_labels`, `build_lp_neighbors`, `vpss_array_from`, `MASK_RATIO`,
`GRAPH_FILE`, `LABELS_FILE`, `SPLIT_FILE`, `MODEL_FILE`
(`TrainModel/masked_edge_audit_leakfix.py`); `rank_avg_scores`
(`TrainModel/masked_edge_hybrid_cs.py`); `evaluated_indices`,
`average_tie_ranks`, `embed`, `W_HR`, `W_LP`
(`TrainModel/masked_edge_audit_complement.py`); `load_vulnchain_dataset`
(`TrainModel/training/dataset.py`); `VulnGAT` (`TrainModel/core/model/vulngat.py`).

- `confirm_gate_run.run()` was **not** called (it aborts by design when
  `confirm_metrics.json` exists); the per-seed scoring block was reproduced with
  the same functions and the same order of operations.
- Frozen checkpoint `phase5/models/vulngat_hr_full.pt`, `torch.load(...,
  weights_only=True)`, `.eval()`, **inference only**. No retraining, no
  fine-tuning, no head refit, no new model, no new modelling.
- Interpreter: `C:/Python313/python.exe` (Python 3.13.7, numpy 2.2.6,
  torch 2.13.0+cpu), the interpreter named in the run script's docstring.
  Run with `-B` / `sys.dont_write_bytecode = True`; no file was written by the
  recomputation (working tree clean afterwards).
- Equal weights `W_HR = W_LP = 0.5`, declared at module import in
  `TrainModel/masked_edge_audit_complement.py:68-70` with
  `assert W_HR == W_LP == 0.5`. `average_tie_ranks` =
  `rankdata(..., method="average")` (average ranks for ties). `compute_auc` is
  the official Wilcoxon-Mann-Whitney function. No tuning, no per-seed choices.
- `n = 12405`, `eligible = 645`, `never_vuln = 8682`, `MASK_RATIO = 0.50`,
  `PERM_SEED_BASE = 20261114` — same as `phase5/CONFIRM_RESULT.md` §1.

Fidelity check: the recomputed AUCs for `LP_clean`, `HR`, `BINARISED_LP`,
`DEGREE`, `NONZERO_NBR` and `CANDIDATE` were compared against
`phase5/confirm_metrics.json` for every seed.

| Seed | max abs difference vs committed (6 methods) |
|---:|---:|
| 2001 | 0.0 |
| 2002 | 0.0 |
| 2003 | 0.0 |
| 2004 | 0.0 |
| 2005 | 0.0 |

## 2. Per-seed ROC-AUC (recomputed), mean and std (ddof=1)

| Seed | CANDIDATE (HR+LP_clean) | NONZERO_NBR | RANK_AVG(HR, NONZERO_NBR) | RANK_AVG(HR, BINARISED_LP) | RANK_AVG(HR, DEGREE) |
|---:|---:|---:|---:|---:|---:|
| 2001 | 0.680167 | 0.637721 | 0.683556 | 0.692036 | 0.613966 |
| 2002 | 0.690736 | 0.641199 | 0.688019 | 0.701364 | 0.611639 |
| 2003 | 0.688267 | 0.634095 | 0.683161 | 0.699920 | 0.610111 |
| 2004 | 0.664565 | 0.618568 | 0.668530 | 0.673495 | 0.607738 |
| 2005 | 0.683560 | 0.629210 | 0.688723 | 0.695158 | 0.627637 |
| mean | 0.681459 | 0.632159 | 0.682398 | 0.692395 | 0.614218 |
| std (ddof=1) | 0.010294 | 0.008801 | 0.008153 | 0.011203 | 0.007836 |

Full precision (recomputed values, not stored in any committed file):

```
2001  CANDIDATE=0.6801669275714949  NONZERO_NBR=0.6377211343214598  RANK_AVG(HR,NONZERO_NBR)=0.6835562984044694  RANK_AVG(HR,BINARISED_LP)=0.6920358893174744  RANK_AVG(HR,DEGREE)=0.6139659153049201
2002  CANDIDATE=0.6907360415226906  NONZERO_NBR=0.6411989244989633  RANK_AVG(HR,NONZERO_NBR)=0.6880193935729094  RANK_AVG(HR,BINARISED_LP)=0.7013639930315595  RANK_AVG(HR,DEGREE)=0.6116390232665284
2003  CANDIDATE=0.6882673389814602  NONZERO_NBR=0.6340950199220183  RANK_AVG(HR,NONZERO_NBR)=0.6831608109299502  RANK_AVG(HR,BINARISED_LP)=0.6999203332565461  RANK_AVG(HR,DEGREE)=0.6101109219870258
2004  CANDIDATE=0.6645650823897078  NONZERO_NBR=0.6185680450345878  RANK_AVG(HR,NONZERO_NBR)=0.6685300614521433  RANK_AVG(HR,BINARISED_LP)=0.6734953245527517  RANK_AVG(HR,DEGREE)=0.6077375054887953
2005  CANDIDATE=0.6835603050635651  NONZERO_NBR=0.6292099750454367  RANK_AVG(HR,NONZERO_NBR)=0.6887234111401054  RANK_AVG(HR,BINARISED_LP)=0.6951577438116304  RANK_AVG(HR,DEGREE)=0.6276365432190076
mean  CANDIDATE=0.681459139106     NONZERO_NBR=0.632158619764     RANK_AVG(HR,NONZERO_NBR)=0.682397995100     RANK_AVG(HR,BINARISED_LP)=0.692394656794     RANK_AVG(HR,DEGREE)=0.614217981853
std   CANDIDATE=0.010294493253     NONZERO_NBR=0.008800803239     RANK_AVG(HR,NONZERO_NBR)=0.008152517204     RANK_AVG(HR,BINARISED_LP)=0.011203045589     RANK_AVG(HR,DEGREE)=0.007836403332
```

`CANDIDATE` and `NONZERO_NBR` values are identical to
`phase5/confirm_metrics.json` (see fidelity table). The three `RANK_AVG` columns
use the same `rank_avg_scores` and `compute_auc` calls, substituting `nonzero`,
`lp_bin`, `degree` for `lp` as the second vector.

## 3. Paired deltas: CANDIDATE minus each of the five methods in section 2

| Seed | CANDIDATE − CANDIDATE | CANDIDATE − NONZERO_NBR | CANDIDATE − RANK_AVG(HR, NONZERO_NBR) | CANDIDATE − RANK_AVG(HR, BINARISED_LP) | CANDIDATE − RANK_AVG(HR, DEGREE) |
|---:|---:|---:|---:|---:|---:|
| 2001 | +0.000000 | +0.042446 | -0.003389 | -0.011869 | +0.066201 |
| 2002 | +0.000000 | +0.049537 | +0.002717 | -0.010628 | +0.079097 |
| 2003 | +0.000000 | +0.054172 | +0.005107 | -0.011653 | +0.078156 |
| 2004 | +0.000000 | +0.045997 | -0.003965 | -0.008930 | +0.056828 |
| 2005 | +0.000000 | +0.054350 | -0.005163 | -0.011597 | +0.055924 |
| mean | +0.000000 | +0.049301 | -0.000939 | -0.010936 | +0.067241 |
| std (ddof=1) | 0.000000 | 0.005177 | 0.004553 | 0.001219 | 0.011150 |

Full precision deltas:

```
CANDIDATE-NONZERO_NBR            [0.042445793250, 0.049537117024, 0.054172319059, 0.045997037355, 0.054350330018]  mean=0.049300519341  std=0.005176660648
CANDIDATE-RANK_AVG(HR,NONZERO_NBR) [-0.003389370833, 0.002716647950, 0.005106528052, -0.003964979062, -0.005163106077]  mean=-0.000938855994  std=0.004552914174
CANDIDATE-RANK_AVG(HR,BINARISED_LP) [-0.011868961746, -0.010627951509, -0.011652994275, -0.008930242163, -0.011597438748]  mean=-0.010935517688  std=0.001218601333
CANDIDATE-RANK_AVG(HR,DEGREE)    [0.066201012267, 0.079097018256, 0.078156416994, 0.056827576901, 0.055923761845]  mean=0.067241157253  std=0.011150250351
CANDIDATE-CANDIDATE              [0, 0, 0, 0, 0]  mean=0  std=0
```

## 4. HR training and the masked edges (one line)

**Yes — HR's training graph included the edges the audit later masks:** the frozen checkpoint `phase5/models/vulngat_hr_full.pt` was trained on the full graph with `hasVulnerability` edges present, the per-seed 50% mask is applied only at inference, and HR is not retrained, fine-tuned or head-refit on the masked graph.

Evidence looked up: `phase5/DIAGNOSIS_39to85.md:122` ("the encoder trained with hasVulnerability edges present; masked inference is out-of-distribution"); `phase5/CONFIRM_GATE.md:61-67` (single `torch.load` of `vulngat_hr_full.pt` before the seed loop; "HR is NOT retrained, fine-tuned or head-refit on the masked graph. The frozen checkpoint is inference-only; the only per-seed change is the masked graph it is run on (`apply_edge_mask` zeroes `Package.x[:, 6]`)"); `TrainModel/implementation_plan.md:189` ("The full graph structure is still used for message passing (this is standard in transductive GNN training)"); `TrainModel/masked_edge_audit.py:162-187` (`apply_edge_mask` operates on a deep copy of the inference `HeteroData`); `TrainModel/masked_edge_audit_leakfix.py:59` (`MODEL_FILE = phase5/models/vulngat_hr_full.pt`).

## 5. PERM_ALL per seed, with the 2004 flag

Values copied from `phase5/confirm_metrics.json` (`PERM_ALL` = LP with `y_clean`
permuted over all 12405 packages, `RandomState(20261114 + seed)`).

| Seed | PERM_ALL | outside 0.45-0.55 |
|---:|---:|---|
| 2001 | 0.505358 | false |
| 2002 | 0.512437 | false |
| 2003 | 0.517253 | false |
| **2004** | **0.560368** | **true — FLAGGED (0.560368 > 0.55)** |
| 2005 | 0.489114 | false |
| mean | 0.516906 | false |
| std (ddof=1) | 0.026527 | — |

Full precision: `0.50535830071103`, `0.5124370104814558`,
`0.5172527735829202`, `0.5603676169644595`, `0.48911387031485587`;
mean `0.5169059144109444`, std (ddof=1) `0.026527137518`.

Seed count outside 0.45-0.55 = 1 of 5 (seed 2004). `phase5/CONFIRM_RESULT.md` §6
reports `outside 0.45-0.55 = False` for the **mean** (`perm_out = false` in
`confirm_metrics.json`), which is a different quantity from the per-seed flag
above. `CANDIDATE_perm` mean = 0.602495.

## 6. CS3 post-hoc line (lookup only)

`verademo-javascript@0.0.0 -> cookie-parser@1.4.6 -> cookie@0.4.1` — the single printed path in `proof/out/flagged_packages.json` for `cookie-parser@1.4.6`, with `advisory_endpoint = cookie@0.4.1`, `advisory_ids = ['GHSA-pxg6-pf52-xh8x']`, `hops = 2`.
