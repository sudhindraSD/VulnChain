# V2 AUTOPSY — Checkpoint Forensics
**Status:** COMPLETE — v2 result classified **(A) execution defect** (quarantine upheld; primary gate was never measured)
**Date:** 2026-09-20
**Scope:** Forensic analysis of the quarantined VulnGAT v2 result (35 checkpoints, `vulngat_v2_final_results.json`, `phase5/vulngat_v2_training.ipynb`, `phase5/VULNGAT_V2_PREREGISTRATION.md`).
**Rules compliance:** NO training of any kind was performed. No thresholds or hyperparameters were changed. Nothing was fixed or rerun. All work is CPU-only inference on the quarantined checkpoints plus code reading. Every number below is reproducible from the scripts listed in Appendix A.

---

## 0. Verdict (TL;DR)

> **Classification: (A) Execution defect — HIGH confidence (~95%).**
> Three independent, individually sufficient defects, all inside the pre-registered notebook artifact itself (the Colab run faithfully executed its own flawed spec — this is a protocol-artifact defect, not a Colab execution slip):
>
> - **A1 — Eligibility filter re-implementation bug:** the notebook's inline re-computation of the masked-audit eligible strata yields **0 packages** (the 0.70 own-ratio threshold is mathematically unreachable on this graph: max own_ratio = 0.6667). The official tool reaches N=645 only via a **silent auto-relaxation to 0.30** that the notebook dropped. Empty positive set → `roc_auc_score` on a single-class label vector → **AUC = NaN on all 35 runs**. **The primary gate was never measured.**
> - **A2 — Missing reverse message-passing directions:** v2's `HeteroConv` contains only the 4 forward edge directions. Package nodes receive messages **only** from other packages via `dependsOn`. CVEs and Authors are architecturally disconnected from the prediction head. Consequence: masking `hasVulnerability` edges **provably cannot change any package prediction** (empirical: removing 100% of them changes predictions by exactly **0.000e+00**), so the auxiliary masked-consistency loss is **identically zero**, and `p_mask` is causally inert.
> - **A3 — Missing feature normalization:** Phase 4 min-max-normalized package dims [2,3,4,5,7], divided CVSS by 10, and normalized author dims [0,1,2,3,6]. v2 fed **raw** features (dim4 max 5,595; dim5 max 4,002; author dim0 max 6,807; CVSS raw 1.7–10.0). Layer-1 preactivations explode to std ≈ 476 (absmax 1,762) at **initialization**; final logits sit at |logit| up to 531 → **sigmoid saturation → gradient ≈ 0 → the models never learned.**
>
> - **(B) degenerate convergence — REJECTED as stated.** The outputs are degenerate (saturated two-point masses at 0.0/0.47 or 0/1), but there was no *convergence*: weights sit 0.2–1.3% (L2) from their random init. The degeneracy is dead-on-arrival saturation caused by A3 (+A2), not an optimum the pre-registered objective found.
> - **(C) temporal generalization failure — REFUTED.** There is no high-train/low-test signature: train Spearman is **−0.073…+0.082 (chance)** and test Spearman −0.017…+0.056 (chance). Nothing was learned in-period, so there was nothing to fail to generalize.
>
> **Counterfactual primary gate** (computed here by inference only, on the *official* N=645 strata with the verbatim 50%-masked evaluation): **AUC = 0.495 ± 0.039** for every `full_v2` config — pure chance, 0.24 below the 0.7391 bar, and indistinguishable across p ∈ {0.1, 0.3, 0.5}.
>
> **Consequence for the Brain:** the pre-committed row "execution defect → one rerun, *identical* protocol" **cannot be applied literally**: an identical-protocol rerun deterministically reproduces all three defects (they are in the spec). The single conditional rerun, if granted, requires a protocol amendment (reverse edge directions or bidirectional conv, Phase-4 normalization, corrected eligibility filter). Per orders, **no rerun was performed**; the decision is the Brain's.

---

## 1. Autopsy Item 1 — Train-set metrics (the missing number)

**Method:** all 35 checkpoints were loaded on CPU; the notebook's data wiring (cell 3) and architecture (cell 4) were rebuilt verbatim; predictions were computed with the trained weights in eval mode. Reproduction fidelity was verified first: my recomputed **val Spearman matches the Colab-stored values bit-exactly** (Δ = 0.00e+00 on all checked runs; test Δ ≤ 3e-7), proving the forensic pipeline is the same computation that produced the quarantined result.

Populations reconstructed: train_fit N=1,807 / val N=451 / test N=1,433 (all non-zero EPSS-closure packages; total 3,691 ✓). Note two small prereg-vs-executed drifts: prereg says val N=452 and test N=1,430; the executed notebook computed 451 and 1,433 (integer floor of 0.20×2,258, and BFS/date boundary details). Documentation-level, listed for completeness.

### 1.1 Seed-42 representative runs (full table in `autopsy_behavior_results.json`)

| Run | Train r_s | Train MSE | Val r_s | Test r_s | Pred mean | Pred std | Pred quantiles [0/25/50/75/100%] |
|---|---|---|---|---|---|---|---|
| full_v2_p10_s42 | **−0.0730** | 0.0618 | −0.0680 | +0.0548 | 0.146 | 0.219 | 0 / 0 / 0 / 0.4735 / 0.4744 |
| full_v2_p30_s42 | −0.0730 | 0.0618 | −0.0680 | +0.0548 | 0.146 | 0.219 | identical to p10 |
| full_v2_p50_s42 | −0.0730 | 0.0618 | −0.0680 | +0.0548 | 0.146 | 0.219 | identical to p10 |
| no_masking_s42 | −0.0732 | 0.0623 | −0.0712 | +0.0544 | 0.146 | 0.220 | 0 / 0 / 0 / 0.4756 / 0.4762 |
| no_ranking_p10_s42 | −0.0711 | 0.0620 | −0.0680 | +0.0562 | 0.146 | 0.219 | 0 / 0 / 0 / 0.4742 / 0.4750 |
| full_v2_p30_s123 | +0.0545 | 0.6192 | +0.0609 | −0.0169 | 0.805 | 0.274 | 0 / 0 / 0.517 / 1.0 / 1.0 |
| full_v2_p30_s789 | +0.0719 | 0.6526 | +0.0818 | −0.0076 | 0.840 | 0.238 | 0.4835 / 0.4835 / 0.4835 / 1.0 / 1.0 |

**Reading the numbers:**

- **There is no train fit anywhere.** Best train Spearman across all arms/seeds is +0.082 (chance). Train MSE is 0.062 (seed 42) to 0.65 (seeds 123/789/1024). Reference: a constant-mean predictor on the train population achieves MSE = Var(y) = 0.1012² = **0.0102**. The models are **6× to 64× worse than predicting a constant**.
- **The "near-zero variance" signature is present but in a specific form:** not a single constant output, but a **saturated two-point mass** — sigmoid clipped at exactly 0.0 and 0.4744 (seed 42) or at 0/0.517/1.0 (seed 123) / 0.4835/1.0 (seed 789). Global pred std 0.22–0.27 is an artifact of this bimodality, not signal. Only 199–1,239 distinct prediction values (at 1e-6) exist across all 12,405 packages.
- **Hypothesis C (high train fit + ~0 test) is refuted**: train and test are both at chance (train −0.07…+0.08, test −0.02…+0.06). The 39%-era signature ("fits in-period, fails out-of-period") is absent because no fitting happened at all.

### 1.2 Audit-strata prediction dispersion (the NaN population, evaluated cleanly)

On the **official** 645 eligible packages and 8,682 never-vulnerable packages (clean graph, eval mode):

| Run | 645-strata pred mean | 645-strata pred std | 8,682-neg pred mean | 8,682-neg pred std |
|---|---|---|---|---|
| full_v2_p10_s42 | 0.1124 | 0.202 | 0.1176 | 0.204 |
| full_v2_p30_s123 | 0.8306 | 0.271 | 0.8299 | 0.253 |
| full_v2_p30_s789 | 0.8743 | 0.219 | 0.8603 | 0.221 |

Positive and negative strata are statistically indistinguishable (Δmean ≤ 0.014 on overlapping saturated bimodal distributions) → **AUC ≈ 0.5 by construction of the dead model**, confirmed exactly by the counterfactual below.

---

## 2. Autopsy Item 2 — p_mask plumbing audit (the smoking gun)

**The direct question: did `full_v2 (p=0.1/0.3/0.5)` contain three distinct trainings or one training tabulated thrice?**

**Answer: three distinct trainings were executed — and they were causally identical, so they produced indistinguishable results.** Not copy-paste, not a logging bug.

### 2.1 Evidence of distinct trainings
- **All 35 checkpoint MD5s are distinct** (`vulngat_v2_checkpoints/`).
- **Weight-level diffs across p within the same seed and arm are nonzero and non-monotonic in p** (max|Δw|): full_v2 s42: p10↔p30 = 2.9e-3, p10↔p50 = 3.1e-3, p30↔p50 = 2.2e-3; s1024: 5.3e-3 / 5.6e-3 / 5.0e-3; s123: 3.9e-4 / 5.4e-4 / 1.7e-4; s789: 2.3e-5 / 4.0e-5 / 1.7e-5. One-training-tabulated-thrice would give exactly 0. These magnitudes are consistent with GPU atomic-scatter nondeterminism over ~30–100 epochs of a barely-moving model, not with a real p-dependence (see 2.3).

### 2.2 The code path (notebook cell 5, verbatim)
```python
if use_edge_mask and p_mask > 0:
    masked_edges = apply_dynamic_edge_dropout(data.edge_index_dict, p_mask)
    preds_masked, _ = model(data.x_dict, masked_edges)
    loss_aux = F.mse_loss(preds_masked[train_mask], preds_clean[train_mask].detach())
    loss_total += LAMBDA_AUX * loss_aux
```
and cell 4:
```python
def apply_dynamic_edge_dropout(edge_index_dict, p_mask=0.30):
    new_edges = copy.copy(edge_index_dict)
    cve_edge_key = ('Package', 'hasVulnerability', 'CVE')
    ...
    mask = torch.rand(edges.size(1), device=edges.device) > p_mask
```
`p_mask` **was plumbed and did vary** — the dropout function is correct, the run matrix passes p ∈ {0.1, 0.3, 0.5} into distinct `run_id`s, and epoch-level edge-mask counts were **not logged** anywhere (the harness stores only per-run final records; `v2_runs/v2_intermediate_results.json` does not exist locally — it lived Colab-side and was not downloaded).

### 2.3 Why the three trainings are nonetheless identical
Three chained facts:
1. **The masked edge type is architecturally dead for the head.** The `HeteroConv` dict (cell 4) contains only forward directions: `Package→CVE`, `Package→Author`, `CVE→Author`, `Package→Package`. Output for `Package` therefore depends **only** on `dependsOn` edges and package features. Dropping `hasVulnerability` edges cannot reach the classifier input. **Empirical proof:** with `full_v2_p30_s42` weights, removing **100%** of hasVulnerability edges changes package predictions by **max|Δpred| = 0.000e+00** exactly (also 0.0 at p_mask = 0.1/0.3/0.5/0.9 partial drops).
2. **Therefore `L_aux ≡ 0` identically**, every epoch, every p: `preds_masked == preds_clean` bitwise on the Package head. The full_v2 arm's third loss term contributes exactly zero gradient. Effective objective of full_v2 = MSE + 0.20·rank; of no_ranking = MSE; of no_masking = MSE + 0.20·rank.
3. **The RNG stream is p-independent.** `torch.rand(edges.size(1))` draws the same number of variates for any p (p only sets the keep threshold), so the full per-epoch draw sequence (clean-forward dropout → ranking `randint` → mask `rand` → masked-forward dropout) is **identical across p10/p30/p50** for a fixed seed. Same effective objective + same RNG stream + (only) float-rounding differences in a causally dead branch → trajectories identical up to GPU nondeterminism.

### 2.4 Why the table rows are identical to 4+ decimals
Spearman is a **rank** statistic over saturated bimodal predictions (gaps of ~0.47 between the two modes; exact ties within a mode). Float-noise differences of 1e-9 cannot flip ranks, so val/test Spearman coincide to machine precision. Observed: `full_v2_p10_s42 = full_v2_p30_s42 = full_v2_p50_s42 = no_ranking_p10_s42 = no_ranking_p30_s42 = no_ranking_p50_s42`, val r_s = **−0.06799244700113821 bit-identically across all six**; stored test r_s differs only at the 1e-9–1e-11 digit. The one arm with a genuinely different RNG stream (`no_masking`: no mask draw, no masked forward) lands elsewhere: −0.07124840085521728 — exactly the signature predicted by this mechanism.

**Plain statement for the record:** `full_v2 (p=0.1/0.3/0.5)` contained **three distinct trainings whose p-difference was causally inert**; the identical-rows anomaly is fully explained and does **not** indicate fabrication, duplication, or a logging fault.

---

## 3. Autopsy Item 3 — Activation collapse check

**Method:** forward hooks on `pkg_proj` output, `conv1` Package output, `conv2` Package output, `classifier[0]` output, and the pre-sigmoid logit, over all 12,405 packages with trained weights (eval mode).

**The pre-registered suspicion — "attention layers collapsed to near-constant outputs" — is REFUTED in its literal form.** Activation stds are enormous, not near-constant:

| Hook point | std | mean | absmax | frac ≤ 0 |
|---|---|---|---|---|
| pkg_proj out (layer 1 pre-conv) | **476.5** | +8.19 | 1,762.5 | 0.518 |
| conv1 Package out | 291.6 | +22.03 | 2,098.7 | 0.499 |
| conv2 Package out | 199.8 | −10.51 | 1,605.0 | 0.481 |
| classifier Linear out | 128.2 | −0.010 | 829.3 | 0.544 |
| **pre-sigmoid logit** | 119.5 | **−132.5** | 531.7 | **1.000** |

**What actually collapsed is the output layer, by saturation:** with logits distributed around −132 (all ≤ 0) for seed 42 and +20…+30 for seeds 123/789, `sigmoid` clips everything to exactly 0.0 / 0.4744 (or 0/1). The sigmoid derivative at logit −132 is σ(1−σ) ≈ 1e-57 — **the learning signal is arithmetically zero**. Dead-ReLU fractions (0.42–0.55) are unremarkable and not the mechanism.

**Corroborating weight evidence — the models never trained:**

| Run | max\|Δw\| from own-seed init | L2 distance from init (total weight L2 ≈ 45.4) | r_s(init preds, trained preds) |
|---|---|---|---|
| full_v2_p10_s42 | 5.6e-3 | 0.450 (1.0%) | +0.441 |
| no_masking_s42 | 4.0e-3 | 0.374 (0.8%) | +0.441 |
| full_v2_p30_s123 | 5.0e-4 | 0.088 (0.2%) | +0.836 |
| full_v2_p30_s456 | 1.0e-3 | 0.145 (0.3%) | +0.814 |
| full_v2_p30_s789 | 1.0e-3 | 0.141 (0.3%) | +0.954 |
| full_v2_p30_s1024 | 1.1e-2 | 0.583 (1.3%) | −0.449 |

The trained checkpoints remain 99%+ random initialization; up to 95% of the trained model's ranking is its init ranking. Also note the `pkg_proj.weight` of the trained s42 checkpoint has absmax 0.3172 / std 0.1837 — statistically indistinguishable from its Kaiming-uniform init (bound 1/√10 = 0.3162).

---

## 4. Autopsy Item 4 — Input pipeline check (normalization)

**Phase 4 reference** (`TrainModel/training/dataset.py`):
- `normalize_features()` min-max normalizes Package continuous dims **[2, 3, 4, 5, 7]** (dataset.py:87), divides **CVSS by 10** (dataset.py:92), min-max normalizes Author dims **[0, 1, 2, 3, 6]** (dataset.py:101).

**v2 notebook (cell 3):** `data['Package'].x = torch.tensor(pkg_features)` — **raw, no normalization of any kind; CVSS used raw (1.7–10.0); no `normalize` string exists anywhere in the notebook or its generator.**

### Raw feature statistics actually consumed by v2 (side by side with Phase-4 treatment)

| Feature | Raw min | Raw max | Phase 4 treatment |
|---|---|---|---|
| Package dim2 out_degree | 0 | 123 | min-max → [0,1] |
| Package dim3 depth_in_tree | 0 | 7 | min-max → [0,1] |
| **Package dim4 version_recency_days** | 5 | **5,595** | min-max → [0,1] |
| **Package dim5 versions_behind_latest** | 0 | **4,002** | min-max → [0,1] |
| Package dim7 weekly_downloads_log | 0 | 8.45 | min-max → [0,1] |
| CVE dim768 CVSS | 1.7 | 10.0 | **divided by 10** |
| **Author dim0 account_age_days** | 13 | **6,807** | min-max → [0,1] |
| Author dim3 days_since_last_commit | 0 | 5,531 | min-max → [0,1] |

**Quantified consequence:** at *initialization*, `pkg_proj` preactivations already have **std = 476.5, absmax = 1,762.5** (a Linear(10→128) with Kaiming-uniform weights multiplying raw inputs of scale 10³–10⁴). This is the direct cause of the sigmoid saturation in Item 3: layer-1 explosion → attention/logit extremes → output saturation → zero gradients. Phase 4's normalized pipeline would have produced O(1) preactivations.

---

## 5. Autopsy Item 5 — Batching check

**Finding: v2 uses full-graph forward with node-masked loss. There is no batching defect, and `bs=32` does not appear in v2 at all.**

- Notebook cell 5: `data = data.to(device)` (whole graph once), then every epoch: `preds_clean, _ = model(data.x_dict, data.edge_index_dict)` — a **full-graph forward** — with `F.mse_loss(preds_clean[train_mask], y_true[train_mask])`, i.e., **loss on the train-node subset only**. Validation/test likewise full-graph.
- No `DataLoader`, `NeighborLoader`, node-slicing, or subgraph sampling exists in the notebook (verified by string search over all cells and the generator).
- The dangerous pattern named in the orders — *node-slicing without neighborhoods* (which orphans sliced nodes from message passing) — is **not present**: full-graph forwards preserve complete neighborhoods by construction.
- For contrast, Phase 4 (`TrainModel/training/train.py`) likewise trains full-graph; `bs=32` appears in neither.

**Item 5 verdict: CLEAN.** Message passing was structurally intact *given the graph as wired* — the wiring itself is what was defective (Item 2/A2).

---

## 6. Autopsy Item 6 — Loss trajectories

**Not recoverable — and stated plainly:** the notebook logs **no per-epoch quantities** (no loss components, no edge-mask counts, no gradient norms). `v2_runs/v2_intermediate_results.json` holds one final record per run (val/test r_s, AUC) and does not exist locally (Colab-side only, not downloaded). No trajectory plot is possible from surviving artifacts.

**Analytical reconstruction from code + checkpoints (the only honest substitute):**
- `L_aux ≡ 0.0` **exactly, every epoch** (Item 2.3) — the consistency term never existed as a signal; its trajectory is a flat zero line.
- `L_rank` = soft-margin over sampled pairs of **saturated** predictions: for tied pairs (the majority — most preds are exactly 0.0 or exactly 1.0/0.4744) the loss is log 2 ≈ 0.693 with gradient throttled through σ′ ≈ 0; its weighted contribution (0.20) was effectively inert.
- `L_MSE` was the only term with any gradient, and it was throttled to ~0 by sigmoid saturation (Item 3). Its magnitude could not translate into weight movement: total displacement ≤ 1.3% L2 over the whole run.
- **No term "dominated or vanished" in the dynamic sense — the entire gradient was stillborn.** This is why no trajectory logging would have caught it mid-run: every logged scalar (loss ≈ const, val r_s ≈ const) looks placid while the model is dead.

---

## 7. Defect inventory (with primary evidence)

| # | Defect | Where | Killing evidence |
|---|---|---|---|
| **A1** | Eligibility filter re-implementation: dropped the `raw_sum=0 → own_ratio=1` fallback **and** the `<15 → relax to 0.30` auto-relaxation | notebook cell 3 vs `TrainModel/masked_edge_audit.py:99-113,141-157` | Notebook formula: max own_ratio = 0.6667 < 0.70 → **eligible = 0**; official formula + relaxation → exactly **645**; `roc_auc_score(single-class y)` → NaN (reproduced); all 35 AUCs NaN |
| **A2** | No reverse message-passing directions (Phase 4 had them; v2 dropped them) | notebook cell 4 `HeteroConv` vs `TrainModel/core/model/layers.py:120-126,159-164` | Package head reads only `dependsOn`; **max\|Δpred\| = 0.000e+00** when all hasVulnerability edges are removed; `L_aux ≡ 0`; `p_mask` causally inert |
| **A3** | No feature normalization (Phase 4 had min-max + CVSS/10) | notebook cell 3 vs `TrainModel/training/dataset.py:19-29,87,92,101` | Layer-1 preact std 476 at init; logits \|·\| ≤ 531; sigmoid saturated; weights ≤1.3% L2 from init; train r_s ≈ chance |
| A4 (minor) | Prereg-vs-executed population drift (val 451 vs 452; test 1,433 vs 1,430) | notebook cell 3 vs prereg §4 | Documented; not outcome-relevant |

---

## 8. Counterfactual primary gate (inference only — no training, no fixes applied)

To establish what the primary gate *would have read* absent A1, the verbatim 50%-masked evaluation was rerun by inference on the **official** 645-package strata (reconstructed with `TrainModel/masked_edge_audit.py`'s own formula including its documented 0.30 relaxation) against the quarantined checkpoints:

| Arm | Per-seed AUC (42/123/456/789/1024) | Mean ± std | Gate (≥ 0.7391) | Label-prop baseline |
|---|---|---|---|---|
| full_v2 p10 | 0.448 / 0.528 / 0.505 / 0.543 / 0.453 | **0.4953 ± 0.0385** | FAIL (Δ −0.244) | 0.7191 |
| full_v2 p30 | 0.448 / 0.528 / 0.505 / 0.543 / 0.453 | **0.4952 ± 0.0386** | FAIL | 0.7191 |
| full_v2 p50 | 0.448 / 0.528 / 0.505 / 0.543 / 0.453 | **0.4953 ± 0.0385** | FAIL | 0.7191 |
| no_masking | 0.446 / 0.529 / 0.529 / 0.553 / 0.453 | 0.5020 ± 0.0437 | (attribution arm) | 0.7191 |

Chance-level (0.5), identical across p to the 3rd decimal, 0.14 below the VulnGAT-HR v1 result (0.6315) and 0.24 below the gate. **The reported NaN column was not hiding a near-miss; it was hiding chance.**

---

## 9. Classification & pre-committed interpretation mapping

| Hypothesis | Verdict | Confidence | Basis |
|---|---|---|---|
| **(A) Execution defect** | **CONFIRMED** (three independent, individually sufficient defects: A1, A2, A3) | High (~95%) | Items 2, 3, 4; counterfactual §8 |
| (B) Degenerate convergence of the protocol | Rejected *as stated* — outputs are degenerate but nothing *converged*; the degeneracy is dead-on-arrival saturation (A3) over a dead pathway (A2), not an optimum of the objective | — | Item 3 (weights ≤1.3% from init), Item 1 (no fit) |
| (C) Temporal generalization failure | Refuted — no in-period fit exists to fail to generalize (train r_s ≈ chance) | High | Item 1.1 |

**Important nuance for the rerun decision:** the defects live **in the pre-registered artifact itself** — the notebook faithfully executed its own spec, and the spec's architecture (forward-only `HeteroConv`), its unnormalized inputs, and its inline eligibility re-implementation are all defective *by construction*. Therefore:

- The pre-committed action row *"Execution defect → one rerun, identical protocol, no tuning"* **cannot be executed as written**: an identical-protocol rerun deterministically reproduces NaN AUC (A1), a zero auxiliary loss (A2), and a dead model (A3).
- A **conditional rerun that could produce evidence** requires exactly three protocol amendments, none of which touches thresholds, hyperparameters, seeds, gates, or margins: (i) bidirectional message passing (restore Phase-4-style reverse convs), (ii) Phase-4-identical feature normalization, (iii) corrected eligibility computation (delegate to `TrainModel/masked_edge_audit.py` rather than re-implementing it). Item 5 (batching) needs no change.
- Per the standing rules, **no such rerun was performed here**; the Brain decides on the single conditional rerun.

**Thesis language under this outcome** (per the pre-committed matrix, execution-defect row, adapted to the fact that the rerun has not yet been run):
> "The pre-registered v2 cycle produced no admissible evidence: the executed protocol contained three defects (empty evaluation strata producing undefined AUC; an architecture in which the masked-auxiliary pathway is provably disconnected from the prediction head, reducing the consistency loss to identically zero; and absent feature normalization producing saturated, gradient-dead outputs). The v2 result is quarantined; the v2 hypothesis remains untested pending the Brain's ruling on a single amended-protocol rerun."

**Ledger actions taken (see §10):** the preregistration §7 sentence attributing a failure to "the structural limitations of GNN propagation on dependency vulnerability graphs" is **RETRACTED** — no such structural conclusion is licensed by this evidence; the v2 result remains **QUARANTINED**; the identical-rows anomaly is **documented and resolved** (Item 2.4).

---

## 10. Deviations / Amendments Ledger — Continuation III entries (also appended to `WORKER_REPORT_PHASE5.md`)

- **D5 (RETRACTION):** The preregistration §7 terminality sentence — *"…it constitutes a final, terminal negative result documenting the structural limitations of GNN propagation on dependency vulnerability graphs"* — is **RETRACTED**. The v2 failure is an execution/protocol-artifact defect (A1–A3), not evidence about GNN propagation on this graph class. No structural claim may be cited from the v2 cycle. A dated retraction notice is appended to `VULNGAT_V2_PREREGISTRATION.md` (locked body unmodified).
- **D6 (QUARANTINE upheld):** The v2 result (35 checkpoints + `vulngat_v2_final_results.json`) remains **QUARANTINED**. Its primary gate was never measured (AUC NaN by construction); its secondary-gate number (mean r_s = 0.0198 vs 0.6571) is vacuous (chance-level output of an untrained model). Neither gate may be cited as a pass or a fail.
- **D7 (Identical-rows anomaly — resolved):** The p10/p30/p50 identical-mean±std anomaly is **real data from three distinct trainings whose p-difference was causally inert** (dead `hasVulnerability` pathway + p-independent RNG stream + rank-statistic insensitivity over saturated outputs). Distinct MD5s and non-monotonic weight diffs prove separate executions; the inertness test (max|Δpred| = 0.0 under 100% edge removal) proves causal identity. No duplication or logging fault.
- **D8 (Conditional rerun — Brain decision pending):** The pre-committed "one identical-protocol rerun" row is **not executable as written** (defects are in the spec). The single conditional rerun, if granted, requires the three amendments in §9 (reverse message passing; Phase-4 normalization; audit-script-based eligibility) with gates, thresholds, seeds, and margins unchanged. No rerun was performed under the standing no-fix/no-rerun rule.

---

## Appendix A — Forensic artifacts produced (all CPU-only, no training)

| File | Content |
|---|---|
| `phase5/autopsy_item2_weightdiff.py` / `.json` | MD5 inventory + per-tensor weight diffs across arms/p/seeds + init-scale reference |
| `phase5/autopsy_behavior2.py` / `autopsy_behavior_results.json` / `autopsy_behavior_log2.txt` | Verbatim cell-3/4 rebuild; train/val/test metrics, strata dispersion, activation hooks, init-distance, inertness test, NaN mechanism, raw feature stats |
| `phase5/autopsy_behavior.py` / `autopsy_behavior_log.txt` | First forensic pass (superseded by v2 script for a logit-replay bug; populations and eligibility finding identical) |
| Counterfactual AUC table (§8) | Computed inline (verbatim masked-eval on official 645 strata); deterministic given seeds |

**Key quarantined inputs (unmodified):** `vulngat_v2_checkpoints/*.pt` (35 files), `vulngat_v2_final_results.json`, `phase5/vulngat_v2_training.ipynb` (pristine, zero stored outputs — the executed Colab source is byte-identical to the generator's output for all audited fragments), `phase5/vulngat_v2_colab_data.zip` (all 5 data files MD5-verified identical to local copies — the Colab run provably consumed this exact data).

---


---

# Appendix B — Rerun Preparation Addendum (2026-09-20, post-autopsy, same session)

**Trigger:** Brain ruling ACTIVE — conditional rerun authorized as **"identical protocol, defect-corrected."** The three amendments below are defect corrections restoring pre-registered intent; they are NOT protocol changes. Gates (0.7391 / 0.6571), the 35-run matrix, λ_rank=0.20, λ_mask=0.30, seeds {42,123,456,789,1024}, mean-across-seeds evaluation, and terminality are ALL UNCHANGED. This session patched and validated on **CPU only** (the only training executed anywhere is the P3 smoke gate and its debug extension, both CPU, weights discarded).

## B.1 Amendment justifications

**(1) Population-pin enforcement [fixes A1].** Pre-registration §4.1 pins the primary-gate population as *"the exact same population where label propagation was measured"* — N=645 eligible vs N=8,682 never-vulnerable. The quarantined notebook violated the pin by re-implementing the strata computation inline and dropping both the `raw_sum=0 → own_ratio=1` fallback and the documented `<15 → relax to 0.30` auto-relaxation (`TrainModel/masked_edge_audit.py:99-113,141-157`), yielding 0 eligible packages (max own_ratio on this graph = 0.6667 < 0.70) and AUC=NaN on all 35 runs. The rerun wires eligibility to a **verbatim port of the official code path** (`compute_own_vpss` / `select_eligible_packages` / `get_never_vuln_indices`) and adds hard runtime assertions `N==645` and `N==8682` (fail-closed). Verified (P4): the official module itself returns 645 / 8,682 and the notebook's values are set-equal to it.

**(2) Intervention-liveness restoration [fixes A2].** The original VulnGAT (`TrainModel/core/model/layers.py`, `HANLayer`) creates a reverse convolution for every edge type (lines 120-126, keys `rev_<edge>`) and runs the reverse pass via `edge_index.flip(0)` (lines 159-164). The quarantined v2 shipped only the 4 forward directions, making Package predictions depend solely on `dependsOn` — so masking `hasVulnerability` provably could not reach the head (max|Δpred| = 0.000e+00 under 100% removal), `L_aux ≡ 0`, and `p_mask` was causally inert. **v1-sensitivity parity argument:** the v1 masked-edge sensitivity that motivated H1 (v1 masked AUC 0.6315; the entire propagation-resilience hypothesis) was measured on an architecture that HAS the reverse directions. A forward-only v2 cannot in principle exhibit masking sensitivity, so H1 was untestable as spec'd, not failed. The rerun restores the 4 reverse directions — direction parity only; per §6.1 the per-type conv remains v2's GATConv, and HeteroConv's `aggr='sum'` (vs HANLayer's per-type mean + residual + LayerNorm) is left exactly as the v2 spec defined it. **Required proof delivered (P2):** removing 100% of `hasVulnerability` edges now changes predictions (max|Δpred| = 3.109e-02 at init; > 0 at every partial p ∈ {0.1, 0.3, 0.5, 0.9}), and the training-time consistency term is live (P5: `L_aux` > 0 in 50/50 logged epochs; quarantined v2: identically 0).

**(3) Preprocessing parity [fixes A3].** Verbatim port of `TrainModel/training/dataset.py::normalize_features` (Package min-max dims [2,3,4,5,7] — line 87; CVSS/10 — line 92; Author min-max dims [0,1,2,3,6] — line 101). **Verified bit-identical (F1):** against `load_vulnchain_dataset()` on identical inputs, max|Δ| = 0.000e+00 on all node types (CVSS compared position-aware: the v2 pre-registration §6.1 places CVSS last, `emb+[cvss]`, while the Phase-4 loader stores it first, `[cvss]+emb` — same values, same normalization, different slot). Without this, layer-1 preactivations explode (std ≈ 476 at init) and the sigmoid saturates (autopsy Item 3).

### Edge-direction parity table (vs `core/model/layers.py`)

| Message-passing direction | layers.py (v1) | v2 quarantined | v2dc rerun |
|---|---|---|---|
| Package→dependsOn→Package (fwd) | yes | yes | yes |
| Package→hasVulnerability→CVE (fwd) | yes | yes | yes |
| Package→maintainedBy→Author (fwd) | yes | yes | yes |
| CVE→introducedBy→Author (fwd) | yes | yes | yes |
| Package←rev_dependsOn←Package | yes (120-126,162) | **NO (A2)** | yes |
| Package←rev_hasVulnerability←CVE | yes | **NO (A2)** | yes |
| Package←rev_maintainedBy←Author | yes | **NO (A2)** | yes |
| CVE←rev_introducedBy←Author | yes | **NO (A2)** | yes |
| Reverse-pass mechanics | `edge_index.flip(0)` per edge type | n/a | `edge_index.flip(0)`, **derived at call time** (so any masking of `hasVulnerability` — train-time dropout or the 50% masked eval — automatically removes the corresponding reverse messages too) |

## B.2 Rerun artifacts (originals untouched)

| File | Content |
|---|---|
| `phase5/generate_v2_notebook_rerun.py` | Generator for the defect-corrected notebook (annotated [FIX A1/A2/A3], [P5], [P6]) |
| `phase5/vulngat_v2_training_rerun.ipynb` | The rerun notebook: run_id prefix `v2dc_`, `protocol_version='v2.1-defect-corrected'`, per-epoch per-term loss trajectories in the intermediate JSON, legacy-record hard-fail on load. The quarantined `vulngat_v2_training.ipynb` / `generate_v2_notebook.py` are byte-untouched forensic artifacts. |
| `phase5/preflight_v2_rerun.py` / `preflight_results.json` / `preflight_log.txt` | Commandment-15 pre-flight suite: executes the notebook's actual cells (pip magics stripped, matrix loop withheld) against the staged real dataset |
| `phase5/debug_p3_trajectory.py` / `debug_p3_trajectory.json` / `debug_p3_log.txt` | P3 failure diagnosis: 300-epoch frozen-config trajectory (CPU, weights discarded) |
| `phase5/probe_rerun.py` | Pre-fix probes: official-path N=645/8,682 confirmation, fixed-arch liveness + timing |

The Colab data zip (`vulngat_v2_colab_data.zip`) is unchanged — the 5 data files are identical to what the rerun consumes.

## B.3 Pre-flight suite results (VERBATIM — Commandment 15)

| Gate | Result | Verbatim evidence |
|---|---|---|
| **P1 Init sanity** | **PASS** | seed 42, normalized inputs: init prediction std = 0.007211 > 0 across 12,405 packages; layer-1 (pkg_proj) preactivation std = **0.2597** ∈ [0.1, 10] (quarantined v2 defect: ≈ 476) |
| **P2 Pathway liveness** | **PASS** | remove 100% of hasVulnerability edges → max\|Δpred\| = **3.109249e-02** > 0 (quarantined v2: exactly 0.000e+00); partial drops p=0.1/0.3/0.5/0.9 → 2.877888e-02 / 3.107876e-02 / 3.107876e-02 / 3.107876e-02, all > 0 |
| **P3 Learnability smoke** | **FAIL** | 50 epochs, full_v2 p=0.30 seed 42, TRAIN population: train Spearman = **−0.1602** (bar: > 0.30). Smoke info: val −0.1119, test +0.1060, masked AUC 0.2924; train pred std 0.0102; 244.3 s CPU; **weights discarded** |
| **P4 Eligibility** | **PASS** | official `masked_edge_audit.py` module: eligible = **645**, never-vuln = **8,682**; notebook cell-3 values set-equal to module output on both populations; max own_ratio = 0.6667 (< 0.70 → the documented 0.30 auto-relaxation is what yields N=645); notebook's runtime assertions fired |
| **P5 Loss logging** | **PASS** | 50/50 epochs logged with `{loss_mse, loss_rank, loss_aux, loss_total, val_spearman}`, all finite; consistency term LIVE: max L_aux = 8.64e-04, > 0 in 50/50 epochs (quarantined v2: identically 0.0) |
| **P6 Resume safety** | **PASS** | 35/35 new run_ids prefixed `v2dc_` and disjoint from the 35 quarantined v2 ids; skip-completed verified on a new id (returns stored record, no retrain); a legacy/quarantined record in the results file **hard-fails** (`RuntimeError`, protocol_version check) — old run_ids can never be reused or resumed |
| F1 Normalization parity (Fix-1 proof) | **PASS** | vs `load_vulnchain_dataset()` on identical inputs: Package max\|Δ\| = 0.000e+00; Author = 0.000e+00; CVE-emb = 0.000e+00; CVE-CVSS (position-aware) = 0.000e+00 — bit-level |

**OVERALL: NOT CLEAN (P3) → per the pre-committed table, Colab was NOT fired.**

## B.4 P3 failure diagnosis (CPU debug, per the pre-committed table)

The smoke's learning indicators were all healthy — MSE 0.1725 → 0.0147 (12×), val ρ rising monotonically −0.225 → −0.112, `L_aux` live — but train ρ was still negative at epoch 50. The 300-epoch debug run of the **identical frozen configuration** (full_v2, p=0.30, seed 42, lr=5e-4, wd=1e-4, λ's unchanged; early-stop disabled for diagnosis; weights discarded) locates the mechanism:

| Milestone | Epoch |
|---|---|
| train ρ > 0 | 72 |
| train ρ > 0.10 | 76 |
| **train ρ > 0.30 (the P3 bar)** | **91** |
| val ρ > 0 | 70 |

- **Mechanism — a ~70-epoch output-mean-fitting phase.** The initialized network outputs mean ≈ 0.46 vs train-label mean ≈ 0.06; under the frozen lr = 5e-4, epochs 0–70 are spent descending the output scale (pred mean 0.46 → 0.03; MSE 0.173 → 0.0146 ≈ the constant-predictor floor Var(y_train) = 0.01026), during which predictions carry almost no rank information (train ρ −0.23 → −0.13). Ranking emerges only after epoch ~70, once MSE drops **below** the constant floor (ep100 MSE = 0.00863 < 0.01026 — i.e., genuine signal beyond the mean).
- **At the pre-registered budget cap (epoch 100): train ρ = +0.4043, val ρ = +0.3784.** The patience-15 simulation never triggers inside the budget (val ρ improves essentially every epoch; simulated stop at epoch 281), so a pre-registered Colab run trains the full 100 epochs and its best-val checkpoint is the epoch-100 model.
- The P3 gate as written (50 epochs) therefore **under-samples the frozen protocol's own budget**: the corrected model crosses the 0.30 bar at epoch 91 — inside the pre-registered 100-epoch cap, outside the smoke's 50-epoch window.
- Context for the Brain (not a gate, no action taken): the trajectory keeps climbing well past the cap (best val ρ = +0.6810 at epoch 266; ep299 train +0.7270 / val +0.6802), so the frozen 100-epoch budget stops the model at val ρ ≈ 0.38, well short of the 0.6571 secondary bar. The 100-epoch cap and lr are FROZEN and were not touched. For reference, v1's Phase-4 trainer (`train.py`) ran lr=1e-3 with ReduceLROnPlateau, gradient clipping (max_norm=1.0), and LayerNorm+residuals — all absent from the v2 frozen spec and not restorable under the no-protocol-change rule.

**Status handed to the Brain:** P1/P2/P4/P5/P6 + F1 clean; P3 as written FAILED. The debug establishes that the failure is a horizon artifact of the 50-epoch smoke window, not a defect in the corrected implementation (the bar is crossed at epoch 91 within the pre-registered 100-epoch budget). Options: (a) accept the debug evidence and fire Colab; (b) amend the P3 horizon (a pre-flight-spec change — Brain's call) and re-gate. Per the pre-committed table, no Colab fire occurred in this session.
