# VulnGAT v2 Pre-Registration Document
**Document Status:** LOCKED & PRE-REGISTERED (PATCHED FOR HARD FIRE)  
**Date:** 2026-09-20  
**Authors:** VulnChain Research Team  
**Pre-registration Standard:** Open Science Framework (OSF) / Preregistered Research Design Standard  

---

## 1. Executive Summary & Brain Directives

This document pre-registers the architectural, training, and evaluation specifications for **VulnGAT v2**, the terminal model intervention of the VulnChain project. 

### Brain Rulings Applied Verbatim (Deviations Ledger)
- **(g) Multi-task loss replaces approved MSE-only:** ACCEPTED with conditions: $\lambda_{\text{rank}}=0.20$, $\lambda_{\text{mask}}=0.30$ FROZEN (no tuning); attribution via ablations; if no-masking ablation also passes primary, headline attributes to ranking loss, not masking.
- **(h) Secondary gate metric = Spearman (not RankAcc-nz):** ACCEPTED, resolves Brain's no-accuracy-metrics rule; floor = ridge-raw + margin = **0.6571**.
- **(i) 5 seeds (not seed 42):** ACCEPTED; BOTH gates evaluate on the **MEAN across seeds**, per-seed values reported. No per-seed pass claims.
- **v2 IS GREENLIT:** One cycle, no v3, terminal outcome either way. This cycle + its ablations = the project's **final training intervention**. Failure = **final negative result**. **NO v3 under any combination of outcomes.**
- **EPSS = Option C amended:** Primary = closure labels; headline framing LOCKED as *"GNN vs formula oracle — approximating EPSS-closure without EPSS inputs"*; NEVER *"beats closure"*. Own-CVE (751) = labeled exploratory arm only.
- **NEW cross-label transfer arm:** VPSS-trained HR head evaluated on EPSS-closure test labels (no retraining) and vice versa. The circularity-escaping comparison.
- **D3 CLARIFICATION:** The v2 clean-test gate floor is the **best learnable baseline (ridge/HR) + $\max(2\text{pp}, 2 \times \text{seed-std})$**. The closure oracle ($r_s = 1.0$) is ceiling context only.

---

## 2. Explicit Training Label Specification

- **Training Ground Truth:** **EPSS-closure** (3,691 non-zero packages, Commandment 6 gate PASSED).
- **Circularity Statement (carried verbatim from Option-C decision):**  
  *"GNN vs formula oracle — approximating EPSS-closure without EPSS inputs; NEVER 'beats closure'."*
- **VPSS Fallback Removal:** The VPSS fallback clause is formally removed (Commandment 6 gate passed with 3,691 non-zero packages — dead branch eliminated).

---

## 3. Pre-Registered Hypotheses

### Primary Hypothesis ($H_1$ — Propagation Resilience)
VulnGAT v1 suffered from distribution shift under edge masking because it was trained exclusively on graphs with complete $hasVulnerability$ edges, learning to rely on local edge presence rather than structural neighborhood context. **VulnGAT v2, trained with edge dropout and masked-edge auxiliary supervision, will achieve a 50% masked-edge AUC that exceeds the label-propagation baseline by at least $\max(0.02, 2 \times \text{std}_{\text{LP}})$.**

### Secondary Hypothesis ($H_2$ — Clean-Test Generalization)
The architectural modifications and auxiliary ranking objectives in VulnGAT v2 will not sacrifice clean-test ranking performance. **VulnGAT v2 will achieve a clean-test Spearman correlation exceeding the best learnable baseline by at least $\max(0.02, 2 \times \text{seed-std})$.**

---

## 4. Pinned Evaluation Populations & Quantitative Gates

All thresholds are derived from measured 5-seed distributions across seeds $\{42, 123, 456, 789, 1024\}$ on the 51-repository dataset.

### 4.1 Primary Gate: 50% Masked-Edge AUC (Out-of-Distribution Propagation)
- **Pinned Evaluation Population:** Masked-audit eligible strata ($N=645$ eligible packages with $\text{own\_ratio} \ge 0.70$ evaluated against $N=8,682$ never-vulnerable negative packages). This is the **exact same population** where label propagation was measured ($0.7191 \pm 0.0069$).
- **Baseline (Label Propagation):** $\mu = 0.7191 \pm 0.0069$
- **Margin:** $\max(0.02, 2 \times 0.0069) = 0.0200$
- **Pre-Registered Success Threshold:**  
  $$\text{Mean}(\text{AUC}_{\text{v2}}) \ge 0.7191 + 0.0200 = \mathbf{0.7391}$$
- **Current Baseline Reference:** VulnGAT-HR v1 achieves $0.6315 \pm 0.0045$ ($\Delta = -0.1076$ below threshold).

### 4.2 Secondary Gate: Clean-Test Spearman Correlation
- **Pinned Evaluation Population:** Temporal-split non-zero test cut ($N=1,430$ packages with newest contributing CVE published date $\ge$ `2026-08-01`). This is the **exact same population** where ridge-raw was measured ($0.6371$).
- **Baseline Distribution (Non-Zero Test Cut, $N=1,430$):**
  - Closure-Decayed-Sum Oracle: $r_s = 1.0000$ *(Ceiling context only, not a gate floor)*
  - Closure-Max (Hill $K=1$): $r_s = 0.9463$
  - Ridge-Raw Baseline: $r_s = 0.6371$
  - VulnGAT-HR Head (5 seeds): $r_s = 0.5614 \pm 0.0014$
- **Best Learnable Baseline:** Ridge-Raw ($r_s = 0.6371$)
- **Seed Standard Deviation:** $\sigma = 0.0014$
- **Margin:** $\max(0.02, 2 \times 0.0014) = 0.0200$
- **Pre-Registered Success Threshold:**  
  $$\text{Mean}(r_{s, \text{v2}}) \ge 0.6371 + 0.0200 = \mathbf{0.6571}$$

### 4.3 Gate Evaluation Rule
- **Both gates evaluate on the MEAN across the 5 seeds $\{42, 123, 456, 789, 1024\}$.**
- Per-seed values are reported in full. No per-seed pass claims are permitted.

---

## 5. Run Matrix & Attribution Rules

### 5.1 Run Matrix (35 Short Runs Total)
The training execution matrix comprises 35 runs across fixed seeds $\{42, 123, 456, 789, 1024\}$:
1. **Full v2 (15 runs):** 3 $p_{\text{mask}}$ values $\{0.10, 0.30, 0.50\} \times 5\text{ seeds}$.
   - Objectives: $\mathcal{L}_{\text{MSE}} + 0.20 \mathcal{L}_{\text{rank}} + 0.30 \mathcal{L}_{\text{aux}}$ with dynamic edge masking at probability $p_{\text{mask}}$.
2. **No-Masking Ablation (5 runs):** $p_{\text{mask}} = 0.0 \times 5\text{ seeds}$.
   - Objectives: $\mathcal{L}_{\text{MSE}} + 0.20 \mathcal{L}_{\text{rank}}$ without edge masking ($\lambda_{\text{aux}} = 0.0$).
3. **No-Ranking Ablation (15 runs):** 3 $p_{\text{mask}}$ values $\{0.10, 0.30, 0.50\} \times 5\text{ seeds}$.
   - Objectives: $\mathcal{L}_{\text{MSE}} + 0.30 \mathcal{L}_{\text{aux}}$ with dynamic edge masking ($\lambda_{\text{rank}} = 0.0$).

### 5.2 Attribution Rules
- **Only Full v2 faces the gates.**
- Ablations are **attribution-only** and reported in the exact same table for comparative attribution.
- **Attribution Condition:** If the no-masking ablation also passes the primary gate ($\ge 0.7391$), the headline result attributes the gain to the **ranking loss**, not edge masking.

---

## 6. Model Architecture & Hyperparameters

### 6.1 VulnGAT v2 Architecture
- **Base Graph Neural Network:** 2-layer Heterogeneous Graph Attention Network (HeteroGAT) with edge-type-specific message passing.
- **Node Types:** `Package` (10-d raw features), `CVE` (768-d SentenceBERT + 1-d CVSS = 769-d), `Author` (7-d features).
- **Edge Types:**
  - `(Package, dependsOn, Package)`
  - `(Package, hasVulnerability, CVE)`
  - `(Package, maintainedBy, Author)`
  - `(CVE, introducedBy, Author)`
- **Hidden Dimension:** 128
- **Attention Heads:** 4 (32 dims per head)
- **Output Head:** Two-layer MLP (`Linear(128, 64) -> GELU -> Dropout(0.1) -> Linear(64, 1) -> Sigmoid`).

### 6.2 Loss Formulation (FROZEN — No Tuning)
$$\mathcal{L}_{\text{total}} = \mathcal{L}_{\text{MSE}} + \lambda_{\text{rank}} \mathcal{L}_{\text{rank}} + \lambda_{\text{aux}} \mathcal{L}_{\text{aux}}$$
- $\lambda_{\text{rank}} = 0.20$ (FROZEN)
- $\lambda_{\text{aux}} = 0.30$ (FROZEN)
- $\mathcal{L}_{\text{rank}}$: Pairwise SoftMargin ranking loss over sampled pairs with $|\Delta y| > 0.05$.
- $\mathcal{L}_{\text{aux}}$: Consistency MSE between clean-graph predictions and masked-graph predictions.

### 6.3 Optimization & Early Stopping
- **Optimizer:** AdamW ($\text{lr} = 5 \times 10^{-4}$, weight decay $= 10^{-4}$).
- **Max Epochs:** 100.
- **Early Stopping:** Patience of 15 epochs monitored on Validation Spearman correlation on non-zero packages ($N=452$).
- **Fixed Seeds:** $\{42, 123, 456, 789, 1024\}$.

---

## 7. Terminality Statement

This cycle and its pre-registered ablations constitute the **final training intervention of the VulnChain project**. 
- If Full v2 meets both gates, VulnGAT v2 is validated.
- If Full v2 fails either gate, it constitutes a **final, terminal negative result** documenting the structural limitations of GNN propagation on dependency vulnerability graphs.
- **Under NO combination of outcomes will a v3 cycle be initiated.**

---

# ⚠️ RETRACTION NOTICE — APPENDED 2026-09-20 (POST-AUTOPSY; LOCKED BODY ABOVE UNMODIFIED)

Per the v2 checkpoint autopsy ([`V2_AUTOPSY.md`](V2_AUTOPSY.md); ledger entries D5–D8 in `WORKER_REPORT_PHASE5.md`):

1. **RETRACTED (§7):** The sentence *"If Full v2 fails either gate, it constitutes a **final, terminal negative result** documenting the structural limitations of GNN propagation on dependency vulnerability graphs"* is **RETRACTED**. The v2 cycle failed for execution/protocol-artifact reasons, not because of any demonstrated structural limitation of GNN propagation. No structural conclusion may be cited from this cycle.
2. **QUARANTINED:** The executed v2 result is quarantined. The primary gate (§4.1) was **never measured** — the notebook's re-implementation of the eligible-strata filter produced an empty positive set (0 packages; the official N=645 relies on a 0.30 auto-relaxation in `TrainModel/masked_edge_audit.py` that the notebook dropped), making all 35 masked AUCs undefined (`NaN`). The secondary-gate number is vacuous (chance-level output of an untrained model: weights ≤ 1.3% L2 from random init; train Spearman ≈ chance). Neither gate outcome (pass or fail) may be reported from this cycle.
3. **STATUS OF H1/H2:** Both hypotheses remain **untested**. Under the pre-committed matrix (execution-defect row), the matter passes to the Brain for a ruling on a single conditional rerun; note that the rerun cannot use an "identical protocol" (the defects are in this document's own specification: forward-only `HeteroConv`, unnormalized inputs, inline eligibility re-computation) and requires the three amendments listed in `V2_AUTOPSY.md` §9, with all gates, thresholds, seeds, and margins unchanged.
4. **Identical-rows anomaly:** The identical full_v2 p=0.1/0.3/0.5 table rows are explained (three distinct trainings whose p-difference was causally inert); see autopsy Item 2. No data-integrity concern.

---

# 🔁 RERUN ADDENDUM — APPENDED 2026-09-20 (POST-RETRACTION; LOCKED BODY ABOVE UNMODIFIED)

1. **Authorization (ledger D8 → RESOLVED):** the Brain authorized exactly **one conditional rerun** as *"identical protocol, defect-corrected."* The three defect corrections — (i) eligibility wired to the official `TrainModel/masked_edge_audit.py` code path including the documented 0.30 auto-relaxation, with hard runtime assertions N=645 / N=8,682; (ii) reverse message-passing directions restored to direction parity with `TrainModel/core/model/layers.py` (HANLayer); (iii) Phase-4-identical feature normalization (Package min-max dims [2,3,4,5,7]; CVSS/10; Author dims [0,1,2,3,6]) — restore pre-registered intent. **No gate, threshold, λ, seed, run-matrix entry, or terminality clause is changed.** Full amendment justifications, the edge-direction parity table, and the verbatim pre-flight record: [`V2_AUTOPSY.md`](V2_AUTOPSY.md) Appendix B.

2. **Rerun artifact:** `phase5/vulngat_v2_training_rerun.ipynb` (run_ids `v2dc_*`, `protocol_version = 'v2.1-defect-corrected'`, per-epoch per-term loss logging into the intermediate JSON, legacy-record hard-fail on load). The quarantined v2 artifacts remain byte-untouched and are never reused or resumed.

3. **Pre-flight (Commandment 15, CPU only):** P1 init-sanity, P2 pathway-liveness, P4 eligibility (official 645 / 8,682), P5 loss-logging, P6 resume-safety, and the Fix-1 normalization-parity check (bit-identical, max|Δ| = 0.000e+00) — **all PASS**. P3 (learnability smoke) failed at its original 50-epoch horizon (train Spearman = −0.1602); the ordered CPU debug showed the corrected model crosses the unchanged 0.30 bar at **epoch 91**, inside the pre-registered 100-epoch budget (train ρ = +0.4043 at the cap; weights discarded).

4. **Ruling D10 (VERBATIM):**
   > "P3 horizon (50 epochs) was Brain-mis-specified relative to frozen protocol dynamics (~70-epoch output-mean-fitting phase). Corrected to budget-matched horizon: train Spearman > 0.30 within the pre-registered 100-epoch budget; bar unchanged. Satisfied by the pre-collected 300-epoch diagnostic (train ρ = +0.4043 at epoch 100; weights discarded; evidence predates this ruling). The 300-epoch trajectory beyond the cap is interpretation context only, never gate-eligible. Precedent: Phase-1 nz-cut anchor correction."

5. **Fire authorization (status line, verbatim):**
   > **PRE-FLIGHT PASSES under corrected P3. Colab fire AUTHORIZED by the Brain. Protocol frozen. No further changes of any kind permitted.**

6. **Fired-artifact identity:** the notebook fired at Colab must be byte-identical to the pre-flighted artifact —
   - **SHA-256:** `aeaeae83c2c3afe91fdf5f1768ef0e6cfc329644099bf490f130c6e6a440372d`
   - **MD5:** `c4c04f8a974d96359ff43900d1d31f19` · **size:** 48,072 bytes
   - Machine-readable record: [`v2dc_fire_manifest.json`](v2dc_fire_manifest.json). **Any hash mismatch invalidates the fire** — a mismatched notebook is not the pre-flighted artifact and must not be run under this authorization.

---

# 🏁 RESULT NOTICE — APPENDED 2026-09-20 (POST-RERUN; LOCKED BODY ABOVE UNMODIFIED)

The conditional rerun authorized under the Rerun Addendum (rulings D8/D10) was fired on Colab (T4 GPU) and **completed the full pre-registered 35-run matrix** under `protocol_version = v2.1-defect-corrected` (fired artifact SHA-256 `aeaeae83c2c3afe91fdf5f1768ef0e6cfc329644099bf490f130c6e6a440372d`; artifacts verified: 35/35 `v2dc_*` runs, gate statistics recomputed from per-seed values — exact match; 35/35 checkpoints, zip integrity OK; archived as `phase5/v2dc_final_results.json` and `phase5/v2dc_checkpoints.zip`).

## Gate outcomes (mean across seeds {42,123,456,789,1024}; only full_v2 faces gates)

| Config | 50% Masked AUC | Primary ≥ 0.7391 | Clean-Test r_s | Secondary ≥ 0.6571 |
|---|---|---|---|---|
| full_v2 (p=0.1) | 0.4156 ± 0.0904 | **FAIL** | 0.1507 ± 0.1122 | **FAIL** |
| full_v2 (p=0.3) | 0.4031 ± 0.1009 | **FAIL** | 0.1503 ± 0.1118 | **FAIL** |
| full_v2 (p=0.5) | 0.3916 ± 0.1120 | **FAIL** | 0.1489 ± 0.1104 | **FAIL** |

Both gates fail under every reading (best-p, pooled 0.4034 / 0.1500, or any single config). Reference: label propagation 0.7191 (primary population), ridge-raw 0.6371 and VulnGAT-HR v1 0.5614 (secondary population). Executed test cut N=1,433 (prereg 1,430 — the documented A4 integer-floor drift).

## Pre-committed interpretation — row "Both < bars" (applied verbatim)

> **"The pre-registered end-to-end protocol, correctly implemented, does not beat label propagation or ridge on this graph at this scale; frozen Phase-4 representations remain the best encoder."**

Attribution note: the pre-registered attribution rule governed a PASS; with no pass anywhere there is nothing to attribute. Empirically the no-masking ablation (AUC 0.4251, r_s 0.1634) is nominally the best arm but within ~1 std of full_v2 — dynamic edge masking neither helps nor rescues; the ranking loss contributes ~+0.07 r_s over no_ranking, far from any bar. Full mechanics (training-depth-dependent below-chance AUC inversion; early-stopping/mean-fitting interaction, 27/35 runs; budget-binding evidence; CPU-debug↔GPU reproduction) are recorded in the worker report's terminal-result section and in the P5 per-epoch trajectories present on all 35 runs.

## Terminality — CONFIRMED

This result, together with the quarantined v2 cycle, **closes the VulnGAT question**. Per §7 of the locked body (as amended by the retraction notice): **no v3 cycle will be initiated under any combination of outcomes; no further training interventions.** The frozen Phase-4 representations remain the project's best encoder; the project's evidence chain rests on the Phase-4/Phase-5 baselines and analyses, not on end-to-end GNN training.
