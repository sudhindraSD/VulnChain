# Worker Report — Phase 5 (VulnGAT Head-Refit)
**Run date:** 2026-09-20 · **Orders:** Phase-5 task brief (VulnGAT Head-Refit, "execute exactly, do not redesign") · **Status: Phases 0/1/2 COMPLETE — Phase 2 masked-edge gate FAILED → Phase 3 GATED OFF — Phase 4 inference reruns complete, comparison table pending**

> Environment note: this machine now has **torch 2.13.0+cpu + PyG 2.8.0.post1** installed locally (it was CPU-only-no-PyG during Phase 4), so everything in Phase 5 ran locally on CPU per the orders' DEFAULT=LOCAL routing. No Colab handoff was triggered: the encoder stayed frozen end-to-end and no step was too slow for CPU (masked-edge audit = 687.7 s wall for all 3 ratios incl. bootstrap).

---

## Phase 0 — Validity gate: **PASS** ✅
Script: `phase5/phase0_validity_gate.py` · Output: `phase5/phase0_validity.json`

Rebuilt the forward pass from `phase4/results_colab/phase4/models/vulngat_51repo.pt` (the epoch-3 best-val snapshot with the anti-aligned head) with the exact wiring of the proven local diagnostic (`phase4/diagnose_embedding_collapse.py`). Against the archived Colab metrics:

| split | metric | archived | reproduced | diff |
|---|---|---|---|---|
| test | Spearman_all | −0.2356973802 | −0.2356973802 | **0.00e+00** |
| test | RankAcc | 0.3910759097 | 0.3910759097 | **0.00e+00** |
| test | MAE / MSE | 0.1676503271 / 0.0581010431 | same | 0.00e+00 |
| train/val | all 8 metrics | — | — | ≤ 1e-7 (float noise) |
| all 12,405 predictions | max abs diff vs `test_predictions_51repo.json` | — | — | **8.9e-08** |

pkg_id order identical. Wiring is valid; gate tolerance set to the ordered ~1e-6 (first run used an over-tight 1e-9 and failed on 1e-7 float noise — documented, then corrected; the failures were pure accumulation-order noise, not wiring).

## Phase 1 — VulnGAT-HR head refit: **DONE** ✅ (with one protocol clarification)
Scripts: `phase5/phase1_head_refit.py`, debug: `phase5/debug_phase1_convergence.py` · Outputs: `phase5/phase1_head_refit.json`, `phase5/phase1_training_curve.json`, `phase5/pkg_embeddings_frozen.npy` (+`pkg_embeddings_meta.json`), `phase5/vulngat_hr.pt`

Protocol as ordered: full encoder frozen (`requires_grad=False`, eval, no dropout); all 12,405 Package nodes forwarded once → cached 128-d embeddings; fresh `Sequential(Linear(128,1), Sigmoid())` head (mirrors original classifier exactly, so the state_dict drops into `model.classifier`); **MSE only, no InfoNCE**; Adam lr=1e-3; max 500 epochs; **selection on val Spearman (non-zero, n=161)**; early stop patience 50; seed 42.

**Protocol clarification (batch size):** the orders pin lr/epochs/seed but not batch size. Read as full-batch, it means 1 Adam step/epoch → 500 total steps → under-converged (best epoch = the 500 cap, test Spear_all only 0.47–0.56; the exact disease the Phase-4 MLP had). Debug evidence (D1): ridge on the cached embeddings reproduces the 0.7775/88.54% anchor **exactly** → cache, masks, labels all correct. Fix: minibatch Adam; bs selected among {32,64,128,256} **purely on the ordered validation metric** (val Spearman-nz: 0.5802/0.5759/0.5749/0.5731 → bs=32 wins); all four converge to the same zone (test RankAcc-all 85.4–85.9%), so this is genuine convergence, not batch luck. Training curve: early stop at epoch 229, **selected epoch 179**, val Spearman-nz 0.5757.

**Test results (saleor-storefront):**

| cut | MSE | MAE | Pearson | Spearman | RankAcc |
|---|---|---|---|---|---|
| (a) all 1,341 | **0.0265** | 0.1100 | 0.6239 (nz) | 0.5487 (nz) / **0.7210 (all)** | **85.55%** |
| (b) non-zero 538 | 0.0421 | 0.1514 | 0.6239 | 0.5487 | 69.98% |

vs as-trained VulnGAT: Spearman_all −0.2357 → **+0.7210**; RankAcc 39.11% → **85.55%**.

**Sanity gate (nz cut ≈85–88% expected): literal expectation NOT met — and it is unmeetable for any linear head.** Evidence: the 85–88% anchors (ridge 88.5%, fresh linear head 87.1%) are **all-cut** numbers; measured on the non-zero cut, ridge — the closed-form ceiling for ANY linear head on these embeddings — gets **72.03%**. VulnGAT-HR's nz-cut RankAcc 69.98% = **97.2% of the linear ceiling**; on the comparable all cut it lands 85.55%, inside the anchor zone. Wiring proven correct (D1 above) → **no encoder-retrain / Colab contingency triggered** (it was justified only if wiring were proven correct AND the refit still failed the anchor zone on the like-for-like cut — it doesn't).

## Phase 2a — Baseline fix: **DONE** ✅
Script: `phase5/phase2a_mlp_reconverge.py` · Output: `phase5/phase2a_baselines.json`, `phase5/mlp_reconverged.pt`

Reconverged the archived MLP (architecture identical: 10-64-64-1-Sigmoid; minibatch bs=256, wd=1e-5 as archived; selection moved to val-Spearman-nz = the protocol fix, so all three final-table models are selected the same way; early stop at epoch 62, selected epoch 11). **Final table (test, saleor-storefront):**

| model | MSE | MAE | Spear_nz | Spear_all | RankAcc | RankAcc_nz |
|---|---|---|---|---|---|---|
| ridge-raw (floor), α=1.0 on val MSE | 0.1997 | 0.4204 | 0.5165 | 0.5520 | 77.13% | 67.87% |
| **MLP reconverged** | 0.0315 | 0.1315 | 0.5198 | 0.5550 | **77.45%** | 67.80% |
| **VulnGAT-HR** | **0.0265** | **0.1100** | **0.5487** | **0.7210** | **85.55%** | **69.98%** |
| *refs:* MLP archived (P4, under-converged) | 0.0383 | 0.1436 | 0.4944 | 0.4426 | 72.18% | — |
| *refs:* VulnGAT archived (P4, anti-aligned) | 0.0581 | 0.1677 | 0.2227 | −0.2357 | 39.11% | — |

The Phase-4 anomaly "MLP loses to ridge" is resolved: a converged MLP **ties** ridge (77.45 vs 77.13). VulnGAT-HR beats both baselines on every ranking metric (+8.1 pp RankAcc, +0.17 Spearman_all over the feature-only models) — on the clean split, the frozen encoder's embeddings now carry real value on top of the 10 raw features.

## Phase 2b — Masked-edge audit on VulnGAT-HR: **pre-registered criterion FAILED** ❌ (honest Outcome 3)
Run: archived `TrainModel/masked_edge_audit.py` unmodified (dim-6 zeroing active per Commandment 2), env-var paths, `PYTHONHASHSEED=42` pinned, seed 42, ratios 10/30/50%, 1,000-iter bootstrap, all on CPU in 687.7 s. Output: `phase5/masked_edge_audit_hr.json` (config: eligible 645 @ own/VPSS ≥ 0.7, never-vuln negatives 8,682).

**AUC (masked-vulnerable vs never-vulnerable), overall stratum:**

| mask | VulnGAT-HR | BFS | label-prop | feat-shuffle |
|---|---|---|---|---|
| 10% | 0.7002 | 0.5694 | **0.7087** | 0.6991 |
| 30% | 0.6501 | 0.5299 | **0.7233** | 0.6522 |
| 50% | 0.6423 | 0.5350 | **0.7150** | 0.6426 |

50% shared stratum: model 0.6472 / BFS 0.5341 / label-prop 0.7208; 50% orphaned: model 0.6237 / label-prop 0.6925.

Readings, verbatim-honest:
- vs the as-trained model (AUC 0.397 at 50% — below chance), VulnGAT-HR is a massive repair (**0.397 → 0.642**) and it beats BFS by ≈ +0.11 everywhere.
- **The number to beat was label-prop 0.72, and it still wins** at every ratio; the pre-registered criterion (beat label-prop by >0.02 at 50% mask, Commandment 9) fails at **−0.073/−0.078**. The audit's distribution-shift caveat applies unchanged: the encoder was trained with its own `hasVulnerability` edges present; masked inference is OOD for it.
- Feature-shuffle drop ≈ 0.0000 at every ratio → still **no CVE-embedding semantic signal used** (identical to Phase 4's finding).
- MRR (embedding-space CVE re-ranking) 0.008–0.012 vs random floor 0.0011 — 7–11× above chance, absolute tiny (unchanged from P4).

## Phase 2c — NodeTestBench OOD (threshold LOCKED ≥0.40, no tuning): **reported — precision does not survive the swap**
Protocol: archived Phase-4 staging reproduced locally — `phase5/bench_run/` = `analyze_project.py` + `core/` + 51-repo `vulnchain_graph.json` (KB) + `models/vulngat_trained.pt` = **VulnGAT-HR merged checkpoint** (`phase5/models/vulngat_hr_full.pt`: frozen 51-repo encoder + refit head; 98 tensors, loads cleanly). Ground truth = non-null `cve` field. Output: `phase5/bench_run/bench_results_hr.json`.

| N=671 (77 CVE-confirmed) | as-trained (P4 archived) | **VulnGAT-HR** |
|---|---|---|
| Flagged ≥0.40 | 25 | 41 |
| TP / FP / FN | 25 / 0 / 52 | 31 / 10 / 46 |
| **Precision** | **100.0%** | **75.6%** |
| **Recall** | 32.5% | **40.3%** |

Honest reading: recall improves (31 TPs, +6 recovered CVE packages) but **10 clean packages cross 0.40** — eslint 0.9995, superagent 0.9685, pg 0.9515, eslint-plugin-node 0.9504, needle 0.9228, rc 0.8493, boxen 0.6493, table 0.6370, wrap-ansi 0.5520, inquirer 0.4838 — most flagged via vulnerable descendants (blast-radius behavior by design; still FPs under this ground truth). The archived "100% precision" claim is **not** a property of the refit model. No threshold tuning was done or allowed.

## Phase 3 — EPSS rebuild + counts + decision matrix: **COMPLETE** ✅ (HARD STOP for Brain)
*Spec confirmation (verbatim): D1 ungated. Corrected rationale: the masked-edge failure is RELEVANT to the EPSS question (the EPSS value-add claim depends on propagation); run anyway because it is cheap and informative. ≥3,000 non-zero hard stop kept.*

Scripts: `phase5/epss_labeler_rebuild.py` · Outputs: `phase5/epss_rebuild_report.json`, `phase5/epss_labels_51repo.json`

### 3.1 Validity Gate: **PASS** ✅ (bit-exact reproduction)
Reconstructed the EPSS labeler and verified against `TrainModel/epss_labels_experimental.json` across all 5,578 pilot packages:
- **Fields checked:** 22,312 (all 4 fields: `epss_risk`, `raw_sum`, `num_contributing_vulns`, `min_depth_to_vuln`).
- **Mismatches:** **0** (tolerance < 1e-10).
- **Algorithmic discoveries (ground truth from archived labels):**
  1. *No exposure tier:* exposure was $1.0$ everywhere (unlike VPSS, which used 1.0/0.5/0.3/0.15).
  2. *Unique CVE deduplication at minimum depth:* if multiple transitive packages share the same CVE, EPSS counted that CVE once at its minimum depth.
  3. *Max BFS depth:* search strictly capped at `depth <= 5`.
  4. *CISA KEV bonus:* if `in_cisa_kev == True`, the CVE score is boosted to $1.0$ (observed on `GHSA-jpcq-cgw6-v4j6` in jQuery).
  5. *CVSS imputation:* for CVEs lacking EPSS score, imputed as `cvss_score / 100.0`.
  6. *Rounded raw_sum input:* `epss_risk = round(raw_sum / (raw_sum + 1.0), 6)` from rounded `raw_sum`.

### 3.2 51-Repo Graph Counts (BOTH Definitions)
Applied the validated labeler to `phase5/bench_run/vulnchain_graph.json` (12,405 packages, 883 CVEs, 2,632 hasVuln edges):

| Definition | Description | Count | Passes Cmd 6 Gate (≥3,000)? |
|---|---|---|---|
| **(a) Closure-derived** | Any package with $raw\_sum > 0$ from BFS closure ($d \le 5$) | **3,303** (26.6%) | **YES** ✅ (3,303 ≥ 3,000) |
| *(a.1) With own CVE* | Labeled package possesses direct `hasVulnerability` edge | 751 (6.1%) | — |
| *(a.2) Closure-only* | Labeled package elevated purely via downstream dependencies | 2,552 (20.6%) | — |
| **(b) Own-CVE only** | Only packages with direct `hasVulnerability` edges | **751** (6.1%) | **NO** ❌ (751 < 3,000, 889-regime) |
| *Zero EPSS* | Packages with zero reachable EPSS risk | 9,102 (73.4%) | — |

**Confirmation:** In the 9-repo era, 889 non-zero packages existed vs 301 packages with `hasVulnerability` edges (588 closure-only). Archived EPSS was **definitively closure-derived** (Definition a).

### 3.3 Advisory-Date Distribution (Temporal Split Feasibility)
All 883 CVE nodes in the 51-repo graph were resolved against `.osv_records_cache.json` (`published` ISO timestamp):
- **Dates resolved:** 883 / 883 (100%, 0 missing).
- **Date range:** 2017-10-24 to 2026-09-17.
- **Quartiles:** Q1 = **2022-01-21** · Q2 (median) = **2025-05-19** · Q3 = **2026-05-14**.
- **Year distribution:** 2017: 11 | 2018: 35 | 2019: 34 | 2020: 49 | 2021: 76 | 2022: 105 | 2023: 52 | 2024: 57 | 2025: 72 | **2026: 392** (44.4% in 2026).
- **Precommitted temporal split:** Cutoff by package's newest contributing CVE published date; cutoff date pre-registered to ensure $\ge 150$ non-zero test nodes (B5 precedent). Residual shared-CVE overlap across train/test splits will be explicitly reported.
- **Limitation:** Current snapshot EPSS scores used for all CVEs — tests advisory-recency generalization, not true historical EPSS drift.

### 3.4 Decision Matrix for the Brain (HARD STOP ENFORCED)
No models trained. No notebook generated. Awaiting Brain directive:

| Option | Track | N (non-zero) | Cmd 6 Gate | Key Methodological Trade-off |
|---|---|---|---|---|
| **A** | **Closure-derived** (Definition a) | **3,303** | **PASS** (≥3,000) | Label is deterministic decayed-sum ($K=1.0$). A GNN predicting this label without seeing EPSS inputs is evaluated against an oracle formula ($r_s \approx 1.0$ baseline). Must reframe headline as "GNN vs formula oracle". |
| **B** | **Own-CVE only** (Definition b) | **751** | **FAIL** (<3,000) | Falls into the underpowered 889-sample regime that degraded in Phase 4. Violates Commandment 6. Not scientifically viable alone. |
| **C** | **Dual-Track** | 3,303 + 751 | Partial | Primary evaluation on Option A (continuity & validity); Option B tracked as clearly labeled underpowered exploratory benchmark with no headline claims. |

---

## Phase 4 — Inference swap: D2 comparison tables **COMPLETE** ✅
*Spec confirmation (verbatim): D2 comparison tables (FP decomposition, quantiles, rank overlap, descriptive P@k, §13.4 packages with caveat) MUST appear in worker report.*

Script: `phase5/phase4_compare.py` · Output: `phase5/phase4_inference_swap.json`  
Arms evaluated: **VulnGAT-HR** (`phase5/models/vulngat_hr_full.pt`) vs **as-trained 51-repo** (`phase4/models/vulngat_51repo.pt`), both under the 51-repo knowledge base. Thresholds locked: Critical $\ge 0.40$, Propagation baseline $> 0.08$.

### Table 1: Per-Lockfile Summary & FP Decomposition
| Lockfile | Pkgs | HR Flagged (own / prop / neither) | Old Flagged (own / prop / neither) | Neither Rate (HR vs Old) |
|---|---|---|---|---|
| `legacy_app` | 9 | 5 (5 / 0 / 0) | 2 (2 / 0 / 0) | 0.0% vs 0.0% |
| `marked` | 617 | 42 (1 / 0 / 41) | 2 (2 / 0 / 0) | 97.6% vs 0.0% |
| `meteor` | 401 | 24 (2 / 0 / 22) | 0 (0 / 0 / 0) | 91.7% vs 0.0% |
| `modern_clean` | 6 | 1 (1 / 0 / 0) | 0 (0 / 0 / 0) | 0.0% vs 0.0% |
| `socket_io` | 1157 | 82 (12 / 0 / 70) | 1 (1 / 0 / 0) | 85.4% vs 0.0% |
| `user_package_lock` | 132 | 10 (6 / 3 / 1) | 0 (0 / 0 / 0) | 10.0% vs 0.0% |
| `vuln_test` | 11 | 1 (1 / 0 / 0) | 1 (1 / 0 / 0) | 0.0% vs 0.0% |

### Table 2: Score Distributions, Rank Overlap & Descriptive Top-K Precision
| Lockfile | HR Quantiles (min/p50/p90/max) | Old Quantiles (min/p50/p90/max) | Spearman Rank Overlap ($r_s$) | HR P@10 (TP/N) | Old P@10 (TP/N) |
|---|---|---|---|---|---|
| `legacy_app` | 0.08 / 0.41 / 0.98 / 1.00 | 0.08 / 0.18 / 0.40 / 0.41 | 0.227 (p=5.6e-01) | 77.8% (7/9) | 77.8% (7/9) |
| `marked` | 0.02 / 0.08 / 0.08 / 1.00 | 0.05 / 0.08 / 0.08 / 0.44 | 0.402 (p=2.6e-25) | 0.0% (0/10) | 40.0% (4/10) |
| `meteor` | 0.01 / 0.08 / 0.08 / 1.00 | 0.05 / 0.08 / 0.08 / 0.28 | 0.327 (p=1.8e-11) | 20.0% (2/10) | 10.0% (1/10) |
| `modern_clean` | 0.05 / 0.08 / 0.47 / 0.62 | 0.08 / 0.08 / 0.27 / 0.33 | 0.870 (p=2.4e-02) | 33.3% (2/6) | 33.3% (2/6) |
| `socket_io` | 0.02 / 0.08 / 0.08 / 1.00 | 0.05 / 0.08 / 0.08 / 0.41 | 0.238 (p=2.1e-16) | 0.0% (0/10) | 20.0% (2/10) |
| `user_package_lock` | 0.03 / 0.08 / 0.08 / 1.00 | 0.05 / 0.08 / 0.08 / 0.31 | 0.177 (p=4.3e-02) | 60.0% (6/10) | 70.0% (7/10) |
| `vuln_test` | 0.02 / 0.08 / 0.40 / 0.65 | 0.08 / 0.08 / 0.21 / 0.53 | 0.521 (p=1.0e-01) | 40.0% (4/10) | 40.0% (4/10) |

### 4.3 Section 13.4 Packages & Credit Split Attribution
1. **§13.4 Packages:** In the 9-repo lore, four benign packages (`@google/genai`: 0.2453, `socket.io-client`: 0.1989, `vite`: 0.1232, `protobufjs`: 0.1229) were cited as evidence of blast-radius propagation above the 0.08 calibration cap.  
   - *Audit Caveat:* Those scores were produced under the 9-repo knowledge base. In `user_package_lock.json` (which parses to 132 packages, matching archived `results.json`), the actual benign parents elevated above the 0.08 cap are:
     - `socket.io@4.8.3`: HR = **0.3046** (no direct CVE; elevated via child `socket.io-parser`)
     - `express@5.2.1`: HR = **0.2220** (no direct CVE; elevated via middleware chain)
     - `concurrently@9.2.1`: HR = **0.2195** (no direct CVE; elevated via downstream tree)
     - `socket.io-adapter@2.5.6`: HR = **0.1330** (no direct CVE)
2. **Honest Credit Attribution:** Across real-world lockfiles, VulnGAT-HR is significantly more aggressive than the under-converged old head:
   - On small/targeted lockfiles (`legacy_app`, `vuln_test`, `user_package_lock`), HR achieves high precision (0–10% neither rate) and recovers genuine multi-hop transitive paths.
   - On large graphs (`marked`, `meteor`, `socket_io`), HR elevates many benign packages into $\ge 0.40$ (85–97% neither rate under flat CVE-ground-truth), directly mirroring the NodeTestBench precision drop (100% $\to$ 75.6%).
   - The credit split between GNN topological propagation and post-hoc pipeline calibration remains approximately **30% GNN / 70% pipeline engineering**.

---

## Artifacts Inventory (Phase 5)
| file | what |
|---|---|
| `phase0_validity_gate.py` / `phase0_validity.json` | Phase-0 gate script + PASS report |
| `phase1_head_refit.py` / `phase1_head_refit.json` / `phase1_training_curve.json` | VulnGAT-HR protocol + results + curve |
| `debug_phase1_convergence.py` | gate-failure debug (ridge anchor reproduction, full-batch vs minibatch evidence) |
| `pkg_embeddings_frozen.npy` + `pkg_embeddings_meta.json` | cached frozen 128-d embeddings for all 12,405 packages |
| `vulngat_hr.pt` | refit head (head_state_dict + meta; load into `model.classifier`) |
| `models/vulngat_hr_full.pt` | merged full VulnGAT state_dict (frozen encoder + HR head) |
| `phase2a_mlp_reconverge.py` / `phase2a_baselines.json` / `mlp_reconverged.pt` | baseline fix + final table |
| `masked_edge_audit_hr.json` | Phase-2b audit results (Outcome 3, FAILED criterion) |
| `bench_run/` (+`bench_results_hr.json`, `hr_*.json`) | staged HR inference dir + outputs |
| `bench_run_astrained/` (+`old_*.json`) | staged as-trained comparison dir + outputs |
| `phase4_compare.py` / `phase4_inference_swap.json` | Phase 4 D2 comparison script + JSON output |
| `demo/` (`demo_runner.py`, `DEMO_REPORT.md`, `demo_comparison.json`) | Part 1 live demo runner + side-by-side tables |
| `DIAGNOSIS_39to85.md` | Part 1 forensic narrative (39% to 85.6%) |
| `epss_labeler_rebuild.py` / `epss_rebuild_report.json` / `epss_labels_51repo.json` | Part 3 EPSS rebuild + validity gate (PASS) + decision matrix |
| `logs_hr_*.txt` / `logs_old_*.txt` | per-run inference logs |
| `NodeTestBench/` | cloned benchmark repo |

---

## Bottom Line & Decisions for the Brain
1. **In-Distribution Ranking:** VulnGAT-HR fully repairs ranking (39% $\to$ **85.6%** RankAcc; Spearman $-0.24 \to \mathbf{+0.72}$) and beats both feature-only baselines (reconverged MLP 77.5%, ridge 77.1%).
2. **Phase 2 Headline Gates:** Masked-edge AUC (0.642) beats BFS (0.535) but still loses to label-prop (0.715, pre-registered criterion failed). NodeTestBench precision dropped from 100% $\to$ 75.6% (recall rose 32.5% $\to$ 40.3%).
3. **EPSS (Part 3):** Validity gate passed bit-exactly (22,312/22,312 fields matched). Definition (a) closure-derived yields **3,303 non-zero samples** (passes Commandment 6 $\ge 3,000$ gate). Definition (b) own-CVE yields **751 samples** (fails gate). Advisory dates span 2017–2026 (883/883 resolved). **HARD STOP ACTIVE: Awaiting Brain decision on Options A, B, or C before training any EPSS arm.**
4. **Deviations / Amendments Ledger (verbatim):**
   - **D1:** EPSS ungated. Corrected rationale: the masked-edge failure is RELEVANT to the EPSS question (the EPSS value-add claim depends on propagation); run anyway because it is cheap and informative. $\ge 3,000$ non-zero hard stop kept.
   - **D1 additions ACTIVE:** closure baselines (max + decayed-sum) are the bar for "embeddings add value"; temporal split by advisory dates, not random; $\ge 5$ seeds reporting mean $\pm$ std; primary metrics = Spearman + precision-at-k; hard-stop decision matrix after counts.
   - **D2:** comparison tables (FP decomposition, quantiles, rank overlap, descriptive P@k, §13.4 packages with caveat) MUST appear in worker report.
   - **D3:** live demo + diagnosis is FIRST in priority order.
   - **D4:** v2 pre-registration (5+ seed audit, protocol fixes, GNN vs closure comparison, 100% precision diagnosis) TIMEBOXED, last.

---

# Phase 5 Continuation II Addendum — Final Pre-v2 Report
**Run date:** 2026-09-20 · **Orders:** Phase 5 Continuation II (Blocking Fixes → EPSS Arms → v2 Pre-registration + Notebook)  
**Status: Parts A, B, C, D, E COMPLETE — v2 Pre-registration locked, Colab Notebook generated, HARD STOP on v2 training enforced.**

### Brain Decisions Logged Verbatim (Deviations Ledger)
- **(g) Multi-task loss replaces approved MSE-only:** ACCEPTED with conditions: $\lambda_{\text{rank}}=0.20$, $\lambda_{\text{mask}}=0.30$ FROZEN (no tuning); attribution via ablations; if no-masking ablation also passes primary, headline attributes to ranking loss, not masking.
- **(h) Secondary gate metric = Spearman (not RankAcc-nz):** ACCEPTED, resolves Brain's no-accuracy-metrics rule; floor = ridge-raw + margin = **0.6571**.
- **(i) 5 seeds (not seed 42):** ACCEPTED; BOTH gates evaluate on the **MEAN across seeds**, per-seed values reported. No per-seed pass claims.
- **v2 IS GREENLIT:** One cycle, no v3, terminal outcome either way. This cycle + its ablations = the project's **final training intervention**. Failure = **final negative result**. **NO v3 under any combination of outcomes.**
- **EPSS = Option C amended:** Primary = closure labels; headline framing LOCKED as *"GNN vs formula oracle — approximating EPSS-closure without EPSS inputs"*; NEVER *"beats closure"*. Own-CVE (751) = labeled exploratory arm only.
- **NEW cross-label transfer arm:** VPSS-trained HR head evaluated on EPSS-closure test labels (no retraining) and vice versa. The circularity-escaping comparison.
- **D3 CLARIFICATION:** The v2 clean-test gate floor is the **best learnable baseline (ridge/HR) + $\max(2\text{pp}, 2 \times \text{seed-std})$**. The closure oracle ($r_s = 1.0$) is ceiling context only.

---

## Part A — Neither-Bucket Reconciliation (100% COMPLETE ✅)
Scripts: `phase5/rerun_inferences.py`, `phase5/phase4_compare_reconciled.py` · Output: `phase5/phase4_inference_swap.json`

Re-ran all 7 lockfiles across both arms (HR and Old, 14 total runs) using an instrumented `analyze_project.py` that directly records `has_own_cve`, `cap_applied`, and `has_vuln_descendant` in each package object.

| Lockfile | Pkgs | HR Flagged | Reconciled Neither (HR) | Old Neither (HR) | Old Neither Rate | Reconciled Neither Rate |
|---|---|---|---|---|---|---|
| `legacy_app` | 9 | 5 | 0 | 0 | 0.0% | **0.0%** |
| `marked` | 617 | 42 | 0 | 41 | 97.6% | **0.0%** |
| `meteor` | 401 | 24 | 0 | 22 | 91.7% | **0.0%** |
| `modern_clean` | 6 | 1 | 0 | 0 | 0.0% | **0.0%** |
| `socket_io` | 1157 | 82 | 0 | 70 | 85.4% | **0.0%** |
| `user_package_lock` | 132 | 10 | 0 | 0 | 0.0% | **0.0%** |
| `vuln_test` | 11 | 1 | 0 | 1 | 0.0% | **0.0%** |

**Mechanism Confirmed:**
- There are **exactly zero (0) true neither survivors** across all lockfiles.
- Every single package flagged $\ge 0.40$ without an own CVE (e.g. `npm@11.18.0`, `eslint@8.57.1`, `nyc@17.0.0`) has `has_vuln_descendant: true`.
- The previous 85–97% neither rates were **100% an artifact of `attack_paths` only tracing paths ending at direct root packages**. When a transitive package has a vulnerable descendant but is not a root-sink chain end, it was miscounted as "neither".
- The old decomposition is quarantined in `phase4_inference_swap.json` with the full explanation.

---

## Part B — EPSS Coverage Completion (100% COMPLETE ✅)
Scripts: `phase5/epss_coverage_and_fetch.py`, `phase5/epss_rebuild_with_coverage.py` · Outputs: `phase5/epss_data_51repo.json`, `phase5/epss_labels_51repo.json`

- **Coverage Expansion:** Re-queried FIRST.org API and CISA KEV catalog for 1,716 CVEs across all 51 repositories.
  - Real EPSS coverage jumped from 34.1% (301) to **92.4% (816 CVEs)** (+515 gained).
  - CVSS fallback: 25 CVEs (2.8%).
  - Neither: 42 CVEs (4.8%) — 38 are pure GHSA records with no CVE alias.
- **Rebuilt 51-Repo Graph Counts:**
  - **(a) Closure-derived non-zero: 3,691 packages (29.8%)** $\to$ **PASSES Commandment 6 gate ($\ge 3,000$)**! (Own CVE: 958; Closure-only: 2,733).
  - **(b) Own-CVE non-zero: 958 packages (7.7%)** $\to$ Fails $\ge 3,000$ gate (confirms Option B is underpowered).
  - Advisory dates: 883/883 resolved (100%), spanning 2017-10-24 to 2026-09-17.

---

## Part C — EPSS Arms & 5-Seed Evaluation (100% COMPLETE ✅)
Scripts: `phase5/part_c_epss_arms.py`, `phase5/part_c_masked_edge_multiseed.py` · Outputs: `phase5/phase3_epss_arms.json`, `phase5/part_c_masked_edge_audit_5seeds.json`

### 1. Temporal Split
- **Cutoff:** `2026-08-01` (by newest contributing CVE published date).
- **Distribution:** Train (fit) = 1,809 | Validation = 452 | **Test = 1,430 non-zeros** (Gate $\ge 150$: **PASS**).
- **Shared CVE Overlap:** 385 / 732 test CVEs (52.6%).

### 2. Pre-Committed EPSS Arms Table (Non-Zero Test Cut, $N=1,430$)
| Arm | Description | Spearman (mean $\pm$ std) | P@10 (mean $\pm$ std) | Recall@top10% |
|---|---|---|---|---|
| **a** | closure-max (Hill $K=1$) | 0.9463 $\pm$ 0.0000 | 1.00 $\pm$ 0.00 | 0.7203 $\pm$ 0.0000 |
| **b** | closure-decayed-sum (ORACLE ceiling) | 1.0000 $\pm$ 0.0000 | 1.00 $\pm$ 0.00 | 1.0000 $\pm$ 0.0000 |
| **c** | ridge-raw $\to$ EPSS | 0.6371 $\pm$ 0.0000 | 0.50 $\pm$ 0.00 | 0.3846 $\pm$ 0.0000 |
| **d** | HR head on frozen embeddings $\to$ EPSS (5 seeds) | 0.5614 $\pm$ 0.0014 | 0.20 $\pm$ 0.00 | 0.4112 $\pm$ 0.0069 |
| **e1** | VPSS-trained HR head on EPSS test (no retraining) | 0.4678 $\pm$ 0.0000 | 0.30 $\pm$ 0.00 | 0.3986 $\pm$ 0.0000 |
| **e2** | EPSS-trained HR head on VPSS test (no retraining) | 0.3948 $\pm$ 0.0000 | 0.20 $\pm$ 0.00 | 0.3706 $\pm$ 0.0000 |
| **f** | EXPLORATORY own-CVE cut ($N=262$ pkgs, clearly labeled) | 0.6024 $\pm$ 0.0000 | 0.40 $\pm$ 0.00 | 0.2222 $\pm$ 0.0000 |

### 3. 5-Seed Masked-Edge Audit (50% Mask ONLY)
- **VulnGAT-HR AUC (overall):** $0.6315 \pm 0.0045$
- **Label-Prop AUC (overall):** $0.7191 \pm 0.0069$
- **Label-Prop std:** $0.0069$
- **Margin = $\max(0.02, 2 \times \text{std})$:** $0.0200$ (2pp)
- **Pre-registered Success Bar:** $0.7191 + 0.0200 = \mathbf{0.7391}$
- **Current VulnGAT-HR vs Bar:** $0.6315$ vs $0.7391$ ($\Delta = -0.1076$)
- **Stratification:** Shared: Model $0.6470 \pm 0.0060$ vs LP $0.7214 \pm 0.0064$ | Orphaned: Model $0.5682 \pm 0.0431$ vs LP $0.7112 \pm 0.0289$.

---

## Part D — v2 Pre-Registration & Notebook (100% COMPLETE ✅)
Artifacts: `phase5/VULNGAT_V2_PREREGISTRATION.md`, `phase5/vulngat_v2_training.ipynb`

1. **Pre-Registration Document:** Complete and locked in `phase5/VULNGAT_V2_PREREGISTRATION.md`.
   - **Primary Gate:** 50% Masked-Edge AUC $\ge \mathbf{0.7391}$ ($\text{LP}_{\text{mean}} + \text{margin}$).
   - **Secondary Gate:** Clean-Test Spearman $\ge \mathbf{0.6571}$ ($\text{Ridge}_{\text{raw}} + \text{margin}$).
   - **Loss Formulation:** Multi-task MSE + Pairwise Ranking ($\lambda=0.20$) + Masked Auxiliary Consistency ($\lambda=0.30$) with dynamic edge dropout.
   - **Ablation Arms:** (1) Full v2, (2) No Edge Masking, (3) No Ranking Loss.
2. **Self-Contained Colab Notebook:** Produced at `phase5/vulngat_v2_training.ipynb`.
   - Fully self-contained with PyG dataset wiring, VulnGAT v2 architecture, training harness across 5 seeds, and automatic verification against the pre-registered thresholds.
   - **HARD STOP ENFORCED:** The notebook was generated but NOT executed locally, per strict orders. Ready for Colab GPU execution by the Brain.

---

## Updated Artifacts Inventory (Continuation II)
| File | Purpose |
|---|---|
| `phase5/epss_data_51repo.json` | Expanded EPSS data (92.4% coverage, 816 CVEs) |
| `phase5/epss_labels_51repo.json` | Rebuilt 51-repo EPSS labels (3,691 closure non-zeros) |
| `phase5/phase4_inference_swap.json` | Reconciled FP decomposition (0 true neither survivors) |
| `phase5/phase3_epss_arms.json` | Pre-committed EPSS arms across 5 seeds |
| `phase5/part_c_masked_edge_audit_5seeds.json` | 5-seed 50% masked-edge audit results + margin |
| `phase5/VULNGAT_V2_PREREGISTRATION.md` | Formal OSF-standard pre-registration document |
| `phase5/vulngat_v2_training.ipynb` | Self-contained Colab notebook for the Brain |

---

# Phase 5 Continuation III Addendum — v2 Autopsy (Checkpoint Forensics)
**Run date:** 2026-09-20 · **Orders:** v2 Autopsy (NO training, CPU only) · **Status:** COMPLETE
**Full evidence:** [`phase5/V2_AUTOPSY.md`](V2_AUTOPSY.md) · Forensic scripts/logs: `phase5/autopsy_*.py|json|txt`

**Classification: (A) Execution defect — HIGH confidence.** Three independent, individually sufficient defects, all in the pre-registered notebook artifact itself (the Colab run faithfully executed its own flawed spec):
- **A1 Eligibility filter bug:** notebook's inline re-computation of the masked-audit strata yields **0 eligible packages** (own_ratio ≥ 0.70 is unreachable on this graph — max 0.6667); the official N=645 comes from a silent auto-relaxation to 0.30 in `TrainModel/masked_edge_audit.py` that the notebook dropped → empty positive set → `roc_auc_score` on single-class labels → **AUC = NaN on all 35 runs. The primary gate was never measured.** Counterfactual (inference only, official 645 strata): AUC = **0.495 ± 0.039** — chance, identical across all p.
- **A2 Missing reverse message passing:** v2's `HeteroConv` has only the 4 forward directions; Package predictions depend solely on `dependsOn`. Masking `hasVulnerability` edges is provably inert (empirical: max|Δpred| = **0.000e+00** when 100% removed) → **L_aux ≡ 0 identically**; `p_mask` never influenced anything.
- **A3 Missing feature normalization:** Phase 4 min-maxed package dims [2,3,4,5,7], CVSS/10, author dims [0,1,2,3,6]; v2 fed raw features → layer-1 preactivations std ≈ 476 at init → sigmoid saturation (logits |·| ≤ 531) → gradient ≈ 0 → **no model ever learned** (weights ≤1.3% L2 from random init; train r_s ≈ chance everywhere).

- **(B) rejected as stated** — outputs are degenerate (saturated two-point masses) but nothing *converged*; the degeneracy is dead-on-arrival saturation, not an optimum. **(C) refuted** — no in-period fit exists to fail temporal generalization (train r_s −0.07…+0.08).

### Brain Decisions / Ledger Entries (verbatim record)
- **D5 (RETRACTION):** The preregistration §7 sentence *"…it constitutes a final, terminal negative result documenting the structural limitations of GNN propagation on dependency vulnerability graphs"* is **RETRACTED**. The v2 failure is an execution/protocol-artifact defect, not evidence about GNN propagation on this graph class. No structural claim may be cited from the v2 cycle. A dated retraction notice is appended to `VULNGAT_V2_PREREGISTRATION.md` (locked body unmodified).
- **D6 (QUARANTINE UPHELD):** The v2 result (35 checkpoints + `vulngat_v2_final_results.json`) remains **QUARANTINED**. Primary gate: never measured (NaN by construction). Secondary gate number (mean r_s = 0.0198 vs 0.6571): vacuous (chance-level output of an untrained model). Neither gate may be cited as pass or fail.
- **D7 (Identical-rows anomaly — documented & resolved):** The p10/p30/p50 identical mean±std rows are **real data from three distinct trainings whose p-difference was causally inert**: all 35 checkpoint MD5s distinct; weight diffs across p nonzero and non-monotonic (GPU atomics scale); the dropout function received and applied varying p correctly; but the masked edge type is architecturally dead for the head and the RNG draw count is p-independent, so all three configs traced the same effective trajectory. Spearman (rank-based, over saturated bimodal outputs) is then identical to machine precision wherever no ranks flip — including a bit-identical val r_s = −0.06799244700113821 shared by six full_v2/no_ranking runs at seed 42. **No duplication, fabrication, or logging fault.**
- **D8 (Conditional rerun — RESOLVED: rerun authorized):** The pre-committed row *"execution defect → one rerun, identical protocol, no tuning"* **cannot be executed as written** — an identical-protocol rerun deterministically reproduces all three defects (they are in the spec). **RESOLUTION: the Brain granted the single conditional rerun as "identical protocol, defect-corrected"** — exactly three amendments (reverse/bidirectional message passing; Phase-4-identical normalization; eligibility delegated to `TrainModel/masked_edge_audit.py`), with gates, thresholds, seeds, and margins unchanged. Batching needs no change (v2 is full-graph; no `bs=32` node-slicing exists). Executed as `phase5/vulngat_v2_training_rerun.ipynb` (`v2dc_*` run ids); see the Rerun Preparation section and `V2_AUTOPSY.md` Appendix B.
- **D9 (Pre-flight suite — ADOPTED, Commandment 15):** The six-gate CPU pre-flight suite (P1 init sanity; P2 pathway liveness; P3 learnability smoke; P4 eligibility assertion via the official code path; P5 per-epoch per-term loss logging; P6 resume-safety with non-reusable run ids) is adopted as a **standing requirement**: no training run may be fired on Colab until P1–P6 pass on CPU, and any failure mandates CPU-side debug before any fire. First application: P1/P2/P4/P5/P6 PASS; P3 initially FAILED at its 50-epoch horizon → resolved by D10.
- **D10 (P3 horizon correction + FIRE AUTHORIZATION — VERBATIM):** "P3 horizon (50 epochs) was Brain-mis-specified relative to frozen protocol dynamics (~70-epoch output-mean-fitting phase). Corrected to budget-matched horizon: train Spearman > 0.30 within the pre-registered 100-epoch budget; bar unchanged. Satisfied by the pre-collected 300-epoch diagnostic (train ρ = +0.4043 at epoch 100; weights discarded; evidence predates this ruling). The 300-epoch trajectory beyond the cap is interpretation context only, never gate-eligible. Precedent: Phase-1 nz-cut anchor correction." Fired-artifact identity recorded: `vulngat_v2_training_rerun.ipynb` SHA-256 `aeaeae83c2c3afe91fdf5f1768ef0e6cfc329644099bf490f130c6e6a440372d` (MD5 `c4c04f8a974d96359ff43900d1d31f19`, 48,072 bytes; `v2dc_fire_manifest.json`). **Status: PRE-FLIGHT PASSES under corrected P3. Colab fire AUTHORIZED by the Brain. Protocol frozen. No further changes of any kind permitted.**
- **D11 (TERMINAL RESULT — pre-committed row executed):** The authorized rerun fired on Colab (T4) and completed the full pre-registered matrix (35/35 runs, all `v2dc_*`, `protocol_version='v2.1-defect-corrected'`; artifacts verified: gate stats recomputed from per-seed values — exact match; 35/35 checkpoints, zip integrity OK; archived as `phase5/v2dc_final_results.json` + `phase5/v2dc_checkpoints.zip`). **Both gates FAIL: full_v2 primary AUC 0.3916-0.4156 (bar 0.7391; below chance 0.5), secondary r_s 0.1489-0.1507 (bar 0.6571).** Pre-committed row "Both < bars -> Terminal negative - now validly measured" applied with the locked thesis: *"The pre-registered end-to-end protocol, correctly implemented, does not beat label propagation or ridge on this graph at this scale; frozen Phase-4 representations remain the best encoder."* P5 loss logging closed in production (full per-epoch trajectories on all 35 runs). Terminality CONFIRMED - no v3, no further training interventions.

### Additional Autopsy Artifacts
| File | Purpose |
|---|---|
| `phase5/V2_AUTOPSY.md` | Full per-item forensic report (items 1–6, counterfactual gate, classification, thesis language) |
| `phase5/autopsy_item2_weightdiff.py` / `.json` | Checkpoint MD5 + weight-diff forensics across arms/p/seeds |
| `phase5/autopsy_behavior2.py` / `autopsy_behavior_results.json` / `autopsy_behavior_log2.txt` | Verbatim rebuild of notebook cells 3–4; train/val/test metrics, activation hooks, init-distance, inertness test, NaN mechanism, raw feature stats |
| `phase5/autopsy_behavior.py` / `autopsy_behavior_log.txt` | First forensic pass (superseded; findings identical) |


---

## Rerun Preparation & Fire Authorization (2026-09-20, CPU only) — COMPLETE ✅

*Spec confirmation (verbatim): v2 rerun preparation — defect fixes + pre-flight validation, NO GPU training. Brain ruling ACTIVE: conditional rerun authorized as "identical protocol, defect-corrected." Gates (0.7391 / 0.6571), 35-run matrix, λ_rank=0.20, λ_mask=0.30, seeds {42,123,456,789,1024}, mean-across-seeds evaluation, terminality: ALL UNCHANGED. Commandment-15 pre-flight suite (P1–P6) on CPU; Brain fires Colab after a clean pre-flight report. Later: D10 logging + fire authorization (CPU, minutes, NO training).*

**Deliverables:**
- **Patched notebook** `phase5/vulngat_v2_training_rerun.ipynb` (generator `generate_v2_notebook_rerun.py`): [FIX A1] eligibility via verbatim port of the official `masked_edge_audit.py` path + hard N=645/8,682 assertions; [FIX A2] reverse message-passing directions (direction parity with `core/model/layers.py`, reverse edges derived at call time so masking removes reverse messages too); [FIX A3] Phase-4 normalization (bit-identical to `load_vulnchain_dataset()`, max|Δ|=0.0); [P5] per-epoch per-term loss trajectories in the intermediate JSON; [P6] run_id prefix `v2dc_` + `protocol_version` marker + legacy-record hard-fail. The quarantined `vulngat_v2_training.ipynb` and `generate_v2_notebook.py` are byte-untouched.
- **Pre-flight suite** `preflight_v2_rerun.py` (+ `preflight_results.json`, `preflight_log.txt`): executes the notebook's actual cells (pip magics stripped, 35-run matrix loop withheld) against the staged real dataset.
- **P3 debug** `debug_p3_trajectory.py` (+ JSON/log): 300-epoch frozen-config diagnostic (CPU, weights discarded).
- **Fire manifest** `v2dc_fire_manifest.json`: SHA-256 `aeaeae83c2c3afe91fdf5f1768ef0e6cfc329644099bf490f130c6e6a440372d`, MD5 `c4c04f8a974d96359ff43900d1d31f19`, 48,072 bytes.
- **Documentation:** `V2_AUTOPSY.md` Appendix B (authorization, amendment justifications incl. v1-sensitivity parity argument, edge-direction parity table, verbatim pre-flight, P3 diagnosis); rerun addendum + D10 + fire authorization appended to `VULNGAT_V2_PREREGISTRATION.md` (locked body untouched); ledger entries below.

**Pre-flight verdict (verbatim, full evidence in Appendix B.3):**
| Gate | Result | Evidence |
|---|---|---|
| P1 Init sanity | PASS | init pred std 0.007211 > 0; layer-1 preact std 0.2597 ∈ [0.1, 10] (v2 defect ≈ 476) |
| P2 Pathway liveness | PASS | 100% hasVuln removal: max\|Δpred\| = 3.109249e-02 > 0 (v2: exactly 0.000e+00); partial p∈{0.1,0.3,0.5,0.9} all > 0 |
| P3 Learnability smoke | FAIL→PASS under D10 | 50-epoch horizon: train ρ = −0.1602 (bar 0.30). D10-corrected budget-matched horizon: bar crossed at epoch 91; train ρ = +0.4043 at the pre-registered 100-epoch cap; weights discarded |
| P4 Eligibility | PASS | official module: 645 / 8,682; notebook values set-equal; assertions fired |
| P5 Loss logging | PASS | 50/50 epochs, all terms finite; L_aux live (max 8.64e-04, >0 in 50/50 epochs; v2: identically 0) |
| P6 Resume safety | PASS | 35/35 `v2dc_` ids disjoint from quarantined ids; skip-completed verified; legacy record hard-fails |
| F1 Normalization parity | PASS | bit-identical vs TrainModel loader: max\|Δ\| = 0.000e+00 (Package/Author/CVE-emb/CVE-CVSS position-aware) |

**P3 diagnosis (Appendix B.4):** ~70-epoch output-mean-fitting phase under the frozen lr=5e-4 (pred mean 0.46 → 0.03; MSE reaches the constant floor Var(y_train)=0.01026); ranking emerges after epoch ~70; train ρ > 0 at 72, > 0.30 at 91, +0.4043 at the 100-epoch cap. The 50-epoch smoke horizon under-sampled the frozen budget; the model itself is sound. Beyond-cap trajectory (best val ρ 0.6810 @ ep266) is interpretation context only, never gate-eligible (D10).

**Status:** PRE-FLIGHT PASSES under corrected P3. Colab fire AUTHORIZED by the Brain (D10). Protocol frozen. No further changes of any kind permitted.


---

## V2 RERUN EXECUTED — TERMINAL RESULT (2026-09-20) — COMPLETE ✅

*Pre-committed row executed: "Both < bars → Terminal negative — now validly measured." The Colab fire (T4 GPU, authorized by D10, artifact SHA-256 `aeaeae83…440372d`) completed the full pre-registered 35-run matrix under `protocol_version = v2.1-defect-corrected`. This is the project's FINAL training intervention outcome; terminality applies.*

### Artifact verification (before interpretation)
- `vulngat_v2_final_results.json`: `protocol_version='v2.1-defect-corrected'`; **35/35 runs present** (15 full_v2 + 5 no_masking + 15 no_ranking), **all run_ids `v2dc_`-prefixed**, every record carries the protocol marker; gate statistics **recomputed from per-seed values — exact match** with the stored summary. Archived as `phase5/v2dc_final_results.json`.
- `vulngat_v2_checkpoints (1).zip`: **35/35 checkpoints, all `v2dc_`-prefixed, zip integrity OK** (74.5 MB). Archived as `phase5/v2dc_checkpoints.zip`.
- **P5 closed in production:** every one of the 35 records carries a full per-epoch `{loss_mse, loss_rank, loss_aux, loss_total, val_spearman}` trajectory with `len(trajectory) == n_epochs_run`. The autopsy's unrecoverable-trajectory hole cannot recur.

### Pre-registered gates (mean across seeds {42,123,456,789,1024}; only full_v2 faces gates)

| Config | 50% Masked AUC (mean ± std) | Primary ≥ 0.7391 | Clean-Test r_s (mean ± std) | Secondary ≥ 0.6571 |
|---|---|---|---|---|
| full_v2 (p=0.1) | **0.4156 ± 0.0904** | FAIL | **0.1507 ± 0.1122** | FAIL |
| full_v2 (p=0.3) | **0.4031 ± 0.1009** | FAIL | **0.1503 ± 0.1118** | FAIL |
| full_v2 (p=0.5) | **0.3916 ± 0.1120** | FAIL | **0.1489 ± 0.1104** | FAIL |
| no_masking (p=0.0) | 0.4251 ± 0.0837 | (attribution) | 0.1634 ± 0.1253 | (attribution) |
| no_ranking (p=0.1/0.3/0.5) | 0.4125–0.4126 | (attribution) | 0.0808 ± 0.0649 | (attribution) |
| *Reference: full_v2 pooled (15 runs)* | *0.4034* | *FAIL* | *0.1500* | *FAIL* |

Both gates fail **under every reading** (best-p, pooled, or any single config) — by 0.32+ AUC and 0.50+ r_s. Reference points: label propagation 0.7191 (primary population), ridge-raw 0.6371 and VulnGAT-HR v1 0.5614 (secondary population). The executed test cut is N=1,433 (prereg documented 1,430 — the autopsy's A4 integer-floor drift, carried).

### Pre-committed thesis (verbatim, row "Both < bars")
> **"The pre-registered end-to-end protocol, correctly implemented, does not beat label propagation or ridge on this graph at this scale; frozen Phase-4 representations remain the best encoder."**

### Mechanics (from the P5 trajectories — reported as interpretation context, never gate-eligible per D10)
1. **Training depth moves the primary metric from chance DOWNWARD.** Runs whose patience-15 early stop fired during the ~70-epoch mean-fitting phase (16-epoch runs, near-init checkpoints) score AUC ≈ **0.524** (chance, as expected for untrained models). Runs that trained past mean-fitting (21- and 100-epoch runs) score AUC ≈ **0.34/0.33**. Learning actively ranks own-CVE-dominated packages **below** never-vulnerable ones under 50% masking — the below-chance AUC is a learned stratum inversion, not noise.
2. **Early-stopping/mean-fitting interaction (27/35 runs early-stopped):** for seeds whose val ρ dips negative during mean-fitting, the frozen patience-15-on-val-ρ rule selects a near-epoch-0 checkpoint (best val ρ = the least-bad dip point). 14 runs stopped at epoch 16, 13 at epoch 21, 8 ran the full 100. This heterogeneity is part of the correctly-executed frozen protocol and is reflected in the per-seed spread (e.g., full_v2 AUC: s123 0.542 ≈ chance vs s42 0.370).
3. **All 8 full-100-epoch runs were still improving at the cap** (val ρ slope UP in the last 10 epochs for every one) — the frozen 100-epoch budget is binding. Per D10 this is context only; the caps were not touched.
4. **The CPU diagnostic was faithful to the GPU run:** seed-42 val ρ at ep70/ep90/ep99 = +0.0015/+0.3000/+0.3718 (GPU) vs +0.0015/+0.3000/+0.3784 (pre-collected CPU debug, ep100) — the debug evidence that grounded D10 reproduced essentially exactly.
5. **Attribution honesty:** the pre-registered attribution rule governed a PASS (if no-masking also passes → attribute to ranking). With **no pass anywhere** there is nothing to attribute; the notebook's canned "masking confirmed necessary" line is **not** a finding. Empirically no_masking (0.425/0.163) is nominally the best arm but within ~1 std of full_v2 — masking neither helps nor rescues; the ranking loss adds ~+0.07 r_s over no_ranking, far from any bar.

### Terminality
**CONFIRMED.** The v2 cycle (quarantined) and this defect-corrected rerun together close the VulnGAT question: under the pre-registered protocol, correctly implemented and validly measured, the heterogeneous GNN does not beat label propagation on the masked population nor ridge on the clean-test population. **No v3. No further training interventions.** Frozen Phase-4 representations remain the project's best encoder. The thesis now rests on the Phase-4/Phase-5 evidence chain (frozen-embedding baselines, label propagation, EPSS-track analyses), not on end-to-end GNN training.

**Ledger:** see D11 below.
