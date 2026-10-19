# V2.2 SANITY DIAGNOSTIC & PROJECT CLOSE-OUT RECORD
**Status:** COMPLETE — Sanity Passed; Matrix Trigger Failed; Final Training Closure Enacted  
**Date:** 2026-09-20  
**Scope:** Sanity diagnostic of the population-fixed VulnGAT v2.2 on CPU (Seed 42, `full_v2`, $p=0.3$, 100 epochs frozen + 300 epochs exploratory), evaluation against pre-committed decision rules, and final close-out package for the thesis and faculty review.  
**Standing Rules:** Fixed seed. No threshold or gate changes. No code changes beyond the two authorized ones. Report every failure verbatim. Do not claim any pass/fail beyond what the numbers show. All original v2 and v2.1 artifacts remain untouched.

---

## 0. Pre-Committed Decision Rules & Protocol Amendments

### 0.1 Pre-Committed Decision Rules (Frozen Before Running)
1. **Sanity Pass Criterion:**
   $$\text{sanity pass} := \text{clean AUC (dim-6-zeroed)} \ge \max(0.60, \text{HR\_clean\_zeroed} - 0.05)$$
   Given the empirical baseline for VulnGAT-HR with dim-6-zeroed globally of **0.7879** (and 0.7716 eligible-only):
   $$\text{Sanity Bar Target} = \max(0.60, 0.7879 - 0.05) = \mathbf{0.7379}$$
2. **Matrix Trigger Criterion:**
   $$\text{matrix trigger} := \text{sanity pass} \land \text{masked-50} \ge 0.65$$
   - The matrix trigger requires both clean-graph sanity ($\ge 0.7379$) and masked-edge AUC $\ge 0.65$. All masked variants (Notebook fully live, Official masked-zeroed, Globally zeroed) are reported side-by-side.
3. **Exploratory 300-Epoch Trigger Rule:**
   - A 300-epoch exploratory run alongside a 100-epoch fail constitutes empirical evidence that the **100-step full-batch optimization budget was the binding constraint**.
   - It is reported strictly as a **single-seed exploratory finding and deviation decision for the human researcher**, NEVER as a gate pass, and NEVER as a matrix trigger.
4. **Default Action:** If the 100-epoch run fails the sanity pass or matrix trigger, recommend **formal project training close-out**.

---

## 1. Step 1: Forensic Verifications of the 35-Run v2.1 Execution

### 1.1 Fact (a): Construction of `train_mask` (Confirmed Nonzero-Only)
In `phase5/generate_v2_notebook_rerun.py` and `vulngat_v2_training_rerun.ipynb` (Cell 3 verbatim):
```python
nz_pkgs = [pid for pid in pkg_id_to_idx if epss_labels[pid]['epss_risk'] > 0]
train_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, '2000-01-01') < TEMPORAL_CUTOFF]
test_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, '2000-01-01') >= TEMPORAL_CUTOFF]

random.seed(42)
shuffled_train = list(train_pkgs)
random.shuffle(shuffled_train)
val_cut = int(0.20 * len(shuffled_train))
val_pkgs = shuffled_train[:val_cut]
train_fit_pkgs = shuffled_train[val_cut:]

train_mask = torch.zeros(num_packages, dtype=torch.bool)
val_mask = torch.zeros(num_packages, dtype=torch.bool)
test_mask = torch.zeros(num_packages, dtype=torch.bool)

for pid in train_fit_pkgs:
    train_mask[pkg_id_to_idx[pid]] = True
for pid in val_pkgs:
    val_mask[pkg_id_to_idx[pid]] = True
for pid in test_pkgs:
    test_mask[pkg_id_to_idx[pid]] = True
```
- **Finding:** `train_mask` was constructed exclusively from `nz_pkgs` ($N=1{,}807$).
- **Defect A4 Confirmed:** All zero-label packages ($N=8{,}714$), including the 8,682 never-vulnerable packages that form the negative stratum of the primary gate, were **completely excluded from the training loss**.
- **Consequence:** The model was never penalized for predicting high risk on safe packages. When evaluated on the clean graph, trained models assigned *higher* risk to never-vulnerable packages (mean 0.1070) than to eligible vulnerable packages (mean 0.0600), resulting in an inverted clean AUC of **0.2078–0.2222**.

### 1.2 Fact (b): 35-Run Early Stopping Breakdown
Full inspection of `phase5/v2dc_final_results.json` (`raw_runs` across all 35 executions):

| Arm | Seed 42 | Seed 123 | Seed 456 | Seed 789 | Seed 1024 |
|---|---|---|---|---|---|
| **full_v2 (p=0.1)** | 100 ep (Full, best ep 99) | 16 ep (ES, best ep 0) | 16 ep (ES, best ep 0) | 100 ep (Full, best ep 99) | 21 ep (ES, best ep 5) |
| **full_v2 (p=0.3)** | 100 ep (Full, best ep 99) | 16 ep (ES, best ep 0) | 16 ep (ES, best ep 0) | 100 ep (Full, best ep 99) | 21 ep (ES, best ep 5) |
| **full_v2 (p=0.5)** | 100 ep (Full, best ep 99) | 16 ep (ES, best ep 0) | 16 ep (ES, best ep 0) | 100 ep (Full, best ep 99) | 21 ep (ES, best ep 5) |
| **no_masking (p=0.0)** | 100 ep (Full, best ep 99) | 16 ep (ES, best ep 0) | 16 ep (ES, best ep 0) | 100 ep (Full, best ep 99) | 21 ep (ES, best ep 5) |
| **no_ranking (p=0.1)** | 21 ep (ES, best ep 5) | 16 ep (ES, best ep 0) | 16 ep (ES, best ep 0) | 21 ep (ES, best ep 5) | 21 ep (ES, best ep 5) |
| **no_ranking (p=0.3)** | 21 ep (ES, best ep 5) | 16 ep (ES, best ep 0) | 16 ep (ES, best ep 0) | 21 ep (ES, best ep 5) | 21 ep (ES, best ep 5) |
| **no_ranking (p=0.5)** | 21 ep (ES, best ep 5) | 16 ep (ES, best ep 0) | 16 ep (ES, best ep 0) | 21 ep (ES, best ep 5) | 21 ep (ES, best ep 5) |

- **Early Stopping Mechanism (A5):** The harness initialized `best_val_sp = -1.0` with `patience = 15`. In seeds 123 and 456, epoch 0 had a slightly negative Spearman (-0.0101 and -0.0595) which became `best_val_sp`. During subsequent epochs, as the model entered mean-fitting, val Spearman drifted further negative, failing to beat epoch 0 within 15 epochs. Early stopping triggered at epoch 16, and the harness restored `best_state` — **saving the near-epoch-0 checkpoint**.
- **Seed 1024:** Recorded peak val Spearman at epoch 5 (-0.0662), and early stopping triggered at epoch 21, **saving epoch 5**.
- **Trained Seeds (42 & 789):** Did not early stop in `full_v2` and `no_masking`. At the 100-epoch cutoff, val Spearman was **actively climbing** (seed 42: -0.11 at ep 50, +0.17 at ep 80, +0.37 at ep 99). Full-batch training meant only 1 optimizer step per epoch, so the model only experienced 100 gradient steps total.

### 1.3 Fact (c): Package Feature Dim 6 in Masked Eval (Confirmed Not Zeroed)
In `vulngat_v2_training_rerun.ipynb` Cell 5 (`evaluate_masked_auc_50`):
```python
masked_edge_index = copy.copy(data.edge_index_dict)
masked_edge_index[('Package', 'hasVulnerability', 'CVE')] = edges[:, keep_mask].to(device)

model.eval()
with torch.no_grad():
    scores, _ = model(data.x_dict, masked_edge_index)
```
- **Confirmed:** `data.x_dict` was passed unmodified. Feature dim 6 was **never zeroed** during training or masked evaluation in the v2 or v2.1 notebooks.
- **The Apples-to-Oranges Discrepancy in v2.1:** The v2.1 notebook's masked evaluation was fully dim-6-live, whereas the pre-registered 0.7391 bar was calibrated on the official zeroed path (`TrainModel/masked_edge_audit.py`). This represents an additional apples-to-oranges defect that rendered the v2.1 primary gate uninterpretable.

### 1.4 Fact (d): Feature Order and Identity of Dim 6
In `merge_graph.py` lines 60–71 and 218–235:
```python
PACKAGE_FEATURE_ORDER = [
    "is_direct_dependency",      # 0
    "is_dev_dependency",         # 1
    "out_degree",                # 2
    "depth_in_tree",             # 3
    "version_recency_days",      # 4
    "versions_behind_latest",    # 5
    "has_known_cve_history",     # 6 <-- LABEL SHORTCUT
    "weekly_downloads_log",      # 7
    "is_deprecated",             # 8
    "license_risk_flag",         # 9
]
```
Step 4 of `merge_graph.py` explicitly populates dim 6:
```python
vuln_pkg_ids = set(e["source"] for e in hv_edges)
for node_id, node in pkg_nodes.items():
    if node_id in vuln_pkg_ids:
        node["features"][6] = 1
```
- **Finding:** Package dim 6 is **literally an indicator of whether a package has at least one vulnerability edge in the graph**. Leaving dim 6 live during masked evaluation allows the model to read vulnerability history directly from node features rather than inferring it from topological propagation.

---

## 2. Step 2: Reference Baseline Measurements (VulnGAT-HR)

Evaluated on `phase5/models/vulngat_hr_full.pt` using the official $N=645$ eligible vs $N=8{,}682$ never-vulnerable strata:

| Metric / Configuration | Dim 6 Treatment | Seed 42 | 5-Seed Mean $\pm$ Std |
|---|---|---|---|
| **Clean Graph AUC** | Live (as trained) | 0.9292 | 0.9292 (deterministic) |
| **Clean Graph AUC** | Zeroed Globally | 0.7879 | 0.7879 (deterministic) |
| **Clean Graph AUC** | Zeroed Eligible-Only | 0.7716 | 0.7716 (deterministic) |
| **Masked-50% AUC** | Fully Live (Notebook style) | 0.8774 | 0.8804 $\pm$ 0.0029 |
| **Masked-50% AUC** | Official (Zeroed for Masked pkgs per C2) | 0.6254 | 0.6315 $\pm$ 0.0045 |
| **Masked-50% AUC** | Zeroed Globally | 0.6334 | 0.6410 $\pm$ 0.0056 |

- **Clean Graph Score Dispersion (HR):**
  - Dim 6 Live: Eligible mean `0.2106` $\pm$ `0.1240` vs Never-vuln mean `0.0571` $\pm$ `0.0712`.
  - Dim 6 Zeroed Globally: Eligible mean `0.1254` $\pm$ `0.1036` vs Never-vuln mean `0.0593` $\pm$ `0.0723`.
- **Sanity Bar Calculation:**
  $$\text{Sanity Bar} = \max(0.60, 0.7879 - 0.05) = \mathbf{0.7379}$$

---

## 3. Reconciliation of Non-Zero Test Population ($N=1{,}430$ vs $1{,}433$)

- **Pre-registration derivation (`check_temporal_split.py`):**
  In line 72 of `check_temporal_split.py`, the BFS traversal from packages to CVEs checks:
  `if cve_epss.get(c, 0.0) > 0:`
  Filtering contributing CVEs to those with positive EPSS published dates yields:
  $$\text{Train (pre-2026-08-01)} = 2{,}261 \quad (\text{Val } = 452, \text{ Train\_fit } = 1{,}809), \quad \text{Test} = 1{,}430$$
- **Executed notebook (`vulngat_v2_training_rerun.ipynb`, Cell 3):**
  The BFS collected published dates of *all* direct and transitive CVEs in OSV cache without checking `cve_epss > 0`. Exactly 3 packages had newest CVE published dates shifted across the 2026-08-01 cutoff date when non-EPSS CVEs were included:
  $$\text{Train (pre-2026-08-01)} = 2{,}258 \quad (\text{Val } = 451, \text{ Train\_fit } = 1{,}807), \quad \text{Test} = 1{,}433$$
- **Reconciliation:** Total nonzero packages is identical ($2{,}261 + 1{,}430 = 3{,}691 = 2{,}258 + 1{,}433$). The 3-package shift is documented as a minor BFS date-filtering discrepancy that does not affect statistical power or outcome interpretation.
- **Ridge 0.637 Baseline Provenance:**
  - Value: $r_s = 0.6371$
  - Metric: Spearman Rho
  - Population: Temporal nonzero test cut ($N=1{,}430$ prereg / $N=1{,}433$ executed)
  - Labels: EPSS closure labels (`phase5/epss_labels_51repo.json`, field: `epss_risk`)
  - Dim-6 State: Live (trained on 10 features with dim 6 live)
  - Source / Script: `phase5/VULNGAT_V2_PREREGISTRATION.md` / `phase5/phase3_epss_arms.json` (arm c), produced by `phase5/part_c_masked_edge_multiseed.py`.
- **VulnGAT-HR Label Distribution Comparison:**
  - VulnGAT-HR was **TRAINED on Phase 4 VPSS labels** (`phase4/vpss_labels_51repo.json`, repo-split training mask).
  - Its temporal-cut Spearman score ($0.4678$ live / $0.4493$ zeroed, $N=1{,}433$) was **SCORED against EPSS closure labels** (`epss_risk`).
  - Because the training target (CVSS-based VPSS) and the test target (EPSS probability closure) represent different label distributions: **Not comparable to v2 secondary gate**. (On its native in-distribution Phase 4 VPSS target, HR achieves Spearman $0.6285$ zeroed / $0.7210$ live).

---

## 4. Headline Metrics & Dim 6 Confound Audit (Phase 4 Population: $N=1{,}341$)

Evaluated on `phase5/models/vulngat_hr_full.pt`, `phase5/mlp_reconverged.pt`, and Ridge-raw on Phase 4's repo-split test set ($N=1{,}341$ all, $N=538$ nonzero):

| Model | Dim 6 Condition | RankAcc (All $N=1{,}341$) | RankAcc (NZ $N=538$) | Spearman (All $N=1{,}341$) | Spearman (NZ $N=538$) | Margin vs Ridge | Margin vs MLP |
|---|---|---|---|---|---|---|---|
| **VulnGAT-HR** | **LIVE** | **85.55%** | 69.98% | **0.7210** | 0.5487 | +8.42 pp | +8.10 pp |
| **VulnGAT-HR** | **ZEROED (at inf)** | **80.59%** | 69.45% | **0.6285** | 0.4914 | +6.78 pp | +6.20 pp |
| **Ridge-Raw** | LIVE | 77.13% | 67.87% | 0.5520 | 0.5165 | — | — |
| **Ridge-Raw** | ZEROED (at inf) | 73.81% | 67.39% | 0.4888 | 0.5443 | — | — |
| **Ridge-Raw** | **REFIT (9-d, no dim 6)**| 73.34% | 67.84% | 0.4778 | 0.5405 | — | — |
| **MLP Reconverged** | LIVE | 77.45% | 67.80% | 0.5550 | 0.5198 | — | — |
| **MLP Reconverged** | ZEROED (at inf) | 74.39% | 67.58% | 0.4984 | 0.5279 | — | — |
| **MLP Reconverged** | **REFIT (9-d, no dim 6)**| 68.23% | 67.62% | 0.3624 | 0.5697 | — | — |
| *Exploratory Refit Head* | **HR Head Refit on Z_zeroed** | **83.98%** | 70.12% | **0.6902** | 0.5207 | +10.64 pp vs Ridge | +15.75 pp vs MLP |

- **Headline Comparison & Nonzero Strata Breakdown:**
  - **All Packages ($N=1{,}341$):** VulnGAT-HR achieves **80.59%** RankAcc (zeroed) and **85.55%** (live) vs Ridge **73.34%–73.81%** (zeroed/refit) and **77.13%** (live) vs MLP **74.39%** (zeroed at inf) and **77.45%** (live). All-package Spearman is **0.6285** (zeroed) / **0.7210** (live) for HR vs **0.4888 / 0.5520** for Ridge.
  - **Nonzero Cut ($N=538$):** RankAcc is **69.5–70.0%** (HR: 69.45% zeroed / 69.98% live) vs **67.4–67.9%** (Ridge: 67.39% zeroed / 67.84% refit / 67.87% live) vs **67.6–67.8%** (MLP: 67.58% zeroed / 67.62% refit / 67.80% live). Spearman is **0.49 zeroed / 0.55 live** (HR: 0.4914 zeroed / 0.5487 live) vs **0.54 / 0.52** (Ridge: 0.5443 zeroed / 0.5165 live).
  - **Interpretation:** The all-package ranking margin (+6.8 to +8.4 pp vs Ridge; +6.2 to +8.1 pp vs MLP) comes **mostly from vulnerable-vs-clean separation**. Within vulnerable packages alone ($N=538$), VulnGAT-HR is **roughly on par with Ridge** (RankAcc 69.5% vs 67.8%; Spearman 0.49 vs 0.54 zeroed).
  - **Capping MLP Margin:** The MLP margin is capped at **+6.2 pp** (the refit MLP on 9 dimensions is under-converged at 68.23%, lower than the 74.39% achieved by the 10-d MLP evaluated with dim 6 zeroed at inference).

- **How Dim 6 is populated at inference (`phase5/bench_run/analyze_project.py:239-245`):**
  ```python
  if pkg_id in kb_pkg_features:
      feat = list(kb_pkg_features[pkg_id])
  else:
      out_degree = sum(1 for e in edges_depends if e["source"] == pkg_id)
      has_vuln = 1 if pkg_id in all_has_vuln else 0
      feat = [info["is_direct"], info["is_dev"], out_degree, depth, 500, 0, has_vuln, 0.0, 0, 0]
  ```
  Where `kb_pkg_features` comes from `vulnchain_graph.json`, and `all_has_vuln` comes from KB `hasVulnerability` edges + live OSV lookups. Dim 6 is directly 1 for vulnerable packages and 0 for non-vulnerable packages.

- **Re-Score at Threshold $\ge 0.40$:**
  - **Dim 6 LIVE (capped, reported in Phase 5):** Flagged = 41 | **31 TP / 10 FP / 46 FN / 584 TN** | **Precision = 75.6%** | **Recall = 40.3%**
  - **Dim 6 LIVE (raw, uncapped):** Flagged = 92 | 31 TP / 61 FP / 46 FN / 533 TN | Precision = 33.7% | Recall = 40.3%
  - **Dim 6 ZEROED (capped):** Flagged = 28 | **20 TP / 8 FP / 57 FN / 586 TN** | **Precision = 71.4%** | **Recall = 26.0%**
  - **Dim 6 ZEROED (raw, uncapped):** Flagged = 81 | 20 TP / 61 FP / 57 FN / 533 TN | Precision = 24.7% | Recall = 26.0%

---

## 6. VulnGAT v2.2 Empirical Results

Both runs executed on CPU via [run_v22_sanity.py](file:///c:/Users/Admin/Desktop/Major%20VulnChain/phase5/run_v22_sanity.py) using Seed 42, `full_v2`, $p=0.3$:
- **Authorized Change 1:** Train mask includes all $N=8{,}714$ zero-label packages ($N_{\text{train}} = 10{,}521$). Validation ($N=451$) and test ($N=1{,}433$) cuts strictly preserve the nonzero temporal evaluation.
- **Authorized Change 2:** No early stopping; full scheduled epochs; evaluation on the final checkpoint.

### 6.1 Side-by-Side Results Table

| Metric | VulnGAT-HR (Phase 4 Checkpoint) | v2.1 Rerun (Quarantined) | VulnGAT v2.2 (100 Epochs) | Exploratory Arm (300 Epochs, Single-Seed) | Threshold / Target Bar |
|---|---|---|---|---|---|
| **Clean AUC (dim 6 LIVE)** | 0.9292 | 0.2078 (Inverted) | **0.9927** | 0.7822 | — |
| **Clean AUC (dim 6 ZEROED global)** | **0.7879** | ~0.21 | **0.9936** | **0.8069** | **$\ge 0.7379$ (Sanity Bar)** |
| **Clean AUC (dim 6 ZEROED elig)** | 0.7716 | ~0.21 | 0.9935 | 0.8044 | — |
| **Eligible Mean (Clean live)** | 0.2106 $\pm$ 0.1240 | 0.0600 | 0.1683 $\pm$ 0.1373 | 0.0970 $\pm$ 0.2100 | — |
| **Never-Vuln Mean (Clean live)** | 0.0571 $\pm$ 0.0712 | 0.1070 | 0.0031 $\pm$ 0.0153 | 0.0016 $\pm$ 0.0143 | — |
| **Eligible Mean (Clean zeroed)** | 0.1254 $\pm$ 0.1036 | — | 0.1747 $\pm$ 0.1375 | 0.0957 $\pm$ 0.1996 | — |
| **Never-Vuln Mean (Clean zeroed)**| 0.0593 $\pm$ 0.0723 | — | 0.0032 $\pm$ 0.0153 | 0.0019 $\pm$ 0.0157 | — |
| **Masked-50 AUC (Fully Live, Notebook eval path)** | 0.8774 (s42) / 0.8804 $\pm$ 0.0029 (mean) | 0.4031 $\pm$ 0.1009 (arm mean; 0.3376 s42) | **0.3503** | **0.3167** | **$\ge 0.7391$ (Primary Gate)** |
| **Masked-50 AUC (Official path: masked zeroed per C2 / HR calib)** | 0.6254 (s42) / 0.6315 $\pm$ 0.0045 (mean) | 0.4286 $\pm$ 0.0483 (arm mean; 0.3342 s42) | **0.3791** | **0.3416** | **$\ge 0.7391$ (Primary Gate)** |
| **Masked-50 AUC (Globally Zeroed)** | 0.6334 (s42) / 0.6410 $\pm$ 0.0056 (mean) | — | 0.4034 | 0.3456 | — |
| **Val Spearman (Nonzero cut, N=451)** | 0.4614 (zeroed) / 0.4782 (live) | 0.3701 (ep 99) | 0.0907 | 0.7224 | — |
| **Test Spearman (Nonzero cut, N=1,433)** | **0.4493** (zeroed) / **0.4678** (live) | 0.1503 $\pm$ 0.1118 (arm mean; 0.2794 s42) | 0.1221 | **0.6702** (single-seed exploratory) | **$\ge 0.6571$ (Secondary Gate)** |
| **Test Spearman (Phase 4 cut, N=1,341 all / 538 nz)**| **0.6285** / 0.4914 (zeroed); **0.7210** / 0.5487 (live) | — | — | — | — |
| **Optimization Budget** | 200 epochs (head refit) | 100 full-batch steps | 100 full-batch steps | 300 full-batch steps | — |
| **Wall Clock Time (CPU)** | — | — | 348.9s (5.8 min) | 994.9s (16.6 min) | — |

*Note on Clean AUC:* The clean AUC of ~0.99 is measured mostly on training-population packages (since zero-label packages were incorporated into `train_mask`). It confirms that the baseline instrument defect (A4) is cured and the model is no longer inverted, but should not be interpreted as out-of-distribution generalization.
*Note on Traced 0.642:* The earlier reported value of 0.642 was a mislabeled entry from HR's masked-50 AUC (0.6423). Recomputation on the temporal nonzero test cut ($N=1{,}433$) yields Spearman = 0.4493 (zeroed) and 0.4678 (live).

---

## 7. Evaluation Against Pre-Committed Decision Rules

### 7.1 Sanity Pass Evaluation (100 Epochs)
$$\text{Sanity Metric} = \text{Clean AUC (dim-6-zeroed)} = \mathbf{0.9936}$$
$$\text{Sanity Bar Target} = \max(0.60, 0.7879 - 0.05) = \mathbf{0.7379}$$
$$\mathbf{0.9936 \ge 0.7379 \implies \text{SANITY PASS: PASS}}$$
- **Diagnosis:** Introducing zero-label packages into `train_mask` completely eliminated the baseline inversion (A4). Safe packages are predicted near zero (`0.0031`), while vulnerable packages average `0.1683`. The clean-graph discriminative instrument is completely rehabilitated.

### 7.2 Matrix Trigger Evaluation (100 Epochs)
$$\text{Trigger Criterion} := \text{Sanity Pass} \land (\text{Masked-50 AUC} \ge 0.65)$$
$$\text{Masked-50 AUC (Official Path)} = \mathbf{0.3791 < 0.65 \implies \text{MATRIX TRIGGER: FAIL}}$$
$$\text{Masked-50 AUC (Fully Live)} = \mathbf{0.3503 < 0.65 \implies \text{MATRIX TRIGGER: FAIL}}$$
- A single-seed diagnostic under the corrected population scored **0.35 to 0.40 vs the 0.7391 bar; the full 35-run matrix was not run per the pre-committed trigger**.
- **Pre-Committed Action:** Sanity passed, but primary masked gate fails decisively across all variants. **No further matrix execution on Colab. Project training close-out enacted.**

### 7.3 Exploratory 300-Epoch Analysis (Single-Seed Budget vs Edge-Masking Breakdown)
1. **Secondary Gate (Spearman) Confirmation (Single-Seed Exploratory):**
   - In 100 epochs, Spearman on the test cut reached only `0.1221` because full-batch training provided only 100 optimizer steps.
   - In 300 epochs, Val Spearman reached `0.7224`, and Test Spearman reached **`0.6702` (single-seed, exploratory; the gates are defined on the 5-seed mean)**, crossing the `0.6571` numerical threshold and beating the Ridge baseline (`0.637`).
   - Because VPSS and EPSS-closure labels are graph-deterministic, this high rank correlation represents successful closed-form formula recovery on the clean graph, confirming that the 100-step budget was indeed the binding constraint on regression fitting.
2. **The Masked-Edge Inversion Finding:**
   - Under 50% edge removal, masked-edge AUC did not improve (0.3503 to 0.3167 on live path; 0.3791 to 0.3416 on zeroed path — a 0.034 difference vs v2.1 seed std ~0.09, so within noise).
   - Under edge removal, the trained GNN consistently ranks masked vulnerable packages below never-vulnerable packages.
   - **Conclusion:** Models trained with this recipe do not survive edge masking; the objective never asked them to (the auxiliary consistency loss pulled masked outputs toward the model's own clean predictions rather than toward $y_{\text{true}}$). Simple label propagation ($0.719$) beats VulnGAT-HR (0.632) and all v2 checkpoints (0.31-0.43).

---

## 8. Ledger Entries, Decisions & Retractions

- **D12 (Finding A4 — Zero-Label Loss Exclusion Confirmed & Resolved):** v2.1 excluded all zero-label packages from `train_mask`, creating an inverted baseline (clean AUC 0.2078). In v2.2, incorporating zero-label packages resolved the inversion (clean AUC 0.9936). The v2.1 primary gate quarantine is upheld as a confounded instrument.
- **D13 (Finding A5 — 100-Step Budget & Early-Stopping Horizon):** Confirmed that full-batch training with patience 15 caused seeds 123/456 to save epoch 0 and seed 1024 to save epoch 5. The single-seed exploratory 300-epoch run confirmed that the 100-step budget was the binding constraint for continuous ranking (Test Spearman rose from 0.1221 at ep 100 to 0.6702 at ep 300).
- **Brain Error #6 (Spec Defect — Population Exclusion):** Acknowledged the omission of zero-label negative packages from `train_mask` in the pre-registered v2 training specification.
- **Brain Error #7 (Spec Defect — Step Budget & Convergence Conflation):** Acknowledged the conflation of 100 full-batch epochs with sufficient convergence iterations, resulting in early stopping cutoffs during the initial plateau.
- **Protocol Deviations Logged:**
  - V2.2 population fix (adding zero-label packages to `train_mask`).
  - Removal of early stopping (full 100 epochs evaluated on the final checkpoint).
  - Exploratory 300-epoch run logged strictly as single-seed non-gate-bearing research evidence.
