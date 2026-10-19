# Pre-Registration Gate: Temporal Vulnerability Forecasting

**Branch:** `temporal-label`  
**Workspace:** `temporal/`  
**Status:** Pre-registered BEFORE any GNN training  
**Cutoff Date ($T$):** `2024-07-01`  
**Target Graph:** Pre-$T$ Frozen Graph (`temporal/pre_t_graph.json`, $N=16,673$ nodes, $E=75,167$ edges)  
**Primary Evaluation Population:** Pooled Validation + Test At-Risk Nodes ($N=1,829$, 47 positives, base rate = 2.570%)  

---

## 1. Protocol Design & Amendment Note

Following the initial feasibility audit ([temporal/AUDIT.md](file:///c:/Users/Admin/Desktop/Major%20VulnChain/temporal/AUDIT.md)), two critical structural facts were discovered:
1. **Severe Test Sparsity on Single Test Split:** Under the Provenance Rule, the single test split (`saleor-storefront`) yields only 25 positives at $T = \text{2024-07-01}$ (and collapses to only 9 positives at $T = \text{2025-07-01}$). A test set with fewer than 30 positives suffers from high estimator variance and insufficient ranking resolution.
2. **Amendment to Pooled Evaluation ($N=1,829$, 47 positives):** The protocol design is formally **amended** to evaluate on the **pooled held-out evaluation splits (`val` + `test`)**. Both splits are provenancely clean (zero repo overlap with train and zero cross-contamination). Pooling provides **47 positives across 32 unique package names and 95 unique post-$T$ advisories**, establishing adequate statistical power for paired grouped-bootstrap significance testing.

---

## 2. Feature Leakage Audit at Cutoff $T = \text{2024-07-01}$

To prevent temporal data leakage, all node features were forensically audited against the cutoff date. Information derived from post-$T$ vulnerability disclosures, live 2026 npm registry scrapes, or live 2026 GitHub API states must not enter the model.

### Package Features (10 Dimensions)

| Dimension | Feature Name | Time-Safe? | Audit Evidence & Action |
| :---: | :--- | :---: | :--- |
| **0** | `is_direct_dependency` | **YES** | Deterministic from frozen repository lockfiles (`package-lock.json`). **KEPT**. |
| **1** | `is_dev_dependency` | **YES** | Deterministic from frozen repository lockfiles / package manifests. **KEPT**. |
| **2** | `out_degree` | **YES** | Structural dependency count declared in lockfile for this version. **KEPT**. |
| **3** | `depth_in_tree` | **YES** | Tree depth measured directly in lockfile dependency graph. **KEPT**. |
| **4** | `version_recency_days` | **NO** | Extracted in mid-2026 as `days_since(release_date)`. Computed relative to 2026 rather than $T$; packages published near 2026 leak future publication recency. **ZEROED**. |
| **5** | `versions_behind_latest` | **NO** | Counted against the "latest" version on npm as of mid-2026. Directly leaks whether new versions were released between 2024 and 2026. **ZEROED**. |
| **6** | `has_known_cve_history` | **NO (in raw graph)** / **YES (rebuilt)** | Original graph backfilled this from all CVEs up to 2026 (including post-$T$ CVEs). **REBUILT** strictly from pre-$T$ ($d \le \text{2024-07-01}$) advisories. On the at-risk evaluation population, this feature is identically **0** for all nodes. |
| **7** | `weekly_downloads_log` | **NO** | Scraped live from npm API in August/September 2026. Directly reflects post-$T$ popularity. **ZEROED**. |
| **8** | `is_deprecated` | **NO** | Scraped live from npm registry in 2026; deprecations occurring between 2024 and 2026 leak future lifecycle status. **ZEROED**. |
| **9** | `license_risk_flag` | **NO** | Derived from live npm metadata during data pipeline execution. Non-provably time-safe. **ZEROED**. |

### Author Features (7 Dimensions)

| Dimension | Feature Name | Time-Safe? | Audit Evidence & Action |
| :---: | :--- | :---: | :--- |
| **0** | `account_age_days` | **NO** | Computed via `days_since(created_at)` relative to mid-2026 scrape date. **ZEROED**. |
| **1** | `total_packages_maintained` | **NO** | Live maintainer package count scraped from npm in mid-2026. **ZEROED**. |
| **2** | `packages_with_known_cves` | **NO** | Computed from `hasVulnerability_edges.json` which included post-$T$ CVEs. Direct label leakage. **ZEROED**. |
| **3** | `days_since_last_commit` | **NO** | Live latest commit date fetched from GitHub API in 2026. Directly leaks post-$T$ maintainer commit activity. **ZEROED**. |
| **4** | `is_organization` | **YES** | GitHub account type (User vs Organization). **KEPT**. |
| **5** | `has_2fa` | **YES** | Constant placeholder 0 (hard external limit). **KEPT**. |
| **6** | `reputation_score` | **NO** | Weighted formula incorporating `cve_penalty` (post-$T$ CVEs) and `activity_score` (2026 commit activity). **ZEROED**. |

### CVE Node Features (Base Graph)
- **Node Filtering:** Only CVEs published on or before `2024-07-01` are admitted to the graph (390 CVE nodes). All 493 post-$T$ CVE nodes are completely dropped from the graph structure.
- **Features (`cvss_score`, `embedding`):** SentenceBERT text embedding and CVSS base scores for pre-$T$ CVEs represent historical public knowledge as of $T$. **KEPT for pre-$T$ nodes**.

---

## 3. Pre-$T$ Graph Construction Summary (`temporal/pre_t_graph.json`)

The pre-$T$ graph was constructed by `temporal/build_pre_t_graph.py` and serialized to `temporal/pre_t_graph.json` (14.27 MB):

| Entity / Edge Type | Original 51-Repo Graph | Pre-$T$ Graph ($T \le \text{2024-07-01}$) | Delta | Rationale |
| :--- | :---: | :---: | :---: | :--- |
| **Package Nodes** | 12,405 | **12,405** | 0 | All package identities preserved; 5 non-time-safe dims zeroed |
| **CVE Nodes** | 883 | **390** | -493 | Post-$T$ advisories purged |
| **Author Nodes** | 3,878 | **3,878** | 0 | All author identities preserved; 5 non-time-safe dims zeroed |
| **Total Nodes** | **17,166** | **16,673** | **-493** | Leak-free node set |
| `dependsOn` | 60,789 | **60,789** | 0 | Unchanged lockfile topology |
| `hasVulnerability` | 2,632 | **994** | -1,638 | Post-$T$ vulnerability edges purged |
| `maintainedBy` | 12,390 | **12,390** | 0 | Unchanged Package $\to$ Author links |
| `introducedBy` | 2,632 | **994** | -1,638 | Post-$T$ CVE $\to$ Author links purged |
| **Total Edges** | **78,443** | **75,167** | **-3,276** | Leak-free edge set |
| Packages with dim 6 = 1 | 977 | **584** | -393 | Rebuilt strictly from pre-$T$ advisories |

---

## 4. Population & Label Definitions

### Target Population: At-Risk Packages
A package is in the **At-Risk population** if and only if it has **zero advisories published on or before $T = \text{2024-07-01}$** directly affecting its version. Packages that were already known to be vulnerable before $T$ are excluded from evaluation because predicting known history is not forecasting.

- **Total Graph Packages:** 12,405
- **Pre-$T$ Vulnerable (Excluded):** 584 nodes (531 train, 2 val, 51 test)
- **Total At-Risk Population:** **11,821 nodes** (95.29% of graph)

### Ground Truth Label: Direct Label A
For any at-risk package node $p$:
- **$y = 1$ (Positive):** $\ge 1$ advisory published strictly **after** `2024-07-01` directly affects package version $p$.
- **$y = 0$ (Negative):** Zero advisories published after `2024-07-01` affect package version $p$.

### Per-Split Breakdown

| Split | Total Nodes | Pre-$T$ Excluded | At-Risk Population | Label A Positives | Base Rate | Unique Advisories | Unique Package Names |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Train** | 10,523 | 531 | **9,992** | **346** | 3.463% | 322 | 112 |
| **Validation** | 541 | 2 | **539** | **22** | 4.082% | 65 | 22 |
| **Test** | 1,341 | 51 | **1,290** | **25** | 1.938% | 34 | 15 |
| **Pooled (Val+Test)** | **1,882** | **53** | **1,829** | **47** | **2.570%** | **95** | **32** |

---

## 5. Pre-Training Baseline Benchmark (Scored on Pooled Val+Test At-Risk, $N=1,829$)

All baselines were executed by `temporal/run_baselines.py`. Grouped bootstrap confidence intervals ($B = 2,000$ iterations) were clustered by package `name` (stripping version suffix; 1,370 clusters in pooled val+test) to account for version-correlation.

| Rank | Model / Heuristic | PR-AUC | PR-AUC 95% CI | ROC-AUC | ROC-AUC 95% CI | Notes |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| **1** | **Ridge on time-safe features** | **0.0514** | **[0.0286, 0.1210]** | 0.6425 | [0.5541, 0.7559] | Trained on train at-risk nodes with lockfile topology |
| **2** | **Label Propagation** | **0.0510** | **[0.0270, 0.0919]** | **0.6829** | **[0.5911, 0.7599]** | Graph diffusion of training labels on pre-$T$ `dependsOn` |
| 3 | Random Uniform | 0.0454 | [0.0154, 0.1057] | 0.4288 | [0.3547, 0.5059] | Stochastic baseline |
| 4 | Descendant Count | 0.0279 | [0.0170, 0.0484] | 0.5206 | [0.4071, 0.6454] | Transitive out-degree in dependency graph |
| 5 | Repos Using Package | 0.0257 | [0.0150, 0.0390] | 0.5000 | [0.5000, 0.5000] | Flat on eval splits due to Provenance Rule |
| 6 | Dependency Pre-$T$ History (Count) | 0.0250 | [0.0152, 0.0396] | 0.4803 | [0.4137, 0.5600] | Upstream dependency vulnerability count |
| 7 | Dependency Pre-$T$ History (Binary) | 0.0249 | [0.0146, 0.0383] | 0.4824 | [0.4146, 0.5640] | Binary indicator of upstream pre-$T$ vuln |
| — | **Base Rate (Prevalence)** | **0.0257** | — | **0.5000** | — | 47 / 1,829 positive instances |

### Baseline Insights
1. **Ridge and Label Propagation are the competitive champions:** Both achieve **PR-AUC ~0.051** (~2.0x base rate). Label propagation achieves the highest discriminative ability with **ROC-AUC = 0.6829**.
2. **Upstream Pre-$T$ Vulnerability has negative correlation:** Packages with pre-$T$ vulnerable dependencies do *not* have higher odds of experiencing direct CVEs on their own code post-$T$ (ROC-AUC ~0.48, slightly below random). Direct post-$T$ vulnerability is driven by library complexity and maintainer scope, not by whether its dependencies were compromised.
3. **Repository count is uninformative for evaluation:** Under the Provenance Rule, held-out evaluation packages belong almost exclusively to a single repo (ROC-AUC = 0.5000).

---

## 6. Pre-Registered Pass Rule for GNN

Before any GNN model training, fine-tuning, or inference is initiated, the success criterion is **LOCKED**:

> ### The Pass Rule:
> A GNN model on the temporal forecasting task will be declared a **PASS** if and only if **BOTH** of the following conditions are met on the pooled validation + test at-risk population ($N = 1,829$):
> 
> 1. **Absolute Superiority:**
>    $$\text{PR-AUC}_{\text{GNN}} > 0.0514$$
>    *(GNN point estimate strictly exceeds the best baseline, Ridge on time-safe features).*
>
> 2. **Statistical Significance via Grouped Bootstrap:**
>    The paired grouped-bootstrap 95% confidence interval of the difference:
>    $$\Delta \text{PR-AUC} = \text{PR-AUC}_{\text{GNN}} - \text{PR-AUC}_{\text{best}}$$
>    clustered by package `name` ($B = 2,000$ iterations), **strictly excludes zero**:
>    $$\text{CI}_{0.025}(\Delta \text{PR-AUC}) > 0.0$$
>
> If $\text{PR-AUC}_{\text{GNN}} \le 0.0514$ or if the lower bound of the paired 95% confidence interval is $\le 0.0$, the hypothesis that the GNN learns temporal propagation beyond linear lockfile heuristics and label diffusion is declared **FAILED**. No retrofitting or post-hoc threshold adjustment is permitted.
