# 🔗 VulnChain — Comprehensive Project Context, Architectural Record & Decision Ledger

> **Document Version:** 2.0 (Post-51-Repo Extraction & Split-Provenance Audit)  
> **Repository:** `Major VulnChain`  
> **Status:** Phase 4 (51-Repo Scale-Up) — Step 1 Complete · Node-Count Anomaly Resolved · Split Leakage Corrected  
> **Primary Purpose:** Authoritative single-source-of-truth documenting every architectural decision, mathematical formulation, pipeline evolution, failure diagnosis, empirical audit, and operational roadmap from project inception to the current state.

---

## 🧭 Executive Summary & Project Navigation

**VulnChain** is a heterogeneous graph neural network framework designed to model, detect, and quantify **transitive software supply chain vulnerability propagation** in open-source dependency ecosystems. Developed as a final-year engineering major project (7th Sem ISE) and flagship portfolio piece, the system moves beyond legacy, flat, regex-based vulnerability scanning (e.g., `npm audit`, Snyk, Dependabot) by learning structural vulnerability cascading patterns across multi-relational graphs of software packages, security advisories, and maintainer identities.

```
                                 ┌──────────────────────────────┐
                                 │     VulnChain HeteroGraph     │
                                 └──────────────┬───────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 │                              │                              │
                 ▼                              ▼                              ▼
        ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
        │   Package Node   │           │     CVE Node     │           │   Author Node    │
        │     (10-dim)     │           │    (768-dim)     │           │     (7-dim)      │
        └────────┬─────────┘           └────────┬─────────┘           └────────┬─────────┘
                 │                              │                              │
                 │◄─────── dependsOn ───────────┤                              │
                 │                              │                              │
                 ├────── hasVulnerability ─────►│                              │
                 │                              │                              │
                 ├──────────────────────── maintainedBy ──────────────────────►│
                 │                                                             │
                 │                      introducedBy ─────────────────────────►│
                 │               (Advisory attribution to author)              │
                 │                                                             │
                 ▼                                                             ▼
        ┌────────────────────────────────────────────────────────────────────────────────┐
        │                  VulnGAT: 3-Layer Hierarchical Attention Network               │
        │               (Edge-Specific Projections → 128-dim Shared Space)               │
        └───────────────────────────────────────┬────────────────────────────────────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │    Classifier Head    │
                                    │ Linear(128,1) → Sigmoid│
                                    │ (Package Risk Score)  │
                                    └───────────────────────┘
```

---

## 1. Project Vision, Academic Grounding & Problem Statement

### 1.1 The Real-World Problem: The Transitive Supply Chain Blindspot
Modern software engineering relies overwhelmingly on open-source packages. A developer executing `npm install express` does not simply import one framework; they pull in a transitive dependency tree containing hundreds of libraries authored by hundreds of unrelated developers. 

Existing tools (`npm audit`, GitHub Dependabot, Snyk) suffer from four fundamental structural deficiencies:
1. **Binary Alerts without Topology Context:** They flag that a leaf package at depth 5 has a CVE, but cannot dynamically compute how that risk propagates up to the application root.
2. **Alert Fatigue & False Alarms:** Up to 80% of reported vulnerabilities reside in dormant, unreachable code paths or development-only utilities, leading engineers to disable or ignore alerts.
3. **Unrated / Zero-Day Blindspots:** When a novel security advisory is published without an official CVSS vector, flat rule-based engines assign it zero risk ($y = 0$).
4. **Neglect of Developer Signals:** Software supply chain security is a human problem. Abandoned libraries, lone maintainers without multi-factor authentication, or packages authored by untrusted accounts represent heightened risk vectors that traditional lockfile scanners completely ignore.

### 1.2 Academic Grounding & Literature Survey
VulnChain addresses this challenge using **Relational Deep Learning**. The approach is rooted in peer-reviewed research across graph representation learning and software security:
* **HAN (Hierarchical Attention Networks) & HGCL (Heterogeneous Graph Contrastive Learning):** Providing the mathematical foundation for cross-relation attention and self-supervised views.
* **DySec & OSCAR:** Demonstrating dynamic software dependency graph modeling for security analysis.
* **VPSS (Vulnerability Propagation Scoring System):** Serving as the baseline theoretical formulation for transitive risk decay ($CVSS \times 0.7^{\text{depth}} \times \text{exposure}$).
* **CFExplainer & GNNExplainer:** Grounding the explainability module to extract minimal subgraph justifications for flagged packages.
* **Independent Literature Validation:** Published work at IEEE conferences, peer-reviewed cybersecurity journals, and an MIT thesis (2025) confirm that modeling software dependency trees as heterogeneous graphs with GNNs achieves $>94\%$ accuracy in vulnerability trend prediction.

### 1.3 Project Scope & Pragmatic Engineering Decisions
* **Initial Proposal (Overambitious):** Multi-ecosystem scanning across npm, PyPI, and Maven; real-time dynamic sandbox execution; full call-graph static reachability analysis; live D3.js frontend and Celery task queues.
* **Locked Engineering MVP:** To ensure end-to-end mathematical rigor and code completeness within academic time constraints, the scope was deliberately focused:
  - **Ecosystem:** 100% npm (Node.js). npm represents the largest, deepest, and most transitive dependency ecosystem in open-source.
  - **Reachability Simplification:** Set to a constant $1.0$ at the package level. While function-level call-graph reachability is ideal, it requires complex language-specific AST execution. A lockfile records hard installation requirements, making package-level inclusion a sound structural proxy.
  - **Pipeline First, Scale Second:** Complete an end-to-end, leak-free pipeline on a 9-repo pilot before scaling to 50+ repositories.

---

## 2. Locked Architectural Contract (`VULNCHAIN_DESIGN_v1.0`)

The architectural specifications were formally frozen in May 2026. The contract dictates the following non-negotiables:

### 2.1 Graph Heterogeneity (3 Node Types, 4 Edge Types)

| Element | Name | Representation / Dimension | Source / Computation |
| :--- | :--- | :--- | :--- |
| **Node** | `Package` | 10-dimensional continuous vector | Extracted from `package-lock.json` + npm registry metadata |
| **Node** | `CVE` (GHSA) | 768-dimensional frozen embedding + scalar CVSS | SentenceBERT (`all-mpnet-base-v2`) on advisory text + numeric CVSS |
| **Node** | `Author` | 7-dimensional continuous vector | GitHub API (repo owner, commits) + npm registry maintainer records |
| **Edge** | `dependsOn` | Directed: `Package → Package` | Lockfile dependency requirements |
| **Edge** | `hasVulnerability`| Directed: `Package → CVE` | Version range matching against OSV.dev advisories |
| **Edge** | `maintainedBy` | Directed: `Package → Author` | Resolved maintainer identity from package repository field |
| **Edge** | `introducedBy` | Directed: `CVE → Author` | Advisory attribution linking vulnerable versions to authors |

### 2.2 Model Architecture: VulnGAT
* **Type:** 3-Layer Hierarchical Attention Network (HAN).
* **Heterogeneous Projection:** Because nodes have heterogeneous feature dimensions (Package: 10, CVE: 768, Author: 7), each node type is first passed through a type-specific linear transformation $W_{\tau} \in \mathbb{R}^{d_{\tau} \times 128}$ projecting all nodes into a shared 128-dimensional hidden space.
* **Edge-Type Attention:** For each relation $r \in \mathcal{R}$, message passing computes attention coefficients $\alpha_{ij}^r$ across neighbors.
* **Semantic Aggregation:** Relation-specific node representations are aggregated using learned semantic attention vectors $\beta_r$.
* **Classification Head:** Linear layer $\mathbb{R}^{128} \to \mathbb{R}^1$ followed by a Sigmoid activation, applied **strictly to Package nodes**, outputting a continuous risk score $\hat{y}_i \in [0.0, 1.0]$.

### 2.3 Loss Function: Continuous MSE + Self-Supervised InfoNCE
$$\mathcal{L}_{\text{total}} = \mathcal{L}_{\text{MSE}} + 0.1 \times \mathcal{L}_{\text{InfoNCE}}$$

* **Why MSE (not BCE):** VPSS weak-supervision labels are continuous risk values in $[0.0, 1.0]$, representing expected blast radius, not discrete binary labels.
* **InfoNCE Contrastive Regularization:** Positive pairs $(z_i, z_i')$ are generated via **Edge Dropout ($p = 0.2$)**, creating two perturbed topological views of the same node. Negative pairs are all other nodes in the minibatch. This enforces topological consistency and prevents representation collapse without artificially forcing same-CVE packages together.

### 2.4 Unrated / Vague CVE Fallback Strategy
For newly disclosed advisories lacking an official CVSS vector or textual details, VulnChain does not drop the node or zero-pad the embedding. Instead, a **synthetic text template** is generated from available metadata fields (package name, affected range, CWE category) and encoded through the exact same frozen SentenceBERT model, preserving topological continuity.

### 2.5 Advisory Data Sources: OSV.dev over NVD
Early architectural drafts proposed querying both the National Vulnerability Database (NVD) and GitHub Advisory Database (GHSA). During implementation, NVD was formally removed:
* **The Empirical Reality:** Modern open-source npm packages track vulnerabilities almost exclusively via GHSA. In the pilot dataset, out of 338 unique vulnerabilities identified by OSV.dev, exactly **zero** were prefixed as standalone CVEs—all were GHSA identifiers (with 92.6% possessing CVE aliases in their metadata).
* **Pipeline Efficiency:** OSV.dev acts as an aggregated, machine-readable API providing GHSA records, affected semantic version ranges, and CVSS v3 vectors. Bypassing NVD eliminated severe API rate-limiting without sacrificing a single vulnerability.

---

## 3. Comprehensive Feature Vector Schemas

Every numeric feature was audited and locked to ensure compatibility with PyTorch Geometric (`torch.tensor` float32) without runtime crashes or NaN pollution.

### 3.1 Package Node Features (10-Dimensional Vector)

| Index | Feature Key | Data Type | Range | Description & Imputation Policy |
| :---: | :--- | :---: | :---: | :--- |
| `0` | `is_direct_dependency` | Binary | $\{0, 1\}$ | $1$ if listed in root `dependencies` / `devDependencies`; $0$ if transitive. |
| `1` | `is_dev_dependency` | Binary | $\{0, 1\}$ | $1$ if listed under `devDependencies`; $0$ if production dependency. |
| `2` | `dependency_depth` | Integer | $[0, \infty)$ | Shortest BFS path distance from application root ($0$ for root package). |
| `3` | `version_recency_days` | Float | $[0, \infty)$ | Days elapsed between package release and extraction date. If unlisted on npm, sentinel `-1` is replaced with median of known values. |
| `4` | `versions_behind_latest`| Integer| $[0, \infty)$ | Number of releases between current version and `latest` dist-tag. Sentinel `-1` replaced with median. |
| `5` | `has_known_cve_history` | Binary | $\{0, 1\}$ | $1$ if package has $\ge 1$ historical advisory in knowledge base; $0$ otherwise. *(Crucial audit finding: see Section 6).* |
| `6` | `num_dependencies` | Integer | $[0, \infty)$ | Out-degree of package (count of direct outbound `dependsOn` edges). |
| `7` | `num_dependents` | Integer | $[0, \infty)$ | In-degree of package (count of inbound `dependsOn` edges within graph). |
| `8` | `is_scoped_package` | Binary | $\{0, 1\}$ | $1$ if package name starts with `@` (e.g., `@babel/core`); $0$ if unscoped. |
| `9` | `weekly_downloads_log` | Float | $[0, \infty)$ | $\log_{10}(\text{weekly\_downloads} + 1)$ fetched from npm registry API. |

### 3.2 Author Node Features (7-Dimensional Vector)

| Index | Feature Key | Data Type | Range | Description & Reality Check |
| :---: | :--- | :---: | :---: | :--- |
| `0` | `account_age_days` | Float | $[0, \infty)$ | Age of GitHub account in days. **Known limitation:** 80% null in 9-repo pilot; imputed with median. Retained for schema stability. |
| `1` | `total_packages_maintained`| Integer| $[1, \infty)$ | Number of packages maintained across npm registry by this identity. |
| `2` | `packages_with_known_cves`| Integer| $[0, \infty)$ | Count of packages authored by this identity that possess confirmed CVEs. |
| `3` | `days_since_last_commit` | Float | $[0, \infty)$ | Days since author's last commit on GitHub repository. Imputed with median when missing (6.2% null). |
| `4` | `is_organization` | Binary | $\{0, 1\}$ | $1$ if GitHub account type is `Organization`; $0$ if `User`. |
| `5` | `has_2fa_enabled` | Binary | $\{0\}$ | Hardcoded to $0$. GitHub/npm APIs do not expose 2FA status publicly. Documented hard limitation. |
| `6` | `derived_reputation_score`| Float | $[0.0, 1.0]$| Heuristic composite index combining account age, package count, and commit activity. |

### 3.3 CVE Node Features (768-Dim Dense Embedding + CVSS Scalar)
* **Embedding Model:** `sentence-transformers/all-mpnet-base-v2` (frozen during training).
* **Input Text Corpus:** Concatenation of advisory `summary` + `details` fields from OSV records.
* **Vector Output:** Fixed 768-dimensional float32 embedding representing natural language exploit semantics (e.g., distinguishing Prototype Pollution from Denial of Service from Remote Code Execution).
* **Scalar CVSS:** CVSS v3.x base score ($0.0 - 10.0$). If missing from OSV record, imputed using the median of known CVSS scores in the active graph pool (dynamic median ~6.5).

---

## 4. Weak Supervision Engine: Mathematical VPSS Label Formulation

Because real-world software graphs lack manual ground-truth risk labels for tens of thousands of intermediate packages, VulnChain uses the **Vulnerability Propagation Scoring System (VPSS)** formulation as weak supervision:

$$\text{VPSS}(p) = \sum_{v \in \mathcal{V}_{\text{desc}}(p)} \text{CVSS}(v) \times \text{reachability} \times 0.7^{\text{depth}(p, v)} \times \text{exposure}(p)$$

### 4.1 Parameter Definitions & Design Justifications
1. **$\text{CVSS}(v)$:** Numeric severity score of downstream vulnerability $v \in [0.0, 10.0]$.
2. **$\text{reachability} \equiv 1.0$:** Package existence in the lockfile confirms dependency inclusion.
3. **Exponential Depth Decay ($0.7^{\text{depth}}$):** Downstream vulnerabilities attenuate rapidly as distance in the dependency DAG increases:
   - Depth 0 (Direct vulnerability): $0.7^0 = 1.00$
   - Depth 1 (Child vulnerability): $0.7^1 = 0.70$
   - Depth 2 (Grandchild vulnerability): $0.7^2 = 0.49$
   - Depth 3 (Great-grandchild): $0.7^3 = 0.343$
4. **4-Tier Exposure Coefficient ($\text{exposure}(p)$):** Derived from package deployment environment:
   - Direct Production Dependency: $1.00$
   - Direct Development Dependency: $0.50$
   - Transitive Production Dependency: $0.30$
   - Transitive Development Dependency: $0.15$
5. **Aggregation via SUM (not MAX):** Early drafts debated using $\max(\dots)$. Summation was deliberately chosen because risk is cumulative. A core library that imports five separate medium-severity vulnerable utilities poses a vastly higher blast radius than one importing a single medium-severity utility.
6. **Non-Linear Normalization (Hill / Michaelis-Menten Saturating Transform):**
   $$y_p = \frac{\text{raw\_sum}_p}{\text{raw\_sum}_p + K}, \quad \text{where } K = 10.0$$
   * **Why not hard-clipping $\min(\text{raw\_sum}, 10)/10$?** Hard-clipping creates an artificial ceiling at $10.0$. Any package with risk $>10.0$ (e.g., deeply entangled web frameworks like Express or NestJS with raw sums of $50 - 130$) collapses to $1.0$. This causes severe statistical censoring (like a Tobit model) where gradient information vanishes in the tail ($\frac{\partial y}{\partial x} = 0$).
   * The rational saturating function is strictly monotonic, ensuring that an extreme-risk package ($\text{raw\_sum} = 80 \implies y = 0.888$) remains distinct from a high-risk package ($\text{raw\_sum} = 20 \implies y = 0.667$).
   * $K = 10.0$ is a fixed mathematical constant, not a learned parameter, guaranteeing zero information leakage across splits.

---

## 5. Phase 1 to Phase 3: The 9-Repo Pilot Pipeline Journey

Between June and August 2026, the complete end-to-end pipeline was constructed and executed across a pilot set of 10 open-source repositories: `Ghost`, `NodeGoat`, `cli`, `dvna`, `express`, `juice-shop`, `nest`, `nodejs-goof`, `strapi`, and `webpack`.

### 5.1 Pipeline Execution Architecture
```
[Cloned Repos] ──► jsonGraphExtractor.py ──► package_graph.json (Packages + dependsOn)
                           │
                           ▼
                   osvExtractor.py ──► hasVulnerability_edges.json + cve_seed_ids.json
                           │
                           ▼
                  osvRecordFetcher.py ──► cve_nodes.json (Full OSV records + CVSS)
                           │
                           ▼
                   embedCveNodes.py ──► cve_nodes_embedded.json (SentenceBERT 768-dim)
                           │
                           ▼
                  authorExtractor.py ──► author_nodes.json + maintainedBy/introducedBy
                           │
                           ▼
                    merge_graph.py ──► vulnchain_graph.json (Heterogeneous Graph)
                           │
                           ▼
                   vpss_labeler.py ──► vpss_labels.json (Continuous Weak Supervision)
```

### 5.2 Critical Pilot Bugs & Pipeline Discoveries

#### 1. The Scoped Package Extraction Bug (Dangling Edges)
* **Symptom:** In the initial merge pass, 1,113 `dependsOn` edges pointed to 478 Package IDs that did not exist in the node set (6.9% topology loss).
* **Root Cause:** In lockfileVersion 3, 98.6% of entries under `packages` lack a top-level `name` attribute. `jsonGraphExtractor.py` used regex `node_modules/(?:@[^/]+/)?([^/]+)$`, which stripped the `@scope/` prefix. A dependency on `@npmcli/fs` was saved as node ID `fs@version`, creating orphaned edges.
* **Resolution:** 
  1. Built [`supplement_packages.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/supplement_packages.py) to fetch real 10-dim npm metadata for all 478 missing packages.
  2. Patched regex at source in [`jsonGraphExtractor.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/jsonGraphExtractor.py) line 119 to `((?:@[^/]+/)?[^/]+)$` to permanently fix the issue for future extractions.
  3. Result: Dangling edges dropped to exactly **zero**.

#### 2. The Strapi / Yarn Berry Exclusion
* **Symptom:** `strapi` produced zero nodes.
* **Root Cause:** Strapi uses Yarn Berry v4.12.0 with a YAML-based `yarn.lock` containing metadata headers (`__metadata:`). The pilot extractor only supported npm `package-lock.json` and Yarn v1.
* **Resolution:** Formally excluded `strapi` from the pilot, establishing a 9-repo dataset. Documented as an engineering parser limitation.

#### 3. Author Identity Resolution Overhaul (v1 vs v2)
* **Initial Failure (v1):** Assumed npm maintainer username equaled GitHub username. This resulted in incorrect GitHub user lookups or 404s.
* **Overhaul (v2):** Rewrote to [`authorExtractor.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/authorExtractor.py) v2. It queries the npm registry for the package's `repository.url`, extracts the real GitHub owner/repo, calls GitHub's commits API to get real commit freshness, and falls back to npm maintainer records only when no repository URL exists.
* **Rate-Limit Mitigation:** Implemented `.env` with `python-dotenv` to supply `GITHUB_TOKEN`, increasing the API quota from 60 req/hr to 5,000 req/hr.

#### 4. The Malicious Advisory (MAL-) Policy
* OSV.dev indexes malicious packages under IDs prefixed with `MAL-`.
* These represent intentional malware (e.g., typo-squatted credential stealers), not traditional vulnerabilities in legitimate software.
* Decision: Excluded `MAL-` records from CVE nodes and dropped all 30 associated edges (22 `hasVulnerability` + 8 `introducedBy`) during graph merge.

### 5.3 9-Repo Pilot Graph Summary (`vulnchain_graph.json`)
* **Package Nodes:** 5,578 (5,100 extracted + 478 supplemented scoped packages)
* **CVE Nodes:** 326 (all GHSA-sourced; 304 with CVSS; 100% embedded via SentenceBERT)
* **Author Nodes:** 2,035 (7-dim features)
* **Total Edges:** 21,812 (16,077 `dependsOn` + 701 `hasVulnerability` + 4,333 `maintainedBy` + 701 `introducedBy`)
* **Dangling Edges:** Exactly 0 (6/6 validation tests passed)
* **Weak Supervision Labels:** 891 / 5,578 packages (16.0%) non-zero VPSS; median non-zero = 0.269.

---

## 6. Training, Audits & The Great Model Diagnoses

With the 9-repo graph assembled, VulnGAT was trained on an RTX 3050 6GB Laptop GPU (CUDA 12.9) using PyG `HeteroData`. The ensuing evaluation uncovered profound machine learning and data engineering insights.

### 6.1 Crisis 1: The Initial Random-Split Leakage
* **The Error:** Initial training ran a standard random per-node stratified shuffle (`train_test_split`, seed=42) across all 5,578 packages.
* **The Catch:** Node-count discrepancy. The evaluation report claimed a test set of $N = 560$ packages, but the designated held-out repository (`juice-shop`) contained 1,269 nodes.
* **The Reality:** A random node split in software graphs causes catastrophic cross-repo contamination. Shared utility packages (e.g., `lodash`, `ms`, `chalk`) from the same repository appeared in both train and test sets, artificially inflating metrics (Test MSE: 0.0142, Pearson $r$: 0.6015, Rank Accuracy: 81.90%).

### 6.2 The August 28 Retrain: Pinned Repository Split
To prevent leakage, training was re-executed with strict repository pinning:
* **Train Split (7 Repos, $N = 3,759$):** `nest`, `NodeGoat`, `cli`, `nodejs-goof`, `express`, `dvna`, `Ghost` (Ghost with 24 nodes pinned to train).
* **Validation Split (1 Repo, $N = 550$):** `webpack` (used strictly for early stopping).
* **Held-Out Test Split (1 Repo, $N = 1,269$):** `juice-shop` (unseen test project).

#### Empirical Results on Juice-Shop ($N = 1,269$)
* **MSE:** `0.019580` (RMSE: `0.13993`)
* **MAE:** `0.085469`
* **Pearson Correlation ($r$):** `0.4320` ($p < 10^{-5}$)
* **Spearman Rank Correlation ($\rho$):** `0.3567`
* **Pairwise Concordant Ranking Accuracy:** `77.24%`
* **Out-of-Distribution Benchmark (Contrast Security `NodeTestBench`, $N=671$):** At critical threshold $\ge 0.40$, achieved **100% Precision** (31/31 confirmed CVEs) and **77.5% Recall** (31/40).

### 6.3 Five Crucial Scientific Diagnoses (Why the Model Was Not Yet Complete)

#### Diagnosis A: The VPSS Redundancy Paradox
VPSS labels are computed via a deterministic graph formula:
$$\text{VPSS} = \text{CVSS} \times 0.7^{\text{depth}} \times \text{exposure}$$
Because this formula is computable by standard Breadth-First Search (BFS), a GNN trained solely to predict VPSS is effectively learning to approximate arithmetic. High correlation against VPSS is a sanity check, not proof of novel representation learning.

#### Diagnosis B: The `is_direct` Feature Dominance & Ranking Inversion
In the VPSS formula, direct production packages receive an exposure tier of $1.00$, while transitive packages receive $0.30$. The GNN learned `is_direct` as an overwhelmingly positive predictor.
* **The Failure:** During inference on a test lockfile, clean direct dependencies (such as `three.js`) were predicted with higher risk scores (~0.39) than genuinely vulnerable transitive packages (such as `nanoid` at 0.32). This caused a ranking inversion.

#### Diagnosis C: The 45% Identical Score Inference Bug
When [`analyze_project.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/TrainModel/analyze_project.py) was tested on unseen external lockfiles, 45% of packages received an identical constant score (~0.1547).
* **Root Cause:** Line 146 contained a hardcoded fallback vector (`depth=1`, default features) for any package not present in the 9-repo training knowledge base. All 22 platform binaries of `esbuild` and numerous utilities collapsed to the exact same prediction.

#### Diagnosis D: The Failed EPSS Relabeling Experiment
To decouple the model from the deterministic VPSS formula, an experiment was conducted replacing VPSS with **EPSS (Exploit Prediction Scoring System)** from FIRST.org + CISA KEV catalog data.
* **Outcome:** Test metrics degraded sharply (Pearson $r$ dropped from 0.43 to 0.25; ranking accuracy dropped from 77% to 71%).
* **Root Cause:** Sample size starvation. Across the 326 CVEs, only 889 packages had non-zero EPSS labels. The dataset was too small to learn a noisy, real-world exploitation probability signal. EPSS was preserved in `epss_data.json` for when graph scale reaches thousands of CVEs.

#### Diagnosis E: The Masked-Edge Audit Feature Leak (Dim 6)
An audit script [`masked_edge_audit.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/TrainModel/masked_edge_audit.py) was built to measure whether the GNN could propagate risk when `hasVulnerability` edges were hidden.
* **The Catch:** Model AUC matched baseline feature-shuffle AUC.
* **Investigation:** When edges were masked, Package feature dim 6 (`has_known_cve_history`) remained unmasked ($= 1$). The model did not need graph edges to detect vulnerability—it simply read feature dim 6 through the back door.

### 6.4 The Three Inference-Pipeline Fixes (`analyze_project.py`)
Rather than retraining on flawed data, three runtime fixes were engineered into [`analyze_project.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/TrainModel/analyze_project.py):
1. **Real Dynamic BFS Depth:** Replaced hardcoded `depth=1` fallback with live BFS depth traversal calculated directly from root dependencies in the parsed lockfile.
2. **Live OSV API Integration:** For unseen packages in an input lockfile, the script dynamically queries `api.osv.dev` for up to 50 unknown packages, injecting synthetic CVE nodes on the fly.
3. **Post-Hoc Calibration Cap:** Any package with no direct CVE and no vulnerable descendant is hard-capped at $\min(\text{score}, 0.08)$. Packages with vulnerable descendants (e.g., `socket.io-client` depending on vulnerable `socket.io-parser`) are never capped, allowing the GNN attention to elevate their risk freely.

* **Honest Credit Attribution:** On novel lockfiles, credit splits **~30% GNN topological blast-radius propagation / 70% pipeline engineering**. Real blast-radius propagation was proven: on a 113-package lockfile, benign parents `@google/genai` (0.2453), `socket.io-client` (0.1989), and `vite` (0.1232) were elevated well above the 0.08 cap purely through GNN message passing across `dependsOn` edges.

---

## 7. The 50-Repo Scale-Up Preparation

Following the 9-repo pilot, the project began Phase 4: scaling the dataset by 5x to 50+ repositories to build an industrial-grade training corpus.

### 7.1 Workspace Sanitation & Reconstructed Tools
1. **Disk Cleanup:** Freed 38.6 GB of duplicate data while strictly preserving all 6 API cache files (`.npm_registry_cache.json`, `.github_repo_cache.json`, `.github_user_cache.json`, `.osv_records_cache.json`, etc.).
2. **Bit-Exact Labeler Reconstruction:** The original `vpss_labeler.py` was reconstructed from design doc specifications and verified bit-exact against `vpss_labels.json` across all 5,578 pilot packages (5,578/5,578 matched on `vpss`, `raw_sum`, `num_contributing_vulns`, and `min_depth_to_vuln`).
3. **Dynamic Median Imputation:** Upgraded `vpss_labeler.py` null-CVSS handling from a hardcoded 6.5 to dynamically computing the median of non-null CVSS scores from the active graph.

### 7.2 Automated Pre-Check & Candidate Selection
To prevent another Yarn Berry failure (like `strapi`), a pre-check tool was paired with You.com Deep Search (`repo_precheck.py` + `deep_you_search.py`):
* **Harvested:** 404 candidate repositories.
* **Curated & Verified:** 58 repositories confirmed completely free of Yarn Berry or pnpm monorepo lockfiles (`has_yarn=false`, `has_pnpm=false`).
* **Profile:** Mix of lockfile versions (22 v1, 17 v2, 19 v3), spanning pushed dates from 2017 to 2026, combining intentionally vulnerable security benchmarks (DVNA, NodeGoat, Juice-Shop, Contrast Security bench) with popular npm libraries and server boilerplates.
* **Usable Scale:** 52 repositories selected for Phase 4.

---

## 8. Phase 4 Step 1: Merged 51-Repo Extraction & The Node-Count Anomaly

In September 2026, Phase 4 Step 1 commenced: executing `jsonGraphExtractor.py` across the merged set of 52 repositories.

### 8.1 Extraction Execution
* **51 Usable Repositories (1 Excluded):** 
  - `strapi`: Excluded (Yarn Berry).
  - `redos-detector`: Excluded (cloned directory was empty due to a Windows colon-in-path git checkout error: `Filename: "test:fixtures:..."`).
  - Remaining 51 repositories extracted cleanly in ~5 minutes.
* **Raw Output:**
  - **Total Package Nodes:** 12,405
  - **Total `dependsOn` Edges:** 60,792

### 8.2 The Node-Count Anomaly Investigation
* **The Concern:** The pre-run projection was ~20,000–24,000 unique Package nodes (based on 5,578 pilot nodes + 23,631 batch-2 pre-dedup nodes). The actual output of 12,405 nodes was below the pre-set validation floor of $\ge 15,000$.
* **The Edge Clue:** The edge count was **exactly 60,792**:
  $$16,077 \text{ (pilot edges)} + 44,715 \text{ (batch-2 edges)} = 60,792 \text{ edges}$$
  Because the edge sum showed zero reduction, extraction had processed every single dependency. The shortfall was entirely localized to **node deduplication**.

#### Diagnostic Findings (`diagnose_node_count.py`)
* **Primary Hypothesis:** Was the extractor deduplicating on package `name` alone instead of `name@version`?
* **Code Verification:** Lines 100–125 of `jsonGraphExtractor.py` confirmed that the unique key is explicitly constructed as:
  ```python
  pkg_id = f"{clean_name}@{version}"
  ```
* **Empirical Package Spread:**
  - `express`: 11 distinct versions (`4.12.4`, `4.16.4`, `4.17.1`, `4.18.2`, `4.19.2`, etc.)
  - `lodash`: 14 distinct versions
  - `debug`: 10 distinct versions
  - `glob`: 8 distinct versions
* **The Root Cause: Massive Ecosystem Overlap:**
  - In the npm ecosystem, secondary and tertiary dependencies converge heavily on canonical versions.
  - A single node, `ms@2.0.0`, appeared in **43 out of 51 repositories**.
  - Total pre-dedup node instances across the 51 repositories = **31,719**.
  - Post-dedup unique `name@version` nodes = **12,405**.
  - Ecosystem overlap rate = **60.9% reduction**.
* **Verdict:** Not a bug. The 12,405 node count is real, structurally sound, and represents a 2.2x scaling over the pilot graph.

---

## 9. The Critical Discovery: Shared-Node Repo-Split Leakage

Following the node-count investigation, a deep diagnostic prompt was executed on how deduplicated nodes interact with repository-level train/validation/test splits.

### 9.1 The Fundamental Flaw in the 9-Repo Split Mapping
When nodes are merged across repositories on `name@version`, a package no longer belongs to a single repository. For instance, `ms@2.0.0` belongs to 43 repositories simultaneously.

Diagnostic script [`diagnose_split_leakage.py`](file:///C:/Users/Admin/.gemini/antigravity-ide/brain/5590351d-d6aa-4ee2-a7fd-cd7b205fe0a9/scratch/diagnose_split_leakage.py) audited the existing `repo_split_mapping.json`:
1. **Per-Node Assignment without Provenance:** The mapping stored flat lists of package IDs (`train_pkg_ids`, `val_pkg_ids`, `test_pkg_ids`). It had been created by assigning all packages found in `juice-shop` to the test list, and all packages in `webpack` to the val list.
2. **Massive Test Contamination:**
   - Out of 1,269 nodes in the "held-out" test set, **886 nodes (69.8%) also appeared in training repositories!**
   - Out of 550 nodes in the validation set, **247 nodes (44.9%) also appeared in training repositories.**
   - Example: `destroy@1.0.4` appeared in `NodeGoat` (a training repo) and was assigned to test.
   - Example: `glob@13.0.6` had repo sources `['cli', 'nest', 'webpack']` (all train or val), yet was assigned to test.

### 9.2 Transductive Graph Edges vs. Inductive Label Leakage
An essential theoretical distinction was clarified:
* **Edge Crossing (26.5% of edges):** In transductive GNN architectures (standard PyG single-graph classification), edges between train and test nodes are expected and necessary for message passing.
* **Label & Identity Leakage (The Real Error):** A node assigned to the test set whose label and local neighborhood structure were already observed through training repository membership is **not held-out**. The August 28 reported test metrics ($MSE = 0.01958$, $r = 0.4320$) were computed on a test set that was **69.8% contaminated**.

### 9.3 The Provenance Rule Fix
To guarantee scientific validity, a strict provenance rule was codified in [`corrected_split_generator.py`](file:///C:/Users/Admin/.gemini/antigravity-ide/brain/5590351d-d6aa-4ee2-a7fd-cd7b205fe0a9/scratch/corrected_split_generator.py):

> [!IMPORTANT]
> **The Provenance Rule:**  
> A package node $p$ is assigned to evaluation split $S$ (Validation or Test) **if and only if EVERY repository in its `repo_sources` belongs exclusively to $S$'s repository group**.  
> If a package has **mixed provenance** (appears in both a training repo and an evaluation repo), it is assigned to **TRAIN** by default. It contributes to message-passing topology and training loss, but is **never evaluated on in validation or test**.

#### Impact on the 9-Repo Graph
When the Provenance Rule was applied retroactively to the 9-repo pilot:
* `juice-shop` test set shrank from 1,269 nodes to **395 exclusive nodes**.
* Crucially, only **24 nodes** in this clean test set had non-zero VPSS labels.
* **Statistical Power Assessment:** Computing Pearson and Spearman correlation on 24 samples is statistically invalid ($N < 30$ minimum; $N \ge 200$ required for stable estimates). This proved definitively that the 9-repo dataset was too small for a true held-out repository split, necessitating the 51-repo scale-up.

---

## 10. The 51-Repo Clean Split & Test Set Selection

Using the 51-repo extracted graph (`package_graph.json`, 12,405 nodes), [`repo_exclusivity.py`](file:///C:/Users/Admin/.gemini/antigravity-ide/brain/5590351d-d6aa-4ee2-a7fd-cd7b205fe0a9/scratch/repo_exclusivity.py) evaluated all 51 repositories to find candidates with sufficient exclusive nodes ($N \ge 200$) to serve as held-out test and validation sets.

### 10.1 Top Repository Exclusivity Ranking

| Repository | Total Nodes in Repo | Exclusive Nodes (0% Overlap) | Exclusivity % | Viability as Held-Out ($N \ge 200$) |
| :--- | :---: | :---: | :---: | :---: |
| **`saleor-storefront`** | 3,038 | **1,341** | 44.1% | **YES — Prime Test Candidate** |
| **`practica`** | 1,292 | **541** | 41.9% | **YES — Prime Val Candidate** |
| `webpack` | 1,384 | 483 | 34.9% | Viable (used in 9-repo pilot) |
| `nest` | 1,648 | 463 | 28.1% | Viable |
| `damn-vulnerable-defi` | 647 | 407 | 62.9% | Viable |
| `production-ready-expressjs-server` | 512 | 354 | 69.1% | Viable |
| `NodeGoat` | 1,090 | 344 | 31.6% | Viable |
| `oss-oopssec-store` | 421 | 288 | 68.4% | Viable |
| `node-express-basic` | 390 | 270 | 69.2% | Viable |
| `backend-node-express` | 382 | 263 | 68.8% | Viable |
| `juice-shop` | 1,269 | 230 | 18.1% | Low exclusivity (high overlap) |

### 10.2 The Selected 51-Repo Split Architecture
To prevent any overlap with the 9-repo pilot, two large repositories from Batch 2 were selected for evaluation:
* **Held-Out Test Repo:** `saleor-storefront` ($N = 1,341$ exclusive nodes)
* **Validation Repo:** `practica` ($N = 541$ exclusive nodes)
* **Training Repositories:** All other 49 repositories + all 2,046 mixed-provenance nodes ($N = 10,523$ nodes)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                   VULNCHAIN 51-REPO PROVENANCE-CLEAN SPLIT PARTITION                   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  TRAIN SPLIT:       10,523 nodes (84.8%) · 49 Repos + 2,046 Mixed-Provenance Nodes     │
│  VALIDATION SPLIT:     541 nodes  (4.4%) · practica (100% Exclusive Nodes)             │
│  HELD-OUT TEST:      1,341 nodes (10.8%) · saleor-storefront (100% Exclusive Nodes)    │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  TOTAL NODES:       12,405 nodes · ZERO LEAKED NODES VERIFIED                          │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 10.3 Pre-Registered Scientific Caveat (Domain Shift)
* **The Risk:** `saleor-storefront` is a modern e-commerce storefront built with **React, TypeScript, and Next.js**. In contrast, the 49 training repositories consist heavily of **Express.js, Node.js backend services, and CLI utilities**.
* **The Commitment:** If test set metrics on `saleor-storefront` show higher MSE or lower correlation than seen on validation, this will be analyzed honestly as an **ecosystem domain shift** (Frontend vs. Backend dependency structures), rather than rationalizing or altering the split post-hoc.
* **PRE-REGISTERED (2026-09-18, before Phase C training):** The test repo `saleor-storefront` is a React/Next.js e-commerce frontend, whereas the training corpus is dominated by Express/Node.js backends and CLI utilities. If test metrics are materially worse than validation metrics on `practica`, the leading hypothesis is **ecosystem domain shift**, not model failure. We commit to reporting both splits side by side and to NOT re-picking test repos, re-tuning thresholds, or re-splitting post-hoc to close the gap. This caveat was registered before any 51-repo training run.

---

## 11. Operational Rules & Lessons Learned (The 14 Commandments)

The project's failures and discoveries are codified into 14 operational rules recorded in [`VULNCHAIN_LESSONS_LEARNED.md`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/VULNCHAIN_LESSONS_LEARNED.md):

1. **Lock Repo Splits via Provenance Files:** Never split nodes randomly. Enforce the strict Provenance Rule where evaluation nodes have zero occurrences in training repositories.
2. **Mask Edge-Derived Features in Audits:** Package feature dim 6 (`has_known_cve_history`) must be zeroed out whenever `hasVulnerability` edges are masked; otherwise, the model cheats.
3. **Run Masked-Edge Audits Immediately:** Run robustness audits immediately following training rather than deferring them.
4. **Do Not Lead with VPSS Correlation:** VPSS is a deterministic formula. Headline results must be (a) Masked-edge audit AUC vs. label propagation, and (b) Out-of-Distribution precision/recall on `NodeTestBench`.
5. **Monitor `is_direct` Confounding:** Explicitly verify that direct benign packages do not outrank vulnerable transitive packages.
6. **Check Non-Zero Sample Sizes Before Relabeling:** Do not attempt EPSS or other label swaps without verifying $\ge 3,000$ non-zero samples exist.
7. **Maintain Inference Fallbacks:** Never hardcode constant feature defaults (`depth=1`) for unseen packages; calculate dynamic BFS depth and query live OSV APIs.
8. **Pre-Check Lockfile Compatibility:** Verify repos do not use Yarn Berry or pnpm before adding them to extraction lists.
9. **Pre-Register Success Criteria for VulnGAT-R:** Success for the robust model is defined as beating label propagation by $>0.02$ AUC at 50% edge mask, with OOD precision $\ge 90\%$.
10. **Resolve Author Identities via Git Repository URL:** Never guess `npm username == GitHub username`. Use the `repository.url` field in package metadata.
11. **Verify Referenced Infrastructure Exists:** Never assume caches mentioned in design docs exist; verify on disk before writing code against them.
12. **Check for Dangling Edges After Every Extraction:** Maintain regex support for scoped packages (`@scope/pkg`) and audit dangling counts after each run.
13. **Verify API Authentication Up Front:** Test `GITHUB_TOKEN` validity before initiating large author extraction runs to avoid the 60 req/hr ceiling.
14. **Enforce Version Control Hygiene:** Always ensure `.env` and large JSON caches are covered in `.gitignore`.

---

## 12. Current Project State & Immediate Execution Roadmap

### 12.1 Current State Checklist

```
[Phase 4 Steps 1–7] ──► COMPLETE (2026-09-18, see WORKER_REPORT_PHASE4.md for full results)
                     - package_graph.json: 12,405 nodes, 60,792 edges
                     - Node count investigated: 60.9% overlap confirmed valid
                     - Shared-node split leakage diagnosed & Provenance Rule implemented
                       (now persistent code: generate_repo_split.py)
                     - 51-repo split mapped & verified: Train 10,523 / Val 541 / Test 1,341 (0 leakage)
                     - OSV batch: 978 vulnerable packages, 2,635 hasVulnerability edges, 883 CVEs embedded
                     - Authors: 3,878 nodes (96% repo-owner resolved), 12,390 maintainedBy edges
                     - Merged graph: phase4/vulnchain_graph.json — 17,166 nodes, 78,443 edges, 6/6 checks
                     - VPSS labels: 3,723 non-zero (30.0%) — Test 538, Val 161 → GATE ≥150 PASSED
                     - Training executed in Google Colab (GPU); results archived in phase4/results_colab/
                     - PHASE C OUTCOME: as-trained VulnGAT loses to the feature-only MLP baseline on
                       every metric (test RankAcc 39% vs 72%; Pearson-nz 0.43 vs 0.57); masked-edge
                       audit Outcome 3 (AUC 0.40 < label-prop 0.72, pre-registered criterion FAILED);
                       NodeTestBench Precision 100% (25/25) @ ≥0.40 holds, Recall 32.5% (77 CVEs in KB).
                       Training protocol deficiencies identified (13-epoch stop, InfoNCE ~93% of loss).
                     - STATUS: PHASE 4 COMPLETE — VulnGAT-v2 protocol fix is the proposed follow-up
```

### 12.2 Remaining Phase 4 Execution Roadmap

```
                                PHASE 4 ROADMAP
                                
  [Step 1]  51-Repo Package & Edge Extraction                ──► ✅ COMPLETE (12,405 nodes)
     │
     ▼
  [Step 2]  OSV Batch Vulnerability Extraction (osvExtractor.py) ──► ⏳ NEXT STEP
            Query api.osv.dev for 12,405 packages
            Output: hasVulnerability_edges.json + cve_seed_ids.json
     │
     ▼
  [Step 3]  CVE Record Fetch & SentenceBERT Embeddings      ──► ⏳ PENDING
            Fetch full OSV records, parse CVSS scores
            Encode advisory texts with all-mpnet-base-v2 (768-dim)
            Output: cve_nodes_embedded.json
     │
     ▼
  [Step 4]  Author Node Extraction & Maintainer Graph        ──► ⏳ PENDING
            Resolve GitHub owners, commit dates, package counts
            Output: author_nodes.json + maintainedBy/introducedBy edges
     │
     ▼
  [Step 5]  Heterogeneous Graph Merge & Validation           ──► ⏳ PENDING
            Merge all 3 node types + 4 edge types
            Impute nulls, verify zero dangling edges (6/6 checks)
            Output: vulnchain_graph.json (51-repo final)
     │
     ▼
  [Step 6]  VPSS Weak-Supervision Labeling & Sanity Audit    ──► ⏳ PENDING
            Recompute VPSS labels on merged 51-repo graph
            VERIFICATION GATE: Confirm saleor-storefront (Test) has >=150
            non-zero vulnerable nodes before proceeding to training
     │
     ▼
  [Step 7]  Model Training & Evaluation (TrainModel/)        ──► ⏳ PENDING
            Train VulnGAT (3-layer HAN, MSE + 0.1*InfoNCE) on RTX 3050
            Evaluate on 100% clean held-out saleor-storefront
            Run Masked-Edge Robustness Audit & NodeTestBench OOD Benchmark
```

---

## 13. Forensic Ledger of Minute Particle Decisions & Micro-Bugs

To ensure zero loss of tribal knowledge, every micro-decision, debugging triumph, and statistical nuance that arose across the project's development is cataloged below:

### 13.1 Pre-Code Socratic Genesis & User Corrections (May 2026)
During the initial architectural formation, three critical user corrections saved the project from fundamental machine learning errors:
1. **Loss Function Formulation (MSE vs. BCE):** The initial design proposed Binary Cross-Entropy (BCE). The user corrected this: VPSS weak-supervision produces continuous values in $[0.0, 1.0]$ representing topological blast radius, not binary classifications. The loss was locked to Mean Squared Error (MSE).
2. **Contrastive Pair Formulation in InfoNCE:** The initial design suggested grouping different packages that share the same CVE as contrastive positive pairs. The user corrected this: two packages sharing a CVE can have completely different dependency contexts and risk profiles. Positive pairs were redefined as **two augmented views of the exact same node** generated via Edge Dropout ($p=0.2$).
3. **Vague CVE Text Fallback:** When security advisories lack text descriptions, proposals suggested using CodeBERT or zero-padding. The user corrected this: zero-padding creates discontinuity in embedding space, and CodeBERT operates on code, not advisory prose. The fallback was locked to **generating synthetic text from CVSS fields** (e.g., `"Vulnerability in package X affecting versions Y with CVSS Z"`) and encoding it through the exact same frozen SentenceBERT (`all-mpnet-base-v2`) model.

### 13.2 Hardware Environment & Runtime Migration
* **Workstation Segregation:** Due to disk space limitations on the primary development machine, data pipeline scripts (`jsonGraphExtractor.py`, OSV fetchers, Author extractors) were initially built and executed on a storage-constrained laptop.
* **Training Hardware:** PyG model training and evaluation were transferred to a dedicated machine equipped with an **NVIDIA GeForce RTX 3050 Laptop GPU (6 GB VRAM, 16 GB System RAM, CUDA 12.9)**.
* **VRAM Scalability:** Peak VRAM consumption during 200 training epochs on the 9-repo graph was measured at only **~500–850 MB** with runtimes of **35–55 seconds**, confirming that the 6 GB VRAM capacity can effortlessly accommodate the 51-repo scale-up without out-of-memory (OOM) risks.

### 13.3 Data Pipeline Micro-Bugs & Serialization Fixes
1. **The Decimal Serialization Crash (`osvRecordFetcher.py`):**
   * *Bug:* When parsing CVSS vectors via Python's `cvss` library, base scores were returned as Python `Decimal` objects. When attempting to save `cve_nodes.json`, Python's `json.dump()` crashed with `TypeError: Object of type Decimal is not JSON serializable`.
   * *Fix:* Injected explicit `float()` type-casting into the CVSS parsing handler.
2. **The Mutating `--verify` Flag Bug (`vpss_labeler.py`):**
   * *Bug:* The verification CLI flag `--verify` was intended to be a non-destructive read-only sanity check. However, the script opened the output file in write mode (`"w"`), mutating `vpss_labels.json` during the check.
   * *Fix:* Rewrote the CLI argument parser to ensure `--verify` operates strictly in read-only validation mode.
3. **Three-Package Hand Calculation Audit:**
   * *Verification:* Before trusting the reconstructed `vpss_labeler.py`, three packages across distinct exposure tiers (`body-parser`, `morgan`, and `debug`) were hand-calculated using manual pencil-and-paper Decimal arithmetic against the design doc formula:
     $$\text{VPSS} = \text{CVSS} \times 1.0 \times 0.7^{\text{depth}} \times \text{exposure}$$
     $$\text{Final Risk} = \frac{\text{raw\_sum}}{\text{raw\_sum} + 10.0}$$
   * All three packages matched the Python script's output to the exact least-significant digit.
4. **Dynamic Null-CVSS Median Pool Testing:**
   * *Audit:* In the 9-repo pilot, 22 CVEs lacked CVSS scores and were assigned a hardcoded fallback of 6.5. This was replaced with a dynamic median computed fresh per run from non-null CVSS scores.
   * *Verification via Null-Injection:* Artificial nulls were injected into graph copies. In a single-null test, the imputed score was the active pool median ($7.5$). In a 76-null test with a shifted distribution, the imputed score shifted dynamically to $6.9$, confirming it computes fresh each run without leaking constants from prior runs.

### 13.4 Debunked Evaluation Claims & Audit Discoveries
1. **Debunking "Test MSE < Train MSE = No Overfitting":**
   * In the August 28 evaluation, the report claimed that a lower test MSE (`0.01958`) than validation MSE (`0.02283`) demonstrated excellent generalization without overfitting.
   * *The Audit:* An inspection of the test set revealed that **83.9% of held-out nodes had zero labels ($y = 0$)**. The model's low MSE was heavily flattered by trivial zero-predictions on benign packages. The claim was permanently dropped from scientific claims.
2. **Debunking "100% Recall at $\ge 0.15$ on NodeTestBench":**
   * The initial report claimed 100% recall on the Contrast Security benchmark by lowering the decision threshold to $\ge 0.15$.
   * *The Audit:* At $\ge 0.15$, precision collapsed to **14.76%**, generating **231 false positives** ($F_1 = 0.257$). This was identified as post-hoc threshold cherry-picking. The claim was rescinded, and the benchmark was locked strictly to the pre-committed threshold of $\ge 0.40$ (100% Precision, 77.5% Recall).
3. **Verified Attention Blast Radius (Proof of GNN Value):**
   * To verify whether VulnGAT performs genuine graph risk propagation (rather than relying on post-hoc inference rules), inference was run on a 113-package user lockfile.
   * Four benign packages with zero direct CVEs were elevated significantly above the 0.08 baseline cap purely through GNN attention across `dependsOn` edges:
     - `@google/genai` (**`0.2453`**) — elevated due to transitive child `protobufjs/utf8`
     - `socket.io-client` (**`0.1989`**) — elevated due to transitive child `socket.io-parser`
     - `vite` (**`0.1232`**) — elevated due to transitive child `nanoid`
     - `protobufjs` (**`0.1229`**) — elevated due to child parser dependencies
   * This provided empirical proof that the GNN learns multi-hop structural risk propagation.

### 13.5 Candidate Harvesting Micro-Nuances
1. **Owner Resolution Flaw in Pre-Check Tool:**
   * An early version of `repo_precheck.py` incorrectly guessed owners as `nicmolo/dvna` and `nicmolo/nodejs-goof`, reporting them as "MISSING" with an ambiguous hedge.
   * *Resolution:* Corrected the tool to resolve repositories against verified GitHub owners: `appsecco/dvna` and `snyk/nodejs-goof`.
2. **Historic Supply Chain Incident Pair:**
   * The 51-repo corpus deliberately includes the historic 2018 `event-stream` / `flatmap-stream` dependency attack pair, providing real-world malware propagation topology.
3. **The Windows Colon-in-Path Git Checkout Bug (`redos-detector`):**
   * During Batch 2 cloning, `redos-detector` failed to check out its working directory on Windows because the repository contained a test fixture with a colon in the filename (`test:fixtures:...`). Windows NTFS forbids colons in filenames. The cloned directory remained empty, and it was properly excluded from the 51-repo extraction without compromising data integrity.
4. **Step 4 Author Extractor Runtime Warning:**
   * Step 4 author extraction runtime estimates (15–40 minutes) assume partial cache hits. Because the 51-repo batch contains 43 completely new repositories, most packages will be initial cache misses against GitHub and npm APIs. The extraction is expected to lean toward the upper end of the runtime window.

---

## 14. File & Component Directory Map

| Path | Role / Description | Status / Content |
| :--- | :--- | :--- |
| [`CURRENT_CONTEXT.md`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/CURRENT_CONTEXT.md) | Authoritative, end-to-end master document (This File) | Up-to-date |
| [`VULNCHAIN_LESSONS_LEARNED.md`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/VULNCHAIN_LESSONS_LEARNED.md) | Operational rules and anti-leakage guidelines | Active |
| [`package_graph.json`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/package_graph.json) | 51-repo extracted Package nodes (12,405) and `dependsOn` edges (60,792) | Step 1 Output |
| [`jsonGraphExtractor.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/jsonGraphExtractor.py) | Lockfile parser with scoped-package regex fix | Production |
| [`osvExtractor.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/osvExtractor.py) | OSV.dev batch querying engine with resumable cache | Ready for Step 2 |
| [`osvRecordFetcher.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/osvRecordFetcher.py) | Full advisory parser & CVSS vector calculator | Ready for Step 3 |
| [`embedCveNodes.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/embedCveNodes.py) | SentenceBERT (`all-mpnet-base-v2`) 768-dim encoder | Ready for Step 3 |
| [`authorExtractor.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/authorExtractor.py) | v2 GitHub repo-owner + npm maintainer extractor | Ready for Step 4 |
| [`merge_graph.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/merge_graph.py) | Multi-relational heterogeneous graph compiler & validator | Ready for Step 5 |
| [`vpss_labeler.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/vpss_labeler.py) | Bit-exact continuous VPSS weak supervision generator | Ready for Step 6 |
| [`TrainModel/`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/TrainModel) | PyTorch Geometric modeling suite (HAN layers, training, loss, eval) | Model Workspace |
| [`TrainModel/core/model/vulngat.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/TrainModel/core/model/vulngat.py) | 3-layer VulnGAT PyTorch Geometric implementation | Model Architecture |
| [`TrainModel/analyze_project.py`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/TrainModel/analyze_project.py) | Standalone lockfile inference scanner with 3 pipeline fixes | Inference Engine |
| [`TrainModel/repo_split_mapping_corrected_9repo.json`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/TrainModel/repo_split_mapping_corrected_9repo.json) | Corrected, leak-free 9-repo split mapping | Audit Artifact |
| [`you_deep_verified_ok.json`](file:///c:/Users/Admin/Desktop/Major%20VulnChain/you_deep_verified_ok.json) | 58 curated, verified npm repositories (no Yarn Berry) | Data Asset |

