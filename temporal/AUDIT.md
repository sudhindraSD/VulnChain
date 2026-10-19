# Temporal Label Feasibility Audit

**Branch:** `temporal-label`  
**Workspace:** `temporal/`  
**Date:** 2026-10-19  
**Dataset:** 51-repo Graph (`vulnchain_graph.json` — 12,405 package nodes)  
**Split Mapping:** `phase4/repo_split_mapping_51repo.json` (Provenance Rule)  

---

## 1. OSV Records & Vulnerability ID Audit (873 Unique IDs)

From `data_pipeline/osv_vulns.json` across all 12,405 package nodes, exactly **873 unique vulnerability IDs** are referenced.

- **Found in `.osv_records_cache.json`:** 871 IDs
- **Missing Published Dates in Cache:** **0** (100% of the 871 cached records have valid ISO-8601 published dates)
- **Missing from Cache:** **2 IDs** (`MAL-2022-5972` and `MAL-2023-462`)
  - *Root Cause:* In `data_pipeline/osvRecordFetcher.py`, `INCLUDE_MAL = False` was set by default during Phase 1–3 scraping because the Malicious Packages Database has a different schema without CVSS vectors.
  - *Direct Upstream Verification:* Querying `https://api.osv.dev/v1/vulns/{id}` confirms:
    - `MAL-2022-5972`: Published `2022-06-20T20:26:25Z` (affects `scrypt-shim@github:web3-js/scrypt-shim#...`)
    - `MAL-2023-462`: Published `2023-04-27T19:20:00Z` (affects `fsevents@1.1.2`, `fsevents@1.2.9`)
  - Both MAL records were published in 2022 and 2023, strictly **before** all evaluated cutoffs ($T \ge \text{2024-07-01}$).
- **Total with No Published Date:** **0 of the 873 IDs** have missing published dates.

---

## 2. Split Sizes (Provenance Rule)

Under the Provenance Rule (a node is assigned to an evaluation split if and only if **all** its `repo_sources` belong to that split's exclusive repo group; mixed-provenance nodes are routed to `train`):

| Split | Repository Group | Node Count | Percentage |
| :--- | :--- | :---: | :---: |
| **Train** | 49 repos + mixed provenance | **10,523** | 84.83% |
| **Validation** | `practica` | **541** | 4.36% |
| **Test** | `saleor-storefront` | **1,341** | 10.81% |
| **Total** | **51 repos** | **12,405** | **100.00%** |

---

## 3. Direct Vulnerability Temporal Labels

A vulnerability is considered to affect a node if it appears as a direct `hasVulnerability` edge on that package node (matching the exact package version).

- **Label A:** Node has $\ge 1$ advisory published **after** $T$ affecting its version **AND** none published on or before $T$. (Newly vulnerable after $T$ with clean prior history).
- **Label B:** Node has $\ge 1$ advisory published **after** $T$ affecting its version.
- **Pre-$T$ History:** Node has $\ge 1$ advisory published **on or before** $T$ affecting its version.

### Summary Table

| Cutoff $T$ | Split | Total ($N$) | Label A Positives | Label A % | Label B Positives | Label B % | Pre-$T$ History | Pre-$T$ % |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **2024-07-01** | **Train** | 10,523 | 346 | 3.29% | 500 | 4.75% | 531 | 5.05% |
| | **Val** | 541 | 22 | 4.07% | 24 | 4.44% | 2 | 0.37% |
| | **Test** | 1,341 | 25 | 1.86% | 46 | 3.43% | 51 | 3.80% |
| | *Combined* | 12,405 | 393 | 3.17% | 570 | 4.60% | 584 | 4.71% |
| **2025-01-01** | **Train** | 10,523 | 296 | 2.81% | 452 | 4.30% | 581 | 5.52% |
| | **Val** | 541 | 16 | 2.96% | 22 | 4.07% | 8 | 1.48% |
| | **Test** | 1,341 | 21 | 1.57% | 44 | 3.28% | 55 | 4.10% |
| | *Combined* | 12,405 | 333 | 2.68% | 518 | 4.18% | 644 | 5.19% |
| **2025-07-01** | **Train** | 10,523 | 258 | 2.45% | 423 | 4.02% | 619 | 5.88% |
| | **Val** | 541 | 10 | 1.85% | 18 | 3.33% | 14 | 2.59% |
| | **Test** | 1,341 | 9 | 0.67% | 31 | 2.31% | 67 | 5.00% |
| | *Combined* | 12,405 | 277 | 2.23% | 472 | 3.80% | 700 | 5.64% |

---

## 4. Transitive Vulnerability Temporal Reachability (Reference)

For comparison, when considering supply chain propagation along `dependsOn` edges (i.e. node or any upstream dependency package has a vulnerability):

| Cutoff $T$ | Split | Total ($N$) | Transitive Label A | Trans. A % | Transitive Label B | Trans. B % | Pre-$T$ History | Pre-$T$ % |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **2024-07-01** | Train | 10,523 | 790 | 7.51% | 2,194 | 20.85% | 2,234 | 21.23% |
| | Val | 541 | 87 | 16.08% | 154 | 28.47% | 74 | 13.68% |
| | Test | 1,341 | 146 | 10.89% | 476 | 35.50% | 392 | 29.23% |
| **2025-01-01** | Train | 10,523 | 704 | 6.69% | 2,102 | 19.98% | 2,320 | 22.05% |
| | Val | 541 | 66 | 12.20% | 150 | 27.73% | 95 | 17.56% |
| | Test | 1,341 | 136 | 10.14% | 469 | 34.97% | 402 | 29.98% |
| **2025-07-01** | Train | 10,523 | 523 | 4.97% | 2,076 | 19.73% | 2,501 | 23.77% |
| | Val | 541 | 47 | 8.69% | 137 | 25.32% | 114 | 21.07% |
| | Test | 1,341 | 99 | 7.38% | 426 | 31.77% | 439 | 32.74% |

---

## 5. Critical Observations & Feasibility Findings

1. **Severe Test Sparsity for Direct Label A at $T = \text{2025-07-01}$ (WARNING):**
   - The Test set (`saleor-storefront`, $N=1,341$) has only **9 positive nodes** (0.67%) under direct Label A.
   - An evaluation set with single-digit positive instances ($N_{\text{pos}} = 9$) lacks statistical power for ranking metrics (Spearman $\rho$, NDCG, Ranking Accuracy) and will suffer from extreme variance across seeds.

2. **Validation Imbalance at $T = \text{2024-07-01}$:**
   - In `practica` ($N=541$), only **2 nodes** (0.37%) had pre-$T$ vulnerability history, while 24 nodes had post-$T$ advisories. This indicates the dependencies in `practica` were largely free of known pre-2024 advisories until a wave of disclosures occurred in 2024/2025.

3. **Comparison of Cutoffs:**
   - **$T = \text{2024-07-01}$:** Offers the highest positive counts (Train: 346, Val: 22, Test: 25 for Label A; Train: 500, Val: 24, Test: 46 for Label B).
   - **$T = \text{2025-01-01}$:** Reasonable balance between pre-cutoff history and post-cutoff disclosure horizon (Train: 296, Val: 16, Test: 21 for Label A; Train: 452, Val: 22, Test: 44 for Label B).
   - **$T = \text{2025-07-01}$:** Feasibility is poor for direct Label A due to test starvation ($N_{\text{pos}} = 9$).

4. **Label B vs. Label A:**
   - Direct Label B maintains $N \ge 31$ positives across all test cutoffs (46, 44, 31), yielding substantially better support than Label A (25, 21, 9).
