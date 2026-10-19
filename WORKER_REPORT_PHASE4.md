# Worker Report — Phase 4
**Worker run date:** 2026-09-18 · **Orders:** `WORKER_ORDERS_PHASE4.md` · **Status: LOCAL PIPELINE COMPLETE (B0–B5 all gates passed) — GPU training handed off to Colab**

> **Environment deviation (pre-approved by user, reported per Hard Rule 6):** This machine has **CPU-only torch** (`2.13.0+cpu`, no CUDA) and no PyG. Per the user's direction, **all model training and model-dependent evaluation (A1 smoke, C1, C2, C3, C4) execute in Google Colab on GPU** via `colab/VULNCHAIN_PHASE4_COLAB.ipynb` + `vulnchain_phase4_colab.zip` (9.9 MB). The local run covered the full data pipeline (B0–B5) and all code preparation.

## Phase A (SMOKE TEST, NOT A RESULT)
- **A0 patches applied** (all backward-compatible, no env var set = old behavior):
  - `TrainModel/training/dataset.py`: `load_vulnchain_dataset()` now accepts `repo_split_path` param; `graph_path`/`labels_path`/`repo_split_path` default to env `GRAPH_FILE` / `LABELS_FILE` / `REPO_SPLIT_FILE`. Split loader now prints **dropped-ID counts** per list (the silent-skip trap from Hard Rule 3).
  - `TrainModel/training/train.py`: dataset call threads the same env vars; `model_save_path` honors env `MODEL_SAVE_PATH` (protects `models/vulngat_trained.pt` from overwrite).
  - Local syntax verification only (no torch/PyG locally — no execution possible here).
- **A1 smoke run:** moved to Colab notebook cell (Phase A) with hard assertions:
  - split printout must contain `0 dropped (train=4487, val=696, test=395)`
  - test line must be `Test:  395 (Vulnerable: 24)`
  - model saved to `TrainModel/models/vulngat_smoke_9repo_corrected.pt`; original `vulngat_trained.pt` untouched
  - EPSS trap guard: notebook asserts `TrainModel/epss_labels.json` does NOT exist before running
- Corrected split file verified locally before handoff: **4,487 / 696 / 395** ✓ (counts read from `repo_split_mapping_corrected_9repo.json`).

## Phase B

### B0 — Split generator persisted + verified ✅
- Wrote **`generate_repo_split.py`** (project root) — the Provenance Rule as permanent code; reads `repo_sources` directly from `package_graph.json` (field confirmed present — no provenance rebuild needed).
- **`phase4/repo_split_mapping_51repo.json`** generated with `_metadata` (rule, repo groups, counts, per-node `repo_sources`, timestamp).
- Programmatic verification:
  - Counts: **Train 10,523 / Val 541 / Test 1,341** — EXACT match to orders §0 expectations.
  - Absorbed mixed-provenance train nodes: **2,046** — EXACT match to CURRENT_CONTEXT §10.2.
  - Leakage: 0 overlap between lists; 0 val/test nodes with provenance outside their repo group → **CLOSED**.

### B1 — OSV batch extraction ✅ + GATE B1 **PASS**
- `osvExtractor.py` over 12,405 packages: **978 packages with ≥1 vuln; 2,635 hasVulnerability edges; 873 unique vuln IDs** (vs pilot: 701 edges / 326 IDs → ~2.4x, consistent with 2.2x node scale).
- Wrote **`phase4/gate_b1_nonzero_precheck.py`** (structural non-zero VPSS predictor; MAL- excluded). Integrity reconciliation: cache and edges file agree exactly (978 vulnerable sources, 0 orphans; 1 fully-MAL package excluded — a git-URL pseudo-version; 2 other sources have mixed MAL+non-MAL edges and stay in via their non-MAL CVEs).
- **Gate B1 measured (pre-registered threshold ≥ 150):**
  - Test (saleor-storefront, 1,341 exclusive): **538 non-zero** (40.1%) — estimate "~200+" was conservative; 22x the corrected 9-repo test's 24.
  - Val (practica, 541 exclusive): **161 non-zero** (29.8%).
  - Whole graph: 3,723 / 12,405 (30.0%).
  - **VERDICT: PASS — statistical power requirement solved (538 ≥ 200 needed for stable correlations).**

### B2 — CVE records + embeddings ✅
- **B2a `osvRecordFetcher.py`:** 883 CVE/GHSA nodes built; **841 with CVSS (95.2%)**; 818 with CVE aliases; **0 vague IDs** (synthetic-text fallback path not needed this batch); MAL- skipped per policy.
- **B2b `embedCveNodes.py`:** 883 texts → 768-dim via frozen `all-mpnet-base-v2` (22 min CPU inference). Verified: all 883 embeddings exactly 768-dim, 0 nulls, 0 MAL-.
- Note: embeddings ran locally on CPU — inference-only, consistent with the "training in Colab" direction.

### B3 — Author extraction ✅ (2h 07m wall — npm phase ~60 min, GitHub repo phase ~70 min due to slow responses, user phase ~25 min)
- Preflight (Commandment 13): **GITHUB_TOKEN valid, 5,000 req/hr** (4,980 remaining at check). PASS.
- Final stats: **3,878 Author nodes** — 3,723 resolved via GitHub repo owner (96.0%), 155 npm-maintainer fallback; **1,691 with real account age (43.6%)**, **3,683 with real last-commit data (95.0%)**; 12,390 `maintainedBy` edges; 2,635 `introducedBy` edges (exactly matches the 2,635 hasVulnerability edges). 750 new GitHub-user lookups, 81 maintainer-count lookups.
- **Deliberate parallelization:** B3 started while B2a was still fetching (independent APIs; B3's input `hasVulnerability_edges.json` already existed) — sequence deviation logged per Hard Rule 6; no data dependency violated.
- Cache files grew incrementally (`.npm_registry_cache.json` → 5,686 names; `.github_repo_cache.json` → 3,819 repos; `.github_user_cache.json` → +750 users). Nothing overwritten from scratch.

### B4 — Merge ✅ **6/6 validation checks passed, 0 dangling edges**
- `merge_graph.py` patched for Phase 4 before running (3 surgical edits):
  1. `OUTPUT` → **`phase4/vulnchain_graph.json`** (9-repo artifact in `TrainModel/` untouchable).
  2. `supplement_packages.json` now optional (file didn't exist at root; 51-repo extraction is complete — script would otherwise crash).
  3. Metadata `repos` now **computed from actual `node.repo_sources`** (was hardcoded to the 9 pilot repos — would have mislabeled the 51-repo graph's metadata); strapi note generalized to cover redos-detector too.
- Output: **`phase4/vulnchain_graph.json`** (22.6 MB): **17,166 nodes** (12,405 Package + 883 CVE + 3,878 Author), **78,443 edges** (60,789 dependsOn + 2,632 hasVulnerability + 12,390 maintainedBy + 2,632 introducedBy).
- MAL- policy applied at merge: 3 MAL- hasVulnerability + 3 introducedBy edges dropped (1 fully-MAL package excluded: a git-URL pseudo-version `scrypt-shim@github:...`; 2 other MAL-affected packages retained via their non-MAL CVEs).
- Imputation: 136 sentinel pairs (dims 4/5) median-imputed; 42 null-CVSS CVEs median-imputed at merge; Author nulls imputed.
- **Micro-anomaly (for the ledger):** 3/60,792 dependsOn edges (0.005%) were dangling in `package_graph.json` and were correctly dropped by merge: `pretty-format@30.4.1 → react-is-19@19.2.7`, `@docusaurus/core@2.4.3 → react-loadable@5.5.2` ×2. Root cause: **npm alias dependencies** (`npm:name@version` syntax) create lockfile keys (e.g. `react-is-19`) that don't reconstruct to canonical `name@version` ids. Candidate extractor fix for the Brain to schedule (resolve alias keys to the resolved package id).

### B5 — VPSS labels ✅ **GATE PASS with exact reconciliation**
- `vpss_labeler.py --graph phase4/vulnchain_graph.json --out phase4/vpss_labels_51repo.json` (9-repo labels file untouched).
- **3,723 / 12,405 packages with reachable vulns (30.0%)** — **exactly matching Gate B1's structural prediction (3,723)**; zero shrinkage from MAL-/fetch drops.
- **Authoritative gate numbers:** Test (saleor-storefront): **538 non-zero / 1,341 (40.1%)**, median non-zero VPSS 0.2852. Val (practica): **161 non-zero / 541 (29.8%)**, median 0.3761. Whole-graph median non-zero: 0.3416.
- **GATE: 538 ≥ 150 → PASS** — statistical power requirement solved (538 ≫ 200 minimum for stable correlation estimates; 22x the corrected 9-repo test's 24).

## Phase C

### C0 — Pre-registration ✅ (timestamped BEFORE any training)
- Exact pre-registered paragraph appended to `CURRENT_CONTEXT.md` §10.3, dated **2026-09-18**: domain-shift hypothesis named in advance; commitment to report val (practica) and test (saleor-storefront) side by side; NO post-hoc test-repo re-picking, threshold re-tuning, or re-splitting.

### Colab deliverable (built; ready for GPU run)
- **`colab/VULNCHAIN_PHASE4_COLAB.ipynb`** — 16 cells, all code cells compile as pure Python (magics converted to subprocess; the `!git`-inside-`if` fragility removed). Flow: GPU check → Phase A smoke (with hard assertions) → C1 training → C1b full + non-zero-only metrics + predictions export → C2 audit → C3 NodeTestBench (locked ≥0.40, ground truth = `cve` field non-null) → C4 MLP baseline + side-by-side table → results zip download.
- **`vulnchain_phase4_colab.zip`** — auto-built by `phase4/build_colab_package.py` once B4/B5 outputs exist (checker refuses to zip incomplete data).

### C1 (Colab) — expected protocol
- Train VulnGAT on 51-repo graph (env-var paths; split assertion `0 dropped (train=10523, val=541, test=1341)` hard-checked in notebook).
- Non-zero-only Pearson/Spearman on test (n≈538) — the statistically valid headline.

### C2 audit fix (applied locally, verified by code read)
- **Dim-6 backdoor WAS present** in `TrainModel/masked_edge_audit.py`: `apply_edge_mask` deleted hasVulnerability edges but left `has_known_cve_history=1` in features — the exact cheat from the first invalidated audit.
- **Fixed:** masked packages' Package feature dim 6 zeroed in `apply_edge_mask` (Commandment 2). Also added env-var path overrides (`MODEL_PATH`, `GRAPH_FILE`, `LABELS_FILE`, `REPO_SPLIT_FILE`, `AUDIT_OUT`) and explicit `repo_split_path` threading. Pre-registered success criterion: > 0.02 AUC over label propagation at 50% mask.

### C3 NodeTestBench (Colab)
- **Discovery:** no persistent NodeTestBench eval code or data exists in the repo (grep: docs only) — same generation-loss pattern as the original split mapping. Protocol reconstructed from `VULNGAT_EVALUATION_REPORT.md` §6: clone `contrast-security-oss/NodeTestBench`, run `analyze_project.py` (confirmed CLI: `analyze_project.py <lockfile> --json out`; reads `vulnchain_graph.json` + `models/vulngat_trained.pt` from CWD — notebook stages a `bench_run/` dir with 51-repo artifacts), ground truth = rows with non-null `cve`, threshold LOCKED ≥ 0.40, no sweeps. If the repo 404s on clone → cell reports blocked (no benchmark substitution allowed).

### C4 MLP baseline (script written, runs in Colab)
- **`phase4/mlp_baseline.py`**: 10 → 64 → 64 → 1 → Sigmoid; MSE; Adam lr=1e-3/wd=1e-5; patience 10 — all mirroring `train.py`. Loads via `load_vulnchain_dataset` for identical preprocessing; **zero graph structure used**. Emits `mlp_baseline_results_51repo.json`; notebook prints VulnGAT vs MLP side-by-side on test (MAE, MSE, Pearson(nz), Spearman(nz), RankAcc).

## Phase C Results (executed in Colab on Tesla T4 — user run 2026-09-18; results archived in `phase4/results_colab/`)

### Phase A smoke ✅ (plumbing only, NOT a result)
- Split printed **4,487 / 696 / 395, 0 dropped**, test vulnerable **24** — all notebook assertions passed. `vulngat_smoke_9repo_corrected.pt` saved; production artifacts untouched.

### C1 — VulnGAT 51-repo training
- Split assertions passed: **0 dropped (train=10523, val=541, test=1341)**; test vulnerable **538** (matches Gate B1/B5 exactly).
- **Training stopped at epoch 13 / 3.32 seconds** — val MSE bottomed at epoch 3 (0.06839) then worsened; patience 10 fired. Best val MSE 0.0684.
- Loss decomposition (epoch 3+): total ≈ 0.85, of which **0.1 × InfoNCE ≈ 0.79 — InfoNCE is ~93% of the loss and sits at chance (~7.9 ≈ ln 2048) for the entire run**. MSE was a minor term.
- Predictions are near-constant: top-10 test scores span only 0.3114–0.3412, and the top ranks are filled with **dev tooling** (`@types/*`, `eslint-plugin-*`, `typescript`) — dev/TS packages outrank genuinely vulnerable production libs.

| Test metric (saleor-storefront, n=538 nz) | **VulnGAT** | **MLP (no graph)** |
|---|---:|---:|
| MAE | 0.1677 | **0.1436** |
| MSE | 0.0581 | **0.0383** |
| Pearson (non-zero) | 0.4263 | **0.5716** |
| Spearman (non-zero) | 0.2227 | **0.4944** |
| Spearman (all) | **−0.2357** | 0.4426 |
| Ranking accuracy | **39.1%** (< coin flip) | **72.2%** |
| Val (practica) RankAcc | 48.7% | 75.1% |

- **The MLP ran its full 200 epochs** (val MSE still improving at cap: 0.0515) vs the GNN's 13 epochs / 3.3 s.
- Domain shift: test RankAcc (39.1%) < val (48.7%) < train (38.8%?) — NOTE train itself is 38.8%, so **the model cannot even rank its own training labels**; this is not a domain-shift story, it is an optimization failure. The pre-registered domain-shift caveat stays in place but is NOT the operative explanation.

### C2 — Masked-edge audit (dim-6 backdoor fix ACTIVE): **Outcome 3 — pre-registered criterion FAILED**
- Model AUC 0.397 < BFS 0.534 < **label-prop 0.721** at 50% mask. Required: beat label-prop by > 0.02 → **FAILED** (model is *below chance*, AUC 0.40 — masked-vulnerable packages rank BELOW never-vulnerable ones).
- Feature-shuffle drop ≈ 0.0000 at every mask ratio → **the model uses no CVE-embedding signal at all**.
- MRR 0.008–0.012 vs random floor 0.0011 (7–10× above chance, absolute still tiny).
- The dim-6 fix is what exposed this: with `has_known_cve_history` unmasked the model would have looked healthy by reading the backdoor — the same cheat as the invalidated first audit.
- Audit's own distribution-shift caveat applies: the model was never trained to handle masked edges.

### C3 — NodeTestBench OOD (threshold locked ≥ 0.40): **Precision 100% holds**
- **N=671 | TP 25 | FP 0 | FN 52 → Precision 100.0%, Recall 32.5%.**
- Precision claim survives the clean re-run: every package flagged ≥ 0.40 is CVE-confirmed. Caveats that must ride along: (a) recall denominator grew 40 → 77 vs the 9-repo era because ground truth is OSV-confirmed with the 2.7× larger KB — the 77.5% → 32.5% drop is NOT comparable; (b) the 0.08 calibration cap suppresses false positives, so precision is partly pipeline engineering (documented ~70% pipeline credit); (c) FN=52 means the model left 52 known-vulnerable packages below threshold.

### C4 — No-graph MLP baseline: **DECISIVE**
- **The feature-only MLP beats VulnGAT on every metric, on every split** (table above). VPSS is substantially predictable from the 10 package features alone (depth, directness, dev-status, CVE history dim, popularity) — **Diagnosis A (VPSS redundancy/circularity) is now empirically quantified on a clean split**, and the GNN currently contributes *negative* value on top of those features (inverted zero-vs-nonzero separation: Spearman-all −0.24, RankAcc 39%).
- This retroactively confirms why the Aug-28 r = 0.4320 was not evidence of GNN value: the same or better correlation is available with no graph at all.

### Brain-level diagnosis of the GNN failure (for the ledger — worker executed, brain analyzed)
1. **Training budget:** 13 epochs / 3.3 s vs MLP's 200 epochs. Val MSE best at epoch 3 then flat-noisy on a 541-node single-repo val set → early stop fired long before convergence. Train MSE was still ~0.056 at stop; predictions near-constant.
2. **Loss imbalance:** with InfoNCE stuck at chance (~7.9), 0.1 × InfoNCE ≈ 0.79 dominates total loss (~93%) — the model was primarily optimized for a contrastive objective it never improved on, with MSE as a perturbation. Design-doc weight 0.1 is only sane if InfoNCE is O(1)-normalized; it isn't.
3. **Metric flattery pattern repeats:** low MAE/MSE vs zero-inflated labels (the §13.4 debunk) — RankAcc/Spearman-all expose what MSE hides. Zero-inflated MSE cannot be the headline metric of this project.
4. **What survives:** C3 precision at the locked threshold; the leak-free pipeline itself; the provenance methodology; the MLP as the honest reference model.
5. **Not proven:** that the HAN architecture cannot work. A VulnGAT-v2 run with (a) InfoNCE weight ~0.01 or normalized to O(1), (b) max_epochs 200 + min_epochs before early stop, (c) patience re-tuned on a less noisy val signal, is a legitimate post-hoc protocol iteration — must be labeled as v2/post-hoc, and its success criterion remains beating label-prop by >0.02 AUC and the MLP on rank metrics, not VPSS correlation.

## Anomalies & deviations from orders
0. **Brain-side notebook bugs caught on first Colab execution (both fixed, zip rebuilt):**
   - C1b metrics cell indexed masks as `masks[s]` but `load_vulnchain_dataset` returns keys `"train_mask"/...` → `KeyError: 'train'`. Model had already trained and saved before the crash (user's run confirmed: 0 dropped IDs, 10,523/541/1,341, test vulnerable 538 — matches Gate B1 exactly). Fix: `masks[s + "_mask"]`.
   - C3 bench cell copied `analyze_project.py` into `bench_run/` without the `core/` package it imports → `ModuleNotFoundError: No module named 'core'`. Fix: `shutil.copytree("TrainModel/core", "bench_run/core", dirs_exist_ok=True)` added to the cell.
   - C3 bench cell passed the lockfile path relative to the notebook CWD while the subprocess ran with `cwd="bench_run"` → subprocess looked for `bench_run/bench_run/...` → `[ERROR] File not found`; `analyze_project.py` exits 0 on that error so `run()` didn't catch it, and the cell crashed later at `json.load`. Fix: pass `os.path.abspath(locks[0])` + explicit assert that `bench_results.json` exists after the run.
1. **Training/eval relocated to Colab** (user decision mid-run after local env check found CPU-only torch + missing PyG). Local work = pipeline + code prep + notebook. Not a deviation from orders' logic; orders' A1/C1/C2/C3/C4 execution environment changed.
2. **B3 parallelized with B2a** (documented above; no dependency violated).
3. **`merge_graph.py` metadata edit** beyond the two ordered changes: hardcoded 9-repo `repos` list + strapi note replaced with computed repo list + general exclusions note — without this, the 51-repo graph would carry false metadata.
4. **Feature-order doc discrepancy discovered (report-only, no doc edit):** `CURRENT_CONTEXT.md` §3.1 table disagrees with the code's actual 10-dim Package feature order. Ground truth (from `package_graph.json`'s own `feature_order` + `merge_graph.py` + `dataset.py` comments): `[is_direct, is_dev, out_degree, depth_in_tree, version_recency_days, versions_behind_latest, has_known_cve_history, weekly_downloads_log, is_deprecated, license_risk_flag]`. The §3.1 table (which lists `dependency_depth` at dim 2, `num_dependencies`/`num_dependents`/`is_scoped_package` at 6/7/8) is stale. **Dim 6 = has_known_cve_history is correct in all audit lore** (matches Commandment 2). Brain should decide whether to fix §3.1.
5. **`build_colab_package.py` zip-gate**: refuses to build the zip until `phase4/vulnchain_graph.json` + `vpss_labels_51repo.json` exist — prevents shipping an incomplete package.

## Files produced / artifacts
| File | Purpose |
|---|---|
| `generate_repo_split.py` | Provenance Rule split generator (persistent, replaces session-lost logic) |
| `phase4/repo_split_mapping_51repo.json` | 51-repo split (10,523/541/1,341, 0 leakage, verified) |
| `phase4/gate_b1_nonzero_precheck.py` | Structural non-zero VPSS gate (ran: PASS 538) |
| `phase4/vulnchain_graph.json` | **51-repo merged graph: 17,166 nodes / 78,443 edges, 6/6 checks** |
| `phase4/vpss_labels_51repo.json` | **51-repo VPSS labels: 3,723 non-zero; test 538 / val 161** |
| `phase4/mlp_baseline.py` | C4 no-graph baseline |
| `phase4/build_colab_package.py` | Notebook + zip builder |
| `colab/VULNCHAIN_PHASE4_COLAB.ipynb` | GPU training/eval notebook (16 cells, all compile) |
| `vulnchain_phase4_colab.zip` | **9.9 MB Colab upload package (code + 9-repo smoke data + 51-repo data)** |
| Root pipeline outputs | `hasVulnerability_edges.json`, `cve_seed_ids.json`, `osv_vulns.json`, `cve_nodes.json`, `cve_nodes_embedded.json`, `author_nodes.json`, `maintainedBy_edges.json`, `introducedBy_edges.json` (51-repo scale; 9-repo versions preserved untouched in `TrainModel/`) |
| Modified code | `TrainModel/training/dataset.py`, `TrainModel/training/train.py` (env vars + dropped-ID check), `TrainModel/masked_edge_audit.py` (dim-6 fix + env paths), `merge_graph.py` (3 edits), `CURRENT_CONTEXT.md` (§10.3 pre-registration only) |

## Colab handoff — what the user does next
1. Download/upload **`vulnchain_phase4_colab.zip`** (project root, 9.9 MB) — no other files needed.
2. Open **`colab/VULNCHAIN_PHASE4_COLAB.ipynb`** in Colab (or upload the zip first and open the notebook from inside it — the notebook's first cell handles extraction either way; if the notebook is opened standalone, upload the zip when the first cell prompts).
3. Runtime → Change runtime type → **GPU** → Run all.
4. The notebook asserts Phase A's split numbers and Phase C1's split numbers programmatically and stops loudly on mismatch.
5. Download `phase4_results.zip` at the end and hand it to the Brain with this report.

## Open questions for the Brain
1. Approve §3.1 feature-order doc fix (stale table) — one-line-per-row correction or full table rewrite?
2. npm **alias-dependency** extractor fix (3 dangling dependsOn edges, 0.005%) — schedule for a future extractor patch, or accept the merge-time drop as the permanent policy? (Worker recommendation: document as known limitation now; fix extractor post-Phase-4.)
3. `authorExtractor.py` wrote 51-repo-scale `author_nodes.json` / `maintainedBy_edges.json` / `introducedBy_edges.json` at root (no prior root copies existed — nothing overwritten). Confirm that's the intended canonical location going forward.
