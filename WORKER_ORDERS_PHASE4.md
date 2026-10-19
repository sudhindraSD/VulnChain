# 🛠️ WORKER ORDERS — PHASE 4 EXECUTION (Brain → Worker Handoff)

> **You are the Worker.** Another session (the Brain) has already made all strategic decisions below. Your job is disciplined execution, verification, and honest reporting — **not** re-decision-making. Full project background: [`CURRENT_CONTEXT.md`](./CURRENT_CONTEXT.md). Operational rules: [`VULNCHAIN_LESSONS_LEARNED.md`](./VULNCHAIN_LESSONS_LEARNED.md) (the 14 Commandments apply to you).

> **Terminology lock:** the merged corpus is called the **51-repo graph** (12,405 nodes, 60,792 `dependsOn` edges, file: `package_graph.json` at project root). Earlier notes saying "52-repo" refer to the same thing (52 selected, 1 lost to the Windows colon bug). Use "51-repo" everywhere.

---

## 0. Decisions Already Locked (do NOT re-litigate, do NOT deviate)

| Decision | Value |
|---|---|
| Execution order | **Phase A (9-repo smoke retrain) → Phase B (51-repo pipeline) → Phase C (51-repo train/eval)** |
| Phase A status | Smoke test / plumbing check only. Its numbers are **NOT results** and must never be recorded as held-out results anywhere. |
| 51-repo Test repo | `saleor-storefront` (exclusive nodes: 1,341) |
| 51-repo Val repo | `practica` (exclusive nodes: 541) |
| Split rule | The **Provenance Rule**: a node belongs to Val/Test only if EVERY repo in its `repo_sources` is in that split's repo group; mixed-provenance nodes → Train. |
| Expected 9-repo corrected split | Train **4,487** / Val **696** / Test **395** (total 5,578; test non-zero VPSS = 24) |
| Expected 51-repo split | Train **10,523** / Val **541** / Test **1,341** (total 12,405; mixed-provenance absorbed into train = 2,046) |
| OOD threshold | Locked at **≥ 0.40** on NodeTestBench. No post-hoc threshold tuning. Ever. |

---

## 1. Hard Rules (violating any of these = stop and report)

1. **Never overwrite or delete 9-repo audit artifacts.** `TrainModel/vulnchain_graph.json`, `TrainModel/vpss_labels.json`, `TrainModel/repo_split_mapping.json` (the old leaked one — it is forensic evidence), `TrainModel/models/vulngat_trained.pt`, all `.osv_records_cache.json` / `.npm_registry_cache.json` / `.github_*_cache.json` dotfiles. All 51-repo outputs go into a new **`phase4/`** directory at project root.
2. **Never create or rename any file to `epss_labels.json`** in a directory you run training from. `dataset.py:116` silently switches to EPSS labels if that file exists in the CWD. This already caused one bad experiment; do not resurrect it.
3. **Silent-skip = red flag.** `dataset.py` builds split indices with `if pid in pkg_id_to_idx`, which silently drops unknown IDs. After any split loads, assert the counts match the Expected table in §0 exactly. If even one ID is dropped, investigate before proceeding.
4. **No post-hoc metric shopping.** Thresholds, splits, and success criteria are pre-registered. If results look bad, you report them badly.
5. **Stop-and-report conditions** (write your report, end your run, hand back to the Brain): any §3/§4 gate fails · dangling edges > 0 after merge · split counts mismatch · `repo_sources` provenance missing from `package_graph.json` and unrecoverable · GitHub token invalid after the preflight · any real risk of clobbering a 9-repo artifact.
6. **Reporting protocol:** maintain `WORKER_REPORT_PHASE4.md` (template in §5) as you go. Update `CURRENT_CONTEXT.md` status lines/checkmarks only — never its conclusions or claims; those require Brain review.

---

## 2. Phase A — 9-Repo Corrected-Split Smoke Retrain

**Purpose:** prove the corrected split file plugs into the training stack cleanly. NOT to produce metrics. Training takes ~1 minute on the RTX 3050; that cheapness is exactly why we run it — insurance before committing hours to the 51-repo pipeline.

### A0. Parameterize the hardcoded paths (small, surgical patch)

`TrainModel/training/dataset.py:151` hardcodes `repo_split_path = "repo_split_mapping.json"` — the **old leaked mapping**. `TrainModel/training/train.py:85` hardcodes `model_save_path = "models/vulngat_trained.pt"` — the **production 9-repo model** that `analyze_project.py` depends on. Do not rename either file. Instead, add env-var overrides with today's behavior as default:

- `dataset.py`: `load_vulnchain_dataset(...)` gains `repo_split_path` param defaulting to `os.environ.get("REPO_SPLIT_FILE", "repo_split_mapping.json")`; same pattern for `graph_path` (env `GRAPH_FILE`) and `labels_path` (env `LABELS_FILE`). In the repo-split branch, **print how many IDs from each list were not found in the graph** (should be 0). Thread the param through from `train.py`.
- `train.py`: `model_save_path = os.environ.get("MODEL_SAVE_PATH", "models/vulngat_trained.pt")`.

Rules for the patch: backward compatible (no env vars set = identical behavior), minimal diff, match existing code style.

### A1. Run the smoke retrain

From `TrainModel/`:

```bash
REPO_SPLIT_FILE=repo_split_mapping_corrected_9repo.json \
MODEL_SAVE_PATH=models/vulngat_smoke_9repo_corrected.pt \
python training/train.py
```

### A2. Pass criteria (all must hold)

- [ ] Split printout: Train **4,487** / Val **696** / Test **395**, zero dropped IDs, test "Vulnerable: **24**"
- [ ] Training completes; early stopping fires normally; no NaN/inf in the loss column
- [ ] Final eval table renders for all three splits (numbers will be noisy — that's expected and fine)
- [ ] `models/vulngat_smoke_9repo_corrected.pt` saved; original `models/vulngat_trained.pt` untouched (verify mtime/content unchanged)
- [ ] No `epss_labels.json` created (dataset.py must print the VPSS label path, not EPSS)

Record the eval numbers in the report under **"Phase A — SMOKE TEST, NOT A RESULT"** with that exact label. Do not paste them into `CURRENT_CONTEXT.md` as results.

---

## 3. Phase B — 51-Repo Pipeline (Steps 2–6) with Gates

All work from the project root unless noted. Create `phase4/` first. Before running any pipeline script, read its header docstring for its exact input/output paths — several use hardcoded relative paths.

### B0. Persist the split generator (fixes the original sin)

The 9-repo mapping was generated inside a chat session and never persisted as code — that's how the leakage went unnoticed. Do not repeat it. Write **`generate_repo_split.py`** at project root:

- Input: `package_graph.json`. **First** inspect the node schema (`python -c "import json; g=json.load(open('package_graph.json')); print(g['nodes'][0])"`) and confirm the provenance field (expected: `repo_sources` or similar listing the repos a node came from). If it's missing, rebuild provenance by re-walking `repos/*/package-lock.json` (clones exist in `repos/`); if that's impossible → stop-and-report.
- Implements the Provenance Rule verbatim (§0). Groups: TEST_REPOS = {`saleor-storefront`}, VAL_REPOS = {`practica`}, everything else + all mixed nodes → train.
- Output: `phase4/repo_split_mapping_51repo.json` containing the three ID lists **plus** metadata: repo groups, per-split counts, generation date, and each node's `repo_sources`.
- Self-verify programmatically and print: (a) counts == 10,523 / 541 / 1,341 (if actuals differ by a few due to the earlier exclusivity analysis being on a slightly different snapshot, that's acceptable — but report the exact numbers and re-run the leakage check on YOUR numbers); (b) **0** val/test nodes with any train-provenance repo; (c) **0** overlap between the three lists.

### B1. (= Roadmap Step 2) OSV batch extraction

```bash
python osvExtractor.py
```

Reads `package_graph.json` (12,405 packages), resumable via `osv_vulns.json`, ~125 batches, ~10 min. Outputs land at root: `hasVulnerability_edges.json`, `cve_seed_ids.json`. Then run **Gate B1**:

- Write `phase4/gate_b1_nonzero_precheck.py`. Logic: non-zero VPSS ⟺ a package has ≥1 contributing (vulnerable-pkg, CVE) pair reachable via `dependsOn` BFS (CVSS is median-imputed > 0, decay and exposure > 0, so zero/non-zero is purely structural). Compute, **excluding `MAL-` IDs** (merge policy), the count of non-zero-VPSS nodes among the 1,341 `saleor-storefront` exclusive test IDs and the 541 `practica` val IDs.
- **GATE:** test non-zero count **≥ 150** → proceed. **< 150** → stop-and-report. This converts the "~200+ expected" estimate into a measured number BEFORE burning Steps 3–4. (Note in the report: this count is exact as of Step 2 data; merge-time MAL- drops and Step-3 fetch failures can only shrink it, and Step 6 re-verifies authoritatively.)

### B2. (= Step 3) CVE records + embeddings

Run `osvRecordFetcher.py` (uses `.osv_records_cache.json`; CVSS parsing already `float()`-cast) then `embedCveNodes.py` (frozen `all-mpnet-base-v2`, 768-dim). Confirm outputs exist and every CVE node has an embedding before moving on.

### B3. (= Step 4) Author extraction

Preflight FIRST (Commandment 13): verify `GITHUB_TOKEN` from `.env` against `https://api.github.com/rate_limit` — expect the 5,000 req/hr quota. If invalid → stop-and-report (do not start a 60 req/hr run). Then run `authorExtractor.py` (v2: resolve via npm `repository.url` → GitHub owner, never username guessing). Expect the upper end of 15–40 min (43 repos are cache misses). Cache files must grow, not be rewritten from scratch.

### B4. (= Step 5) Merge + validation

Run `merge_graph.py`. Confirm where it writes the merged graph; the 51-repo output must go to **`phase4/vulnchain_graph.json`** (pass args if supported, else adjust CWD so nothing lands on `TrainModel/vulnchain_graph.json`). All 6/6 validation checks pass, dangling edges = **exactly 0**, MAL- records excluded. Sanity-print node/edge counts by type.

### B5. (= Step 6) VPSS labels + authoritative gate

```bash
python vpss_labeler.py --graph phase4/vulnchain_graph.json --out phase4/vpss_labels_51repo.json
```

(`--verify` is read-only now; do NOT point `--out` at the 9-repo `TrainModel/vpss_labels.json` — that file is the bit-exactness anchor and must never be touched.)

- **GATE:** non-zero VPSS count within the `saleor-storefront` exclusive test set **≥ 150**. Then cross-check against Gate B1's structural count — they should match exactly (or shrink slightly via MAL-/fetch drops). Any **increase** or large delta → investigate before proceeding; report the reconciliation.
- Also record: total non-zero count, val (practica) non-zero count, median non-zero VPSS.

---

## 4. Phase C — 51-Repo Training, Evaluation, Audits

### C0. Pre-register the domain-shift caveat BEFORE any training run

Append this exact paragraph to `CURRENT_CONTEXT.md` §10.3 now, while results are still unseen (this is the point of pre-registration — do it first, timestamp it):

> **PRE-REGISTERED (before Phase C training):** The test repo `saleor-storefront` is a React/Next.js e-commerce frontend, whereas the training corpus is dominated by Express/Node.js backends and CLI utilities. If test metrics are materially worse than validation metrics on `practica`, the leading hypothesis is **ecosystem domain shift**, not model failure. We commit to reporting both splits side by side and to NOT re-picking test repos, re-tuning thresholds, or re-splitting post-hoc to close the gap. This caveat was registered before any 51-repo training run.

### C1. Train VulnGAT on the 51-repo graph

From `phase4/` (this CWD also guarantees the `epss_labels.json` trap can't fire):

```bash
GRAPH_FILE=phase4/vulnchain_graph.json \
LABELS_FILE=phase4/vpss_labels_51repo.json \
REPO_SPLIT_FILE=phase4/repo_split_mapping_51repo.json \
MODEL_SAVE_PATH=phase4/models/vulngat_51repo.pt \
python ../TrainModel/training/train.py
```

- [ ] Split printout: 10,523 / 541 / 1,341 (or your B0-verified actuals), zero dropped IDs
- [ ] Full training completes; note epochs, early-stop epoch, best val loss, wall time
- [ ] Report Train/Val/Test metric table verbatim. Also report non-zero-only subsets: Pearson/Spearman on test **non-zero VPSS nodes only** (N will be ~Gate B1's number — finally statistically valid)

### C2. Masked-edge robustness audit (Commandments 2, 3, 9)

Open `TrainModel/masked_edge_audit.py` and **verify feature dim 6 (`has_known_cve_history`) is zeroed whenever `hasVulnerability` edges are masked**. If not, fix it first — this exact backdoor already invalidated one audit. Run the audit at 50% edge mask on the 51-repo model. Success criterion (pre-registered): beat label propagation by **> 0.02 AUC**.

### C3. NodeTestBench OOD benchmark (Commandment 4)

Locate the existing NodeTestBench evaluation path (`grep -ri "nodetestbench\|NodeTestBench\|0.40" TrainModel/`). Point it at `phase4/models/vulngat_51repo.pt`. Report precision/recall at the locked **≥ 0.40** threshold ONLY. No threshold sweeps in the report.

### C4. No-graph ablation baseline (the circularity kill-shot)

The Brain requires this run: it answers "does the GNN earn its complexity, or is VPSS ≈ readable off the 10 input features?" Check `TrainModel/training/ablation.py` first — if it already implements a feature-only baseline, run it; otherwise write `phase4/mlp_baseline.py`: a small MLP (10-dim package features → 2 hidden layers → sigmoid → 1, MSE loss, same early stopping, **same split mapping, same labels, zero graph input**) trained on the same 51-repo data. Report its test metrics **side by side with VulnGAT's**. If the MLP matches the GNN, say so plainly — that's a finding, not a failure, and it's exactly why the headline claims must rest on C2/C3 rather than VPSS correlation.

---

## 5. Report Template — `WORKER_REPORT_PHASE4.md` (create at root, fill as you go)

```markdown
# Worker Report — Phase 4
## Phase A (SMOKE TEST, NOT A RESULT)
- patch summary (files, lines) · split counts · dropped IDs · run/early-stop info
- eval table (labeled: SMOKE) · original model file untouched: Y/N
## Phase B
- B0 split actuals + leakage check output
- B1 OSV stats + Gate B1 counts (test/val non-zero) + verdict
- B2/B3/B4/B5 run stats, merge validation results, VPSS stats + gate verdict + B1 reconciliation
## Phase C
- timestamp of §10.3 pre-registration insert (must precede training log timestamps)
- training log summary, val/test tables, non-zero-only correlations
- C2 audit AUC vs label propagation · C3 precision/recall @0.40 · C4 GNN vs MLP table
## Anomalies & deviations from orders
(anything you had to change, and why — no silent deviations)
## Files produced / artifacts
## Open questions for the Brain
```

---

## 6. Environment Facts & Known Traps

- Windows 10, Git Bash, RTX 3050 Laptop 6 GB VRAM (9-repo training peaked ~500–850 MB, 35–55 s — the 51-repo graph at 2.2x scale should still fit comfortably; if you OOM, report, don't quietly reduce layers).
- Repo clones live in `repos/`. Lockfiles: mixed v1/v2/v3, no Yarn Berry (pre-checked). `redos-detector` clone is empty (Windows colon bug) — that's known and already excluded.
- Root `package_graph.json` IS the 51-repo graph (12,405 nodes). `TrainModel/` IS the 9-repo workspace. Never mix the two.
- `vpss_labeler.py` default `--out` points at the 9-repo labels file — always pass explicit `--graph`/`--out` for Phase B.
- Do not commit or print `.env` contents; only report whether the token works and its quota tier.
