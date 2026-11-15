# PROOF_PROTOCOL.md — STEP 4 PROOF MODULE (pre-registration)

- **Branch:** `proof-module`, cut from `02b68dc3de85aec2a475b1e0442da792ab825bc8` (hybrid-cs).
- **Written:** 2026-11-15 10:02:56 IST (2026-11-15T04:32:56Z).
- **Status:** FROZEN. This file is committed alone, before any code. It is never edited after its commit.
- **Time-box:** 3 days (planning bound only; not a data-collection stop rule).
- **Scope limits:** no new models, no GNN training or retraining, no new ideas, no edits to `phase5/`, no edits to any frozen gate file, no merge of `proof-module` back into any other branch.

---

## 0. Frozen inputs (hashes taken before any code was written)

| Input | SHA-256 | Role |
|---|---|---|
| `demo/sample-lock.json` | `f7a147023dcd3d1fa12c6451b5a93e441e415fb9835b561cffa6f123623314ba` | sample lockfile (small, real, lockfileVersion 3, 193 `packages` entries; contains known vulnerable transitive dependencies incl. `lodash@4.17.15`, `axios@0.18.0`) |
| `phase5/bench_run/vulnchain_graph.json` | `8fe4dca9e3e001cab708c8f987d8f46dd80684dfcea3f963b3ab13665cf0c72d` | advisory source part 1: `edges.hasVulnerability` (`source` = `name@version`, `target` = advisory ID) |
| `phase5/bench_run/osv_cache.json` | `aade9a5d13937f16d06de18ea70cf6034cb16fd8554ccb97411fcf7561423335` | advisory source part 2: cached OSV lookups (key = `name@version`, `cve_id`) |
| `phase5/confirm_metrics.json` | `0225d3e3bb4310e60640d6d48a2c58a9c6559b834a2b0d0f41ddab35d329e960` | Task D numbers (must be PARSED, never typed) |

`data_pipeline/osv_vulns.json` exists but is **not** read by the analyzer (`phase5/bench_run/analyze_project.py`) and is therefore **not** part of the advisory source. `phase5/bench_run/models/vulngat_trained.pt` is frozen and is **not executed**: torch is not installed and no model inference is performed in this module.

### 0.1 The advisory source the tool uses (fixed definition)

`analyze_project.py` builds its vulnerability map from exactly three things: (i) `vulnchain_graph.json` `edges.hasVulnerability`, (ii) `osv_cache.json` `cve_id` entries, and (iii) live queries to `https://api.osv.dev/v1/query` when `--offline` is not set. Accordingly:

- **OFFLINE advisory set** `ADV_OFF(p)` for a package id `p = name@version` = the sorted, de-duplicated set of advisory IDs from (i) all `hasVulnerability` edges whose `source == p`, plus (ii) `osv_cache.json[p]["cve_id"]` when non-null. No network.
- **ONLINE advisory set** `ADV_ON(p)` = the sorted, de-duplicated set of `vulns[].id` returned by a live `POST https://api.osv.dev/v1/query` with body `{"version": <version>, "package": {"name": <name>, "ecosystem": "npm"}}`. It does **not** include `ADV_OFF`. Timeout 8 s, zero retries, 8 concurrent workers. A failed/timed-out query gives status `NO_ONLINE_RESULT`, not an empty set.
- The verifier's advisory check uses **ADV_OFF only**, because that is what the proof CLI prints against.

---

## 1. Claim

> For every flagged package, the tool prints the exact dependency path from the project root to a vulnerable descendant, checkable by hand.

Operational definitions, fixed here:

- **Project root** = the `""` entry of `package-lock.json` `packages` (name/version from that entry, or from top-level `name`/`version`).
- **Package id** = the string `name@version`.
- **Vulnerable node** = a lockfile node whose id `p` has `ADV_OFF(p) != {}`.
- **Flagged package** = any non-root lockfile node that is (a) reachable from the project root over resolved `dependsOn` edges, and (b) has a vulnerable node reachable from it over zero or more resolved `dependsOn` edges (so a vulnerable node flags itself, and every ancestor of a vulnerable node is flagged). Nodes excluded by (a) or (b) are counted as `excluded_not_reachable` / `excluded_no_vulnerable_descendant`.
- **Exact path** = a simple path (no repeated lockfile node key) of lockfile nodes `root -> ... -> vulnerable descendant`, printed as a list of `name@version` strings with the exact versions recorded in the lockfile.
- **One path per flagged package**, selected mechanically: among all simple root-to-vulnerable paths of at most `MAX_HOPS = 8` edges that pass through the flagged package, choose the one with the fewest edges; tie-break by lexicographically smallest sequence of `name@version` strings. No other path is printed and no path is hand-picked.
- Path enumeration is pruned to nodes with a finite distance-to-any-vulnerable-node and capped at `MAX_PATHS = 200000`; hitting either cap sets `truncated = true` and is reported, never hidden.
- **Printed per flagged package:** `package@version`, the path, the advisory ID(s) of the vulnerable descendant, and `model_score`.

### 1.1 Model score (fixed; no model is run)

`model_score` is a **lookup**, not a computation and not a new model. It is the frozen VulnGAT-HR `risk_score` from the tracked analyzer reports, scanned in this fixed order:

1. `phase5/bench_run/bench_results_hr.json`
2. `phase5/bench_run/hr_*_lock.json` in lexicographic filename order
3. `phase5/demo/vc_*.json` in lexicographic filename order

matched on **exact** `name@version`; first match wins. If no exact match exists, `model_score = null` and the CLI prints `model_score: UNRESOLVED`. No imputation, no interpolation, no fallback score. The count of `UNRESOLVED` is reported in `PROOF_RESULT.md`.

---

## 2. Independence rule

`proof/verify_paths.py` is the independent verifier. It:

- parses `package-lock.json` **directly** with its own parser;
- imports **nothing** from the project's graph, model, or feature code — no `vulnchain`, no `phase5`, no `data_pipeline`, no `webapp`, no `TrainModel`, no relative imports, no `torch`, no `numpy`;
- imports **only** Python stdlib modules plus `json` (already stdlib): the allowed set is `argparse, collections, hashlib, json, os, pathlib, re, sys, typing`;
- reads only three kinds of **data**: the lockfile, `flagged_packages.json`, and the two frozen advisory-source JSON files; it never imports a project module and never reads the CLI's graph/path code;
- must be runnable as a standalone script from a fresh checkout with no installed dependencies.

`verify_paths.py`'s parser deliberately re-implements lockfile parsing. Any shared code between the CLI and the verifier would void the independence claim. `graph_subgraph.json` is built **from that independent parser**, so the exported subgraph is not derived from the CLI's graph code.

---

## 3. Path verification (what `verify_paths.py` checks)

For every printed path `[p_0, p_1, ..., p_n]`:

1. **Root check**: `p_0` must equal the root's `name@version`.
2. **Node resolution**: each `p_i` must resolve to at least one lockfile node key with exactly that name and exactly that version. The verifier searches over all candidate keys.
3. **Edge check, including nested `node_modules` resolution**: for each consecutive pair `(p_i, p_{i+1})` there must exist an assignment of node keys `k_i, k_{i+1}` such that `k_{i+1}` is the resolution of `p_{i+1}`'s name as a dependency of `k_i`. Resolution follows npm nesting: try `k_i + "/node_modules/" + dep_name`, then repeatedly walk up `k_i` by stripping the trailing `"/node_modules/<segment>"` and trying again, ending at root-level `"node_modules/" + dep_name`. The dependency must actually be declared in `k_i`'s `dependencies` (or `devDependencies` for the root). Matching on names alone is **not** sufficient.
4. **Version check**: every `k_i`'s recorded version must equal the version string in `p_i` exactly.
5. **Endpoint advisory check**: `p_n` must have `ADV_OFF(p_n) != {}`, i.e. the vulnerable descendant carries an advisory ID from the advisory source the tool uses. The ID(s) printed by the CLI must be a subset of `ADV_OFF(p_n)`.
6. **Simplicity check**: no node key repeats within the path.

The verifier uses backtracking over candidate keys; the first fully valid assignment yields PASS. Otherwise the path is FAIL and the verifier records the **failing edge** as `{"from": p_i, "to": p_{i+1}, "reason": ...}` (or `failing_check` for root/version/endpoint/simplicity failures). Every failure is listed and counted in `verify_report.json`; failures are reported, never dropped, never hidden.

---

## 4. npm audit comparison

- Command (run in a temp dir containing the exact sample lockfile bytes plus a `package.json` reconstructed only from the lockfile root's `dependencies`/`devDependencies`): `npm audit --json`. Exit code 1 is a normal "vulnerabilities found" result, not a crash. stdout/stderr and exit code are all recorded.
- **Comparison item** = a `name@version` in the lockfile that a tool reports as vulnerable (carries an advisory ID / is listed as vulnerable). `VC_ITEMS` = all lockfile nodes with `ADV_OFF != {}`. `NPM_ITEMS` = `name@version` pairs derived from `npm audit --json` `vulnerabilities[*].nodes` resolved against the lockfile (fallback: root-level `node_modules/<name>` entry). Items outside the lockfile are recorded as `UNMATCHED_NPM_ITEM`, not discarded.
- **Three groups**: `found_by_both = VC_ITEMS ∩ NPM_ITEMS`; `vulnchain_only = VC_ITEMS − NPM_ITEMS`; `npm_audit_only = NPM_ITEMS − VC_ITEMS`.
- Every item in `vulnchain_only` / `npm_audit_only` gets exactly **one** cause label. Items in `found_by_both` get `NOT_A_DISCREPANCY`.
- **FIXED rule list**, applied in this exact priority order, first match wins; decisions are made from recorded fields only:

| # | Label | Decidable predicate |
|---|---|---|
| R1 | `advisory_db_differences` | `npm_ids(item)` is non-empty and (`ADV_OFF(item)` is empty or `ADV_OFF(item) ∩ npm_ids(item) == {}`), i.e. the two sources cite disjoint/missing advisory IDs for this exact `name@version`. `npm_ids` = advisory IDs from `via[].url`/`via[].name`/`source` in the npm audit record. |
| R2 | `version_range_resolution` | the same package **name** has an advisory ID in `ADV_OFF` at some other version `v' != v`, or the npm audit record's `range`/`vulnerable_versions` string does not contain the exact installed version `v` as a substring. (Our source is exact-version keyed; npm audit is range based.) |
| R3 | `dev_vs_prod_scope` | **all** lockfile entries for this `name@version` carry `dev: true`, and the item appears in only one of the two groups. |
| R4 | `transitive_depth` | the shortest verified path from the project root to this `name@version` has `>= 5` edges, matching the frozen analyzer's `attack_paths` depth cap (`len(curr_path) < 5`). |
| R5 | `tool_bug` | the item is listed in `proof/out/tool_bug_cases.json` with a recorded failing case (file, line, test). This file is empty by default; R5 therefore does not fire unless a defect is explicitly recorded there. |

- **Items matching no rule are labelled `UNEXPLAINED`, not forced into a rule.** `UNEXPLAINED` count is reported explicitly.
- If `npm audit --json` cannot be run at all (missing binary, network failure, invalid output), the comparison is recorded as `NOT_COMPLETED` with the exact error text; no groups are fabricated, and criterion (b) is FAIL.

---

## 5. Offline vs online agreement

- **Offline** = `ADV_OFF` as defined in §0.1: cached/frozen advisories only, zero network calls.
- **Online** = `ADV_ON` as defined in §0.1: live OSV.dev query per package, zero cached advisories mixed in.
- Unit of comparison = every distinct `name@version` in the sample lockfile.
- For each package with status `OK`, `agree = (ADV_OFF(p) == ADV_ON(p))` (exact string-set equality; empty == empty counts as agreement).
- **Agreement-rate formula (fixed):**

```
D          = { p : online_query_status(p) == "OK" }
agree_count = |{ p in D : ADV_OFF(p) == ADV_ON(p) }|
A          = agree_count / |D|          (undefined, reported as N/A, if |D| == 0)
```

- `NO_ONLINE_RESULT` packages are excluded from `D` but their count and IDs are reported. Also reported: `offline_only_count`, `online_only_count`, `both_nonempty_disagree_count` — all pure counts, no interpretation.

---

## 6. Case studies (rule fixed here, before looking at any results)

Exactly three, chosen mechanically; tie-break alphabetical ascending on `name@version` everywhere; no cherry-picking and no substitution when a group is empty:

1. **CS1 — deepest verified path**: the flagged package whose printed path has the maximum number of edges; tie-break alphabetical by `name@version`. If multiple printed paths exist for one package, use its printed path.
2. **CS2 — one VulnChain-only item**: alphabetically first item of `vulnchain_only`. If the group is empty, record `EMPTY` with count 0.
3. **CS3 — one npm-audit-only item**: alphabetically first item of `npm_audit_only`. If the group is empty, record `EMPTY` with count 0.

Each case study reports: the path (or `NO_PATH` if the item is not on any printed path), advisory ID(s), and the `verify_paths.py` result for that path. Selections never involve judgement about which example looks better.

---

## 7. Success criteria

- **(a)** 100% of printed paths pass `verify_paths.py` **OR** every failure is listed and counted in `verify_report.json` and `PROOF_RESULT.md`. Reported as `PASS` with `paths_total`, `paths_pass`, `paths_fail`. A failure that is hidden or dropped makes (a) FAIL regardless of the pass rate.
- **(b)** npm audit comparison **completed** with the `UNEXPLAINED` count reported. Reported as `PASS` only if the command ran and produced parseable JSON, all three groups were computed, and `unexplained_count` is present.
- **(c)** fresh-clone test passes: a clean clone of `proof-module`, a fresh virtualenv, install from scratch, then CLI + `verify_paths.py` + all six exports regenerate and every JSON is valid. Reported with the exact commands and their results.

All three are reported PASS/FAIL with counts; none is silently upgraded.

---

## 8. Outputs (single source of truth for the frontend)

All under `proof/out/`:

| File | Required content |
|---|---|
| `flagged_packages.json` | per package: `paths` as lists of `"name@version"` strings |
| `verify_report.json` | per path pass/fail and `failing_edge` if any, from `verify_paths.py` |
| `npm_audit_comparison.json` | three groups, cause label per item, `unexplained_count` |
| `graph_subgraph.json` | per flagged package: `nodes [{id, direct, depth, advisories}]`, `edges [{from, to}]`, `verified_path`, `truncated`; parsed by `verify_paths.py`'s parser; **cap 300 nodes**, truncation recorded |
| `audit_scores.json` | `LP_original`, `LP_clean`, `HR`, `BFS` (parsed from the frozen `phase5/HYBRID_GATE.md` table, not typed), plus Task D numbers **PARSED from `phase5/confirm_metrics.json`** (not typed) |
| `meta.json` | source commit hash, timestamp, lockfile hash |

Auxiliary outputs (also valid JSON): `offline_online.json`, `case_studies.json`, `tool_bug_cases.json`, `fresh_clone_log.json`.

---

## 9. Build and run order

- **PHASE 0**: this file, committed alone. No code exists before that commit.
- **PHASE 1**, one commit per item, in order: (1) CLI `python -m vulnchain.proof <lockfile>`; (2) `proof/verify_paths.py` committed alone; (3) npm audit comparison script + classification; (4) offline/online agreement script; (5) case-study generator.
- **PHASE 2**: six JSON exports to `proof/out/`.
- **PHASE 3**: fresh-clone test.
- **PHASE 4**: independence audit (list every import in `verify_paths.py`; any project import = FAIL), then `PROOF_RESULT.md` committed alone.

### RUN RULES

1. **No edits after commit.** `PROOF_PROTOCOL.md` and `PROOF_RESULT.md` are never edited after their commits. If any other committed file needs a change, it happens in a new commit **and** is recorded in `PROOF_ADDENDUM.md` with the reason; it is never done silently.
2. **A failed verification is reported, not hidden.** Any failing path, crashed command, missing group, unreachable service, empty case-study group, or `UNEXPLAINED` item appears verbatim in `PROOF_RESULT.md` with its count.
3. **Arithmetic only.** `PROOF_RESULT.md` contains counts, sets, hashes, commands and PASS/FAIL against the fixed criteria. No interpretation, no narrative claims, no post-hoc explanations.
4. No new models, no GNN, no new ideas, no retraining, no threshold tuning, no cherry-picking, no merging `proof-module` back.

---

## 10. Environment notes recorded before the run

- Python 3.13.14, node v22.22.2, npm 10.9.7.
- `torch` and `numpy` are **not installed** in either the system Python or the repo's `venv`; therefore the frozen VulnGAT checkpoint is not executed. The proof module is **stdlib-only** and needs no third-party package.
- `https://api.osv.dev/v1/query` and `https://registry.npmjs.org` were reachable at pre-registration time; reachability is not a result about any package.
- The six data files listed in §0 are all tracked in git, so a fresh clone contains every frozen input.
