# PROOF_RESULT.md — STEP 4 PROOF MODULE

Arithmetic only. Counts, sets, hashes, commands and PASS/FAIL against the fixed
criteria in `PROOF_PROTOCOL.md` §7. No interpretation.

| Field | Value |
|---|---|
| Branch | `proof-module` |
| Protocol commit | `e16ef1ea4f7e0a2514bc051a0391d0e1d9512e4f` (2026-11-15 10:04:08 IST) |
| Source commit at export time (`meta.json`) | `177f63a4224c9a8c047cba6307cc5e90a5510de4` |
| Sample lockfile | `demo/sample-lock.json` |
| Lockfile SHA-256 | `f7a147023dcd3d1fa12c6451b5a93e441e415fb9835b561cffa6f123623314ba` |
| KB SHA-256 | `8fe4dca9e3e001cab708c8f987d8f46dd80684dfcea3f963b3ab13665cf0c72d` |
| OSV cache SHA-256 (main worktree) | `aade9a5d13937f16d06de18ea70cf6034cb16fd8554ccb97411fcf7561423335` |
| Export timestamp | `2026-11-15T04:45:29+00:00` |

---

## 1. Success criteria

| Criterion | Fixed rule | Observed | Verdict |
|---|---|---|---|
| (a) | 100% of printed paths pass `verify_paths.py`, OR every failure is listed and counted | `paths_total=34`, `paths_pass=34`, `paths_fail=0`, `packages_with_no_path=0`; failing rows listed in `proof/out/verify_report.json` = 0 | **PASS** |
| (b) | npm audit comparison completed with `UNEXPLAINED` count reported | `status=COMPLETED`, three groups computed, `unexplained_count=1` | **PASS** |
| (c) | fresh-clone test passes | `clone_ok=true`, `install_ok=true`, `all_six_valid=true`, `all_required_commands_exit_zero=true` | **PASS** |

---

## 2. Path verification counts (`verify_report.json`, `flagged_packages.json`)

| Field | Value |
|---|---:|
| lockfile entries | 193 |
| resolved dependency edges | 266 |
| vulnerable nodes | 26 |
| enumerated paths | 30 |
| flagged packages | 34 |
| printed paths | 34 |
| `paths_total` | 34 |
| `paths_pass` | 34 |
| `paths_fail` | 0 |
| `packages_with_no_path` | 0 |
| `no_path_within_caps` | 0 |
| `excluded_not_reachable` | 2 |
| `excluded_no_vulnerable_descendant` | 156 |
| `model_score_unresolved` (printed `UNRESOLVED`) | 25 |
| `MAX_HOPS` / `MAX_PATHS` | 8 / 200000 |
| `truncated` | `false` |
| `truncation_reason` | `null` |
| `graph_subgraph.json` subgraphs | 34 |
| truncated subgraphs (300-node cap) | 0 |
| max closure size | 84 |

Verification checks applied per path: root match, exact `name@version` node
resolution, resolved `dependsOn` edge with nested `node_modules` resolution,
exact version, endpoint advisory ID in `ADV_OFF`, printed advisory IDs subset of
`ADV_OFF`, simple path. Negative controls (mutation tests, not part of the 34
reported paths): wrong version → `VERSION`; dropped edge → `EDGE`; fake advisory
ID → `ADVISORY_ENDPOINT`. Lockfile nested `node_modules` entries = 46.

---

## 3. npm audit comparison (`npm_audit_comparison.json`)

`npm audit --json` exit code = 1 (vulnerabilities present, not a crash).
Resolved binary: `C:\Users\soumy\.workbuddy-ai\binaries\node\versions\22.22.2-6\npm.cmd`.
npm audit vulnerability entries = 29. `status = COMPLETED`.
`unmatched_npm_nodes = 0`. `VC_ITEMS = 25`, `NPM_ITEMS = 30`.

| Group | Count | Items |
|---|---:|---|
| `found_by_both` | 24 | `axios@0.18.0`, `body-parser@1.20.2`, `brace-expansion@1.1.11`, `cookie@0.4.1`, `cookie@0.6.0`, `doc-path@2.1.1`, `express@4.19.2`, `follow-redirects@1.15.6`, `handlebars@4.7.7`, `lodash@4.17.15`, `minimatch@3.1.2`, `minimist@0.0.10`, `morgan@1.9.1`, `nodemailer@6.9.14`, `on-headers@1.0.2`, `path-to-regexp@0.1.7`, `picomatch@2.3.1`, `qs@6.11.0`, `safe-eval@0.3.0`, `send@0.18.0`, `serve-static@1.15.0`, `swig@1.4.2`, `uglify-js@2.4.24`, `validator@13.5.2` |
| `vulnchain_only` | 1 | `multer@1.4.5-lts.1` |
| `npm_audit_only` | 6 | `cookie-parser@1.4.6`, `express-session@1.18.0`, `hbs@4.2.0`, `moment@2.30.1`, `optimist@0.6.1`, `proxy-addr@2.0.7` |

Discrepancy items = 7. Cause labels, fixed rule list R1–R5 in priority order:

| Item | Group | Cause |
|---|---|---|
| `multer@1.4.5-lts.1` | `vulnchain_only` | `version_range_resolution` |
| `cookie-parser@1.4.6` | `npm_audit_only` | `UNEXPLAINED` |
| `express-session@1.18.0` | `npm_audit_only` | `version_range_resolution` |
| `hbs@4.2.0` | `npm_audit_only` | `advisory_db_differences` |
| `moment@2.30.1` | `npm_audit_only` | `advisory_db_differences` |
| `optimist@0.6.1` | `npm_audit_only` | `version_range_resolution` |
| `proxy-addr@2.0.7` | `npm_audit_only` | `advisory_db_differences` |

Cause counts: `NOT_A_DISCREPANCY=24`, `version_range_resolution=3`,
`advisory_db_differences=3`, `dev_vs_prod_scope=0`, `transitive_depth=0`,
`tool_bug=0`, **`UNEXPLAINED=1`**. `tool_bug_cases.json` = `{}`.

---

## 4. Offline vs online agreement (`offline_online.json`)

Definitions: OFFLINE = `ADV_OFF` (KB `hasVulnerability` + `osv_cache.json`, zero
network calls); ONLINE = `ADV_ON` (live `POST https://api.osv.dev/v1/query` per
package, timeout 8 s, 0 retries, 8 workers). Comparison = exact string-set
equality; empty == empty counts as agreement.

```
D           = { p : online_query_status(p) == "OK" }
agree_count = |{ p in D : ADV_OFF(p) == ADV_ON(p) }|
A           = agree_count / |D|
```

| Quantity | Value |
|---|---:|
| `units_total` | 168 |
| `evaluated_D` (\|D\|) | 168 |
| `agree_count` | 156 |
| `disagree_count` | 12 |
| `no_online_result_count` | 0 |
| `offline_only_count` | 0 |
| `online_only_count` | 3 |
| `both_nonempty_disagree_count` | 9 |
| `both_empty_agree_count` | 140 |
| elapsed seconds | 19.398 |

`A = 156 / 168 = 0.9285714285714286`. `no_online_result_packages = []`.

---

## 5. Case studies (`case_studies.json`)

Selection rule fixed in `PROOF_PROTOCOL.md` §6: CS1 = deepest verified path
(max edges, tie-break alphabetical by `name@version`); CS2 = alphabetically
first `vulnchain_only`; CS3 = alphabetically first `npm_audit_only`. No group
was empty; no substitution was used.

**CS1 — `anymatch@3.1.3`** (`hops=4`, `tie_count=4`)
- Path: `verademo-javascript@0.0.0 -> nodemon@3.1.4 -> chokidar@3.6.0 -> anymatch@3.1.3 -> picomatch@2.3.1`
- Advisory IDs: `GHSA-3v7f-55p6-f55p`, `GHSA-c2c7-rcm5-vvqj`
- Verification: `PASS`; `failing_edge = null`

**CS2 — `multer@1.4.5-lts.1`** (`vulnchain_only` group count = 1, cause `version_range_resolution`)
- Path: `verademo-javascript@0.0.0 -> multer@1.4.5-lts.1`
- Advisory IDs: `GHSA-44fp-w29j-9vj5`, `GHSA-4pg4-qvpc-4q3h`, `GHSA-535w-7cp7-47q4`, `GHSA-5528-5vmv-3xc2`, `GHSA-72gw-mp4g-v24j`, `GHSA-fjgf-rc76-4x9p`, `GHSA-g5hg-p3ph-g8qg`, `GHSA-qvfw-j98x-7q72`, `GHSA-v52c-386h-88mc`, `GHSA-wc9g-mqfw-jrwm`, `GHSA-xf7r-hgr6-v32p`
- Verification: `PASS`; `failing_edge = null`

**CS3 — `cookie-parser@1.4.6`** (`npm_audit_only` group count = 6, cause `UNEXPLAINED`)
- Path: `NO_PATH` (`path = null`)
- Advisory IDs: `[]`
- Verification: `NO_PATH_TO_VERIFY`

---

## 6. Fresh-clone log (`proof/out/fresh_clone_log.json`)

Clone source: `C:\Users\soumy\Desktop\VulnChain`, branch `proof-module`.
Temp dir: `C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa`
(removed after test = `true`). Started `2026-11-15T04:47:10Z`, finished
`2026-11-15T04:48:21Z`.

| # | Exact command | Exit | Result line |
|---|---|---:|---|
| 1 | `git clone --no-hardlinks --branch proof-module C:\Users\soumy\Desktop\VulnChain C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa\clone` | 0 | — |
| 2 | `C:\Users\soumy\.workbuddy-ai\binaries\python\versions\3.13.12\python.exe -m venv C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa\freshvenv` | 0 | — |
| 3 | `C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa\freshvenv\Scripts\python.exe -m pip install --no-deps -e .` | 0 | `Successfully installed vulnchain-proof-0.0.0` |
| 4 | `C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa\freshvenv\Scripts\python.exe -m vulnchain.proof demo/sample-lock.json --json proof/out/flagged_packages.json` | 0 | `flagged=34 paths=34`, `no_path_within_caps: 0` |
| 5 | `C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa\freshvenv\Scripts\python.exe proof/verify_paths.py demo/sample-lock.json proof/out/flagged_packages.json --kb phase5/bench_run/vulnchain_graph.json --cache phase5/bench_run/osv_cache.json --json proof/out/verify_report.json` | 0 | `paths_total: 34`, `paths_pass: 34`, `paths_fail: 0` |
| 6 | `C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa\freshvenv\Scripts\python.exe proof/make_exports.py --lockfile demo/sample-lock.json --out-dir proof/out --repo-root .` | 0 | `ALL_SIX_VALID=True` |
| 7 | `C:\Users\soumy\AppData\Local\Temp\vulnchain_fresh_clone_oj2zj1qa\freshvenv\Scripts\python.exe -c "import json,pathlib,sys;names=['flagged_packages.json', 'verify_report.json', 'npm_audit_comparison.json', 'graph_subgraph.json', 'audit_scores.json', 'meta.json'];d=pathlib.Path('proof/out');out={n:(d/n).exists() for n in names};[json.loads((d/n).read_text()) for n in names if out[n]];print(json.dumps(out));sys.exit(0 if all(out.values()) else 1)"` | 0 | `{"flagged_packages.json": true, "verify_report.json": true, "npm_audit_comparison.json": true, "graph_subgraph.json": true, "audit_scores.json": true, "meta.json": true}` |

Fallback install attempt count = 0. `clone_ok=true`, `install_ok=true`,
`all_six_valid=true`, `all_required_commands_exit_zero=true`,
`criterion_c_pass=true`.

| Export | valid JSON after regeneration | hash changed vs committed copy |
|---|---|---|
| `flagged_packages.json` | true | true |
| `verify_report.json` | true | false |
| `npm_audit_comparison.json` | true | true |
| `graph_subgraph.json` | true | false |
| `audit_scores.json` | true | true |
| `meta.json` | true | true |

`audit_scores.json`: `LP_original=0.719099±0.006897`, `LP_clean=0.632905±0.007867`,
`HR=0.631473±0.004468`, `BFS=0.528650±0.003851` (parsed from
`phase5/HYBRID_GATE.md`, `parse_failures=[]`). Task D parsed from
`phase5/confirm_metrics.json`: seeds `[2001,2002,2003,2004,2005]`,
`primary_pass=true`, `mean_delta=0.06574642801644279`,
`sd_delta=0.005479641448113535`, `threshold=0.02`,
`perm_mean=0.5169059144109444`, `perm_out=false`; computed from rows
`mean_CANDIDATE=0.6814591391057837`, `mean_LP_clean=0.6157127110893409`,
`mean_HR=0.6362134469529052`,
`mean_paired_delta_CANDIDATE_minus_LP_clean=0.06574642801644279`,
`sd_paired_delta_ddof1=0.005479641448113535`.

---

## 7. Independence audit (`proof/out/independence_audit.json`)

Audited file: `proof/verify_paths.py`. Import count = 5. Failures = 0.
Result = **PASS**. Allow-list: `argparse, collections, hashlib, json, os,
pathlib, re, sys, typing`. Project prefixes checked: `vulnchain, phase5,
data_pipeline, webapp, TrainModel, core, model, models, graph, features,
verify_paths, compare_npm_audit, offline_online, case_studies, make_exports`.

| Line | Kind | Module | Verdict |
|---:|---|---|---|
| 12 | `import` | `argparse` | `OK_STDLIB` |
| 13 | `import` | `json` | `OK_STDLIB` |
| 14 | `import` | `sys` | `OK_STDLIB` |
| 15 | `import_from` | `collections` | `OK_STDLIB` |
| 16 | `import_from` | `pathlib` | `OK_STDLIB` |

Relative imports = 0. Project-code imports = 0. Non-allow-list imports = 0.

---

## 8. Negative and unresolved records (reported, not hidden)

| Item | Count |
|---|---:|
| `UNEXPLAINED` comparison items | 1 (`cookie-parser@1.4.6`) |
| CS3 path | `NO_PATH`; verification `NO_PATH_TO_VERIFY` |
| `model_score` printed `UNRESOLVED` | 25 of 34 |
| excluded non-root nodes with no root path | 2 |
| excluded non-root nodes with no vulnerable descendant | 156 |
| `NO_ONLINE_RESULT` packages | 0 |
| `truncated` exports / truncated subgraphs | 0 / 0 |
| `post-commit` edits to committed files | 0 |
| `PROOF_ADDENDUM.md` entries | 3 fix records (all before their own commits) + 1 line-ending hash table |

Line-ending record: `core.autocrlf=true` in the main repo; `phase5/confirm_metrics.json`
and `phase5/bench_run/osv_cache.json` are CRLF in the main worktree and LF in a
fresh clone, so their git-blob SHA-256 values differ from the worktree values
frozen in `PROOF_PROTOCOL.md` §0. JSON content is identical. Full table in
`PROOF_ADDENDUM.md` §2.

---

## 9. Export inventory (`proof/out/`)

| File | Bytes |
|---|---:|
| `flagged_packages.json` | 20909 |
| `verify_report.json` | 9778 |
| `npm_audit_comparison.json` | 9550 |
| `graph_subgraph.json` | 101188 |
| `audit_scores.json` | 5939 |
| `meta.json` | 541 |
| `offline_online.json` | 35957 |
| `case_studies.json` | 2118 |
| `tool_bug_cases.json` | 4 |
| `fresh_clone_log.json` | 21410 |
| `independence_audit.json` | 1817 |

All six required exports validate as JSON (`ALL_SIX_VALID=True` in both the
main run and the fresh-clone run).
