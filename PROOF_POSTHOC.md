# POST-HOC, DESCRIPTIVE, NOT PART OF THE PRE-REGISTERED CRITERIA

Arithmetic and lookups only. No interpretation. All values below are read from
committed files in `proof/out/` or from frozen files under `phase5/`; no gate was
re-adjudicated and no export was rewritten.

**Scope of this step (counts of runs):**

| Action | Count |
|---|---:|
| `git push -u origin proof-module` (STEP A backup) | 1 |
| read-only `npm audit --json` diagnostic lookups (temp dir, stdout not written to repo) | 3 |
| `make_exports.py` runs | 0 |
| `fresh_clone_test.py` runs | 0 |
| pre-registered criteria (a)/(b)/(c) re-runs | 0 |
| model / GNN runs | 0 |
| frozen files edited (`PROOF_PROTOCOL.md`, `PROOF_RESULT.md`, `phase5/*`) | 0 |
| `proof/out/*` files written or modified | 0 |

Diagnostic lookup command (run 3 times, cwd = temp dir containing the exact
`demo/sample-lock.json` bytes plus a `package.json` reconstructed from its root):
`npm audit --json` (resolved binary
`C:\Users\soumy\.workbuddy-ai\binaries\node\versions\22.22.2-6\npm.cmd`).
All three lookups returned exit code 1. Recorded stdout sizes: 70866 bytes
(lookup 1), 70866 bytes (lookup 3); lookup 2 did not record a stdout size.
`npm_audit_comparison.json:stdout_bytes = 70866`.

---

## 1. The 6 npm-audit-only items

Source of group: `proof/out/npm_audit_comparison.json`, `groups.npm_audit_only`
(count = 6). Advisory IDs below come from the diagnostic `npm audit --json`
lookup: `via[].url` for direct advisories, and the same field resolved through
string-valued `via[]` entries for indirect ones. The committed comparison stored
`npm_ids = []` for the three indirect-only items because its extractor reads only
dict-valued `via[]` entries.

| # | `name@version` | npm audit advisory IDs | direct / indirect `via` | npm `range` |
|---:|---|---|---|---|
| 1 | `cookie-parser@1.4.6` | `GHSA-pxg6-pf52-xh8x` | indirect: `cookie` | `1.0.1 - 1.4.6` |
| 2 | `express-session@1.18.0` | `GHSA-76c9-3jph-rj3q`, `GHSA-pxg6-pf52-xh8x` | indirect: `cookie`, `on-headers` | `1.0.1 - 1.18.1` |
| 3 | `hbs@4.2.0` | direct `GHSA-7f5c-rpf4-86p8`; indirect via `handlebars`: `GHSA-2qvq-rjwj-gvw9`, `GHSA-2w6w-674q-4c4q`, `GHSA-3mfm-83xf-c92r`, `GHSA-442j-39wm-28r2`, `GHSA-7rx3-28cr-v5wh`, `GHSA-8r5x-fm3f-whwj`, `GHSA-9cx6-37pm-9jff`, `GHSA-p8wg-vrv2-v86f`, `GHSA-xhpv-hc6g-r9c6`, `GHSA-xjpj-3mr7-gcpf`, `GHSA-xw65-4hp5-5hc7` (12 total) | direct + indirect: `handlebars` | `*` |
| 4 | `moment@2.30.1` | `GHSA-4p3w-j4w9-5jqw` | direct | `2.29.2 - 2.30.1` |
| 5 | `optimist@0.6.1` | `GHSA-vh95-rmgr-6w4m`, `GHSA-xvch-5gv4-984h` | indirect: `minimist` | `>=0.6.0` |
| 6 | `proxy-addr@2.0.7` | `GHSA-jqcg-44mw-7w3h` | direct | `1.1.0 - 2.0.7` |

### 1.1 Frozen-source membership lookups

`kb_exact` = exact `name@version` has >= 1 edge in
`phase5/bench_run/vulnchain_graph.json:edges.hasVulnerability`.
`cache_key` = exact `name@version` is a key in
`phase5/bench_run/osv_cache.json`. `kb_other_versions` = edges for the same
package name at a different version.

| `name@version` | `kb_exact` | `cache_key` | `cache.cve_id` | `kb_other_versions` (n) | `cache_other_versions_with_cve` (n) |
|---|---|---|---|---:|---:|
| `cookie-parser@1.4.6` | false | false | absent | 0 | 0 |
| `express-session@1.18.0` | false | true | `null` | 0 | 0 |
| `hbs@4.2.0` | false | false | absent | 2 (`hbs@4.0.4`, `hbs@4.1.1`) | 0 |
| `moment@2.30.1` | false | false | absent | 6 (`moment@2.0.0`, `2.15.1`, `2.18.1`, `2.24.0`, `2.27.0`, `2.29.1`) | 0 |
| `optimist@0.6.1` | false | false | absent | 0 | 0 |
| `proxy-addr@2.0.7` | false | false | absent | 0 | 0 |

### 1.2 Reason assignment

Fixed lookup rule, first match wins:

```
L1 version_range_mismatch : kb_other_versions >= 1
L2 not_in_KB              : kb_exact == false AND cache_key == true
L3 not_in_osv_cache       : kb_exact == false AND cache_key == false
L4 other                  : none of L1-L3
```

| `name@version` | Primary reason | Pre-registered cause label |
|---|---|---|
| `cookie-parser@1.4.6` | `not_in_osv_cache` (L3) | `UNEXPLAINED` |
| `express-session@1.18.0` | `not_in_KB` (L2) | `version_range_resolution` |
| `hbs@4.2.0` | `version_range_mismatch` (L1) | `advisory_db_differences` |
| `moment@2.30.1` | `version_range_mismatch` (L1) | `advisory_db_differences` |
| `optimist@0.6.1` | `not_in_osv_cache` (L3) | `version_range_resolution` |
| `proxy-addr@2.0.7` | `not_in_osv_cache` (L3) | `advisory_db_differences` |

**Counts per primary reason:** `version_range_mismatch = 2`,
`not_in_KB = 1`, `not_in_osv_cache = 3`, `other = 0`. Total = 6.

**Literal membership counts:** exact pid with 0 KB advisory edges = 6/6;
exact pid with no non-null `osv_cache.json` `cve_id` = 6/6; exact pid present as
an `osv_cache.json` key = 1/6; exact pid absent as an `osv_cache.json` key = 5/6;
same-name KB advisory at another version = 2/6; same-name cache advisory at
another version = 0/6.

Lookup: the lockfile pids reached by the indirect `via[]` targets —
`cookie@0.4.1`, `cookie@0.6.0`, `on-headers@1.0.2`, `minimist@0.0.10` — each
have >= 1 KB advisory edge and each appears in `groups.found_by_both`.

---

## 2. The 1 VulnChain-only item and the 1 UNEXPLAINED item

Definition used for "first rule that almost matched": the earliest rule in the
fixed R1 -> R5 priority order of `PROOF_PROTOCOL.md` §4 whose predicate
evaluated False; the deciding field is recorded. R1 is first for both items.

### 2.1 `multer@1.4.5-lts.1` — VulnChain-only

| Field | Value |
|---|---|
| group | `vulnchain_only` (group count = 1) |
| assigned cause | `version_range_resolution` |
| `vc_ids` | 11 IDs: `GHSA-44fp-w29j-9vj5`, `GHSA-4pg4-qvpc-4q3h`, `GHSA-535w-7cp7-47q4`, `GHSA-5528-5vmv-3xc2`, `GHSA-72gw-mp4g-v24j`, `GHSA-fjgf-rc76-4x9p`, `GHSA-g5hg-p3ph-g8qg`, `GHSA-qvfw-j98x-7q72`, `GHSA-v52c-386h-88mc`, `GHSA-wc9g-mqfw-jrwm`, `GHSA-xf7r-hgr6-v32p` |
| `npm_ids` (committed evidence) | `[]` |
| `multer` key present in diagnostic npm audit `vulnerabilities` | false |
| `range` | `null` |
| `kb_exact` / `cache_key` / `cache.cve_id` | true / false / absent |
| `kb_other_versions` | 4: `multer@1.4.4`, `multer@1.4.5-lts.2`, `multer@2.1.1`, `multer@2.2.0` |
| `all_dev` / `depth_from_root` / `tool_bug_case_listed` | false / 1 / false |
| printed path | `verademo-javascript@0.0.0 -> multer@1.4.5-lts.1` |
| verification | `PASS` |

R1 -> R5 evaluation:

| Rule | Predicate observed | Fired |
|---|---|---|
| R1 `advisory_db_differences` | `npm_ids = []` (requires non-empty) | **false — first rule that almost matched** |
| R2 `version_range_resolution` | `other_version_advisory = true`; `range = null` | **true (assigned)** |
| R3 `dev_vs_prod_scope` | `all_dev = false` | false |
| R4 `transitive_depth` | `depth = 1` (< 5) | false |
| R5 `tool_bug` | `tool_bug_case_listed = false` | false |

### 2.2 `cookie-parser@1.4.6` — UNEXPLAINED

| Field | Value |
|---|---|
| group | `npm_audit_only` (group count = 6) |
| assigned cause | `UNEXPLAINED` (`unexplained_count = 1`) |
| `vc_ids` / `npm_ids` (committed evidence) | `[]` / `[]` |
| npm advisory ID from diagnostic lookup | `GHSA-pxg6-pf52-xh8x`, from indirect `via = ["cookie"]` |
| `range` | `1.0.1 - 1.4.6` (contains `1.4.6` = true) |
| `kb_exact` / `cache_key` / `cache.cve_id` | false / false / absent |
| `kb_other_versions` | 0 |
| `all_dev` / `depth_from_root` / `tool_bug_case_listed` | false / 1 / false |
| printed path / verification | `NO_PATH` / `NO_PATH_TO_VERIFY` |
| CS3 selection | alphabetically first `npm_audit_only` item |

R1 -> R5 evaluation:

| Rule | Predicate observed | Fired |
|---|---|---|
| R1 `advisory_db_differences` | `npm_ids = []` in committed evidence (requires non-empty); diagnostic lookup field = `['GHSA-pxg6-pf52-xh8x']` | **false — first rule that almost matched** |
| R2 `version_range_resolution` | `other_version_advisory = false`; `1.4.6 in "1.0.1 - 1.4.6" = true` so range condition false | false |
| R3 `dev_vs_prod_scope` | `all_dev = false` | false |
| R4 `transitive_depth` | `depth = 1` (< 5) | false |
| R5 `tool_bug` | `tool_bug_case_listed = false` | false |

---

## 3. The 12 offline-vs-online disagreements

Source: `proof/out/offline_online.json`, rows with `agree = false` (n = 12).
`offline` = `ADV_OFF` (frozen KB + `osv_cache.json`); `online` = `ADV_ON` (live
OSV query). Classification lookup rule:

```
stale_cache     : offline_ids non-empty AND online_ids empty
newer_advisory  : online_ids non-empty AND offline_ids empty
other           : both non-empty AND sets differ
```

| # | `name@version` | offline n | online n | side with advisory | offline-only IDs n | online-only IDs n | class |
|---:|---|---:|---:|---|---:|---:|---|
| 1 | `axios@0.18.0` | 1 | 25 | both (online superset) | 0 | 24 | `other` |
| 2 | `body-parser@1.20.2` | 2 | 3 | both (online superset) | 0 | 1 (`GHSA-27r3-jxmh-p828`) | `other` |
| 3 | `brace-expansion@1.1.11` | 5 | 8 | both (online superset) | 0 | 3 (`GHSA-6j4f-fj2g-mc7p`, `GHSA-q2hr-2g5m-vwhr`, `GHSA-qhr7-859c-m2p7`) | `other` |
| 4 | `handlebars@4.7.7` | 8 | 11 | both (online superset) | 0 | 3 (`GHSA-8r5x-fm3f-whwj`, `GHSA-p8wg-vrv2-v86f`, `GHSA-xw65-4hp5-5hc7`) | `other` |
| 5 | `hbs@4.2.0` | 0 | 1 | online only | 0 | 1 (`GHSA-7f5c-rpf4-86p8`) | `newer_advisory` |
| 6 | `lodash@4.17.15` | 6 | 5 | both (offline superset) | 1 (`GHSA-f23m-r3pf-42rh`) | 0 | `other` |
| 7 | `moment@2.30.1` | 0 | 1 | online only | 0 | 1 (`GHSA-4p3w-j4w9-5jqw`) | `newer_advisory` |
| 8 | `morgan@1.9.1` | 2 | 3 | both (online superset) | 0 | 1 (`GHSA-9f6g-j8ch-79g4`) | `other` |
| 9 | `nodemailer@6.9.14` | 1 | 21 | both (online superset) | 0 | 20 | `other` |
| 10 | `proxy-addr@2.0.7` | 0 | 1 | online only | 0 | 1 (`GHSA-jqcg-44mw-7w3h`) | `newer_advisory` |
| 11 | `qs@6.11.0` | 3 | 4 | both (online superset) | 0 | 1 (`GHSA-6pq8-jhm2-2vcw`) | `other` |
| 12 | `safe-eval@0.3.0` | 1 | 6 | both (online superset) | 0 | 5 (`GHSA-79xf-67r4-q2jj`, `GHSA-9pcf-h8q9-63f6`, `GHSA-hcg3-56jf-x4vh`, `GHSA-hrpq-r399-whgw`, `GHSA-ww6v-677g-p656`) | `other` |

Full ID sets for every row are in `proof/out/offline_online.json:rows`.

**Counts:** `stale_cache = 0`, `newer_advisory = 3`, `other = 9`. Total = 12.
Cross-check against `offline_online.json:counts`: `offline_only_count = 0`,
`online_only_count = 3`, `both_nonempty_disagree_count = 9`,
`disagree_count = 12`, `agree_count = 156`, `evaluated_D = 168`,
`no_online_result_count = 0`. The single offline-only ID
(`GHSA-f23m-r3pf-42rh` on `lodash@4.17.15`) belongs to an `other` item, not to a
`stale_cache` item.

---

## 4. Model score coverage

Source: `proof/out/flagged_packages.json`. Flagged packages = 34;
`model_score` resolved = 9; `model_score` = `null` (printed `UNRESOLVED`) = 25
records = 24 distinct `name@version` ids (`cookie@0.6.0` occurs twice at two
nested lockfile keys). No model was run.

Resolved 9: `anymatch@3.1.3`, `brace-expansion@1.1.11`, `chokidar@3.6.0`,
`lodash@4.17.15`, `minimatch@3.1.2`, `on-headers@1.0.2`,
`path-to-regexp@0.1.7`, `picomatch@2.3.1`, `readdirp@3.6.0`.

Frozen-score lookup procedure: `git ls-files` over 338 tracked files; 20 tracked
JSON files contain `"risk_score"`; 28 tracked JSON files contain at least one of
the 24 distinct ids. Each of those 28 files was parsed and walked for any dict
containing the exact id together with a numeric field whose key is in
`{risk_score, score, pred, prediction, prob, probability, vpss, epss, risk, auc,
y_score, y_pred}`. The four repo XML dumps (`part3.xml`, `part4.xml`,
`part5.xml`, `repomix-output.xml`) were also scanned for lines containing an
exact id and score text: 43 such lines in `repomix-output.xml`, 1 containing the
word `score`, which is a graph metadata line (no per-package score).

Result: 0 of 24 distinct ids has a frozen score anywhere in the repo.

| # | `name@version` | lockfile key | tracked files containing the id (n) | frozen score anywhere in repo |
|---:|---|---|---:|---|
| 1 | `axios@0.18.0` | `node_modules/axios` | 9 | NO |
| 2 | `body-parser@1.20.2` | `node_modules/body-parser` | 22 | NO |
| 3 | `cookie-parser@1.4.6` | `node_modules/cookie-parser` | 22 | NO |
| 4 | `cookie@0.4.1` | `node_modules/cookie` | 28 | NO |
| 5 | `cookie@0.6.0` | `node_modules/express-session/node_modules/cookie` | 22 | NO |
| 6 | `cookie@0.6.0` | `node_modules/express/node_modules/cookie` | 22 | NO |
| 7 | `doc-path@2.1.1` | `node_modules/doc-path` | 8 | NO |
| 8 | `express-session@1.18.0` | `node_modules/express-session` | 8 | NO |
| 9 | `express@4.19.2` | `node_modules/express` | 22 | NO |
| 10 | `follow-redirects@1.15.6` | `node_modules/follow-redirects` | 22 | NO |
| 11 | `handlebars@4.7.7` | `node_modules/handlebars` | 28 | NO |
| 12 | `hbs@4.2.0` | `node_modules/hbs` | 27 | NO |
| 13 | `minimist@0.0.10` | `node_modules/minimist` | 28 | NO |
| 14 | `morgan@1.9.1` | `node_modules/morgan` | 28 | NO |
| 15 | `multer@1.4.5-lts.1` | `node_modules/multer` | 23 | NO |
| 16 | `nodemailer@6.9.14` | `node_modules/nodemailer` | 8 | NO |
| 17 | `nodemon@3.1.4` | `node_modules/nodemon` | 8 | NO |
| 18 | `optimist@0.6.1` | `node_modules/optimist` | 27 | NO |
| 19 | `qs@6.11.0` | `node_modules/qs` | 22 | NO |
| 20 | `safe-eval@0.3.0` | `node_modules/safe-eval` | 8 | NO |
| 21 | `send@0.18.0` | `node_modules/send` | 22 | NO |
| 22 | `serve-static@1.15.0` | `node_modules/serve-static` | 22 | NO |
| 23 | `swig@1.4.2` | `node_modules/swig` | 29 | NO |
| 24 | `uglify-js@2.4.24` | `node_modules/swig/node_modules/uglify-js` | 28 | NO |
| 25 | `validator@13.5.2` | `node_modules/validator` | 28 | NO |

---

## 5. npm audit count reconciliation

| Quantity | Value | Unit |
|---|---:|---|
| `vulnerabilities` object keys in `npm audit --json` | 29 | one key per **package name** |
| `metadata.vulnerabilities.total` | 29 | one count per **package name** |
| `nodes[]` paths summed over the 29 keys | 31 | one per **installed lockfile path** |
| distinct `name@version` produced from those paths | 30 | one per **name + version** (`NPM_ITEMS`) |
| `unmatched_npm_nodes` | 0 | paths with no lockfile key |

Arithmetic: 28 names have 1 `nodes[]` path each = 28; `cookie` has 3 paths
(`node_modules/cookie`, `node_modules/express-session/node_modules/cookie`,
`node_modules/express/node_modules/cookie`) = 31 paths total. Those 3 paths map
to 2 distinct pids (`cookie@0.4.1`, `cookie@0.6.0`), so distinct pids =
28 + 2 = 30. `found_by_both (24) + npm_audit_only (6) = 30 = NPM_ITEMS`;
`found_by_both (24) + vulnchain_only (1) = 25 = VC_ITEMS`.

---

## 6. What `verify_paths.py` does NOT check

`verify_paths.py` does not check advisory correctness (whether an advisory ID genuinely applies to that package/version) and does not check scoring (any model score value, ranking, or calibration).
