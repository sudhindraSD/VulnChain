# POST-HOC, DESCRIPTIVE, NOT PART OF THE PRE-REGISTERED CRITERIA

Read-only lookups. No model runs, no gate re-adjudication, no edits to
`PROOF_PROTOCOL.md`, `PROOF_RESULT.md`, `PROOF_POSTHOC.md`, `phase5/*` or any
`proof/out/*` file. Recomputations used throwaway in-memory scripts; the CLI was
not changed, re-run or re-exported.

| Action | Count |
|---|---:|
| model / GNN runs | 0 |
| pre-registered criteria (a)/(b)(c) re-runs | 0 |
| `make_exports.py` / `fresh_clone_test.py` / CLI runs | 0 |
| `proof/out/*` files written or modified | 0 |
| frozen files edited | 0 |
| live OSV package-level `POST /v1/query` calls (item 4) | 9 |
| live OSV `GET /v1/vulns/{id}` calls (item 4) | 2 (1 in alias run, 1 verification of the same ID) |
| live OSV call failures / retries | 0 / 0 |

Sources: `proof/out/flagged_packages.json`, `proof/out/npm_audit_comparison.json`,
`proof/out/case_studies.json`, `proof/out/offline_online.json`,
`demo/sample-lock.json`, `phase5/bench_run/vulnchain_graph.json`,
`phase5/bench_run/osv_cache.json`.

---

## 1. The 6 npm-audit-only items vs `flagged_packages.json`

`ADV_OFF` = frozen KB `hasVulnerability` edges + non-null `osv_cache.json`
`cve_id`. Independent parser: 193 nodes, 266 resolved edges, **0 unresolved
edges**, 190 non-root nodes reachable from root, 26 vulnerable nodes.

| `name@version` | in `flagged_packages.json` | printed path | vulnerable descendant (endpoint) |
|---|---|---|---|
| `cookie-parser@1.4.6` | YES | `verademo-javascript@0.0.0 -> cookie-parser@1.4.6 -> cookie@0.4.1` | `cookie@0.4.1` |
| `express-session@1.18.0` | YES | `verademo-javascript@0.0.0 -> express-session@1.18.0 -> cookie@0.6.0` | `cookie@0.6.0` |
| `hbs@4.2.0` | YES | `verademo-javascript@0.0.0 -> hbs@4.2.0 -> handlebars@4.7.7` | `handlebars@4.7.7` |
| `moment@2.30.1` | NO | — | — |
| `optimist@0.6.1` | YES | `verademo-javascript@0.0.0 -> swig@1.4.2 -> optimist@0.6.1 -> minimist@0.0.10` | `minimist@0.0.10` |
| `proxy-addr@2.0.7` | NO | — | — |

Exact reasons for the 2 absences, from the three listed options:

| `name@version` | reachable from root | has vulnerable descendant in `ADV_OFF` | resolution failure | reason |
|---|---|---|---|---|
| `moment@2.30.1` | true | false | false | **no vulnerable descendant in ADV_OFF** |
| `proxy-addr@2.0.7` | true | false | false | **no vulnerable descendant in ADV_OFF** |

Supporting lookups for all 6:

| `name@version` | `ADV_OFF` (own) | reachable | has vuln descendant | own unresolved edges | lockfile key |
|---|---|---|---|---|---|
| `cookie-parser@1.4.6` | `[]` | true | true | 0 | `node_modules/cookie-parser` |
| `express-session@1.18.0` | `[]` | true | true | 0 | `node_modules/express-session` |
| `hbs@4.2.0` | `[]` | true | true | 0 | `node_modules/hbs` |
| `moment@2.30.1` | `[]` | true | false | 0 | `node_modules/moment` |
| `optimist@0.6.1` | `[]` | true | true | 0 | `node_modules/optimist` |
| `proxy-addr@2.0.7` | `[]` | true | false | 0 | `node_modules/proxy-addr` |

Counts: present = 4, absent = 2; reason `no vulnerable descendant in ADV_OFF` = 2,
`not reachable from root` = 0, `resolution failure` = 0.

---

## 2. `cookie-parser@1.4.6` — dependencies, NO_PATH, and flagged-set completeness

### 2.1 Declared dependencies and their resolutions

Lockfile key `node_modules/cookie-parser`, `dev = false`, `ADV_OFF = []`.

| declared dependency | resolved node key | version | `ADV_OFF` of resolved node | vulnerable node (ADV_OFF non-empty) |
|---|---|---|---|---|
| `cookie` | `node_modules/cookie` | `0.4.1` | `['GHSA-pxg6-pf52-xh8x']` | YES |
| `cookie-signature` | `node_modules/cookie-signature` | `1.0.6` | `[]` | NO |

- Reachable from root: **true**. Has a vulnerable descendant in `ADV_OFF`: **true**
  (via `cookie@0.4.1`).
- Present in `proof/out/flagged_packages.json`: **YES**, with printed path
  `verademo-javascript@0.0.0 -> cookie-parser@1.4.6 -> cookie@0.4.1` and
  `advisory_endpoint = cookie@0.4.1`.
- The npm-audit-only label for `cookie-parser@1.4.6` refers to the item itself not
  carrying an advisory in `ADV_OFF` (`VC_ITEMS` unit); it is not absent from the
  CLI flagged set.

### 2.2 Why `case_studies.json` shows `NO_PATH`

`case_studies.py::path_for_endpoint()` selects candidates with `path[-1] == item`
(first printed path **ending at** the selected item). Lookup counts over the 34
printed paths:

| Lookup | Count |
|---|---:|
| printed paths total | 34 |
| paths ending at `cookie-parser@1.4.6` | 0 |
| paths containing `cookie-parser@1.4.6` at any position | 2 |
| `cookie-parser@1.4.6` in the set of path endpoints | false |
| `ADV_OFF(cookie-parser@1.4.6)` | 0 IDs |

`NO_PATH` is the case-study generator's endpoint lookup returning 0 candidates.
The CLI flagged set contains `cookie-parser@1.4.6` as an **internal ancestor node**
on two paths, not as a vulnerable endpoint. CS3 record: `path = null`,
`path_label = NO_PATH`, `advisory_ids = []`, `verification = NO_PATH_TO_VERIFY`,
`cause = UNEXPLAINED`.

### 2.3 Flagged-set completeness recomputation (throwaway script, CLI unchanged)

Rule from `PROOF_PROTOCOL.md` §1: flagged = non-root node that is (a) reachable
from root over resolved `dependsOn` edges and (b) has a vulnerable node reachable
from it over >= 0 resolved `dependsOn` edges. Recomputed with
`proof/verify_paths.py`'s independent parser and the frozen advisory source.

| Quantity | Independent recomputation | CLI `flagged_packages.json` |
|---|---:|---:|
| lockfile nodes | 193 | 193 |
| resolved edges / unresolved edges | 266 / 0 | 266 / not recorded |
| vulnerable nodes | 26 | 26 |
| non-root reachable from root | 190 | 190 (`excluded_not_reachable = 2`) |
| reachable non-root with no vulnerable descendant | 156 | 156 |
| expected flagged node keys | 34 | 34 records |
| expected distinct `name@version` pids | 33 | 33 |
| **packages expected but omitted by CLI** | **0** | — |
| packages flagged by CLI but not expected | 0 | — |

**The CLI did NOT omit any ancestor it should have flagged per
`PROOF_PROTOCOL.md` §1. The list of omitted packages across the whole lockfile
is empty: 0 packages, `[]`.** The 2 non-root nodes excluded as not reachable from
root are `fsevents@2.3.3` (`node_modules/fsevents`) and `uglify-js@3.18.0`
(`node_modules/uglify-js`); the 156 excluded for no vulnerable descendant are
listed by count only. No CLI file was modified.

---

## 3. Alternative unit (POST-HOC ONLY — not the pre-registered comparison)

The pre-registered comparison used `VC_ITEMS` = lockfile nodes carrying an
`ADV_OFF` advisory (25 pids) vs `NPM_ITEMS` (30 pids). The unit below is
**different and post-hoc**: `VC_FLAGGED` = the CLI's flagged packages (reachable
ancestors, including vulnerable nodes themselves). Set arithmetic uses distinct
`name@version` pids; `VC_FLAGGED` has 34 records but 33 distinct pids because
`cookie@0.6.0` occurs at two nested keys.

| Group | Count |
|---|---:|
| `VC_FLAGGED` | 34 records / **33 distinct pids** |
| `NPM_ITEMS` | **30** |
| both | **28** |
| VC-flagged-only | **5** |
| npm-only | **2** |

`both` (28): `axios@0.18.0`, `body-parser@1.20.2`, `brace-expansion@1.1.11`,
`cookie-parser@1.4.6`, `cookie@0.4.1`, `cookie@0.6.0`, `doc-path@2.1.1`,
`express-session@1.18.0`, `express@4.19.2`, `follow-redirects@1.15.6`,
`handlebars@4.7.7`, `hbs@4.2.0`, `lodash@4.17.15`, `minimatch@3.1.2`,
`minimist@0.0.10`, `morgan@1.9.1`, `nodemailer@6.9.14`, `on-headers@1.0.2`,
`optimist@0.6.1`, `path-to-regexp@0.1.7`, `picomatch@2.3.1`, `qs@6.11.0`,
`safe-eval@0.3.0`, `send@0.18.0`, `serve-static@1.15.0`, `swig@1.4.2`,
`uglify-js@2.4.24`, `validator@13.5.2`.

`VC-flagged-only` (5): `anymatch@3.1.3`, `chokidar@3.6.0`,
`multer@1.4.5-lts.1`, `nodemon@3.1.4`, `readdirp@3.6.0`.

`npm-only` (2): `moment@2.30.1`, `proxy-addr@2.0.7`.

Arithmetic: 28 + 5 = 33; 28 + 2 = 30. Pre-registered unit for comparison:
24 + 1 = 25 (`VC_ITEMS`), 24 + 6 = 30 (`NPM_ITEMS`).

---

## 4. Alias normalisation of the 9 both-nonempty disagreements (POST-HOC, counts only)

Frozen sets from `proof/out/offline_online.json:rows` with `agree = false`,
`offline_ids` non-empty and `online_ids` non-empty (n = 9; matches
`both_nonempty_disagree_count = 9`). Live OSV lookups: 9 `POST /v1/query`
package queries (one per package, timeout 8 s, 0 retries) plus 1
`GET /v1/vulns/GHSA-f23m-r3pf-42rh` for the one ID not returned by those
queries; 10 calls in the alias run, 0 failures, 15.24 s. One additional
read-only GET of the same ID returned `aliases = ['CVE-2026-2950']`.

Normalisation lookup rule: union-find over all OSV `aliases` edges (bidirectional
`id <-> alias`); `norm(S) = { canonical_class(id) : id in S }`; a package becomes
equal iff `norm(ADV_OFF) == norm(ADV_ON)`. Alias graph: 171 distinct IDs,
84 with >= 1 alias, 127 alias edges.

| `name@version` | ADV_OFF | ADV_ON | norm classes OFF / ON | equal after alias |
|---|---|---|---|---|
| `axios@0.18.0` | `GHSA-42xw-2xvc-qx8m` | `GHSA-3p68-rc4w-qgx5`, `GHSA-42xw-2xvc-qx8m`, `GHSA-43fc-jf86-j433`, `GHSA-4w2v-q235-vp99`, `GHSA-5c9x-8gcm-mpgx`, `GHSA-62hf-57xw-28j9`, `GHSA-6chq-wfr3-2hj9`, `GHSA-7q8q-rj6j-mhjq`, `GHSA-898c-q2cr-xwhg`, `GHSA-cph5-m8f7-6c5x`, `GHSA-fvcv-3m26-pcqx`, `GHSA-hfxv-24rg-xrqf`, `GHSA-j5f8-grm9-p9fc`, `GHSA-jr5f-v2jv-69x6`, `GHSA-m7pr-hjqh-92cm`, `GHSA-mmx7-hfxf-jppx`, `GHSA-p92q-9vqr-4j8v`, `GHSA-pf86-5x62-jrwf`, `GHSA-pjwm-pj3p-43mv`, `GHSA-pmwg-cvhr-8vh7`, `GHSA-vf2m-468p-8v99`, `GHSA-w9j2-pvgh-6h63`, `GHSA-wf5p-g6vw-rhxx`, `GHSA-xhjh-pmcv-23jw`, `GHSA-xx6v-rp6x-q39c` | 1 / 25 | false |
| `body-parser@1.20.2` | `GHSA-qwcr-r2fm-qrc7`, `GHSA-v422-hmwv-36x6` | `GHSA-27r3-jxmh-p828`, `GHSA-qwcr-r2fm-qrc7`, `GHSA-v422-hmwv-36x6` | 2 / 3 | false |
| `brace-expansion@1.1.11` | `GHSA-3jxr-9vmj-r5cp`, `GHSA-f886-m6hf-6m8v`, `GHSA-mh99-v99m-4gvg`, `GHSA-rgw5-rvv9-x895`, `GHSA-v6h2-p8h4-qcjw` | `GHSA-3jxr-9vmj-r5cp`, `GHSA-6j4f-fj2g-mc7p`, `GHSA-f886-m6hf-6m8v`, `GHSA-mh99-v99m-4gvg`, `GHSA-q2hr-2g5m-vwhr`, `GHSA-qhr7-859c-m2p7`, `GHSA-rgw5-rvv9-x895`, `GHSA-v6h2-p8h4-qcjw` | 5 / 8 | false |
| `handlebars@4.7.7` | `GHSA-2qvq-rjwj-gvw9`, `GHSA-2w6w-674q-4c4q`, `GHSA-3mfm-83xf-c92r`, `GHSA-442j-39wm-28r2`, `GHSA-7rx3-28cr-v5wh`, `GHSA-9cx6-37pm-9jff`, `GHSA-xhpv-hc6g-r9c6`, `GHSA-xjpj-3mr7-gcpf` | `GHSA-2qvq-rjwj-gvw9`, `GHSA-2w6w-674q-4c4q`, `GHSA-3mfm-83xf-c92r`, `GHSA-442j-39wm-28r2`, `GHSA-7rx3-28cr-v5wh`, `GHSA-8r5x-fm3f-whwj`, `GHSA-9cx6-37pm-9jff`, `GHSA-p8wg-vrv2-v86f`, `GHSA-xhpv-hc6g-r9c6`, `GHSA-xjpj-3mr7-gcpf`, `GHSA-xw65-4hp5-5hc7` | 8 / 11 | false |
| `lodash@4.17.15` | `GHSA-29mw-wpgm-hmr9`, `GHSA-35jh-r3h4-6jhm`, `GHSA-f23m-r3pf-42rh`, `GHSA-p6mc-m468-83gw`, `GHSA-r5fr-rjxr-66jc`, `GHSA-xxjr-mmjv-4gpg` | `GHSA-29mw-wpgm-hmr9`, `GHSA-35jh-r3h4-6jhm`, `GHSA-p6mc-m468-83gw`, `GHSA-r5fr-rjxr-66jc`, `GHSA-xxjr-mmjv-4gpg` | 6 / 5 | false |
| `morgan@1.9.1` | `GHSA-4vj7-5mj6-jm8m`, `GHSA-jxfw-x594-9x9m` | `GHSA-4vj7-5mj6-jm8m`, `GHSA-9f6g-j8ch-79g4`, `GHSA-jxfw-x594-9x9m` | 2 / 3 | false |
| `nodemailer@6.9.14` | `GHSA-2x7j-588g-ccc2` | `GHSA-268h-hp4c-crq3`, `GHSA-2x7j-588g-ccc2`, `GHSA-39m8-27wv-hr27`, `GHSA-4ffr-jq9g-5ffx`, `GHSA-4g23-2xm8-66gc`, `GHSA-6vj9-mwq6-2f5v`, `GHSA-85x2-q946-cp5h`, `GHSA-8c8m-p3m8-cjg8`, `GHSA-8m3c-c648-2xjj`, `GHSA-8vvx-rff5-p5rq`, `GHSA-c7w3-x93f-qmm8`, `GHSA-g73g-hqqh-jr95`, `GHSA-m943-m63m-w62w`, `GHSA-mm7p-fcc7-pg87`, `GHSA-p6gq-j5cr-w38f`, `GHSA-r7g4-qg5f-qqm2`, `GHSA-rcmh-qjqh-p98v`, `GHSA-v53p-9fqp-m79j`, `GHSA-vvjj-xcjg-gr5g`, `GHSA-wmmp-3585-3rmp`, `GHSA-wqvq-jvpq-h66f` | 1 / 21 | false |
| `qs@6.11.0` | `GHSA-4mjr-xmp4-gh2g`, `GHSA-6rw7-vpxm-498p`, `GHSA-w7fw-mjwx-w883` | `GHSA-4mjr-xmp4-gh2g`, `GHSA-6pq8-jhm2-2vcw`, `GHSA-6rw7-vpxm-498p`, `GHSA-w7fw-mjwx-w883` | 3 / 4 | false |
| `safe-eval@0.3.0` | `GHSA-33vh-7x8q-mg35` | `GHSA-33vh-7x8q-mg35`, `GHSA-79xf-67r4-q2jj`, `GHSA-9pcf-h8q9-63f6`, `GHSA-hcg3-56jf-x4vh`, `GHSA-hrpq-r399-whgw`, `GHSA-ww6v-677g-p656` | 1 / 6 | false |

Counts: `equal_before_alias_normalisation = 0`;
`equal_after_alias_normalisation = 0`; `still_unequal = 9`;
`packages_with_online_only_ids = 8`; `packages_with_offline_only_ids = 1`
(`GHSA-f23m-r3pf-42rh`, alias `CVE-2026-2950`, not merged with any ADV_ON ID);
`distinct_ids_in_alias_graph = 171`; `ids_with_>=1_alias = 84`;
`alias_edges = 127`; `live_call_failures = 0`; `retries = 0`. No new gate.

---

## 5. Paper-safe wording (one line)

On this single lockfile the two tools report overlapping but differently defined sets — VulnChain's 34 flagged packages (33 distinct `name@version`, reachable ancestors of `ADV_OFF` advisories) and npm audit's 30 vulnerable installed instances — so the comparison is descriptive of unit scope and supports no claim of superiority or greater completeness in either direction.
