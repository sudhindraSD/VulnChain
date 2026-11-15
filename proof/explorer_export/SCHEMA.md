# SCHEMA.md — proof/explorer_export/

Presentation layer only. See `PROOF_ADDENDUM2.md`. All JSON is written with
sorted keys, 2-space indent and LF newlines; all lists are explicitly sorted.
No generated timestamp exists anywhere; the only timestamps in this directory
are copies of committed values in `meta.json`.

**Provenance.** Every flag, status, count, group, cause, advisory ID and model
score is copied from an already-committed file. Structural facts — `depth_min`,
`n_dependencies`, `n_dependents`, `n_ancestors`, `n_descendants`, plus nesting
`lookup_order` and JSON pointers — are derived from the lockfile by stdlib code
using `proof/verify_paths.py`'s independent parser and are labelled
**descriptive** (`nodes[].structural_facts_label = "descriptive"`). They carry
no criterion, gate or claim. `status` categories come from committed sets:
flagged keys from `flagged_packages.json`, vulnerable pids from
`offline_online.json:rows[].offline_ids`, and the two excluded-not-reachable
keys from `PROOF_POSTHOC2.md` section 2.3.

**Null policy.** If a value cannot be found in a committed file it is `null`
and listed in `MISSING.md`. Nothing is computed or guessed to fill it.

**Sources (read-only).** `demo/sample-lock.json`,
`proof/out/{flagged_packages,verify_report,offline_online,npm_audit_comparison,graph_subgraph,fresh_clone_log,independence_audit,meta}.json`,
`phase5/bench_run/{vulnchain_graph,osv_cache}.json`,
`data_pipeline/cve_nodes.json`, `proof/verify_paths.py`,
`PROOF_RESULT.md`, `PROOF_POSTHOC2.md`. No frozen file was edited.

---

## 1. `lockfile_graph.json`

`schema`, `label`, `sources[]`, `counts`, `unit2`, `nodes[]`, `edges[]`,
`non_graph_declarations[]`.

`counts`: `lockfile_entries` (193), `resolved_edges` (266),
`non_graph_declarations` (2), `status` (per-category counts),
`vulnerable_nodes` (26), `flagged_records` (34).

`unit2`: `label` = `"POST-HOC"`, `source`, `definition`, `counts`
(`both`/`vc_flagged_only`/`npm_only`), `items` (same three lists). It reproduces
`PROOF_POSTHOC2.md` section 3 and is **not** a pre-registered comparison.

### `nodes[]` — one record per lockfile `packages` entry (including root)

| Field | Meaning / source |
|---|---|
| `key` | verbatim `packages` key; `""` is the root |
| `id` | `name@version` (independent parser) |
| `name`, `version` | from the independent parser |
| `is_root` | `key == ""` |
| `direct` | resolved direct dependency of root; cross-checked against `flagged_packages.json` and `graph_subgraph.json` |
| `dev`, `optional` | verbatim lockfile booleans; `dev` cross-checked against `flagged_packages.json` |
| `license`, `resolved`, `integrity` | verbatim lockfile strings, or `null` when absent |
| `depth_min` | **descriptive** BFS hops from root over the 266-edge graph; `null` if unreachable |
| `n_dependencies`, `n_dependents` | **descriptive** out/in edge counts |
| `n_ancestors`, `n_descendants` | **descriptive** distinct reachable nodes in each direction, excluding self |
| `status` | `root` \| `vulnerable` \| `flagged_ancestor` \| `excluded_no_vulnerable_descendant` \| `excluded_not_reachable` |
| `structural_facts_label` | always `"descriptive"` |
| `advisories_offline` | sorted IDs copied from `offline_online.json:rows[].offline_ids`, cross-checked against frozen KB edges + cache |
| `advisories_offline_sources` | `{id: [kb_edge, osv_cache]}` from the frozen sources |
| `advisories_online`, `advisories_online_status`, `advisories_online_error` | `online_ids`, `status`, `error` copied from `offline_online.json`; `null` if no row |
| `flagged_record_index` | 0-based index into `flagged_packages.json:flagged[]`, else `null` |
| `model_score` | verbatim `model_score` (number or `null`) from that flagged record, else `null` |
| `verified` | `pass` from the aligned `verify_report.json` row, else `null` |
| `npm.listed` | pid in `NPM_ITEMS` = `found_by_both` + `npm_audit_only` |
| `npm.advisory_ids` | `causes[].evidence.npm_ids` when recorded, else `null` |
| `npm.severity` | `null` — raw audit stdout was not saved (see `MISSING.md`) |
| `npm.group` | `both` \| `vulnchain_only` \| `npm_audit_only` \| `none` from `npm_audit_comparison.json:groups` |
| `npm.cause` | verbatim `causes[].cause`, else `null` (includes `NOT_A_DISCREPANCY`) |
| `unit2_group` | `both` \| `vc_flagged_only` \| `npm_only` \| `none`, POST-HOC |
| `unit2_label` | always `"POST-HOC"` |

### `edges[]` — the independent parser's 266 resolved edges

`from_key`, `to_key`, `dep_name`, `declared_range` (verbatim string from the
parent's declaration), `dep_kind` (`dependencies` / `devDependencies` /
`optionalDependencies` / `peerDependencies`), `lookup_order[]`
(`key`, `exists` = key present in the lockfile, `resolver_match` = key present
in `by_name[dep_name]`), `resolved_key` (first `resolver_match`, identical to
`verify_paths.py::resolve_edge`).

### `non_graph_declarations[]`

The 2 `optionalDependencies` declarations that the independent parser does not
add to its dependency set. Same fields plus `in_independent_graph: false`,
`resolved_key: null` and a `reason`. Their targets are the two
`excluded_not_reachable` nodes recorded in `PROOF_POSTHOC2.md` section 2.3.
`peerDependencies` declarations: 0 in this lockfile.

---

## 2. `edge_evidence.json`

`schema`, `label`, `sources[]`, `counts` (`printed_paths`, `path_edges`),
`paths[]`. Per path: `flagged_record_index`, `package`, `path_index`, `path`
(the printed `name@version` list), `lockfile_keys` (deterministic key
assignment using the same nesting rule), `edges[]`.

Per edge: `edge_index`, `from_pid`, `to_pid`, `parent_key`, `child_name`,
`child_key`, `declared_range`, `dep_kind`, `lookup_order[]` (`key`, `exists`,
`resolver_match`, `winning`), `resolved_key`, `resolved_version`,
`parent_pointer`, `child_pointer` (RFC 6901 pointers into `/packages`; `~1`
escapes `/`), `parent_entry_raw`, `child_entry_raw` (verbatim lockfile JSON,
serialised with sorted keys).

---

## 3. `advisories.json`

`schema`, `label`, `sources[]`, `counts`, `advisories[]`. Per advisory ID:
`id`, `sources[]` (which committed source carries it), `packages_offline[]`,
`packages_online[]`, `url` = `https://osv.dev/vulnerability/<ID>`, `aliases`
(copied only when `data_pipeline/cve_nodes.json` records them, else `null`),
`alias_source`.

---

## 4. `npm_audit_detail.json`

`schema`, `status` (`FOUND` or `MISSING`), `label`, `raw_stdout`,
`raw_stdout_match_reason`, `reason`, `recorded` (verbatim fields from
`proof/out/npm_audit_comparison.json`), `searched_files[]`, `entries`,
`missing_fields[]`, `comparison_items[]` (per `name@version`: `item`, `name`,
`severity`, `via`, `range`, `fixAvailable`, `nodes`, `npm_advisory_ids`,
`comparison_group`, `cause`).

The comparison step recorded only `stdout_sha256`, `stdout_bytes`, `stderr` and
derived fields. If `status = MISSING`, `entries` and all raw-only fields are
`null`; no `npm audit` was re-run.

---

## 5. `independence.json`

`schema`, `label`, `sources[]`, `audited_file`, `parsed_with` (`ast`),
`import_count`, `imports[]` (`line`, `kind`, `module`, `names`, `level`,
`alias`, `statement`, `verdict`), `committed_record` (copy of
`independence_audit.json`), `negative_controls[]` (`mutation`, `outcome`,
`source`) or `null`, `negative_controls_status`. Negative controls are parsed
from `PROOF_RESULT.md`; `MISSING` if not parseable.

---

## 6. `reproduce.json`

`schema`, `label`, `sources[]`, `counts`, `per_package[]`
(`flagged_record_index`, `package`, `lock_key`, `cli_command`,
`verify_paths_command`, `cli_result`, `verify_result`, `note`), `fresh_clone`
(`source`, `source_repo`, `branch`, `temp_dir`, `temp_dir_removed`,
`commands[]`, `validation`, `exports_before`, `exports_after`). Commands and
results are copied verbatim from `proof/out/fresh_clone_log.json`.

---

## 7. `sample-lock.json`

Byte-for-byte copy of `demo/sample-lock.json`. `meta.json: sample_lock_copy`
holds `worktree_sha256`, `git_blob_sha256`, `bytes_equal`, `json_content_equal`.
A CRLF/LF difference is not a failure; a JSON-content difference is.

---

## 8. `meta.json`

The only file containing timestamps, all copied from committed files:
`source_commit_at_export_time`, `source_timestamp`
(`proof/out/meta.json:timestamp`), `fresh_clone_started_utc`,
`fresh_clone_finished_utc`. Also `schema`, `label`, `lockfile`,
`lockfile_sha256`, `advisory_source_sha256`, `sample_lock_copy`, `source_files[]`,
`export_files[]`.

---

## 9. `SCHEMA.md` / 10. `MISSING.md`

This document and the null-value register.

---

## Reconciliation (hard assertions, evaluated before any write)

| Check | Expected |
|---|---|
| lockfile entries | 193 |
| resolved edges | 266 |
| status | root 1 + (vulnerable + flagged_ancestor) 34 + excluded_not_reachable 2 + excluded_no_vulnerable_descendant 156 = 193 |
| vulnerable nodes | 26 |
| printed paths | 34 |
| verified | 34 / 34 |
| npm groups | 24 / 1 / 6 |
| unit2 groups (POST-HOC) | 28 / 5 / 2 |
| every status, group, cause, score, advisory ID, direct/dev flag | equal to the corresponding committed `proof/out/*.json` value |
| `sample-lock.json` | JSON content equals the git blob |

On any mismatch the script prints the reconciliation table and exits without
writing a single file. It never changes a value to make a check pass.
