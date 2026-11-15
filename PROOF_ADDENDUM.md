# PROOF_ADDENDUM.md — post-hoc records (no protocol change)

Per `PROOF_PROTOCOL.md` §9 RUN RULES, later changes and observations are recorded
here. **No frozen gate file, no `phase5/` file, and `PROOF_PROTOCOL.md` itself was
edited after its commit.** `git log --name-status` on `proof-module` shows only `A`
(add) statuses for every commit in this module; there are zero `M` statuses, i.e.
zero post-commit edits.

## 1. Fixes made BEFORE their own commits (not post-commit edits)

| File | Observed | Fix | Commit |
|---|---|---|---|
| `vulnchain/proof/graph.py` | first run produced 11 of 34 flagged packages with `NO_PATH` because enumeration stopped at the first vulnerable node | keep exploring past a vulnerable node so deeper flagged packages also receive a root-to-vulnerable-descendant path | `4ca1791` (before commit) |
| `proof/compare_npm_audit.py` | `FileNotFoundError: [WinError 2]` — Python `subprocess` cannot resolve `npm` on Windows without the `.cmd` suffix | resolve via `shutil.which("npm.cmd") or shutil.which("npm")`, record `resolved_binary` | `f0b0218` (before commit) |
| `proof/offline_online.py` | unused `urllib.error` import | removed | `872b573` (before commit) |

## 2. Fresh-clone observations (read-only, no action taken)

- `core.autocrlf=true` in the main repo. In the main worktree,
  `phase5/confirm_metrics.json` and `phase5/bench_run/osv_cache.json` are CRLF;
  the git blobs are LF. A fresh clone (global `core.autocrlf` unset) checks them
  out as LF.
- Consequence: the SHA-256 values frozen in `PROOF_PROTOCOL.md` §0 are the **main
  worktree** hashes. The fresh clone sees LF-normalised bytes with different
  hashes. JSON content is identical; no advisory ID, version or result changes.

| File | main worktree SHA-256 | git blob / fresh-clone SHA-256 | EOL |
|---|---|---|---|
| `phase5/confirm_metrics.json` | `0225d3e3bb4310e60640d6d48a2c58a9c6559b834a2b0d0f41ddab35d329e960` | `d5d6d81b5faec613c6ba6588fa41f8b8cba9de16ff653f5f8dce0a80f9d4c2af` | `i/lf w/crlf` |
| `phase5/bench_run/osv_cache.json` | `aade9a5d13937f16d06de18ea70cf6034cb16fd8554ccb97411fcf7561423335` | `2932c4131f9d55fd2b087b56e1435d308b6939d4a6bc4403ba64994b39da803a` | `i/lf w/crlf` |
| `demo/sample-lock.json` | `f7a147023dcd3d1fa12c6451b5a93e441e415fb9835b561cffa6f123623314ba` | same | `i/none w/none` |
| `phase5/HYBRID_GATE.md` | `7a6ec2503b91d6951ada346d721833400bdc1fb2f6a6f842ccf725e2fe2b06ac` | same | `i/lf w/lf` |
| `phase5/bench_run/vulnchain_graph.json` | `8fe4dca9e3e001cab708c8f987d8f46dd80684dfcea3f963b3ab13665cf0c72d` | same | `i/none w/none` |

- `npm audit --json` is a live service; its stdout is not byte-deterministic. Its
  stored SHA-256 in `npm_audit_comparison.json` therefore differs between the
  committed export and the fresh-clone regeneration, while the three group counts
  and `UNEXPLAINED` count reproduced exactly.
- `flagged_packages.json` and `meta.json` contain generated timestamps, so their
  hashes change on every regeneration. `verify_report.json` and
  `graph_subgraph.json` were byte-identical on regeneration.

## 3. Standing rules unchanged

No threshold, formula, selection rule, cause rule, or success criterion was
altered. No new model, no GNN, no retraining, no merge of `proof-module`.
