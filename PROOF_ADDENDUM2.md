# PROOF_ADDENDUM2.md — explorer export (presentation layer only)

Branch `hybrid-cs`. MAIN VulnChain repo. This document is committed **alone**,
before the export script or any export file exists.

## Scope

This export **reshapes already-committed results for a web front end**. It is a
presentation-layer reformat of `proof/out/*.json`, `demo/sample-lock.json` and the
frozen advisory-source files. It **adds no criterion, no claim and no result**.

- No new model, no GNN, no training or retraining, no new gate, no threshold,
  no score computation, no hypothesis and no success criterion.
- No `npm audit` run, no live OSV query, no CLI run, no verifier re-run against
  mutated inputs. Only recorded outputs are read.
- No frozen file is edited: `PROOF_PROTOCOL.md`, `PROOF_RESULT.md`,
  `PROOF_POSTHOC.md`, `PROOF_POSTHOC2.md`, `PROOF_ADDENDUM.md`, `phase5/*`,
  `proof/out/*`, `paper_notes/claims_ledger.md`.
- New files only: `proof/explorer_export/*`, `proof/make_explorer_export.py`,
  this document.

## Provenance of every field

**Every flag, status, count and advisory ID is copied from existing committed
files** — `proof/out/flagged_packages.json` (flags, status counts, printed
paths, model scores, record indices), `proof/out/verify_report.json`
(verification), `proof/out/offline_online.json` (offline/online advisory IDs and
query status), `proof/out/npm_audit_comparison.json` (npm groups and cause
labels), `proof/out/independence_audit.json`, `proof/out/fresh_clone_log.json`,
`proof/out/meta.json`, `PROOF_POSTHOC2.md` (the POST-HOC unit), the frozen
advisory sources (`phase5/bench_run/vulnchain_graph.json`,
`phase5/bench_run/osv_cache.json`) and the committed lockfile. Where a per-node
status is not stored as a column in any committed file, it is resolved by
membership in those committed sets, and its category totals are asserted equal
to the committed counts. Any value that cannot be found in a committed file is
**not computed or guessed**: it is listed in `proof/explorer_export/MISSING.md`
and the field is left `null`.

**Only structural facts are derived from the lockfile by stdlib code**: minimum
depth from the root, in/out degree, and ancestor/descendant counts, plus the
nesting-rule lookup order and the JSON pointers used as evidence. These are
**labelled descriptive** in `proof/explorer_export/SCHEMA.md`. They are derived
from `proof/verify_paths.py`'s independent parser (stdlib only); nothing is
imported from `vulnchain/`, `phase5/`, `TrainModel/` or any model code.

## Mechanical properties

Deterministic output: sorted keys, LF newlines, no timestamps except the
timestamp copied into `proof/explorer_export/meta.json` from the committed
`proof/out/meta.json`. `sample-lock.json` is a byte copy of
`demo/sample-lock.json`; both the worktree and git-blob SHA-256 are recorded,
and only a JSON-content difference would be a mismatch (a CRLF/LF difference
would not). Reconciliation assertions are hard: on any mismatch the exporter
stops, prints a table and writes nothing; nothing is changed to make a check
pass.
