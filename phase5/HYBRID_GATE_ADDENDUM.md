# Addendum to `phase5/HYBRID_GATE.md` — the adjudicated hybrid is C&S

**Status: POST-HOC CLARIFICATION, not a pre-registration.** `phase5/HYBRID_GATE.md`
is **not edited**; it remains exactly as committed in `8989cd4`. This is a
separate document, committed alone with message
`hybrid gate addendum: adjudicated hybrid is C&S`.

Written: 2026-11-14 ~17:05 IST · branch `hybrid-cs` · parent `8989cd4`.

---

## 1. Chronology check — raw output

Command 1:

```bash
git log --format='%h %ad %s' --date=iso -- phase5/HYBRID_GATE.md
```

```text
8989cd4 2026-11-14 16:37:47 +0530 pre-register hybrid gate
```

Command 2:

```bash
git log --format='%h %ad %s' --date=iso -- TrainModel/masked_edge_audit_complement.py phase5/COMPLEMENT_CHECK.md
```

```text
(no output — empty)
```

Supporting facts from `git status` / filesystem mtimes (all `+0530`, 2026-11-14):

| File | mtime | git status |
|---|---|---|
| `phase5/HYBRID_GATE.md` | 16:37:41 (commit at 16:37:47) | tracked, committed `8989cd4` |
| `TrainModel/masked_edge_audit_complement.py` | 16:39:47 | **untracked, never committed** |
| `phase5/COMPLEMENT_CHECK.md` | 16:40:10 | **untracked, never committed** |
| `TrainModel/masked_edge_hybrid_cs.py` | 16:56:54 | **untracked, never committed** |
| `phase5/HYBRID_RESULT.md` | 16:58:24 | **untracked, never committed** |

### Chronology result, stated plainly

- **By filesystem time: YES.** `HYBRID_GATE.md` was committed at 16:37:47;
  the complementarity script was created at 16:39:47 and its output at
  16:40:10 — both after the gate commit.
- **By git history: NOT ESTABLISHED, and the question cannot be answered from
  git.** Command 2 returned **no output**. Both complementarity files are
  untracked and have **never been committed**. They never "existed in the
  repo" as tracked objects, so there is no commit for the gate to be before
  or after. If "existed in the repo" means tracked by git, the plain answer
  is **NO** — git history contains no record of them at all. No claim of
  git-verified pre-registration ordering for the complementarity work is
  made here.
- **This addendum is retroactive.** `TrainModel/masked_edge_hybrid_cs.py`
  already existed (16:56:54) and had already been run once, producing
  `phase5/HYBRID_RESULT.md` (16:58:24) with the gate verdict (mean paired
  delta `+0.192059`, PASS), before this addendum was written and committed.
  The instruction to commit it "BEFORE writing or running any hybrid code"
  **could not be satisfied**: hybrid code and its results already existed
  and had already been seen. This document must **not** be cited as
  pre-specification of the C&S architecture or as evidence that the design
  was fixed before results were observed. No hybrid code was written or run
  while producing this addendum.

---

## 2. The hybrid adjudicated against the gate

The single hybrid adjudicated against `phase5/HYBRID_GATE.md` is exactly:

> **Correct & Smooth with the HR base.**

- **Base:** VulnGAT-HR scores from `phase5/models/vulngat_hr_full.pt` on the
  masked graph, with `Package.x[:, 6]` zeroed for masked packages.
- **Labels:** leak-free VPSS recomputed on the **MASKED** graph by
  `data_pipeline/vpss_labeler.label_all()`; the original
  `phase4/vpss_labels_51repo.json` are never used by any label-consuming
  step (`HYBRID_GATE.md` §3).
- **Hyperparameters:** `alpha ∈ {0.5, 0.7, 0.8, 0.9}` ×
  `n_iter ∈ {10, 25, 50}` selected **only** on the tuning mask seeds
  `[52, 72, 92]`; the single best pair is **frozen**, then the hybrid is
  evaluated **once** on the gate seeds `[42, 123, 456, 789, 1024]`.
- **Gate rule (unchanged):** `mean_s[AUC(hybrid_s) − AUC(LP_clean_s)] >
  max(0.02, 2 * std_pop(LP_clean))`, paired by seed on identical masks.

Nothing in this addendum changes that rule, the comparator, or the
pre-declared negative-result fallback in `HYBRID_GATE.md` §4.

---

## 3. `RANK_AVG(HR, LP_clean)` is exploratory, not the adjudicated hybrid

`RANK_AVG(HR, LP_clean)` = `0.692055 ± 0.006061` on the gate seeds was
observed in `phase5/COMPLEMENT_CHECK.md` as a **complementarity diagnostic**
(equal-weight average of average-tie rank vectors over the evaluated set).
It is **NOT** the adjudicated hybrid. It is reported **separately** and is
labelled **exploratory**.

Chronology result restated here as required by §1: the gate was committed at
`16:37:47`, while the complementarity script and its output were created at
`16:39:47` / `16:40:10` and are **untracked with an empty `git log`** — so
git history provides **no** record of them and no git-verified ordering
relative to the gate. The rank-average number was observed before any hybrid
code was written, but it was never committed and it is not the registered
hybrid.

---

## 4. Controls reported next to the hybrid

The following are **controls**, not gate candidates, and are reported next
to the adjudicated hybrid:

1. `RANK_AVG(RIDGE_RAW, LP_clean)` — equal-weight rank average of the
   ridge-raw control and `LP_clean` (diagnostic).
2. **C&S with `RIDGE_RAW` as the base model** — same frozen `alpha` /
   `n_iter`, same masked-graph labels, same masks.
3. **Label-permuted sanity control** — C&S hybrid with `label_clean`
   randomly permuted among known nodes; expected near 0.5, and a failure
   stops the harness.

`LP_clean`, the HR baseline, and the original (superseded) leaky gate are
also reported alongside, as required by the amendment note in
`HYBRID_GATE.md` §1.

---

## 5. Scope

This addendum does not re-adjudicate any gate, does not change any
hyperparameter, threshold, seed, or comparator, and does not introduce any
new tuning. It is a new, self-contained document: it reads no data, runs no
model, and changes no existing script, result, label, model or data file.
