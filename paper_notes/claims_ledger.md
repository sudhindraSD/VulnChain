# Paper claims ledger

Evidence state: branch `hybrid-cs` at `7a4a28d96c6356877df24d7052c9ec7c42670c30`
(after `git merge --ff-only proof-module` and `git push origin hybrid-cs`,
immediately before this ledger's own commit).

Every number in the `exact number` column was copied from a **committed file**
(read from the working tree of that commit), not typed from memory. `MISSING` is
written where a number cannot be found in a committed file. **MISSING count = 0.**

`commit hash` = short hash of `git log -1 --format=%h -- <source file>` on
`hybrid-cs`, except the three Stage 4 rows, whose hashes come from the separate
`vulnchain-rebuild-gate` repo (branch `stage4`). Those three source files are
tracked in that repo and are **not** present on `hybrid-cs`.

Status legend: `PRE-REGISTERED` = fixed in a gate/protocol committed before the
run; `POST-HOC` = descriptive observation recorded after the fact, not a gate
verdict; `INVALID` = withdrawn / superseded / not citable as a result.

| claim | exact number | source file | commit hash | status |
|---|---|---|---|---|
| `LP_original` leaky comparator, withdrawn (original gate comparator) | `0.719099 ± 0.006897` | `phase5/HYBRID_GATE.md` | `8989cd4` | INVALID |
| `LP_clean` amended comparator, vs `LP_original` above | `0.632905 ± 0.007867` | `phase5/HYBRID_GATE.md` | `8989cd4` | PRE-REGISTERED |
| VulnGAT-HR baseline | `0.631473 ± 0.004468` | `phase5/HYBRID_GATE.md` | `8989cd4` | PRE-REGISTERED |
| BFS baseline | `0.528650 ± 0.003851` | `phase5/HYBRID_GATE.md` | `8989cd4` | PRE-REGISTERED |
| C&S original "PASS" INVALID: all 8,682 evaluated negatives were in the known set; result withdrawn | `0.824964` mean AUC; `+0.192059` mean paired delta; `8682` negatives | `HYBRID_GATE_ADDENDUM2.md` | `7da0771` | INVALID |
| `C&S_STRICT` negative result, FAILS the gate (frozen `alpha = 0.5`, `n_iter = 25`, no rerun / no retuning) | `0.598608` vs `LP_clean 0.632905`; paired delta `-0.034297` | `phase5/HYBRID_AUDIT.md` | `8442952` | POST-HOC |
| `RANK_AVG(HR, LP_clean)` 0.692 is exploratory, NOT a result until fresh-seed confirmation; retraction audit: the implied "LP_clean adds complementary signal" is retracted - HR-LP_clean correlation is `0.008021 ± 0.007011` overall and `-0.179661 ± 0.022889` on positives | `0.692055 ± 0.006061`; correlations `0.008021 ± 0.007011`, `-0.179661 ± 0.022889` | `HYBRID_GATE_ADDENDUM2.md`; `phase5/COMPLEMENT_CHECK.md` | `7da0771`; `20d68de` | INVALID |
| Task D PRIMARY: `CANDIDATE - LP_clean` mean paired delta, vs threshold, verdict PASS | `mean_delta 0.06574642801644279`; `sd_delta 0.005479641448113535`; `threshold 0.02`; `primary_pass true` | `phase5/confirm_metrics.json` | `02b68dc` | PRE-REGISTERED |
| Task D secondary 1: `CANDIDATE - HR` | `+0.045246 > 0.02` YES (mean `0.04524569215287864`) | `phase5/CONFIRM_RESULT.md` | `2d6a836` | PRE-REGISTERED |
| Task D secondary 2: `CANDIDATE - RANK_AVG(RIDGE,LP_clean)` | `+0.030896 > 0` YES (mean `0.030896160689218966`) | `phase5/CONFIRM_RESULT.md` | `2d6a836` | PRE-REGISTERED |
| `NONZERO_NBR` beats `LP_clean` on Task D seeds (post-hoc gap, not a pre-registered gate) | `0.632159` vs `0.615713`; gap `+0.016446` (exact `0.016445908675152388`) | `phase5/CONFIRM_RESULT.md` | `2d6a836` | POST-HOC |
| Task D post-hoc: `RANK_AVG(HR, NONZERO_NBR)` and `RANK_AVG(HR, BINARISED_LP)` vs `CANDIDATE` (paired deltas, delta = `CANDIDATE` minus fusion, descriptive, no gate) | `CANDIDATE - RANK_AVG(HR, NONZERO_NBR)` mean `-0.000939` (std `0.004553`); `CANDIDATE - RANK_AVG(HR, BINARISED_LP)` mean `-0.010936` (std `0.001219`) | `phase5/CONFIRM_POSTHOC.md` | `f788355` | POST-HOC |
| `RANK_AVG(HR, NONZERO_NBR)` on Task D seeds 2001-2005 (post-hoc recomputation with the gate's own `rank_avg_scores`/`compute_auc` code) | per-seed `0.683556`, `0.688019`, `0.683161`, `0.668530`, `0.688723`; mean `0.682398`, std `0.008153` | `phase5/CONFIRM_POSTHOC.md` | `f788355` | POST-HOC |
| Task D interpretation limit: the verdict PASS stands, but the supported claim is only that "HR combined with a locality signal beats either alone"; HR was trained with the audited edges visible, and `PERM_ALL` on seed 2004 is outside the band | `PERM_ALL` seed 2004 `0.560368` > 0.55 (`1` of `5` seeds outside 0.45-0.55); HR trained on the full graph with `hasVulnerability` edges present, 50% mask applied at inference only, no retraining | `phase5/CONFIRM_POSTHOC.md` | `f788355` | POST-HOC |
| Proof module criterion (a): 100% of printed paths verified | `34/34`; `paths_pass 34`, `paths_fail 0`, `paths_total 34` | `proof/out/verify_report.json` | `80a819a` | PRE-REGISTERED |
| Proof module criterion (b): UNEXPLAINED comparison items | `1` | `proof/out/npm_audit_comparison.json` | `80a819a` | PRE-REGISTERED |
| Offline vs online agreement rate `A = agree_count / size(D)` | `156/168 = 0.9285714285714286`; `disagree_count 12`; `no_online_result_count 0` | `proof/out/offline_online.json` | `80a819a` | PRE-REGISTERED |
| VC_FLAGGED vs NPM_ITEMS, alternative unit (post-hoc, NOT the pre-registered comparison); retraction audit: supports no claim of superiority or greater completeness in either direction - the 2 npm-only items lack a vulnerable descendant in ADV_OFF (unit-scope reasons, not missed detections) | `both 28`; `VC-flagged-only 5`; `npm-only 2` (33 distinct VC_FLAGGED pids vs 30 NPM_ITEMS) | `PROOF_POSTHOC2.md` | `7a4a28d` | POST-HOC |
| Model score coverage | 25 UNRESOLVED records, 24 distinct packages, 0 with a frozen score anywhere in the repo | `PROOF_POSTHOC.md` | `1ce4487` | POST-HOC |
| CLI flagged-set completeness (post-hoc recomputation, CLI unchanged) | `0` omitted; `0` extra; `34` expected node keys / `33` distinct pids | `PROOF_POSTHOC2.md` | `7a4a28d` | POST-HOC |
| Stage 4 popularity-matched gate (a) PASS: `Ridge_raw - random` PR-AUC | `Ridge_raw 0.208244`; `+0.151926` 95% CI `[+0.089961, +0.214983]` | `../vulnchain-rebuild-gate/STAGE4_RESULT.md` | `9e2883c` | PRE-REGISTERED |
| Stage 4 popularity-matched gate (b) PASS: `Ridge_raw - POPULARITY_ONLY` PR-AUC | `+0.114275` 95% CI `[+0.063540, +0.161861]`; baselines `random 0.056318`, `POPULARITY_ONLY 0.093969` | `../vulnchain-rebuild-gate/STAGE4_RESULT.md` | `9e2883c` | PRE-REGISTERED |
| Stage 4 caveats: unmatched positives are systematically more popular; feature popularity proxies; provenance limit; null margin | `29/155` unmatched positives; median versions `189.00` vs `5.50` (`34.364x`), age `3443.34` vs `692.17` (`4.975x`), degree `21.00` vs `2.00` (`10.500x`); flagged columns `prior_adv`, version-level `age`, `maj`, `min`, `pat`, `pre`; null margin `+0.005857`; `630` matched never-advised negatives; no commits before `d18ac03` so Stage 1-3 files are untracked and not time-verifiable | `../vulnchain-rebuild-gate/STAGE4_POSTHOC.md`; `../vulnchain-rebuild-gate/STAGE4_RESULT.md` | `d6f8901`; `9e2883c` | POST-HOC |

## Provenance notes

- Stage 4 gate pre-registration commit in the sibling repo: `d18ac03bbcad6038a1f48b9a90ee14b9a41d0a75` (`d18ac03`, 2026-11-14T20:17:54+05:30), from `git log -1 -- STAGE4_GATE.md` in `vulnchain-rebuild-gate`.
- `phase5/HYBRID_GATE.md`, `phase5/CONFIRM_RESULT.md`, `proof/out/*.json` and the `PROOF_*.md` files (`PROOF_PROTOCOL.md`, `PROOF_RESULT.md`, `PROOF_ADDENDUM.md`, `PROOF_POSTHOC.md`, `PROOF_POSTHOC2.md`) are all tracked on `hybrid-cs` at `7a4a28d`.
- `proof/out/audit_scores.json` independently parses `LP_original 0.719099`, `LP_clean 0.632905`, `HR 0.631473`, `BFS 0.528650` from `phase5/HYBRID_GATE.md` with `parse_failures = []`; its Task D block is parsed from `phase5/confirm_metrics.json` (not typed).
- Two derived values are arithmetic from committed numbers rather than literal
  strings: the `NONZERO_NBR - LP_clean` gap (`0.632159 - 0.615713 = +0.016446`;
  full precision `0.016445908675152388` from `phase5/confirm_metrics.json` rows)
  and the agreement quotient `156/168 = 0.9285714285714286` (the rate is also
  stored verbatim in `proof/out/offline_online.json`).
- Rows marked POST-HOC are descriptive and carry no gate verdict. Rows marked INVALID must not be cited as results.
