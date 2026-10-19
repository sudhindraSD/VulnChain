# VulnChain — Lessons Learned (9-repo build → 50-repo rebuild)

**Purpose of this doc:** every mistake made during the original 9-repo build, why it happened, and the exact rule that prevents it from recurring. This is meant to be followed literally by whoever (human or AI) runs the 50-repo extraction/training, not just read for context. Pipeline scripts themselves are reused unchanged — this doc governs *how they're run and evaluated*, not what code to write.

---

## Mistake 1: Random split instead of locked repo-level split
**What happened:** Training used a random per-node stratified shuffle (seed=42) across all Package nodes, instead of the pre-decided repo-level split (specific repos assigned to train/val/test). This inflated results (Pearson 0.60, rank acc 82%) because nodes from the same repo leaked between train and test — the model could partially "recognize" a repo it had already seen packages from.
**How it was caught:** Node-count mismatch. The eval report claimed test N=560 but the actual designated test repo (juice-shop) has 1,269 nodes. The numbers didn't match what they claimed to measure.
**Rule for the 50-repo rebuild:**
- Lock the repo→split assignment **in a checked-in file** (`repo_split_mapping.json`) *before* any training run, not after.
- Every training/eval script must load split assignment from that file — never generate a split inline, never use `train_test_split` on nodes directly.
- Before trusting any eval number, verify test-set N against the known node count of the assigned test repos. If it doesn't match, the split is wrong — stop and fix it before reading any other metric.

## Mistake 2: Feature leak in the audit (dim 6 not masked alongside edges)
**What happened:** Package feature dim 6 (`has_known_cve_history`) was backfilled from hasVulnerability edges at graph-merge time. The masked-edge audit hid the *edges* but never zeroed this *feature* — so a "masked" package still told the model "I have known CVEs = 1" through the back door. This partially explains why model AUC ≡ feature-shuffle AUC (the shuffle only touched CVE embeddings, not dim 6).
**How it was caught:** Manual code review of the audit script against the feature-construction code in the merge step — not caught by any automated check.
**Rule for the 50-repo rebuild:**
- **Before merging**, write down every Package feature dimension and explicitly flag which ones are derived from edges that will later be masked in any robustness/audit experiment. Dim 6 is the known one; check whether any new features added for the 50-repo build have the same property.
- Any masking experiment (audit or training-time robustness) must zero **all** edge-derived features for the masked node, not just remove the edges. Write this as a single shared utility function (`mask_package_for_eval(node, edges_to_hide)`) used by both the audit script and `train_robust.py`, so the masking logic can't drift out of sync between the two.
- Treat "model AUC ≡ baseline AUC" as a leak red flag, not a null result — investigate before accepting.

## Mistake 3: Trusting first-pass numbers before running the pre-registered audit
**What happened:** Initial (leaked) training numbers were treated as close to final for a stretch before the masked-edge audit was actually run and read. The audit script existed with a caveat comment about what to do if results collapsed — but that follow-up sat unbuilt for a while after collapse was actually observed.
**How it was caught:** Deliberate later re-read of the audit script, its output JSON, and the training code together, rather than accepting the eval report's headline numbers.
**Rule for the 50-repo rebuild:**
- Run the masked-edge audit (with Mistake 2's fix applied) **immediately after the first successful training run** on the 50-repo graph — not as a later afterthought once numbers "look good enough."
- Any pre-registered caveat or follow-up written into a script's comments is a commitment, not a suggestion — if the triggering condition is observed, the follow-up gets built in the same work session, not deferred indefinitely.

## Mistake 4: Treating VPSS-correlation metrics as the headline result
**What happened:** Pearson/Spearman correlation against VPSS labels was initially presented as the primary evidence of model quality. But VPSS is a deterministic formula (CVSS × depth-decay × exposure-tier) computable via plain BFS — so a high correlation partly just proves the model learned to approximate arithmetic, not that it found real signal.
**Rule for the 50-repo rebuild:**
- Do **not** lead with VPSS-correlation metrics in any report, demo, or interview narrative. They're a sanity check, not evidence.
- The headline metrics are: (a) masked-edge audit AUC vs label-propagation baseline (post dim-6 fix), and (b) NodeTestBench-style out-of-distribution precision/recall against real, independently-verified CVEs. These are the two evaluations VPSS cannot trivially win by construction.

## Mistake 5: `is_direct` feature dominance traced late
**What happened:** The VPSS exposure formula gives direct+prod dependencies a flat 1.00 regardless of real vulnerability status. The model learned `is_direct` as a strong positive signal, causing clean direct dependencies to outrank genuinely vulnerable transitive ones. This was diagnosed only after a confusing ranking-inversion result (three.js outranking nanoid) was investigated case-by-case.
**Rule for the 50-repo rebuild:**
- Before training on the 50-repo graph, explicitly check the correlation between `is_direct` and the VPSS label independent of actual vulnerability presence. If it's still strongly confounded (likely, since it's a property of the label formula, not the data), document it in the v1.1 design doc up front instead of re-discovering it via a confusing inference result later.
- When manually spot-checking any ranked output, always include at least one clean direct-dependency package deliberately, to catch this failure mode early rather than by accident.

## Mistake 6: EPSS retrained without checking sample size first
**What happened:** Switched training labels to EPSS scores as a "real fix" for VPSS redundancy, without first checking whether there was enough non-zero-labeled data (there wasn't — only 889 examples from 302/326 CVEs). The experiment failed (Pearson 0.43→0.25) in a way that cost a full retrain cycle before the root cause (data volume, not label quality) was identified.
**Rule for the 50-repo rebuild:**
- Before any label-source swap experiment, count non-zero labeled examples for the *new* label source first, and compare against the count for the current source. If it's meaningfully smaller, treat that as the likely explanation for any regression before concluding the new label source itself doesn't work.
- At 50-repo scale, if EPSS non-zero count crosses roughly 3,000-4,000 examples, it's worth a clean re-attempt. Below that, don't re-run it — it's not a fair test yet.

## Mistake 7: Inference-time coverage gap for unseen packages
**What happened:** 45% of packages on a novel, never-before-seen lockfile got an identical constant risk score because of a hardcoded default feature vector fallback (`depth=1`) for any package missing from the training knowledge base.
**Rule for the 50-repo rebuild:**
- The three inference-pipeline fixes already built (real BFS depth, live OSV lookup for unseen packages, post-hoc calibration cap) should be re-verified against the 50-repo knowledge base, not assumed to still be sufficient. A bigger KB reduces how often a package is "unseen," but doesn't eliminate the case — test with at least one genuinely novel lockfile after the 50-repo model is trained.

## Mistake 8: Manual repo selection without diversity criteria
**What happened:** The original 9 repos were selected somewhat opportunistically (popular, well-known npm projects) without an explicit diversity rationale, and one (strapi) turned out to be incompatible (Yarn Berry v4 lockfile, unsupported by the parser) and had to be dropped after the fact.
**Rule for the 50-repo rebuild:**
- Check lockfile format compatibility **before** committing a repo to the extraction list, not after running the extractor and hitting a parse failure.
- Explicitly select for diversity across: lockfile version, dependency-tree size (small/medium/large), vulnerability density (mix of CVE-heavy and clean repos), and domain (not just web frameworks — include build tools, backend-only, monorepos if the extractor supports workspaces).

## Mistake 9: No fixed pre-registered success criteria for the robustness variant
**What happened (anticipated, not yet occurred — included here so it doesn't happen this time):** Earlier experiments (EPSS) were judged somewhat after the fact against shifting expectations.
**Rule for the 50-repo rebuild:**
- Before training VulnGAT-R (or any new variant), the success criteria must be written down first: (a) masked-edge audit AUC beats label-propagation by >0.02 at 50% mask ratio, (b) NodeTestBench-style OOD precision @ ≥0.40 stays ≥90%. If either fails, report both models honestly in the final doc — do not retroactively lower the bar to declare success.

## Mistake 10: Author identity resolved wrong on the first attempt
**What happened:** `author_extractor.py` (v1) assumed npm username = GitHub username to resolve author identity. This is often false — plenty of npm maintainers use a different handle than their GitHub account. Had to be rewritten from scratch as `author_extractor_v2.py`, resolving identity via the npm registry's `repository` field (real GitHub owner/repo) instead of guessing from the username.
**Rule for the 50-repo rebuild:** Never assume identity equivalence across platforms (npm username ≠ GitHub username). Resolve Author identity via `repository` field first; fall back to npm maintainer name only when no GitHub repo URL exists at all — this is already what v2 does, just don't regress to the v1 shortcut under time pressure at 50-repo scale.

## Mistake 11: Design doc referenced infrastructure that was never built
**What happened:** `VULNCHAIN_DESIGN_v1.0.md` said "Round 3 uses local GitHub Advisory cache only" for author data — but no such cache existed anywhere in the codebase. This was only caught when actually implementing that stage, and resolved on the fly by switching to live npm registry + GitHub API calls instead.
**Rule for the 50-repo rebuild:** Don't treat the design doc as ground truth for what infrastructure exists — verify every referenced cache, file, or intermediate artifact actually exists in the repo before building against it. If v1.1 references anything similar, check it exists before writing code that assumes it does.

## Mistake 12: Scoped npm package names silently broke edges
**What happened:** A regex in `jsonGraphExtractor.py` was stripping the `@scope/` prefix off scoped package names (e.g. `@babel/core`), causing dangling edges instead of a clear error. Fixed at the source once found.
**Rule for the 50-repo rebuild:** npm package name parsing has multiple edge cases beyond scoped packages — workspace/monorepo packages, git-URL dependencies, file: protocol local deps — that can silently produce dangling or malformed edges rather than erroring loudly. At 50 repos (especially if any monorepos are included per Mistake 8's diversity criteria), add an explicit dangling-edge count check as a required pipeline step after each repo's extraction, not just at final merge time.

## Mistake 13: Started API-heavy extraction before setting up auth
**What happened:** Hit GitHub's 60 req/hr unauthenticated rate limit mid-extraction, before `GITHUB_TOKEN` was set up via `.env` + `python-dotenv`.
**Rule for the 50-repo rebuild:** Verify `GITHUB_TOKEN` is set and working (test with a single API call) before kicking off any author-resolution run — at 50-75 repo scale, hitting the unauthenticated wall mid-run wastes far more time than it did at 9 repos.

## Mistake 14: `.env` file nearly committed to version control
**What happened:** A `.gitignore` reminder had to be issued after the fact for the `.env` file holding `GITHUB_TOKEN`.
**Rule for the 50-repo rebuild:** Confirm `.gitignore` covers `.env` before the first commit of any extraction work — check this once, up front, not as a reactive reminder later.

## Note (not a mistake, a re-verification flag): `account_age_days` coverage
**What happened:** At 9-repo scale, `account_age_days` (one of the 7 Author dims) was 80% null — accepted as a documented limitation rather than fixed, with the decision to keep the Author schema locked at 7-dim and revisit only if ablation showed it contributed nothing.
**Rule for the 50-repo rebuild:** Don't assume this stays at 80% null. Re-measure it fresh on the 50-repo Author set — more repos may mean more resolvable GitHub owners (better coverage) or the same structural gap (unchanged). Either way, log the new percentage in the v1.1 doc rather than carrying forward the 9-repo number unchanged.

---

## Quick-reference checklist (run through this before declaring the 50-repo build "done")
- [ ] Repo split locked in `repo_split_mapping.json` before any training run
- [ ] Test-set N verified against known test-repo node counts
- [ ] Dim-6 (or equivalent edge-derived feature) masking utility shared between audit and robust-training scripts
- [ ] Masked-edge audit run immediately after first successful training run, not deferred
- [ ] Headline metrics = masked-edge audit AUC + OOD precision/recall, not VPSS correlation
- [ ] `is_direct`/VPSS confounding documented in v1.1 doc proactively
- [ ] EPSS non-zero label count checked before any relabel attempt
- [ ] Inference-time coverage fixes re-verified against 50-repo KB with a genuinely novel lockfile
- [ ] Lockfile compatibility checked before committing each repo to the extraction list
- [ ] Repo selection covers lockfile-version, size, vulnerability-density, and domain diversity
- [ ] VulnGAT-R success criteria written down before training, not after
- [ ] Author identity resolved via `repository` field first, npm-username-guessing never used
- [ ] Every artifact/cache referenced in v1.1 doc verified to actually exist before building against it
- [ ] Dangling-edge count checked per-repo after extraction, not just at final merge
- [ ] `GITHUB_TOKEN` verified working before starting author-resolution run
- [ ] `.gitignore` confirmed to cover `.env` before first commit
- [ ] `account_age_days` null-rate re-measured fresh on 50-repo data, not assumed to match 9-repo's 80%
