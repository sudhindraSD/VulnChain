# HYBRID GATE — ADDENDUM 2 (post-hoc, committed after the fact)

Branch `hybrid-cs`. This document does not edit `phase5/HYBRID_GATE.md` (still
exactly as committed in `8989cd4`), does not change any gate rule, threshold,
seed, comparator or hyperparameter, and runs no model. It states plainly what
happened and what the numbers are.

1. **Gate rule commit `8989cd4` is valid.** `phase5/HYBRID_GATE.md` was
   pre-registered in that standalone commit before any hybrid code existed,
   and its amended comparator `LP_clean` and paired-difference rule stand.

2. **The Correct & Smooth hybrid code ran BEFORE this addendum, and some files
   were committed after the fact.** `TrainModel/masked_edge_hybrid_cs.py` and
   `phase5/HYBRID_RESULT.md` already existed and had already been run and read
   before the first addendum was written; several evidence files
   (`TrainModel/masked_edge_audit_leakfix.py`,
   `TrainModel/masked_edge_hybrid_audit.py`, `phase5/HYBRID_AUDIT.md`,
   `phase5/LEARNING_CURVE.md`, `phase5/LP_LEAKCHECK.md`,
   `phase5/learning_curve_diagnostic.py`, the Repomix dumps and the modified
   OSV cache) were uncommitted evidence and were committed as-is in commit
   `8442952` ("evidence files, committed after the fact (produced before
   addendum)") before this document was written. No file was edited.

3. **The original C&S "PASS" is INVALID.** It reported mean AUC 0.825
   (`0.824964`) and a mean paired delta of +0.192 (`+0.192059`) over
   `LP_clean` (0.632905). The `known_CURRENT` set contained **all 8,682
   evaluated negatives** (with `label_clean` = 0), so every evaluated negative
   was clamped to its own known label. C&S with a `RIDGE_RAW` base reached
   0.997 (`0.997288`), confirming the known-set composition as the source of
   the score. The 0.825 / +0.192 PASS is withdrawn and must not be cited as a
   result.

4. **C&S_STRICT is a negative result.** With all evaluated nodes excluded from
   the known set, frozen `alpha = 0.5`, `n_iter = 25` (selected only on tuning
   seeds `[52, 72, 92]`), C&S_STRICT scored mean AUC **0.5986** (`0.598608`)
   versus `LP_clean` **0.6329** (`0.632905`); paired delta **-0.034297**. It
   **FAILS** the gate. Recorded as a negative result; no rerun, no retuning.

5. **The strict permuted-label control scored 0.662** (`0.662439 ± 0.014961`),
   not near 0.5. This is a **mis-specified null**: the audit rewards locality,
   so permuting labels among `known_STRICT` nodes does not remove the
   structural signal. Reported as a failed sanity control, not rerun.

6. **The rank-average 0.692 is EXPLORATORY, not a result.**
   `RANK_AVG(HR, LP_clean)` = equal-weight average of average-tie rank vectors
   over the evaluated set = **0.692055 ± 0.006061**, found on the gate seeds
   `[42, 123, 456, 789, 1024]`. It is a complementarity diagnostic seen on
   those same seeds. It is **NOT a result until confirmed on fresh seeds**.
