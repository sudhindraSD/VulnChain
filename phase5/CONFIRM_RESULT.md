# Task D - confirmatory run result

Pre-registered in `phase5/CONFIRM_GATE.md` (commit `ddcb442`). Mask seeds [2001, 2002, 2003, 2004, 2005], 50% edge mask, official eligible/negative construction, official `compute_auc`. Frozen VulnGAT-HR inference only (no retraining). VPSS and all graph-derived features recomputed on the masked graph. Equal-weight rank-average with average ranks for ties, no tuning, no weights. std = sample (ddof=1) throughout.

## 1. Set sizes per seed

| Seed | n | n_eligible | n_neg | n_pos | len_eval_idx |
|---:|---:|---:|---:|---:|---:|
| 2001 | 12405 | 645 | 8682 | 313 | 8995 |
| 2002 | 12405 | 645 | 8682 | 320 | 9002 |
| 2003 | 12405 | 645 | 8682 | 324 | 9006 |
| 2004 | 12405 | 645 | 8682 | 309 | 8991 |
| 2005 | 12405 | 645 | 8682 | 299 | 8981 |

Hard assertions: n_eligible == 645 PASS; n_neg == 8682 PASS. n = 12405.

## 2. Per-seed ROC-AUC (all methods and controls)

| Seed | LP_clean | HR | RIDGE_RAW | CANDIDATE | RANK_AVG(RIDGE,LP_clean) | CANDIDATE_perm | PERM_ALL | BINARISED_LP | DEGREE | NONZERO_NBR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2001 | 0.619517 | 0.631715 | 0.586556 | 0.680167 | 0.649256 | 0.591221 | 0.505358 | 0.626068 | 0.557868 | 0.637721 |
| 2002 | 0.626477 | 0.638697 | 0.592832 | 0.690736 | 0.663333 | 0.600346 | 0.512437 | 0.629783 | 0.547382 | 0.641199 |
| 2003 | 0.624669 | 0.636164 | 0.580513 | 0.688267 | 0.654035 | 0.599466 | 0.517253 | 0.628738 | 0.547789 | 0.634095 |
| 2004 | 0.599411 | 0.629985 | 0.578980 | 0.664565 | 0.631020 | 0.630036 | 0.560368 | 0.601961 | 0.550211 | 0.618568 |
| 2005 | 0.608489 | 0.644507 | 0.601568 | 0.683560 | 0.655172 | 0.591407 | 0.489114 | 0.611570 | 0.565778 | 0.629210 |

| mean | 0.615713 | 0.636213 | 0.588090 | 0.681459 | 0.650563 | 0.602495 | 0.516906 | 0.619624 | 0.553806 | 0.632159 |
| std (ddof=1) | 0.011494 | 0.005788 | 0.009313 | 0.010294 | 0.012042 | 0.015987 | 0.026527 | 0.012295 | 0.007909 | 0.008801 |

## 3. Per-seed paired deltas

| Seed | CANDIDATE-LP_clean | CANDIDATE-HR | CANDIDATE-RANK_AVG(RIDGE,LP_clean) |
|---:|---:|---:|---:|
| 2001 | +0.060650 | +0.048452 | +0.030911 |
| 2002 | +0.064259 | +0.052039 | +0.027404 |
| 2003 | +0.063598 | +0.052104 | +0.034233 |
| 2004 | +0.065154 | +0.034580 | +0.033545 |
| 2005 | +0.075071 | +0.039053 | +0.028389 |

| mean | +0.065746 | +0.045246 | +0.030896 |
| std (ddof=1) | 0.005480 | 0.007993 | 0.003026 |

## 4. Primary gate (verdict only on this)

- deltas = [+0.060650, +0.064259, +0.063598, +0.065154, +0.075071]
- mean_delta = 0.065746
- sd_delta (ddof=1) = 0.005480
- 2 * sd_delta = 0.010959
- threshold = max(0.02, 2 * sd_delta) = 0.020000
- mean_delta - threshold = +0.045746
- PRIMARY: PASS

## 5. Secondary (reported, verdict unchanged)

| Secondary | mean paired delta | bar | outcome |
|---|---:|---:|---|
| CANDIDATE - HR | +0.045246 | > 0.02 | YES |
| CANDIDATE - RANK_AVG(RIDGE,LP_clean) | +0.030896 | > 0 | YES |

## 6. Null control

- PERM_ALL = LP with y_clean permuted over ALL 12405 packages, RandomState(20261114+seed).
- mean = 0.516906; std (ddof=1) = 0.026527; outside 0.45-0.55 = False.
- CANDIDATE_perm mean = 0.602495 (HR unchanged by permutation).

## 7. Crash log

- none.

