"""
preflight_v2_rerun.py — Commandment-15 Pre-Flight Suite (P1–P6) for the VulnGAT v2
defect-corrected rerun. CPU ONLY. NO GPU TRAINING. The only training executed is
the P3 50-epoch learnability smoke test, whose weights are DISCARDED (gate, not
a checkpoint).

Method: executes the ACTUAL code cells of phase5/vulngat_v2_training_rerun.ipynb
(cells 2-6; the pip-install cell is skipped) in a shared namespace, against the
staged real dataset, then runs the six gates plus the Fix-1 normalization parity
check against TrainModel's own pipeline.

Gates:
  P1  Init sanity (seed 42): pred std > 0 across packages; layer-1 (pkg_proj)
      preactivation std within [0.1, 10].
  P2  Pathway liveness: autopsy ablation — remove 100% of hasVulnerability edges
      must now change predictions by > 0 (was exactly 0.000e+00 in v2).
  P3  Learnability smoke: 50 epochs, full_v2 (p=0.30, seed 42) config via the
      notebook's own train_single_run; train Spearman must exceed 0.30; weights
      discarded afterwards.
  P4  Eligibility assertion: N=645 / N=8,682 via the OFFICIAL
      TrainModel/masked_edge_audit.py module, set-equal to the notebook's values.
  P5  Loss logging: per-epoch per-term magnitudes (MSE / ranking / consistency)
      present in the record; consistency term > 0 (liveness corroboration).
  P6  Resume safety post-patch: skip-completed works on new 'v2dc_' run_ids;
      legacy v2 records hard-fail; new run_ids disjoint from all old ones.
  F1  (Fix-1 parity, reported alongside) notebook normalization vs
      TrainModel/training/dataset.py loader on identical inputs: bit-level or <= 1e-7.
"""

import contextlib
import io
import json
import os
import shutil
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import torch

warnings.filterwarnings('ignore')

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
NB_PATH = HERE / 'vulngat_v2_training_rerun.ipynb'
STAGING = HERE / 'preflight_staging'
sys.path.insert(0, str(ROOT / 'TrainModel'))

t_start = time.time()
print('=' * 100)
print('  VULNGAT v2 RERUN — PRE-FLIGHT SUITE (P1-P6) — CPU ONLY, NO GPU TRAINING')
print('=' * 100)
print(f'notebook under test: {NB_PATH}')
print(f'torch {torch.__version__} (cuda available: {torch.cuda.is_available()})')

# ---------------------------------------------------------------- staging
DATA_FILES = [
    ('phase5/bench_run/vulnchain_graph.json', 'phase5/bench_run/vulnchain_graph.json'),
    ('phase5/epss_labels_51repo.json', 'phase5/epss_labels_51repo.json'),
    ('phase4/vpss_labels_51repo.json', 'phase4/vpss_labels_51repo.json'),
    ('phase4/repo_split_mapping_51repo.json', 'phase4/repo_split_mapping_51repo.json'),
    ('.osv_records_cache.json', '.osv_records_cache.json'),
]
print('\n--- staging dataset (mirror of vulngat_v2_colab_data.zip layout) ---')
for src_rel, arc in DATA_FILES:
    src = ROOT / src_rel
    dst = STAGING / arc
    if not dst.exists() or dst.stat().st_size != src.stat().st_size:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f'  copied {src_rel} ({src.stat().st_size/1e6:.1f} MB)')
    else:
        print(f'  present {src_rel}')
os.chdir(STAGING)

# ---------------------------------------------------------------- extract notebook cells
nb = json.load(open(NB_PATH, encoding='utf-8'))
CELL_MARKERS = {
    'env': '# 1. Environment Setup',
    'constants': '# 2. Pre-Registered Constants',
    'data': '# 3. Load & Wire HeteroData',
    'arch': '# 4. VulnGAT v2 Architecture',
    'harness': '# 5. Training, Evaluation',
    'final': '# 6. Final Pre-Registered',
}
cells_src = {}
for c in nb['cells']:
    if c['cell_type'] != 'code':
        continue
    src = ''.join(c['source'])
    for key, marker in CELL_MARKERS.items():
        if marker in src[:150]:
            cells_src[key] = src
assert set(cells_src) == set(CELL_MARKERS), f'cell extraction failed: {set(cells_src)}'
# cell 1 carries the IPython `!pip install` magics (Colab-only); strip those two lines and
# execute the rest (imports, device selection, data-presence check) — the namespace the
# remaining cells assume comes from here, exactly as in a real Colab session.
env_src = '\n'.join(l for l in cells_src['env'].split('\n') if not l.lstrip().startswith('!pip'))
compile(env_src, 'cell1_no_pip', 'exec')
print(f'\nnotebook cells extracted: {sorted(cells_src)} (pip MAGICS stripped from cell 1; imports kept)')

# The harness cell's FINAL matrix-execution loop is cut off: pre-flight must NOT run the
# 35-run matrix. Everything before it (functions, RUN_MATRIX construction, data.to(device))
# is executed verbatim.
LOOP_MARKER = 'for run_id, arm_name, p_mask, seed, use_mask, use_rank in RUN_MATRIX:'
harness_src = cells_src['harness']
cut = harness_src.index(LOOP_MARKER)
harness_head = harness_src[:cut]
assert 'train_single_run(run_id' in harness_src[cut:], 'split marker mislocated'
print(f"harness cell split at the matrix loop: executing {len(harness_head)} of {len(harness_src)} chars (matrix loop NOT executed)")

ns = {}
print('\n--- executing notebook cell 1 (imports & device; pip magics stripped) ---')
exec(compile(env_src, 'cell1_no_pip', 'exec'), ns)
print('\n--- executing notebook cell 2 (constants & path resolution) verbatim ---')
exec(compile(cells_src['constants'], 'cell2', 'exec'), ns)
print('\n--- executing notebook cell 3 (data wiring, [FIX A3] normalization, [FIX A1] eligibility) verbatim ---')
t3 = time.time()
exec(compile(cells_src['data'], 'cell3', 'exec'), ns)
print(f'  (cell 3 took {time.time()-t3:.1f}s; N=645/8,682 assertions passed inside the cell)')
print('\n--- executing notebook cell 4 (architecture, [FIX A2] reverse edges) verbatim ---')
exec(compile(cells_src['arch'], 'cell4', 'exec'), ns)
print('\n--- executing notebook cell 5 (harness functions + run matrix construction, WITHOUT the training loop) ---')
exec(compile(harness_head, 'cell5_head', 'exec'), ns)

data = ns['data']
eligible_pkg_ids = ns['eligible_pkg_ids']
never_vuln_indices = ns['never_vuln_indices']
RUN_MATRIX = ns['RUN_MATRIX']
RESULTS = {}
FAILURES = []


def gate(name, ok, detail):
    RESULTS[name] = {'pass': bool(ok), 'detail': detail}
    print(f"\n>>> GATE {name}: {'PASS' if ok else 'FAIL'}")
    for line in detail.split('\n'):
        print(f'    {line}')
    if not ok:
        FAILURES.append(name)
    return ok


# ================================================================= P6 (run-id namespace, no training needed first)
print('\n' + '=' * 100)
print('  P6 — RESUME SAFETY POST-PATCH')
print('=' * 100)
new_ids = [r[0] for r in RUN_MATRIX]
old_ids = ([f'full_v2_p{int(p*100)}_s{s}' for p in (0.10, 0.30, 0.50) for s in ns['SEEDS']]
           + [f'no_masking_s{s}' for s in ns['SEEDS']]
           + [f'no_ranking_p{int(p*100)}_s{s}' for p in (0.10, 0.30, 0.50) for s in ns['SEEDS']])
p6_prefix_ok = all(i.startswith('v2dc_') for i in new_ids) and len(new_ids) == 35
p6_disjoint = set(new_ids).isdisjoint(old_ids)
print(f'  new run_ids: {len(new_ids)} (all prefixed v2dc_: {p6_prefix_ok}) | disjoint from the 35 quarantined v2 ids: {p6_disjoint}')
print(f'  examples: {new_ids[:2]} ... {new_ids[-1]}')

# P6a skip-completed on a NEW run_id (disposable dir, dummy artifacts)
tmp6 = HERE / 'preflight_tmp_p6'
if tmp6.exists():
    shutil.rmtree(tmp6)
tmp6.mkdir(parents=True)
ns['RUNS_DIR'] = tmp6
ns['CHECKPOINTS_DIR'] = tmp6 / 'checkpoints'
ns['CHECKPOINTS_DIR'].mkdir()
ns['RESULTS_FILE'] = tmp6 / 'v2_intermediate_results.json'
skip_id = 'v2dc_no_masking_s42'
injected = {'run_id': skip_id, 'protocol_version': ns['PROTOCOL_VERSION'], 'arm': 'no_masking',
            'p_mask': 0.0, 'seed': 42, 'val_spearman': 0.999, 'test_spearman': 0.999,
            'masked_auc_50': 0.999, 'checkpoint': str(ns['CHECKPOINTS_DIR'] / f'{skip_id}.pt')}
ns['save_intermediate_results']({skip_id: injected})
torch.save({}, ns['CHECKPOINTS_DIR'] / f'{skip_id}.pt')
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ret = ns['train_single_run'](skip_id, 'no_masking', 0.0, 42, False, True)
p6_skip_ok = ('[SKIP]' in buf.getvalue()) and ret == injected
print(f'  skip-completed on new id: [SKIP] printed={("[SKIP]" in buf.getvalue())}, returned record is the stored one={ret == injected}')

# P6b legacy record must hard-fail (never reused or resumed)
legacy_results = {'full_v2_p30_s42': {'run_id': 'full_v2_p30_s42', 'arm': 'full_v2', 'p_mask': 0.3,
                                      'seed': 42, 'val_spearman': -0.068, 'test_spearman': 0.055,
                                      'masked_auc_50': None, 'checkpoint': 'x.pt'}}
ns['save_intermediate_results'](legacy_results)
legacy_raised = False
legacy_msg = ''
try:
    with contextlib.redirect_stdout(io.StringIO()):
        ns['load_intermediate_results']()
except RuntimeError as e:
    legacy_raised = True
    legacy_msg = str(e)
print(f'  legacy record (quarantined v2 id, no protocol_version) refusal: raised RuntimeError={legacy_raised}')
if legacy_raised:
    print(f'    message: {legacy_msg[:160]}...')

p6_ok = p6_prefix_ok and p6_disjoint and p6_skip_ok and legacy_raised
gate('P6', p6_ok,
     f'35/35 new ids prefixed v2dc_ and disjoint from the 35 quarantined v2 ids: {p6_prefix_ok and p6_disjoint}\n'
     f'skip-completed verified on new id (no retrain): {p6_skip_ok}\n'
     f'legacy v2 record hard-fails with RuntimeError (old run_ids can never be reused/resumed): {legacy_raised}')

# ================================================================= Fix-1 parity (normalization vs TrainModel pipeline)
print('\n' + '=' * 100)
print('  FIX-1 PARITY — notebook normalization vs TrainModel/training/dataset.py on identical inputs')
print('=' * 100)
from training.dataset import load_vulnchain_dataset
tm_data, tm_maps, tm_masks = load_vulnchain_dataset(
    graph_path=str(STAGING / 'phase5/bench_run/vulnchain_graph.json'),
    labels_path=str(STAGING / 'phase4/vpss_labels_51repo.json'),
    repo_split_path=str(STAGING / 'phase4/repo_split_mapping_51repo.json'),
)
nb_pkg = ns['data']['Package'].x.cpu()
nb_cve = ns['data']['CVE'].x.cpu()
nb_auth = ns['data']['Author'].x.cpu()
tm_pkg = tm_data['Package'].x
tm_cve = tm_data['CVE'].x
tm_auth = tm_data['Author'].x
d_pkg = float((nb_pkg - tm_pkg).abs().max())
d_auth = float((nb_auth - tm_auth).abs().max())
# Phase-4 stores CVSS FIRST ([cvss]+emb); v2 spec keeps CVSS LAST (emb+[cvss]) — position-aware compare
d_cve_emb = float((nb_cve[:, :768] - tm_cve[:, 1:769]).abs().max())
d_cve_cvss = float((nb_cve[:, 768] - tm_cve[:, 0]).abs().max())
print(f'  Package [2,3,4,5,7] min-max : max|delta| = {d_pkg:.3e}  (shapes {tuple(nb_pkg.shape)} vs {tuple(tm_pkg.shape)})')
print(f'  Author  [0,1,2,3,6] min-max : max|delta| = {d_auth:.3e}')
print(f'  CVE embedding dims          : max|delta| = {d_cve_emb:.3e}')
print(f'  CVE CVSS/10 (position-aware): max|delta| = {d_cve_cvss:.3e}  (v2 spec: CVSS last; Phase-4 file: CVSS first)')
f1_ok = max(d_pkg, d_auth, d_cve_emb, d_cve_cvss) <= 1e-7
gate('F1-normalization-parity', f1_ok,
     f'package max|delta|={d_pkg:.3e}; author={d_auth:.3e}; cve-emb={d_cve_emb:.3e}; cve-cvss={d_cve_cvss:.3e}\n'
     f'bit-level parity (or <=1e-7): {f1_ok}')

# ================================================================= P1 init sanity
print('\n' + '=' * 100)
print('  P1 — INIT SANITY (fixed seed 42, normalized inputs)')
print('=' * 100)
ns['set_seed'](42)
m1 = ns['VulnGATv2']().to(ns['device'])
acts = {}
h1 = m1.pkg_proj.register_forward_hook(lambda mod, inp, out: acts.__setitem__('pkg_proj_preact', out.detach()))
h2 = m1.cve_proj.register_forward_hook(lambda mod, inp, out: acts.__setitem__('cve_proj_preact', out.detach()))
h3 = m1.author_proj.register_forward_hook(lambda mod, inp, out: acts.__setitem__('author_proj_preact', out.detach()))
with torch.no_grad():
    p1_base, _ = m1(ns['data'].x_dict, ns['data'].edge_index_dict)
h1.remove(); h2.remove(); h3.remove()
pred_std = float(p1_base.std())
preact_std = float(acts['pkg_proj_preact'].std())
print(f'  layer-1 (pkg_proj) preactivation std = {preact_std:.4f}  [required within [0.1, 10]]  (v2 defect was ~476)')
print(f'  cve_proj preact std = {float(acts["cve_proj_preact"].std()):.4f} | author_proj preact std = {float(acts["author_proj_preact"].std()):.4f}')
print(f'  init prediction std across {p1_base.numel()} packages = {pred_std:.6f}  [required > 0]')
p1_ok = (pred_std > 0) and (0.1 <= preact_std <= 10.0)
gate('P1', p1_ok, f'pred_std={pred_std:.6f} > 0: {pred_std > 0}\nlayer-1 preact_std={preact_std:.4f} in [0.1, 10]: {0.1 <= preact_std <= 10.0}')

# ================================================================= P2 pathway liveness
print('\n' + '=' * 100)
print('  P2 — PATHWAY LIVENESS (autopsy ablation rerun on the patched architecture)')
print('=' * 100)
m1.eval()
with torch.no_grad():
    e_all = ns['data'].edge_index_dict
    e_nocve = dict(e_all)
    e_nocve[('Package', 'hasVulnerability', 'CVE')] = e_all[('Package', 'hasVulnerability', 'CVE')][:, :0]
    p_nocve, _ = m1(ns['data'].x_dict, e_nocve)
delta_100 = float((p_nocve - p1_base).abs().max())
print(f'  remove 100% of hasVulnerability edges: max|delta_pred| over {p1_base.numel()} packages = {delta_100:.6e}   (v2 defect: 0.000e+00 exactly)')
partial = {}
for pm in (0.1, 0.3, 0.5, 0.9):
    torch.manual_seed(0)
    with torch.no_grad():
        e_m = ns['apply_dynamic_edge_dropout'](e_all, pm)
        kept = e_m[('Package', 'hasVulnerability', 'CVE')].size(1)
        pp, _ = m1(ns['data'].x_dict, e_m)
    partial[pm] = (kept, float((pp - p1_base).abs().max()))
    print(f'  p_mask={pm:<4} kept {kept:4d}/2632 edges -> max|delta_pred| = {partial[pm][1]:.6e}')
p2_ok = delta_100 > 0 and all(v[1] > 0 for v in partial.values())
gate('P2', p2_ok,
     f'100% removal delta = {delta_100:.6e} > 0: {delta_100 > 0}\n'
     + '\n'.join(f'partial p={p}: delta={v[1]:.6e} > 0' for p, v in partial.items()))

# ================================================================= P4 eligibility via the OFFICIAL module
print('\n' + '=' * 100)
print('  P4 — ELIGIBILITY VIA THE OFFICIAL masked_edge_audit.py CODE PATH')
print('=' * 100)
import masked_edge_audit as mea
own_official = mea.compute_own_vpss(ns['graph_json'], ns['vpss_labels'])
elig_official = mea.select_eligible_packages(own_official)
never_official = mea.get_never_vuln_indices(ns['vpss_labels'], ns['pkg_id_to_idx'], ns['num_packages'])
set_eq_elig = set(elig_official) == set(eligible_pkg_ids)
set_eq_never = set(never_official) == set(never_vuln_indices)
print(f'  official module counts : eligible={len(elig_official)}  never_vuln={len(never_official)}')
print(f'  notebook cell-3 counts : eligible={len(eligible_pkg_ids)}  never_vuln={len(never_vuln_indices)}')
print(f'  set equality eligible  : {set_eq_elig} | set equality never-vuln: {set_eq_never}')
print(f'  max own_ratio on graph : {max(d["own_ratio"] for d in own_official.values()):.4f} (< 0.70 -> documented 0.30 auto-relaxation is what yields N=645)')
p4_ok = len(elig_official) == 645 and len(never_official) == 8682 and set_eq_elig and set_eq_never
gate('P4', p4_ok,
     f'N_eligible=645: {len(elig_official) == 645} | N_never_vuln=8,682: {len(never_official) == 8682}\n'
     f'notebook ported values set-equal to official module output: {set_eq_elig and set_eq_never}')

# ================================================================= P3 learnability smoke (50 epochs, weights discarded)
print('\n' + '=' * 100)
print('  P3 — LEARNABILITY SMOKE TEST (50 epochs, full_v2 p=0.30 seed 42, TRAIN population, CPU)')
print('=' * 100)
tmp3 = HERE / 'preflight_tmp_p3'
if tmp3.exists():
    shutil.rmtree(tmp3)
tmp3.mkdir(parents=True)
ns['RUNS_DIR'] = tmp3
ns['CHECKPOINTS_DIR'] = tmp3 / 'checkpoints'
ns['CHECKPOINTS_DIR'].mkdir()
ns['RESULTS_FILE'] = tmp3 / 'v2_intermediate_results.json'
ns['MAX_EPOCHS'] = 50   # smoke length only — the Colab matrix itself stays at 100
ns['PATIENCE'] = 50     # disable early stop so all 50 epochs run
t_p3 = time.time()
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rec3 = ns['train_single_run']('v2dc_full_v2_p30_s42', 'full_v2', 0.30, 42, True, True)
p3_log = buf.getvalue()
print(p3_log.strip())
print(f'  (50-epoch smoke took {time.time()-t_p3:.1f}s on CPU)')
ck3 = tmp3 / 'checkpoints' / 'v2dc_full_v2_p30_s42.pt'
m3 = ns['VulnGATv2']()
m3.load_state_dict(torch.load(ck3, map_location='cpu', weights_only=True))
m3.eval()
with torch.no_grad():
    preds3, _ = m3(ns['data'].x_dict, ns['data'].edge_index_dict)
tm = ns['data']['Package'].train_mask.numpy()
yy = ns['data']['Package'].y.numpy()
from scipy import stats as sp_mod
train_sp = float(sp_mod.spearmanr(yy[tm], preds3.numpy()[tm])[0])
preds3 = preds3.numpy()
print(f'  TRAIN-population Spearman after 50 epochs = {train_sp:+.4f}   [required > 0.30]  (quarantined v2: ~+/-0.08 = chance)')
print(f'  train pred std = {preds3[tm].std():.4f} (was saturated 2-point mass in v2)')
p3_ok = train_sp > 0.30
gate('P3', p3_ok, f'train Spearman = {train_sp:+.4f} > 0.30: {p3_ok}\n'
     f'val_spearman(best)={rec3["val_spearman"]:.4f} | test_spearman={rec3["test_spearman"]:.4f} | masked_auc_50={rec3["masked_auc_50"]:.4f} (smoke-run info only, not a gate)')
shutil.rmtree(tmp3)  # [P3] weights DISCARDED — gate, not a checkpoint
print('  [OK] smoke checkpoint deleted (weights discarded; nothing persisted)')

# ================================================================= P5 loss logging
print('\n' + '=' * 100)
print('  P5 — LOSS LOGGING (per-epoch per-term magnitudes in the record)')
print('=' * 100)
traj = rec3['loss_trajectory']
keys_ok = all(set(e) == {'epoch', 'loss_mse', 'loss_rank', 'loss_aux', 'loss_total', 'val_spearman'} for e in traj)
finite_ok = all(np.isfinite([e['loss_mse'], e['loss_rank'], e['loss_aux'], e['loss_total']]).all() for e in traj)
aux_max = max(e['loss_aux'] for e in traj)
aux_epochs = sum(1 for e in traj if e['loss_aux'] > 0)
print(f'  trajectory length: {len(traj)} epochs (run reported n_epochs_run={rec3["n_epochs_run"]}, early_stopped={rec3["early_stopped"]})')
print(f'  per-epoch keys correct: {keys_ok} | all values finite: {finite_ok}')
print(f'  first epoch: {json.dumps(traj[0])}')
print(f'  last  epoch: {json.dumps(traj[-1])}')
print(f'  consistency term L_aux: max={aux_max:.6f}, >0 in {aux_epochs}/{len(traj)} epochs   (quarantined v2: identically 0.0 every epoch)')
p5_ok = len(traj) == 50 and keys_ok and finite_ok and aux_max > 0
gate('P5', p5_ok,
     f'50/50 epochs logged with per-term magnitudes (MSE/ranking/consistency/total/val_spearman): {len(traj) == 50 and keys_ok and finite_ok}\n'
     f'consistency term is LIVE (max L_aux = {aux_max:.6f} > 0 in {aux_epochs} epochs): {aux_max > 0}')

# ================================================================= cell-6 code path (final table) on the smoke record
print('\n--- executing notebook cell 6 (final evaluation table) verbatim, on the smoke record ---')
# point the harness at a clean disposable results file holding the smoke record, and at an
# existing checkpoints dir (cell 6 zips it); the P3 tmp dir was deleted per the discard rule
ns['RESULTS_FILE'] = tmp6 / 'v2_intermediate_results_finalcheck.json'
ns['CHECKPOINTS_DIR'] = tmp6 / 'checkpoints'
ns['save_intermediate_results']({'v2dc_full_v2_p30_s42': rec3})
exec(compile(cells_src['final'], 'cell6', 'exec'), ns)

# ================================================================= verdict
print('\n' + '=' * 100)
print('  PRE-FLIGHT VERDICT')
print('=' * 100)
for k in ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'F1-normalization-parity']:
    r = RESULTS[k]
    print(f"  {k:<26} {'PASS' if r['pass'] else 'FAIL'}")
overall = not FAILURES
print('-' * 100)
print(f'  OVERALL: {"CLEAN — all gates passed. Colab may be fired." if overall else "FAILED: " + ", ".join(FAILURES) + " — debug on CPU; do NOT fire Colab."}')
print(f'  (total wall time: {time.time()-t_start:.1f}s)')

json.dump({
    'suite': 'v2-rerun pre-flight P1-P6 (Commandment 15)',
    'date': '2026-09-20',
    'notebook_under_test': 'phase5/vulngat_v2_training_rerun.ipynb',
    'device': 'cpu (no GPU training; P3 smoke weights discarded)',
    'gates': RESULTS,
    'p3_smoke_record_summary': {k: rec3[k] for k in ('run_id', 'arm', 'p_mask', 'seed', 'val_spearman', 'test_spearman', 'masked_auc_50', 'n_epochs_run', 'early_stopped')},
    'p3_train_spearman': train_sp,
    'overall_pass': overall,
}, open(HERE / 'preflight_results.json', 'w'), indent=2)
print('\nsaved -> phase5/preflight_results.json')
sys.exit(0 if overall else 1)
