"""
debug_p3_trajectory.py — P3 FAILURE DEBUG (CPU only).

P3 measured train Spearman = -0.1602 after 50 epochs (gate: > 0.30) while every
learning indicator was healthy (MSE 0.1725 -> 0.0147, val rho -0.225 -> -0.112
monotone, L_aux live). Hypothesis: the model is in an extended MEAN-FITTING phase
(init sigmoid output ~0.98 vs target mean ~0.10) and ranking emerges only later
under the frozen optimizer settings (AdamW lr=5e-4, wd=1e-4).

This debug run extends the IDENTICAL frozen configuration (full_v2, p_mask=0.30,
seed 42, lambda_rank=0.20, lambda_aux=0.30, lr=5e-4) to 300 epochs with early
stopping DISABLED, logging per-epoch: loss terms, TRAIN-population Spearman,
val Spearman. It also tracks what the pre-registered patience-15 rule would
have done. No checkpoints are kept; this is diagnosis, not the pre-registered
matrix, and nothing here feeds any gate.
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
import torch.nn.functional as F
from scipy import stats as scipy_stats

warnings.filterwarnings('ignore')

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
NB_PATH = HERE / 'vulngat_v2_training_rerun.ipynb'
STAGING = HERE / 'preflight_staging'
sys.path.insert(0, str(ROOT / 'TrainModel'))
os.chdir(STAGING)

MAX_EP = 300
CKPT_EVERY = None  # no checkpoints — debug only

nb = json.load(open(NB_PATH, encoding='utf-8'))
MARKERS = {'env': '# 1. Environment Setup', 'constants': '# 2. Pre-Registered Constants',
           'data': '# 3. Load & Wire HeteroData', 'arch': '# 4. VulnGAT v2 Architecture',
           'harness': '# 5. Training, Evaluation'}
cells = {}
for c in nb['cells']:
    if c['cell_type'] != 'code':
        continue
    src = ''.join(c['source'])
    for k, m in MARKERS.items():
        if m in src[:150]:
            cells[k] = src

ns = {}
exec(compile('\n'.join(l for l in cells['env'].split('\n') if not l.lstrip().startswith('!pip')), 'c1', 'exec'), ns)
exec(compile(cells['constants'], 'c2', 'exec'), ns)
exec(compile(cells['data'], 'c3', 'exec'), ns)
exec(compile(cells['arch'], 'c4', 'exec'), ns)
harness_head = cells['harness'][:cells['harness'].index('for run_id, arm_name, p_mask, seed, use_mask, use_rank in RUN_MATRIX:')]
exec(compile(harness_head, 'c5', 'exec'), ns)

data = ns['data'].to(ns['device'])
train_mask = data['Package'].train_mask.to(ns['device'])
val_mask = data['Package'].val_mask.to(ns['device'])
y = data['Package'].y.to(ns['device'])
ns['set_seed'](42)
model = ns['VulnGATv2']().to(ns['device'])
opt = torch.optim.AdamW(model.parameters(), lr=ns['LR'], weight_decay=ns['WEIGHT_DECAY'])

print(f'P3 DEBUG: full_v2 p=0.30 seed=42, {MAX_EP} epochs, early stop DISABLED, CPU', flush=True)
traj = []
best_val, best_ep, patience_sim = -1.0, -1, 0
would_have_stopped = None
t0 = time.time()
for epoch in range(MAX_EP):
    model.train()
    opt.zero_grad()
    preds_clean, _ = model(data.x_dict, data.edge_index_dict)
    loss_mse = F.mse_loss(preds_clean[train_mask], y[train_mask])
    loss_rank = ns['compute_pairwise_ranking_loss'](preds_clean, y, train_mask)
    masked_edges = ns['apply_dynamic_edge_dropout'](data.edge_index_dict, 0.30)
    preds_masked, _ = model(data.x_dict, masked_edges)
    loss_aux = F.mse_loss(preds_masked[train_mask], preds_clean[train_mask].detach())
    loss_total = loss_mse + ns['LAMBDA_RANK'] * loss_rank + ns['LAMBDA_AUX'] * loss_aux
    loss_total.backward()
    opt.step()

    model.eval()
    with torch.no_grad():
        vp, _ = model(data.x_dict, data.edge_index_dict)
        vp = vp.cpu().numpy()
    tr_rho = float(scipy_stats.spearmanr(y[train_mask].cpu().numpy(), vp[train_mask.cpu().numpy()])[0])
    va_rho = float(scipy_stats.spearmanr(y[val_mask].cpu().numpy(), vp[val_mask.cpu().numpy()])[0])
    tr_mse = float(loss_mse.item())
    traj.append({'epoch': epoch, 'loss_mse': tr_mse, 'loss_rank': float(loss_rank.item()),
                 'loss_aux': float(loss_aux.item()), 'train_rho': tr_rho, 'val_rho': va_rho,
                 'pred_std': float(vp.std()), 'pred_mean': float(vp.mean())})
    # simulate the pre-registered patience-15 rule
    if va_rho > best_val:
        best_val, best_ep, patience_sim = va_rho, epoch, 0
    else:
        patience_sim += 1
        if would_have_stopped is None and patience_sim >= ns['PATIENCE']:
            would_have_stopped = epoch
    if epoch % 10 == 0 or epoch == MAX_EP - 1:
        e = traj[-1]
        print(f"  ep{epoch:3d} mse={e['loss_mse']:.5f} rank={e['loss_rank']:.4f} aux={e['loss_aux']:.2e} "
              f"train_rho={e['train_rho']:+.4f} val_rho={e['val_rho']:+.4f} pred_mean={e['pred_mean']:.4f} pred_std={e['pred_std']:.4f} "
              f"[{time.time()-t0:.0f}s]", flush=True)

cross_train = next((e['epoch'] for e in traj if e['train_rho'] > 0.30), None)
cross_train_10 = next((e['epoch'] for e in traj if e['train_rho'] > 0.10), None)
cross_train_0 = next((e['epoch'] for e in traj if e['train_rho'] > 0.0), None)
cross_val_0 = next((e['epoch'] for e in traj if e['val_rho'] > 0.0), None)
print('\n===== CROSSING POINTS =====')
print(f'  train rho > 0.00 first at epoch: {cross_train_0}')
print(f'  train rho > 0.10 first at epoch: {cross_train_10}')
print(f'  train rho > 0.30 (P3 bar) first at epoch: {cross_train}')
print(f'  val   rho > 0.00 first at epoch: {cross_val_0}')
print(f'  best val rho = {best_val:+.4f} at epoch {best_ep}')
print(f'  patience-15 simulation would have stopped at epoch: {would_have_stopped}')
print(f'  final: train_rho={traj[-1]["train_rho"]:+.4f} val_rho={traj[-1]["val_rho"]:+.4f} mse={traj[-1]["loss_mse"]:.5f} pred_std={traj[-1]["pred_std"]:.4f}')
print(f'  constant-mean floor: Var(y_train)={float(y[train_mask].var()):.5f}  (MSE below this = signal beyond the mean)')

json.dump({'config': 'full_v2 p=0.30 seed=42 lr=5e-4 (frozen), 300 epochs, early-stop disabled (DEBUG ONLY)',
           'crossings': {'train_rho>0': cross_train_0, 'train_rho>0.1': cross_train_10, 'train_rho>0.3': cross_train,
                         'val_rho>0': cross_val_0},
           'best_val_rho': best_val, 'best_val_epoch': best_ep, 'patience15_would_stop_at': would_have_stopped,
           'var_y_train': float(y[train_mask].var()), 'trajectory': traj},
          open(HERE / 'debug_p3_trajectory.json', 'w'), indent=2)
print('\nsaved -> phase5/debug_p3_trajectory.json')
