# AUTOPSY ITEM 2 — p_mask plumbing: weight-level comparison of checkpoints.
# NO TRAINING. CPU only. Read-only forensics on vulngat_v2_checkpoints/.
import torch, json, math
from pathlib import Path

CK = Path(r'C:\Users\Admin\Desktop\Major VulnChain\vulngat_v2_checkpoints')
SEEDS = [42, 123, 456, 789, 1024]

def load(name):
    return torch.load(CK / name, map_location='cpu', weights_only=True)

def maxabs(a, b):
    d = 0.0
    for k in a:
        if a[k].dtype.is_floating_point:
            d = max(d, (a[k] - b[k]).abs().max().item())
        else:
            if not torch.equal(a[k], b[k]):
                d = math.inf
    return d

def wstats(sd, prefix=''):
    tot_sq = 0.0; n = 0; nan = 0
    for k, v in sd.items():
        if v.dtype.is_floating_point:
            tot_sq += (v.double() ** 2).sum().item(); n += v.numel()
            nan += int(torch.isnan(v).sum().item()) + int(torch.isinf(v).sum().item())
    return dict(l2=math.sqrt(tot_sq), n_params=n, nan_inf=nan)

report = {}

# sanity: inspect one checkpoint's keys/shapes
sd0 = load('full_v2_p10_s42.pt')
print('== checkpoint content type:', type(sd0).__name__, '| tensors:', len(sd0))
for k, v in list(sd0.items()):
    print(f'   {k:55s} {tuple(v.shape)}')

print('\n== global weight stats per checkpoint ==')
for f in ['full_v2_p10_s42.pt', 'no_masking_s42.pt', 'no_ranking_p10_s42.pt']:
    s = wstats(load(f))
    print(f'   {f:28s} L2={s["l2"]:.6f}  params={s["n_params"]}  nan/inf={s["nan_inf"]}')

print('\n== max|Δw| across p_mask within arm, same seed ==')
for arm in ['full_v2', 'no_ranking']:
    for s in SEEDS:
        a = load(f'{arm}_p10_s{s}.pt'); b = load(f'{arm}_p30_s{s}.pt'); c = load(f'{arm}_p50_s{s}.pt')
        report[f'{arm}_s{s}'] = {
            'p10_vs_p30': maxabs(a, b), 'p10_vs_p50': maxabs(a, c), 'p30_vs_p50': maxabs(b, c)}
        print(f'   {arm} s{s:<5d}  p10~p30: {maxabs(a,b):.3e}   p10~p50: {maxabs(a,c):.3e}   p30~p50: {maxabs(b,c):.3e}')

print('\n== max|Δw| across arms, same seed (p10) ==')
for s in SEEDS:
    f1 = load(f'full_v2_p10_s{s}.pt'); f2 = load(f'no_ranking_p10_s{s}.pt'); nm = load(f'no_masking_s{s}.pt')
    report[f'arms_s{s}'] = {
        'full_vs_norank': maxabs(f1, f2), 'full_vs_nomask': maxabs(f1, nm), 'norank_vs_nomask': maxabs(f2, nm)}
    print(f'   s{s:<5d}  full~norank: {maxabs(f1,f2):.3e}   full~nomask: {maxabs(f1,nm):.3e}   norank~nomask: {maxabs(f2,nm):.3e}')

# reference scale: typical weight magnitude & init-level diff
import hashlib
g = torch.Generator().manual_seed(42)
init = torch.nn.Linear(10, 128).weight  # just to show a U(−1/√10,1/√10) scale ~ 0.3
print(f'\n   reference: Linear(10,128) init bound = {1/math.sqrt(10):.3f} (typical |w| ~0.17)')
print(f'   actual full_v2_p10_s42 pkg_proj.weight absmax = {sd0["pkg_proj.weight"].abs().max().item():.6f}, std = {sd0["pkg_proj.weight"].std().item():.6e}')

with open(r'C:\Users\Admin\Desktop\Major VulnChain\phase5\autopsy_item2_weightdiff.json', 'w') as f:
    json.dump(report, f, indent=2)
print('\nsaved -> phase5/autopsy_item2_weightdiff.json')
