# V2 AUTOPSY — behavioral forensics. NO TRAINING. CPU only.
# Rebuilds notebook cell 3 (data wiring) verbatim, loads seed-42 checkpoints,
# and measures: train/val/test metrics, prediction dispersion, activation
# variance per layer, p_mask inertness, NaN-AUC reproduction, feature stats.
import json, copy, math, warnings
from pathlib import Path
from collections import defaultdict, deque
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from scipy import stats as scipy_stats
from torch_geometric.data import HeteroData
from torch_geometric.nn import GATConv, HeteroConv

warnings.filterwarnings('ignore')
ROOT = Path(r'C:\Users\Admin\Desktop\Major VulnChain')
CK = ROOT / 'vulngat_v2_checkpoints'
torch.set_grad_enabled(False)

# ---------------- cell 3 verbatim (data wiring) ----------------
graph_json = json.load(open(ROOT / 'phase5/bench_run/vulnchain_graph.json', encoding='utf-8'))
epss_labels = json.load(open(ROOT / 'phase5/epss_labels_51repo.json', encoding='utf-8'))
vpss_labels = json.load(open(ROOT / 'phase4/vpss_labels_51repo.json', encoding='utf-8'))
osv_data = json.load(open(ROOT / '.osv_records_cache.json', encoding='utf-8'))

pkg_nodes = graph_json['nodes']['Package']; cve_nodes = graph_json['nodes']['CVE']; author_nodes = graph_json['nodes']['Author']
pkg_id_to_idx = {n['id']: i for i, n in enumerate(pkg_nodes)}
cve_id_to_idx = {n['id']: i for i, n in enumerate(cve_nodes)}
num_packages = len(pkg_nodes)

pkg_features = np.array([n['features'] for n in pkg_nodes], dtype=np.float32)
pkg_targets = np.array([epss_labels[n['id']]['epss_risk'] for n in pkg_nodes], dtype=np.float32)
cve_features = []
for n in cve_nodes:
    emb = n.get('embedding')
    if emb is None: emb = [0.0] * 768
    cvss = n.get('cvss_score'); cvss_val = float(cvss) if cvss is not None else 0.0
    cve_features.append(emb + [cvss_val])
cve_features = np.array(cve_features, dtype=np.float32)
author_features = np.array([n['features'] for n in author_nodes], dtype=np.float32)

def build_edge_index(edge_list, src_map, dst_map):
    src, dst = [], []
    for e in edge_list:
        if e['source'] in src_map and e['target'] in dst_map:
            src.append(src_map[e['source']]); dst.append(dst_map[e['target']])
    return torch.tensor([src, dst], dtype=torch.long)

E = {
    ('Package', 'dependsOn', 'Package'): build_edge_index(graph_json['edges']['dependsOn'], pkg_id_to_idx, pkg_id_to_idx),
    ('Package', 'hasVulnerability', 'CVE'): build_edge_index(graph_json['edges']['hasVulnerability'], pkg_id_to_idx, cve_id_to_idx),
    ('Package', 'maintainedBy', 'Author'): build_edge_index(graph_json['edges']['maintainedBy'], pkg_id_to_idx, {n['id']: i for i, n in enumerate(author_nodes)}),
    ('CVE', 'introducedBy', 'Author'): build_edge_index(graph_json['edges']['introducedBy'], cve_id_to_idx, {n['id']: i for i, n in enumerate(author_nodes)}),
}

pkg_to_cves = defaultdict(list)
for edge in graph_json['edges']['hasVulnerability']:
    pkg_to_cves[edge['source']].append(edge['target'])
cve_cvss = {c['id']: float(c.get('cvss_score') or 0.0) for c in cve_nodes}
eligible_pkg_ids = []
for pid, clist in pkg_to_cves.items():
    vp = vpss_labels.get(pid, {}); raw_sum = float(vp.get('raw_sum', 0.0))
    own_raw = sum(cve_cvss.get(c, 0.0) / 10.0 for c in clist)
    own_ratio = (own_raw / raw_sum) if raw_sum > 1e-9 else 0.0
    if own_ratio >= 0.70 and float(vp.get('vpss', 0.0)) > 1e-6:
        eligible_pkg_ids.append(pid)
never_vuln_indices = [pkg_id_to_idx[pid] for pid, l in vpss_labels.items() if l.get('vpss', 0.0) < 1e-9 and pid in pkg_id_to_idx]

TEMPORAL_CUTOFF = '2026-08-01'
cve_dates = {c['id']: osv_data[c['id']]['published'][:10] for c in cve_nodes if c['id'] in osv_data and osv_data[c['id']].get('published')}
deps_of = defaultdict(list)
for e in graph_json['edges']['dependsOn']: deps_of[e['source']].append(e['target'])
pkg_newest_date = {}
for pid in pkg_id_to_idx:
    visited = {pid: 0}; q = deque([pid]); contrib_dates = []
    while q:
        cur = q.popleft(); d = visited[cur]
        if cur in pkg_to_cves:
            for cve in pkg_to_cves[cur]:
                if cve in cve_dates: contrib_dates.append(cve_dates[cve])
        if d < 5:
            for nxt in deps_of.get(cur, ()):
                if nxt not in visited and nxt in pkg_id_to_idx:
                    visited[nxt] = d + 1; q.append(nxt)
    if contrib_dates: pkg_newest_date[pid] = max(contrib_dates)

import random
nz_pkgs = [pid for pid in pkg_id_to_idx if epss_labels[pid]['epss_risk'] > 0]
train_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, '2000-01-01') < TEMPORAL_CUTOFF]
test_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, '2000-01-01') >= TEMPORAL_CUTOFF]
random.seed(42); shuffled = list(train_pkgs); random.shuffle(shuffled)
val_cut = int(0.20 * len(shuffled)); val_pkgs = shuffled[:val_cut]; train_fit_pkgs = shuffled[val_cut:]
train_idx = np.array([pkg_id_to_idx[p] for p in train_fit_pkgs])
val_idx = np.array([pkg_id_to_idx[p] for p in val_pkgs])
test_idx = np.array([pkg_id_to_idx[p] for p in test_pkgs])
y = pkg_targets
print(f'populations: packages={num_packages} cves={len(cve_nodes)} authors={len(author_nodes)}')
print(f'train_fit={len(train_idx)} val={len(val_idx)} test={len(test_idx)} eligible={len(eligible_pkg_ids)} never_vuln={len(never_vuln_indices)}')

x_dict = {'Package': torch.tensor(pkg_features), 'CVE': torch.tensor(cve_features), 'Author': torch.tensor(author_features)}

# ---------------- model (cell 4 verbatim) ----------------
class VulnGATv2(nn.Module):
    def __init__(self, pkg_in_dim=10, cve_in_dim=769, author_in_dim=7, hidden_dim=128, heads=4):
        super().__init__()
        self.pkg_proj = nn.Linear(pkg_in_dim, hidden_dim)
        self.cve_proj = nn.Linear(cve_in_dim, hidden_dim)
        self.author_proj = nn.Linear(author_in_dim, hidden_dim)
        cm = lambda st, dt: GATConv((st and hidden_dim, dt and hidden_dim) if (st, dt) != (hidden_dim, hidden_dim) or True else None, hidden_dim // heads, heads=heads, add_self_loops=False)
        self.conv1 = HeteroConv({
            ('Package', 'dependsOn', 'Package'): GATConv(hidden_dim, hidden_dim // heads, heads=heads, add_self_loops=False),
            ('Package', 'hasVulnerability', 'CVE'): GATConv((hidden_dim, hidden_dim), hidden_dim // heads, heads=heads, add_self_loops=False),
            ('Package', 'maintainedBy', 'Author'): GATConv((hidden_dim, hidden_dim), hidden_dim // heads, heads=heads, add_self_loops=False),
            ('CVE', 'introducedBy', 'Author'): GATConv((hidden_dim, hidden_dim), hidden_dim // heads, heads=heads, add_self_loops=False),
        }, aggr='sum')
        self.conv2 = HeteroConv({
            ('Package', 'dependsOn', 'Package'): GATConv(hidden_dim, hidden_dim // heads, heads=heads, add_self_loops=False),
            ('Package', 'hasVulnerability', 'CVE'): GATConv((hidden_dim, hidden_dim), hidden_dim // heads, heads=heads, add_self_loops=False),
            ('Package', 'maintainedBy', 'Author'): GATConv((hidden_dim, hidden_dim), hidden_dim // heads, heads=heads, add_self_loops=False),
            ('CVE', 'introducedBy', 'Author'): GATConv((hidden_dim, hidden_dim), hidden_dim // heads, heads=heads, add_self_loops=False),
        }, aggr='sum')
        self.classifier = nn.Sequential(nn.Linear(hidden_dim, 64), nn.GELU(), nn.Dropout(0.1), nn.Linear(64, 1), nn.Sigmoid())
    def forward(self, x_dict, edge_index_dict):
        h_dict = {'Package': F.relu(self.pkg_proj(x_dict['Package'])),
                  'CVE': F.relu(self.cve_proj(x_dict['CVE'])),
                  'Author': F.relu(self.author_proj(x_dict['Author']))}
        h1 = self.conv1(h_dict, edge_index_dict); h1 = {k: F.relu(v) for k, v in h1.items()}
        h2 = self.conv2(h1, edge_index_dict)
        return self.classifier(h2['Package']).squeeze(-1), h2['Package']

def apply_dynamic_edge_dropout(edge_index_dict, p_mask=0.30):
    new_edges = copy.copy(edge_index_dict)
    k = ('Package', 'hasVulnerability', 'CVE')
    if k in new_edges:
        edges = new_edges[k]
        mask = torch.rand(edges.size(1)) > p_mask
        new_edges[k] = edges[:, mask]
    return new_edges

def q(x): return np.percentile(x, [0, 1, 25, 50, 75, 99, 100]).round(6).tolist()
def sp(a, b):
    s = scipy_stats.spearmanr(a, b)[0]
    return float('nan') if np.isnan(s) else float(s)

RUNS = ['full_v2_p10_s42', 'full_v2_p30_s42', 'full_v2_p50_s42', 'no_masking_s42', 'no_ranking_p10_s42']
out = {}

for run in RUNS:
    sd = torch.load(CK / f'{run}.pt', map_location='cpu', weights_only=True)
    m = VulnGATv2(); m.load_state_dict(sd); m.eval()
    # per-layer activation capture (item 3)
    acts = {}
    hooks = []
    hooks.append(m.pkg_proj.register_forward_hook(lambda mo, i, o: acts.__setitem__('pkg_proj_out', o.detach())))
    hooks.append(m.conv1.register_forward_hook(lambda mo, i, o: acts.__setitem__('conv1_out_Package', o['Package'].detach())))
    hooks.append(m.conv2.register_forward_hook(lambda mo, i, o: acts.__setitem__('conv2_out_Package', o['Package'].detach())))
    hooks.append(m.classifier[0].register_forward_hook(lambda mo, i, o: acts.__setitem__('cls_hidden', o.detach())))
    # pre-sigmoid logits via functional replay of classifier
    preds, emb = m(x_dict, E)
    for h in hooks: h.remove()
    p = preds.numpy()
    logit = (emb @ sd['classifier.3.weight'].T).squeeze(-1).numpy() + sd['classifier.3.bias'].item()

    r = {}
    for name, idx in [('train', train_idx), ('val', val_idx), ('test', test_idx)]:
        pp, tt = p[idx], y[idx]
        r[name] = dict(n=len(idx), spearman=sp(tt, pp), mse=float(np.mean((pp - tt) ** 2)),
                       pred_mean=float(pp.mean()), pred_std=float(pp.std()), pred_quantiles=q(pp),
                       target_mean=float(tt.mean()), target_std=float(tt.std()))
    # audit strata (item 1b) — clean graph
    el_idx = np.array([pkg_id_to_idx[pid] for pid in eligible_pkg_ids if pid in pkg_id_to_idx])
    nv_idx = np.array(never_vuln_indices)
    r['audit_clean'] = dict(eligible_std=float(p[el_idx].std()), eligible_quantiles=q(p[el_idx]),
                            nevervuln_std=float(p[nv_idx].std()), nevervuln_quantiles=q(p[nv_idx]),
                            combined_std=float(np.concatenate([p[el_idx], p[nv_idx]]).std()),
                            frac_exact_mode=float(np.mean(p == np.bincount(p.astype(np.int64) if False else p.round(6), ).max() and 0) ) if False else None)
    # constant-output measure across ALL packages and on strata
    uniq = len(np.unique(p.round(9)))
    r['global'] = dict(pred_std=float(p.std()), unique_vals_at_1e9=uniq, n_packages=num_packages,
                       mean_abs_dev_from_median=float(np.mean(np.abs(p - np.median(p)))))
    # activation stats
    r['activations'] = {k: dict(std=float(v.std()), mean=float(v.mean()),
                                frac_relu_dead=float((v <= 0).float().mean()),
                                per_node_dim_std_mean=float(v.std(dim=0).mean())) for k, v in acts.items()}
    r['logit_stats'] = dict(std=float(logit.std()), quantiles=q(logit))
    out[run] = r
    print(f'\n===== {run} =====')
    for name in ['train', 'val', 'test']:
        d = r[name]
        print(f"  {name:5s} n={d['n']:5d} spearman={d['spearman']:+.4f} mse={d['mse']:.6f} pred mean={d['pred_mean']:.6f} std={d['pred_std']:.2e} q={d['pred_quantiles']}")
    print(f"  audit strata clean: eligible std={r['audit_clean']['eligible_std']:.2e} q={r['audit_clean']['eligible_quantiles']}")
    print(f"                     nevervuln std={r['audit_clean']['nevervuln_std']:.2e} q={r['audit_clean']['nevervuln_quantiles']}")
    print(f"  global: pred_std={r['global']['pred_std']:.2e} unique@1e-9={r['global']['unique_vals_at_1e9']}/{num_packages}")
    print(f"  logits: std={r['logit_stats']['std']:.3f} q={r['logit_stats']['quantiles']}")
    for k, v in r['activations'].items():
        print(f"  act {k:16s} std={v['std']:.4f} mean={v['mean']:+.4f} dead-ReLU={v['frac_relu_dead']:.3f}")

# ---- item 2 inertness: does masking hasVulnerability change package predictions AT ALL? ----
sd = torch.load(CK / 'full_v2_p30_s42.pt', map_location='cpu', weights_only=True)
m = VulnGATv2(); m.load_state_dict(sd); m.eval()
base, _ = m(x_dict, E)
print('\n===== p_mask inertness test (full_v2_p30_s42 weights) =====')
torch.manual_seed(0)
for pm in [0.1, 0.3, 0.5, 0.9, 0.999]:
    Em = apply_dynamic_edge_dropout(E, pm)
    pm_pred, _ = m(x_dict, Em)
    kept = Em[('Package', 'hasVulnerability', 'CVE')].size(1)
    print(f'  p_mask={pm:<6} kept {kept:5d}/{E[("Package","hasVulnerability","CVE")].size(1)} hasVuln edges -> max|Δpred_packages| = {(pm_pred - base).abs().max().item():.3e}')

# cross-run prediction identity on the strata: p10 vs p30 vs p50 vs arms
print('\n===== cross-checkpoint prediction agreement (max|Δpred| over ALL packages) =====')
preds_by_run = {}
for run in RUNS:
    sd = torch.load(CK / f'{run}.pt', map_location='cpu', weights_only=True)
    mm = VulnGATv2(); mm.load_state_dict(sd); mm.eval()
    preds_by_run[run], _ = mm(x_dict, E)
import itertools
for a, b in itertools.combinations(RUNS, 2):
    d = (preds_by_run[a] - preds_by_run[b]).abs().max().item()
    sp_all = sp(y, preds_by_run[a].numpy()); print(f'  {a:20s} vs {b:20s}: max|Δpred|={d:.3e}')
for run in RUNS:
    pp = preds_by_run[run].numpy()
    print(f'  {run}: all-pkg spearman vs labels = {sp(y, pp):+.6f} | train spearman = {sp(y[train_idx], pp[train_idx]):+.6f}')

# ---- item 1b: reproduce evaluate_masked_auc_50 verbatim, diagnose NaN ----
print('\n===== NaN-AUC reproduction (verbatim evaluate_masked_auc_50, seed 42) =====')
from sklearn.metrics import roc_auc_score
def evaluate_masked_auc_50(model, seed):
    rng = np.random.RandomState(seed)
    mask_flags = rng.random(len(eligible_pkg_ids)) < 0.50
    masked_pkg_ids = {eligible_pkg_ids[i] for i in range(len(eligible_pkg_ids)) if mask_flags[i]}
    masked_pkg_indices = [pkg_id_to_idx[pid] for pid in masked_pkg_ids if pid in pkg_id_to_idx]
    edges = E[('Package', 'hasVulnerability', 'CVE')]
    keep_mask = ~np.isin(edges[0].numpy(), masked_pkg_indices)
    masked_E = copy.copy(E); masked_E[('Package', 'hasVulnerability', 'CVE')] = edges[:, torch.from_numpy(keep_mask)]
    scores, _ = model(x_dict, masked_E); scores = scores.numpy()
    pos = scores[masked_pkg_indices]; neg = scores[never_vuln_indices]
    print(f'    masked pos n={len(pos)} std={pos.std():.3e} | neg n={len(neg)} std={neg.std():.3e} | any NaN in scores: {bool(np.isnan(scores).any())}')
    y_eval = np.concatenate([np.ones(len(pos)), np.zeros(len(neg))])
    pred_eval = np.concatenate([pos, neg])
    try:
        return float(roc_auc_score(y_eval, pred_eval))
    except Exception as ex:
        return f'EXCEPTION: {type(ex).__name__}: {ex}'

for run in RUNS:
    sd = torch.load(CK / f'{run}.pt', map_location='cpu', weights_only=True)
    mm = VulnGATv2(); mm.load_state_dict(sd); mm.eval()
    auc = evaluate_masked_auc_50(mm, 42)
    print(f'  {run}: masked_auc_50 = {auc}')

# ---- item 4: raw vs normalized feature stats side by side ----
print('\n===== INPUT FEATURE STATS (raw, as v2 used them) =====')
names_pkg = ['0:?','1:?','2:out_degree','3:depth_in_tree','4:version_recency_days','5:versions_behind','6:?','7:weekly_downloads_log','8:?','9:?']
print('  Package features (raw):')
for i in range(10):
    c = pkg_features[:, i]
    print(f'    dim{i:2d} {names_pkg[i]:24s} min={c.min():12.4f} max={c.max():12.4f} mean={c.mean():12.4f} std={c.std():12.4f}')
print(f'  CVE dim 0..767 = embedding dims; dim768 = CVSS: min={cve_features[:,768].min():.2f} max={cve_features[:,768].max():.2f} std={cve_features[:,768].std():.2f}')
print(f'  CVE embedding dims summary: absmax={np.abs(cve_features[:,:768]).max():.3f} std={cve_features[:,:768].std():.4f}')
print('  Author features (raw):')
for i in range(7):
    c = author_features[:, i]
    print(f'    dim{i} min={c.min():12.4f} max={c.max():12.4f} std={c.std():12.4f}')
print(f'  targets y: min={y.min():.6f} max={y.max():.6f} mean={y.mean():.6f} std={y.std():.6f}')

json.dump(out, open(ROOT / 'phase5/autopsy_behavior_results.json', 'w'), indent=2, default=str)
print('\nsaved -> phase5/autopsy_behavior_results.json')
