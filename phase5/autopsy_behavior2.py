# V2 AUTOPSY — behavioral forensics v2. NO TRAINING. CPU only.
import json, copy, math, warnings, random, itertools
from pathlib import Path
from collections import defaultdict, deque
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from scipy import stats as scipy_stats
from torch_geometric.nn import GATConv, HeteroConv

warnings.filterwarnings('ignore')
ROOT = Path(r'C:\Users\Admin\Desktop\Major VulnChain')
CK = ROOT / 'vulngat_v2_checkpoints'
torch.set_grad_enabled(False)

graph_json = json.load(open(ROOT / 'phase5/bench_run/vulnchain_graph.json', encoding='utf-8'))
epss_labels = json.load(open(ROOT / 'phase5/epss_labels_51repo.json', encoding='utf-8'))
vpss_labels = json.load(open(ROOT / 'phase4/vpss_labels_51repo.json', encoding='utf-8'))
osv_data = json.load(open(ROOT / '.osv_records_cache.json', encoding='utf-8'))

pkg_nodes = graph_json['nodes']['Package']; cve_nodes = graph_json['nodes']['CVE']; author_nodes = graph_json['nodes']['Author']
pkg_id_to_idx = {n['id']: i for i, n in enumerate(pkg_nodes)}
cve_id_to_idx = {n['id']: i for i, n in enumerate(cve_nodes)}
author_id_to_idx = {n['id']: i for i, n in enumerate(author_nodes)}
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
    ('Package', 'maintainedBy', 'Author'): build_edge_index(graph_json['edges']['maintainedBy'], pkg_id_to_idx, author_id_to_idx),
    ('CVE', 'introducedBy', 'Author'): build_edge_index(graph_json['edges']['introducedBy'], cve_id_to_idx, author_id_to_idx),
}
x_dict = {'Package': torch.tensor(pkg_features), 'CVE': torch.tensor(cve_features), 'Author': torch.tensor(author_features)}

# notebook-verbatim eligibility (expected EMPTY)
pkg_to_cves = defaultdict(list)
for edge in graph_json['edges']['hasVulnerability']: pkg_to_cves[edge['source']].append(edge['target'])
cve_cvss = {c['id']: float(c.get('cvss_score') or 0.0) for c in cve_nodes}
eligible_nb = []
for pid, clist in pkg_to_cves.items():
    vp = vpss_labels.get(pid, {}); raw_sum = float(vp.get('raw_sum', 0.0))
    own_raw = sum(cve_cvss.get(c, 0.0)/10.0 for c in clist)
    own_ratio = (own_raw/raw_sum) if raw_sum > 1e-9 else 0.0
    if own_ratio >= 0.70 and float(vp.get('vpss', 0.0)) > 1e-6: eligible_nb.append(pid)
# official 0.30-relaxed strata (the true N=645)
own_data = {}
for pid, clist in pkg_to_cves.items():
    le = vpss_labels.get(pid, {}); raw_sum = float(le.get('raw_sum', 0.0)); full = float(le.get('vpss', 0.0))
    own_raw = sum(cve_cvss.get(c,0.0)/10.0 for c in clist)
    if raw_sum > 1e-9: r = min(own_raw/raw_sum, 1.0)
    elif own_raw > 0: r = 1.0
    else: r = 0.0
    own_data[pid] = (r, full)
eligible_official = [pid for pid, (r, f) in own_data.items() if r >= 0.30 and f > 1e-6]
never_vuln_indices = [pkg_id_to_idx[pid] for pid, l in vpss_labels.items() if l.get('vpss', 0.0) < 1e-9 and pid in pkg_id_to_idx]

TEMPORAL_CUTOFF = '2026-08-01'
cve_dates = {c['id']: osv_data[c['id']]['published'][:10] for c in cve_nodes if c['id'] in osv_data and osv_data[c['id']].get('published')}
deps_of = defaultdict(list)
for e in graph_json['edges']['dependsOn']: deps_of[e['source']].append(e['target'])
pkg_newest_date = {}
for pid in pkg_id_to_idx:
    visited = {pid: 0}; q = deque([pid]); cd = []
    while q:
        cur = q.popleft(); d = visited[cur]
        if cur in pkg_to_cves:
            for cve in pkg_to_cves[cur]:
                if cve in cve_dates: cd.append(cve_dates[cve])
        if d < 5:
            for nxt in deps_of.get(cur, ()):
                if nxt not in visited and nxt in pkg_id_to_idx:
                    visited[nxt] = d + 1; q.append(nxt)
    if cd: pkg_newest_date[pid] = max(cd)
nz_pkgs = [pid for pid in pkg_id_to_idx if epss_labels[pid]['epss_risk'] > 0]
train_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, '2000-01-01') < TEMPORAL_CUTOFF]
test_pkgs = [pid for pid in nz_pkgs if pkg_newest_date.get(pid, '2000-01-01') >= TEMPORAL_CUTOFF]
random.seed(42); shuffled = list(train_pkgs); random.shuffle(shuffled)
val_cut = int(0.20 * len(shuffled)); val_pkgs = shuffled[:val_cut]; train_fit_pkgs = shuffled[val_cut:]
train_idx = np.array([pkg_id_to_idx[p] for p in train_fit_pkgs])
val_idx = np.array([pkg_id_to_idx[p] for p in val_pkgs])
test_idx = np.array([pkg_id_to_idx[p] for p in test_pkgs])
y = pkg_targets
off_idx = np.array([pkg_id_to_idx[p] for p in eligible_official if p in pkg_id_to_idx])
nv_idx = np.array(never_vuln_indices)
print(f'pops: train_fit={len(train_idx)} val={len(val_idx)} test={len(test_idx)} | eligible(notebook)={len(eligible_nb)} eligible(official 0.30-relaxed)={len(eligible_official)} never_vuln={len(nv_idx)}')

class VulnGATv2(nn.Module):
    def __init__(self, pkg_in_dim=10, cve_in_dim=769, author_in_dim=7, hidden_dim=128, heads=4):
        super().__init__()
        self.pkg_proj = nn.Linear(pkg_in_dim, hidden_dim)
        self.cve_proj = nn.Linear(cve_in_dim, hidden_dim)
        self.author_proj = nn.Linear(author_in_dim, hidden_dim)
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

def q(x): return [float(round(v, 7)) for v in np.percentile(x, [0, 1, 25, 50, 75, 99, 100])]
def sp(a, b):
    s = scipy_stats.spearmanr(a, b)[0]
    return float('nan') if np.isnan(s) else float(s)

RUNS = ['full_v2_p10_s42', 'full_v2_p30_s42', 'full_v2_p50_s42', 'no_masking_s42', 'no_ranking_p10_s42', 'full_v2_p30_s123', 'full_v2_p30_s789']
out = {}

# also build a fresh INIT model with seed 42 for distance-to-init
torch.manual_seed(42)
init_model = VulnGATv2()
init_sd = {k: v.clone() for k, v in init_model.state_dict().items()}
init_preds, _ = init_model(x_dict, E)

for run in RUNS:
    sd = torch.load(CK / f'{run}.pt', map_location='cpu', weights_only=True)
    m = VulnGATv2(); m.load_state_dict(sd); m.eval()
    acts = {}; hooks = []
    hooks.append(m.pkg_proj.register_forward_hook(lambda mo, i, o: acts.__setitem__('1_pkg_proj', o.detach())))
    hooks.append(m.conv1.register_forward_hook(lambda mo, i, o: acts.__setitem__('2_conv1_Pkg', o['Package'].detach())))
    hooks.append(m.conv2.register_forward_hook(lambda mo, i, o: acts.__setitem__('3_conv2_Pkg', o['Package'].detach())))
    hooks.append(m.classifier[0].register_forward_hook(lambda mo, i, o: acts.__setitem__('4_cls_lin', o.detach())))
    hooks.append(m.classifier[3].register_forward_hook(lambda mo, i, o: acts.__setitem__('5_logit', o.detach())))
    preds, emb = m(x_dict, E)
    for h in hooks: h.remove()
    p = preds.numpy()
    # distance from init
    d_init = max((sd[k] - init_sd[k]).abs().max().item() for k in sd)
    l2_init = math.sqrt(sum(((sd[k].double() - init_sd[k].double()) ** 2).sum().item() for k in sd))
    r = {'max_abs_param_dist_from_seed42_init': d_init, 'l2_dist_from_seed42_init': l2_init}
    for name, idx in [('train', train_idx), ('val', val_idx), ('test', test_idx)]:
        pp, tt = p[idx], y[idx]
        r[name] = dict(n=int(len(idx)), spearman=sp(tt, pp), mse=float(np.mean((pp - tt) ** 2)),
                       pred_mean=float(pp.mean()), pred_std=float(pp.std()), pred_quantiles=q(pp),
                       target_mean=float(tt.mean()), target_std=float(tt.std()))
    r['official_645_strata'] = dict(std=float(p[off_idx].std()), mean=float(p[off_idx].mean()), quantiles=q(p[off_idx]))
    r['never_vuln_8682'] = dict(std=float(p[nv_idx].std()), mean=float(p[nv_idx].mean()), quantiles=q(p[nv_idx]))
    r['global'] = dict(pred_std=float(p.std()), pred_mean=float(p.mean()),
                       unique_vals_at_1e6=int(len(np.unique(p.round(6)))),
                       unique_vals_exact=int(len(np.unique(p))), n=num_packages)
    r['vs_init_predictions'] = dict(max_abs_diff=float((p - init_preds.numpy()).max()), spearman_init_vs_trained=sp(init_preds.numpy(), p))
    r['activations'] = {k: dict(std=float(v.std()), mean=float(v.mean()), absmax=float(v.abs().max()),
                                frac_dead=float((v <= 0).float().mean())) for k, v in acts.items()}
    out[run] = r
    print(f'\n===== {run} =====')
    print(f"  dist from seed-42 INIT weights: max|Δw|={d_init:.3e}  L2={l2_init:.3e}")
    for name in ['train', 'val', 'test']:
        d = r[name]
        print(f"  {name:5s} n={d['n']:5d} spearman={d['spearman']:+.4f} mse={d['mse']:.6f} predmean={d['pred_mean']:.6f} predstd={d['pred_std']:.2e} q={d['pred_quantiles']}")
    print(f"  official-645 strata: std={r['official_645_strata']['std']:.2e} mean={r['official_645_strata']['mean']:.6f}")
    print(f"  never-vuln-8682:     std={r['never_vuln_8682']['std']:.2e} mean={r['never_vuln_8682']['mean']:.6f}")
    print(f"  global pred: std={r['global']['pred_std']:.2e} unique@1e-6={r['global']['unique_vals_at_1e6']} exact-unique={r['global']['unique_vals_exact']}/{num_packages}")
    print(f"  vs init predictions: max|Δpred|={r['vs_init_predictions']['max_abs_diff']:.3e} spearman(init,trained)={r['vs_init_predictions']['spearman_init_vs_trained']:+.4f}")
    for k, v in r['activations'].items():
        print(f"  act {k:12s} std={v['std']:10.4f} mean={v['mean']:+10.4f} absmax={v['absmax']:10.2f} dead={v['frac_dead']:.3f}")

print('\n===== p_mask inertness (weights: full_v2_p30_s42; drop ALL hasVuln edges) =====')
sd = torch.load(CK / 'full_v2_p30_s42.pt', map_location='cpu', weights_only=True)
m = VulnGATv2(); m.load_state_dict(sd); m.eval()
base, _ = m(x_dict, E)
E_nocve = copy.copy(E); E_nocve[('Package', 'hasVulnerability', 'CVE')] = E[('Package', 'hasVulnerability', 'CVE')][:, :0]
p2, _ = m(x_dict, E_nocve)
print(f'  remove ALL 100% hasVulnerability edges -> max|Δpred| over 12,405 packages = {(p2 - base).abs().max().item():.3e}')
torch.manual_seed(0)
for pm in [0.1, 0.3, 0.5, 0.9]:
    Em = apply_dynamic_edge_dropout(E, pm)
    pp, _ = m(x_dict, Em)
    print(f'  p_mask={pm:<5} kept {Em[("Package","hasVulnerability","CVE")].size(1):5d} edges -> max|Δpred| = {(pp - base).abs().max().item():.3e}')

print('\n===== NaN-AUC mechanism (empty eligible -> single-class y_true) =====')
from sklearn.metrics import roc_auc_score
try:
    v = roc_auc_score(np.zeros(8682), np.random.rand(8682))
    print('  roc_auc_score(all-negative y) returned:', v)
except Exception as ex:
    print(f'  roc_auc_score(all-negative y) raised: {type(ex).__name__}: {ex}')

print('\n===== INPUT FEATURE STATS (raw, exactly as v2 consumed them) =====')
pkg_names = ['0 pkg_type_flag', '1 is_app', '2 out_degree', '3 depth_in_tree', '4 version_recency_days',
             '5 versions_behind_latest', '6 binary?', '7 weekly_downloads_log', '8 ?', '9 ?']
print('  Package (raw):')
for i in range(10):
    c = pkg_features[:, i]
    print(f'    dim{i:2d} {pkg_names[i]:24s} min={c.min():11.3f} max={c.max():11.3f} mean={c.mean():11.3f} std={c.std():11.3f}')
print(f'  CVE[0:768] embedding: std={cve_features[:, :768].std():.4f} absmax={np.abs(cve_features[:, :768]).max():.3f}')
print(f'  CVE[768] CVSS raw:    min={cve_features[:, 768].min():.1f} max={cve_features[:, 768].max():.1f} std={cve_features[:, 768].std():.3f}  (Phase 4 divided by 10; v2 did not)')
print('  Author (raw):')
for i in range(7):
    c = author_features[:, i]
    print(f'    dim{i} min={c.min():11.3f} max={c.max():11.3f} std={c.std():11.3f}')
print(f'  labels y: min={y.min():.6f} max={y.max():.6f} mean={y.mean():.6f} std={y.std():.6f}')
# what the projections see
pw = sd['pkg_proj.weight']; pb = sd['pkg_proj.bias']
z = torch.tensor(pkg_features) @ pw.T + pb
print(f'  -> pkg_proj preactivation at INIT: mean={z.mean():.3f} std={z.std():.3f} absmax={z.abs().max():.1f} (Kaiming-uniform init)')

json.dump(out, open(ROOT / 'phase5/autopsy_behavior_results.json', 'w'), indent=2, default=str)
print('\nsaved -> phase5/autopsy_behavior_results.json')
