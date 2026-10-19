# probe_rerun.py — pre-flight probes: official eligibility N=645/8682 + reverse-arch forward timing (CPU only, no training)
import json, sys, time
from pathlib import Path
from collections import defaultdict
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, HeteroConv

ROOT = Path(r'C:\Users\Admin\Desktop\Major VulnChain')
torch.set_grad_enabled(False)

graph_json = json.load(open(ROOT / 'phase5/bench_run/vulnchain_graph.json', encoding='utf-8'))
vpss_labels = json.load(open(ROOT / 'phase4/vpss_labels_51repo.json', encoding='utf-8'))

# 1. OFFICIAL code path: import the actual TrainModel/masked_edge_audit.py module
sys.path.insert(0, str(ROOT / 'TrainModel'))
import masked_edge_audit as mea

own = mea.compute_own_vpss(graph_json, vpss_labels)
elig70 = [p for p, d in own.items() if d['own_ratio'] >= 0.70 and d['full_vpss'] > 1e-6]
elig = mea.select_eligible_packages(own)
print(f'official compute_own_vpss: {len(own)} packages with own-CVE decomposition')
print(f'official select_eligible_packages: {len(elig)} eligible (threshold-0.70 pass count: {len(elig70)})')
print(f'max own_ratio: {max(d["own_ratio"] for d in own.values()):.4f}')

pkg_id_to_idx = {n['id']: i for i, n in enumerate(graph_json['nodes']['Package'])}
never = mea.get_never_vuln_indices(vpss_labels, pkg_id_to_idx, len(pkg_id_to_idx))
print(f'official get_never_vuln_indices: {len(never)}')

# 2. Graph size + forward timing on the FIXED architecture (with reverse edges)
pkg_nodes = graph_json['nodes']['Package']; cve_nodes = graph_json['nodes']['CVE']; author_nodes = graph_json['nodes']['Author']
print(f'nodes: pkg={len(pkg_nodes)} cve={len(cve_nodes)} author={len(author_nodes)}')
for k, v in graph_json['edges'].items():
    print(f'  edges {k}: {len(v)}')

pkg_features = np.array([n['features'] for n in pkg_nodes], dtype=np.float32)
cve_features = []
for n in cve_nodes:
    emb = n.get('embedding')
    if emb is None: emb = [0.0] * 768
    cvss = n.get('cvss_score'); cvss_val = float(cvss) if cvss is not None else 0.0
    cve_features.append(emb + [cvss_val])
cve_features = np.array(cve_features, dtype=np.float32)
author_features = np.array([n['features'] for n in author_nodes], dtype=np.float32)
cve_id_to_idx = {n['id']: i for i, n in enumerate(cve_nodes)}
author_id_to_idx = {n['id']: i for i, n in enumerate(author_nodes)}

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

FWD = [('Package', 'dependsOn', 'Package'), ('Package', 'hasVulnerability', 'CVE'),
       ('Package', 'maintainedBy', 'Author'), ('CVE', 'introducedBy', 'Author')]

def with_reverse_edges(edge_index_dict):
    full = dict(edge_index_dict)
    for (s, r, d) in FWD:
        k = (s, r, d)
        if k in full:
            full[(d, 'rev_' + r, s)] = full[k].flip(0)
    return full

class VulnGATv2Fixed(nn.Module):
    def __init__(self, pkg_in_dim=10, cve_in_dim=769, author_in_dim=7, hidden_dim=128, heads=4):
        super().__init__()
        self.pkg_proj = nn.Linear(pkg_in_dim, hidden_dim)
        self.cve_proj = nn.Linear(cve_in_dim, hidden_dim)
        self.author_proj = nn.Linear(author_in_dim, hidden_dim)
        convspec = lambda a, b: GATConv(a, b, heads=heads, add_self_loops=False)
        both = {
            ('Package', 'dependsOn', 'Package'): convspec(hidden_dim, hidden_dim // heads),
            ('Package', 'hasVulnerability', 'CVE'): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ('Package', 'maintainedBy', 'Author'): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ('CVE', 'introducedBy', 'Author'): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ('Package', 'rev_dependsOn', 'Package'): convspec(hidden_dim, hidden_dim // heads),
            ('CVE', 'rev_hasVulnerability', 'Package'): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ('Author', 'rev_maintainedBy', 'Package'): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
            ('Author', 'rev_introducedBy', 'CVE'): convspec((hidden_dim, hidden_dim), hidden_dim // heads),
        }
        self.conv1 = HeteroConv(both, aggr='sum')
        self.conv2 = HeteroConv(both, aggr='sum')
        self.classifier = nn.Sequential(nn.Linear(hidden_dim, 64), nn.GELU(), nn.Dropout(0.1), nn.Linear(64, 1), nn.Sigmoid())
    def forward(self, x_dict, edge_index_dict):
        h = {'Package': F.relu(self.pkg_proj(x_dict['Package'])),
             'CVE': F.relu(self.cve_proj(x_dict['CVE'])),
             'Author': F.relu(self.author_proj(x_dict['Author']))}
        ef = with_reverse_edges(edge_index_dict)
        h1 = self.conv1(h, ef); h1 = {k: F.relu(v) for k, v in h1.items()}
        h2 = self.conv2(h1, ef)
        return self.classifier(h2['Package']).squeeze(-1), h2['Package']

t0 = time.time()
torch.manual_seed(42)
m = VulnGATv2Fixed()
t1 = time.time()
p, _ = m(x_dict, E)
t2 = time.time()
print(f'\nFIXED-arch init: {t1-t0:.1f}s | full forward (with reverse edges): {t2-t1:.1f}s')
print(f'preds: std={p.std():.6f} mean={p.mean():.6f} min={p.min():.6f} max={p.max():.6f}')

# 3. liveness probe: remove 100% hasVuln edges
E2 = dict(E); E2[('Package', 'hasVulnerability', 'CVE')] = E[('Package', 'hasVulnerability', 'CVE')][:, :0]
p2, _ = m(x_dict, E2)
print(f'liveness: max|delta| removing 100% hasVuln = {(p2-p).abs().max():.3e}')

# 4. timed fwd+bwd step (for P3 cost estimate)
torch.set_grad_enabled(True)
y = torch.rand(len(pkg_nodes))
opt = torch.optim.AdamW(m.parameters(), lr=5e-4)
t3 = time.time()
opt.zero_grad()
pc, _ = m(x_dict, E)
loss = F.mse_loss(pc, y)
loss.backward()
opt.step()
t4 = time.time()
pm = dict(E); e = E[('Package', 'hasVulnerability', 'CVE')]
pm[('Package', 'hasVulnerability', 'CVE')] = e[:, torch.rand(e.size(1)) > 0.3]
pmm, _ = m(x_dict, pm)
la = F.mse_loss(pmm, pc.detach())
la.backward()
opt.step()
t5 = time.time()
print(f'timed train step: clean fwd+bwd {t4-t3:.1f}s + masked fwd+bwd {t5-t4:.1f}s -> est. 50-epoch smoke (incl. val fwd): {(t4-t3+t5-t4+1.0)*50/60:.1f}-{(t4-t3+t5-t4+2.0)*50/60:.1f} min')
