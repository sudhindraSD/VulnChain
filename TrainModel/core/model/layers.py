"""
core/model/layers.py — HAN Attention Layer for VulnGAT

Implements a single Heterogeneous Graph Attention layer with:
- Separate weight matrices per edge type (true HAN, Design Decision D5)
- Multi-head attention (4 heads × 32 dim = 128)
- Residual connection + LayerNorm (anti-over-smoothing, Section 8.4)
- Configurable dropout
- Explicit bipartite size handling for heterogeneous nodes

Reference: Wang et al. 2019 — Heterogeneous Graph Attention Network (P1)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import MessagePassing
from torch_geometric.utils import softmax


class HeteroGATConv(MessagePassing):
    """
    Single-relation GAT convolution for one edge type.
    Computes attention-weighted message passing between source and target nodes.
    
    Uses multi-head attention: each head operates on (hidden_dim // num_heads) dims,
    then concatenates back to hidden_dim.
    """
    
    def __init__(self, in_dim: int, out_dim: int, num_heads: int = 4, dropout: float = 0.3):
        super().__init__(aggr="add", flow="source_to_target", node_dim=0)
        
        self.num_heads = num_heads
        self.head_dim = out_dim // num_heads
        assert out_dim % num_heads == 0, f"out_dim ({out_dim}) must be divisible by num_heads ({num_heads})"
        
        # Linear transform for source nodes (per this edge type)
        self.W_src = nn.Linear(in_dim, out_dim, bias=False)
        # Linear transform for target nodes (for attention computation)
        self.W_tgt = nn.Linear(in_dim, out_dim, bias=False)
        
        # Attention vector per head
        self.attn = nn.Parameter(torch.zeros(1, num_heads, 2 * self.head_dim))
        nn.init.xavier_uniform_(self.attn.data, gain=1.414)
        
        self.leaky_relu = nn.LeakyReLU(0.2)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x_src: torch.Tensor, x_tgt: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x_src: Source node features [num_src_nodes, in_dim]
            x_tgt: Target node features [num_tgt_nodes, in_dim] 
            edge_index: [2, num_edges] — edge_index[0]=source, edge_index[1]=target
            
        Returns:
            Updated target node features [num_tgt_nodes, out_dim]
        """
        # Transform source and target nodes
        h_src = self.W_src(x_src).view(-1, self.num_heads, self.head_dim)
        h_tgt = self.W_tgt(x_tgt).view(-1, self.num_heads, self.head_dim)
        
        # Explicitly pass bipartite graph size: (num_src, num_tgt)
        size = (x_src.size(0), x_tgt.size(0))
        
        # Propagate messages
        out = self.propagate(edge_index, h_src=h_src, h_tgt=h_tgt, size=size)
        
        # Reshape back: [num_tgt, out_dim]
        return out.view(-1, self.num_heads * self.head_dim)
    
    def message(self, h_src_j: torch.Tensor, h_tgt_i: torch.Tensor, index: torch.Tensor, 
                ptr: torch.Tensor = None, size_i: int = None) -> torch.Tensor:
        """
        Compute attention-weighted messages.
        h_src_j: source node features gathered by edge [num_edges, num_heads, head_dim]
        h_tgt_i: target node features gathered by edge [num_edges, num_heads, head_dim]
        """
        # Concatenate source and target for attention
        h_cat = torch.cat([h_tgt_i, h_src_j], dim=-1)  # [num_edges, num_heads, 2*head_dim]
        
        # Compute attention scores
        attn_score = (h_cat * self.attn).sum(dim=-1)  # [num_edges, num_heads]
        attn_score = self.leaky_relu(attn_score)
        
        # Softmax over all incoming edges per target node
        attn_weight = softmax(attn_score, index, ptr, size_i)  # [num_edges, num_heads]
        attn_weight = self.dropout(attn_weight)
        
        # Weight messages
        return h_src_j * attn_weight.unsqueeze(-1)  # [num_edges, num_heads, head_dim]


class HANLayer(nn.Module):
    """
    One full Heterogeneous Attention Network layer.
    
    Performs per-edge-type message passing via separate HeteroGATConv modules,
    then aggregates all incoming messages per node with residual + LayerNorm.
    
    Design Decisions:
    - D5: Separate weight matrices per edge type (true HAN)
    - Section 8.4: Residual connections to prevent over-smoothing
    """
    
    EDGE_TYPES = [
        ("Package", "dependsOn", "Package"),
        ("Package", "hasVulnerability", "CVE"),
        ("Package", "maintainedBy", "Author"),
        ("CVE", "introducedBy", "Author"),
    ]
    
    def __init__(self, hidden_dim: int = 128, num_heads: int = 4, dropout: float = 0.3):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        
        # Separate GAT conv per edge type (Design Decision D5)
        self.convs = nn.ModuleDict()
        for src_type, edge_type, tgt_type in self.EDGE_TYPES:
            key = f"{src_type}__{edge_type}__{tgt_type}"
            self.convs[key] = HeteroGATConv(hidden_dim, hidden_dim, num_heads, dropout)
            
            # Also add reverse direction for message passing
            rev_key = f"{tgt_type}__rev_{edge_type}__{src_type}"
            self.convs[rev_key] = HeteroGATConv(hidden_dim, hidden_dim, num_heads, dropout)
        
        # LayerNorm per node type (for residual connection)
        self.layer_norms = nn.ModuleDict({
            "Package": nn.LayerNorm(hidden_dim),
            "CVE": nn.LayerNorm(hidden_dim),
            "Author": nn.LayerNorm(hidden_dim),
        })
        
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x_dict: dict, edge_index_dict: dict) -> dict:
        """
        Args:
            x_dict: {"Package": [N_pkg, 128], "CVE": [N_cve, 128], "Author": [N_auth, 128]}
            edge_index_dict: {("src_type", "edge_type", "tgt_type"): [2, num_edges], ...}
            
        Returns:
            Updated x_dict with same shapes
        """
        # Collect messages per target node type
        out_dict = {ntype: [] for ntype in x_dict}
        
        for (src_type, edge_type, tgt_type), edge_index in edge_index_dict.items():
            if edge_index.size(1) == 0:
                continue
                
            # Forward direction
            fwd_key = f"{src_type}__{edge_type}__{tgt_type}"
            if fwd_key in self.convs:
                msg = self.convs[fwd_key](x_dict[src_type], x_dict[tgt_type], edge_index)
                out_dict[tgt_type].append(msg)
            
            # Reverse direction (so target nodes send info back to source)
            rev_key = f"{tgt_type}__rev_{edge_type}__{src_type}"
            if rev_key in self.convs:
                rev_edge_index = edge_index.flip(0)
                msg = self.convs[rev_key](x_dict[tgt_type], x_dict[src_type], rev_edge_index)
                out_dict[src_type].append(msg)
        
        # Aggregate messages and apply residual + LayerNorm
        result = {}
        for ntype in x_dict:
            if out_dict[ntype]:
                agg = torch.stack(out_dict[ntype], dim=0).mean(dim=0)
                agg = self.dropout(agg)
                result[ntype] = self.layer_norms[ntype](agg + x_dict[ntype])
            else:
                result[ntype] = x_dict[ntype]
        
        return result
