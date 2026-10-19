"""
core/model/vulngat.py — VulnGAT: 3-Layer Heterogeneous Graph Attention Network

The trained GNN model for VulnChain. Takes an enriched heterogeneous graph
and produces a risk score (0.0–1.0) for every Package node.

Architecture (Section 8 of design doc):
  1. Input Projection: Package(10→128), CVE(769→128), Author(7→128)
  2. Three HANLayer passes (1-hop → 2-hop → 3-hop context)
  3. Classifier: Linear(128,1) → Sigmoid → Risk Score per Package

Design Decisions:
  D5: Separate weight matrices per edge type
  D6: All types projected to 128-dim before GAT
  D7: Risk score output per Package node only
"""

import torch
import torch.nn as nn
from core.model.layers import HANLayer


class VulnGAT(nn.Module):
    """
    VulnGAT — 3-layer Heterogeneous Graph Attention Network.
    
    Produces a risk score ∈ [0.0, 1.0] for every Package node in the graph,
    based on 3-hop neighbourhood context across all node and edge types.
    """
    
    # Feature dimensions per node type (from design doc Section 5)
    PACKAGE_DIM = 10     # 10-dim feature vector
    CVE_DIM = 769        # 768-dim SentenceBERT embedding + 1 CVSS score
    AUTHOR_DIM = 7       # 7-dim feature vector
    HIDDEN_DIM = 128     # Common projection dimension (Design Decision D6)
    
    def __init__(self, hidden_dim: int = 128, num_layers: int = 3, 
                 num_heads: int = 4, dropout: float = 0.3):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # ── Step 1: Input Projection (Section 8.2) ─────────────────────
        # Project all node types to common 128-dim space
        self.projections = nn.ModuleDict({
            "Package": nn.Linear(self.PACKAGE_DIM, hidden_dim),
            "CVE": nn.Linear(self.CVE_DIM, hidden_dim),
            "Author": nn.Linear(self.AUTHOR_DIM, hidden_dim),
        })
        
        # ── Step 2: Three HAN Layers (Section 8.4) ─────────────────────
        # Each layer expands the neighbourhood view by 1 hop
        self.layers = nn.ModuleList([
            HANLayer(hidden_dim, num_heads, dropout)
            for _ in range(num_layers)
        ])
        
        # ── Step 3: Classifier Head (Section 8.5) ──────────────────────
        # Linear(128,1) → Sigmoid → risk score per Package node
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )
    
    def encode(self, x_dict: dict, edge_index_dict: dict) -> dict:
        """
        Encode all nodes into 128-dim embeddings through projection + 3 GAT layers.
        
        Args:
            x_dict: Raw features per node type
                {"Package": [N_pkg, 10], "CVE": [N_cve, 769], "Author": [N_auth, 7]}
            edge_index_dict: Edge indices per edge type
                {("Package", "dependsOn", "Package"): [2, E1], ...}
        
        Returns:
            Encoded embeddings per node type (all 128-dim)
        """
        # Project to common 128-dim space
        h_dict = {}
        for ntype, x in x_dict.items():
            h_dict[ntype] = self.projections[ntype](x)
        
        # 3 layers of message passing
        for layer in self.layers:
            h_dict = layer(h_dict, edge_index_dict)
        
        return h_dict
    
    def forward(self, x_dict: dict, edge_index_dict: dict) -> torch.Tensor:
        """
        Full forward pass: features → embeddings → risk scores.
        
        Returns:
            risk_scores: [N_pkg] tensor of floats in [0.0, 1.0]
        """
        h_dict = self.encode(x_dict, edge_index_dict)
        
        # Classify Package nodes only (Design Decision D7)
        risk_scores = self.classifier(h_dict["Package"]).squeeze(-1)
        
        return risk_scores
    
    def predict(self, x_dict: dict, edge_index_dict: dict) -> torch.Tensor:
        """Inference mode — no gradient tracking."""
        self.eval()
        with torch.no_grad():
            return self.forward(x_dict, edge_index_dict)
