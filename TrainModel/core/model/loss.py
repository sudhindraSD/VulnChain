"""
core/model/loss.py — Loss Functions for VulnGAT Training

Total Loss = MSE Loss + 0.1 × InfoNCE Loss  (Section 9)

MSE Loss (Section 9.2):
  Primary supervision signal. Penalizes distance between predicted risk scores
  and continuous VPSS labels. NOT binary cross entropy — labels are continuous.

InfoNCE Loss (Section 9.3):
  Contrastive regularizer. Prevents embedding space collapse by ensuring
  each node has a distinctive representation. Uses edge dropout augmentation
  to create two views of the same node.

Design Decisions:
  D3: MSE not BCE (continuous labels)
  D4: Positive pairs = same-node augmentations (NOT same-CVE grouping)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import copy


def compute_mse_loss(predictions: torch.Tensor, labels: torch.Tensor, 
                     mask: torch.Tensor = None) -> torch.Tensor:
    """
    MSE regression loss between predicted risk scores and VPSS labels.
    
    Args:
        predictions: [N_pkg] predicted risk scores (Sigmoid output, 0–1)
        labels: [N_pkg] VPSS weak supervision labels (continuous, 0–1)
        mask: [N_pkg] boolean mask for train/val/test split
        
    Returns:
        Scalar MSE loss
    """
    if mask is not None:
        predictions = predictions[mask]
        labels = labels[mask]
    
    return F.mse_loss(predictions, labels)


def augment_edge_index(edge_index_dict: dict, drop_rate: float = 0.2) -> dict:
    """
    Create an augmented view of the graph by randomly dropping edges.
    
    Used for InfoNCE contrastive loss — two augmented views of the same graph
    produce different embeddings for the same node, forming positive pairs.
    
    Args:
        edge_index_dict: Original edge indices per edge type
        drop_rate: Fraction of edges to drop (0.2 = 20%, from Section 6.4)
        
    Returns:
        New edge_index_dict with randomly dropped edges
    """
    augmented = {}
    for edge_type, edge_index in edge_index_dict.items():
        num_edges = edge_index.size(1)
        if num_edges == 0:
            augmented[edge_type] = edge_index
            continue
            
        # Keep (1 - drop_rate) fraction of edges randomly
        keep_mask = torch.rand(num_edges, device=edge_index.device) > drop_rate
        
        # Ensure at least 1 edge survives
        if not keep_mask.any():
            keep_mask[0] = True
            
        augmented[edge_type] = edge_index[:, keep_mask]
    
    return augmented


def compute_infonce_loss(model, x_dict: dict, edge_index_dict: dict,
                         drop_rate: float = 0.2, temperature: float = 0.5) -> torch.Tensor:
    """
    InfoNCE contrastive loss for embedding quality (Section 9.3).
    
    Process:
      1. Create two augmented views via edge dropout (p=0.2)
      2. Forward both views → get Package node embeddings
      3. Positive pairs: same node, two views → pull together
      4. Negative pairs: different nodes → push apart
      5. Cross-entropy over cosine similarity distribution
    
    CRITICAL (Design Decision D4):
      Positive pairs MUST be augmented views of the SAME node.
      NOT packages sharing the same CVE. That would cluster all vulnerable
      packages together, destroying risk score differentiation.
    
    Args:
        model: VulnGAT model (uses encode() to get embeddings)
        x_dict: Raw node features
        edge_index_dict: Original edge indices
        drop_rate: Edge dropout rate (0.2)
        temperature: InfoNCE temperature parameter
        
    Returns:
        Scalar InfoNCE loss
    """
    # Create two augmented views
    aug_edges_1 = augment_edge_index(edge_index_dict, drop_rate)
    aug_edges_2 = augment_edge_index(edge_index_dict, drop_rate)
    
    # Get embeddings for both views (Package nodes only)
    h1_dict = model.encode(x_dict, aug_edges_1)
    h2_dict = model.encode(x_dict, aug_edges_2)
    
    z1 = h1_dict["Package"]  # [N_pkg, 128]
    z2 = h2_dict["Package"]  # [N_pkg, 128]
    
    # L2 normalize embeddings
    z1 = F.normalize(z1, dim=1)
    z2 = F.normalize(z2, dim=1)
    
    # For memory efficiency on large graphs, sample a subset of nodes
    N = z1.size(0)
    max_nodes = min(N, 2048)  # Cap at 2048 to fit in 6GB VRAM
    
    if N > max_nodes:
        idx = torch.randperm(N, device=z1.device)[:max_nodes]
        z1 = z1[idx]
        z2 = z2[idx]
        N = max_nodes
    
    # Cosine similarity matrix: [N, N]
    sim_11 = torch.mm(z1, z1.t()) / temperature
    sim_22 = torch.mm(z2, z2.t()) / temperature
    sim_12 = torch.mm(z1, z2.t()) / temperature
    sim_21 = torch.mm(z2, z1.t()) / temperature
    
    # Positive pairs: diagonal of sim_12 (same node, different views)
    # Negatives: all off-diagonal entries
    
    # InfoNCE: for each node in view 1, the positive is the same node in view 2
    # logits = [sim(z1_i, z2_i), sim(z1_i, z2_j!=i)]
    # label = 0 (first element is the positive)
    
    # Mask out self-similarity for negatives
    mask = torch.eye(N, device=z1.device, dtype=torch.bool)
    sim_11.masked_fill_(mask, float('-inf'))
    sim_22.masked_fill_(mask, float('-inf'))
    
    # View 1 → View 2 direction
    logits_12 = torch.cat([sim_12, sim_11], dim=1)  # [N, 2N]
    # View 2 → View 1 direction  
    logits_21 = torch.cat([sim_21, sim_22], dim=1)  # [N, 2N]
    
    # Labels: positive is always index 0..N-1 (diagonal of first half)
    labels = torch.arange(N, device=z1.device)
    
    loss = (F.cross_entropy(logits_12, labels) + F.cross_entropy(logits_21, labels)) / 2
    
    return loss


class VulnChainLoss(nn.Module):
    """
    Combined loss: MSE + 0.1 × InfoNCE (Section 9.1)
    
    MSE is the primary supervision signal (weight=1.0).
    InfoNCE is a regularizer (weight=0.1) — prevents embedding collapse
    while keeping MSE dominant.
    """
    
    def __init__(self, infonce_weight: float = 0.1, edge_drop_rate: float = 0.2,
                 temperature: float = 0.5):
        super().__init__()
        self.infonce_weight = infonce_weight
        self.edge_drop_rate = edge_drop_rate
        self.temperature = temperature
    
    def forward(self, model, predictions: torch.Tensor, labels: torch.Tensor,
                x_dict: dict, edge_index_dict: dict, 
                mask: torch.Tensor = None) -> tuple:
        """
        Compute total loss = MSE + 0.1 × InfoNCE.
        
        Returns:
            (total_loss, mse_loss, infonce_loss) — all scalar tensors
        """
        mse = compute_mse_loss(predictions, labels, mask)
        infonce = compute_infonce_loss(model, x_dict, edge_index_dict,
                                       self.edge_drop_rate, self.temperature)
        
        total = mse + self.infonce_weight * infonce
        
        return total, mse, infonce
