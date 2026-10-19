# VulnGAT Training Pipeline — Implementation Plan

## Goal

Build the complete **Stage 5 training pipeline** for VulnChain: convert the merged graph to PyG format, implement the 3-layer HAN model (VulnGAT), train with MSE + InfoNCE loss, evaluate on CISA KEV ground truth, and save `vulngat_trained.pt`.

---

## Step 0 — Environment Setup

Create a Python venv and install all dependencies:

```
python -m venv venv
venv\Scripts\activate
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu126
pip install torch_geometric
pip install pyg_lib torch_scatter torch_sparse -f https://data.pyg.org/whl/torch-{VERSION}+cu126.html
pip install scipy numpy scikit-learn
```

> We'll detect the exact PyTorch version after install to get the right PyG wheel URL.

---

## Step 1 — Project Structure

All files will be created inside `c:\Users\sudhindra\Desktop\TrainModel\`:

```
TrainModel/
├── venv/                          ← Python virtual environment
├── vulnchain_graph.json           ← Already exists (8.2 MB)
├── vpss_labels.json               ← Already exists (685 KB)
├── VULNCHAIN_DESIGN_v1.0.md       ← Already exists
├── vulnchain_project_status.md    ← Already exists
│
├── training/
│   ├── dataset.py                 ← [NEW] Graph → PyG HeteroData conversion
│   ├── train.py                   ← [NEW] Full training loop (entry point)
│   └── evaluate.py                ← [NEW] Metrics + CISA KEV evaluation
│
├── core/
│   └── model/
│       ├── vulngat.py             ← [NEW] VulnGAT 3-layer HAN model
│       ├── layers.py              ← [NEW] HAN attention layer definition
│       └── loss.py                ← [NEW] MSE + 0.1 × InfoNCE loss
│
└── models/
    └── vulngat_trained.pt         ← [OUTPUT] Saved model weights
```

**6 new Python files total.**

---

## Step 2 — File-by-File Breakdown

### `training/dataset.py` — Graph Loading & HeteroData Conversion

- Load `vulnchain_graph.json` and `vpss_labels.json`
- Build ID → integer index mappings for each node type
- Stack feature tensors:
  - Package: `[5578, 10]` → normalize continuous features (min-max)
  - CVE: `[326, 769]` (768-dim embedding + 1 CVSS score)
  - Author: `[2035, 7]` → normalize continuous features
- Build edge_index tensors (COO format) for all 4 edge types
- Assign VPSS labels to Package nodes → `[5578]` float tensor
- Tag each Package node with its source repo (for repo-level split)
- **Pinned repo-level split**:
  - Train: nest, NodeGoat, cli, nodejs-goof, express, dvna, Ghost (7 repos)
  - Val: webpack (1 repo)
  - Test: juice-shop (1 repo)
- Return `HeteroData` object + split masks + labels

---

### `core/model/layers.py` — HAN Attention Layer

- One `HANLayer` class that performs per-edge-type message passing:
  - Separate `W_transform` linear layers per edge type (128×128)
  - Attention coefficients computed via LeakyReLU + softmax
  - Multi-head attention (4 heads × 32 dim = 128)
- Residual connection + LayerNorm after each layer
- Dropout configurable (default 0.3)

---

### `core/model/vulngat.py` — VulnGAT Model

- **Input projection**: 3 separate `Linear` layers:
  - Package: `Linear(10, 128)`
  - CVE: `Linear(769, 128)` — 768 embedding + 1 CVSS
  - Author: `Linear(7, 128)`
- **3 × HANLayer** (from `layers.py`) with residual + LayerNorm
- **Classifier head**: `Linear(128, 1)` → `Sigmoid`
- Output: risk score per Package node only (float 0.0–1.0)
- Leverages PyG's `HeteroConv` or manual per-relation message passing

---

### `core/model/loss.py` — Loss Functions

- **MSE Loss**: `F.mse_loss(predicted, vpss_labels)` — primary signal
- **InfoNCE Loss** (contrastive regularizer):
  - Create 2 augmented views of the graph via edge dropout (p=0.2)
  - Forward both views through the model → get embeddings
  - Positive pairs = same node's two augmented embeddings
  - Negative pairs = all other nodes in batch
  - Cross-entropy over cosine similarity
- **Total Loss** = `MSE + 0.1 × InfoNCE`

---

### `training/train.py` — Training Loop (Entry Point)

```
python training/train.py
```

- Load HeteroData + labels + split masks from `dataset.py`
- Initialize VulnGAT model
- Optimizer: Adam, lr=1e-3
- Scheduler: ReduceLROnPlateau (patience=5)
- Early stopping: patience=10
- Max epochs: 100
- Per epoch:
  1. Forward pass on train graph → get predictions
  2. Compute MSE loss on train Package nodes
  3. Compute InfoNCE loss via edge dropout augmentation
  4. Total loss = MSE + 0.1 × InfoNCE
  5. Backward + optimizer step
  6. Evaluate on val split → val loss
  7. Scheduler step on val loss
  8. Early stopping check
- Save best model to `models/vulngat_trained.pt`
- Print training curves (loss, MAE per epoch)

---

### `training/evaluate.py` — Evaluation & Metrics

- **MAE**: Mean absolute error (predicted vs VPSS)
- **Precision@10**: Top-10 highest-scored packages → check against CISA KEV list
- **Ranking Accuracy**: % of (high-risk, low-risk) pairs correctly ordered
- **Spearman ρ**: Rank correlation between predictions and VPSS
- CISA KEV ground truth packages (hardcoded from design doc):
  - `log4j-core`, `event-stream`, `ua-parser-js`, `node-ipc`, `minimist`, `lodash`, `handlebars`, `colors`
- Report metrics on val and test splits separately

---

## Step 3 — Execution Order

| # | Action | Time Estimate |
|---|--------|---------------|
| 1 | Create venv + install dependencies | ~5–10 min |
| 2 | Write all 6 Python files | ~15 min |
| 3 | Test graph loading + HeteroData conversion | ~1 min |
| 4 | Run training (`python training/train.py`) | ~10–30 min on RTX 3050 |
| 5 | Evaluate on test split | ~1 min |
| 6 | Save `vulngat_trained.pt` | Automatic |

---

## Verification Plan

### Automated
- Graph loads correctly: assert node counts (5578 Package, 326 CVE, 2035 Author)
- Edge counts match: assert 16077 + 701 + 4333 + 701 = 21812
- No NaN in features or labels
- Model output shape: `[num_package_nodes]`, all values in [0, 1]
- Training loss decreases monotonically in early epochs
- Val loss tracked + early stopping triggers

### Manual
- Review training curves for convergence
- Check Precision@10 — does VulnGAT rank known-vulnerable packages high?
- Inspect top-10 and bottom-10 predictions for sanity

---

## Open Questions

> [!IMPORTANT]
> **CVE feature dimension**: The design doc says CVE nodes are 768-dim (SentenceBERT only). But the graph metadata says `"768 (SentenceBERT) + 1 CVSS score"`. I'll use **769-dim** (768 embedding + 1 CVSS) since that's what the actual data contains. This doesn't contradict the design — it's just the CVSS appended.

> [!NOTE]
> **Graph is one big graph (9 repos merged)**, not 9 separate graphs. The repo-level split will be done via **node masks** — we mask which Package nodes belong to which split during loss computation and evaluation. The full graph structure is still used for message passing (this is standard in transductive GNN training).
