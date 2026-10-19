# VulnChain

VulnChain is an automated supply chain vulnerability propagation and risk ranking pipeline powered by heterogeneous graph neural networks (VulnGAT-HR).

## Architecture & Structure
- `data_pipeline/`: Data collection, OSV and npm scraping, author extraction, and heterogeneous graph construction pipeline (Phases 1-3).
- `TrainModel/`: Core model definition, heterogeneous GNN layers (`vulngat.py`, `layers.py`, `loss.py`), training loops, and evaluation metrics.
- `phase4/`: 51-repo dataset, VPSS labels, reconciled comparison, and Colab experiment outputs.
- `phase5/`: Defect-corrected protocol execution (`v2dc`), EPSS arms integration, multi-seed masked edge audit, ablation studies, and HR validation benchmarks.
- `webapp/`: Interactive vulnerability ranking dashboard with Python backend and React/Vite frontend.
- `docs/` & `presentations/`: Design documentation, research papers, and presentations.

## Regenerating Large Files

Due to repository size constraints and GitHub best practices, single files exceeding 50MB are excluded from version control:

### 1. `phase5/v2dc_checkpoints.zip` (~71.08 MB)
- **Description:** Contains the 20 defect-corrected model checkpoints (`v2dc_full_v2_p{10,30,50}_s{42,123,456,789,1024}.pt`) across all seeds and masking fractions.
- **How to Rebuild:**
  1. Generate the Colab rerun notebook:
     ```bash
     python phase5/generate_v2_notebook_rerun.py
     ```
  2. Package the Colab dataset bundle:
     ```bash
     python phase5/build_v2_colab_zip.py
     ```
  3. Execute `phase5/vulngat_v2_training_rerun.ipynb` in Google Colab (GPU runtime). The final cells train all seed configurations, validate against pre-flight gates, and zip the output checkpoints to `v2dc_checkpoints.zip`.
