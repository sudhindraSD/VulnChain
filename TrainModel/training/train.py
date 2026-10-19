"""
training/train.py — Main Training Pipeline for VulnGAT

Executes the training loop per VULNCHAIN_DESIGN_v1.0.md:
- 3-Layer HAN model (VulnGAT, 128 hidden dim)
- Total Loss = MSE + 0.1 * InfoNCE (Edge dropout p=0.2)
- Adam optimizer (lr=1e-3), ReduceLROnPlateau (patience=5)
- Early stopping (patience=10 epochs on validation loss)
- Saves best model state dict to models/vulngat_trained.pt
- Evaluates on Train, Validation, and Test sets with CISA KEV benchmark
"""

import os
import sys
import time
import torch
from torch.optim.lr_scheduler import ReduceLROnPlateau

# Add project root to sys.path to enable core imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.model.vulngat import VulnGAT
from core.model.loss import VulnChainLoss
from training.dataset import load_vulnchain_dataset
from training.evaluate import evaluate_model


def train():
    print("=" * 70)
    print("VulnChain -- VulnGAT Training Pipeline (Stage 5)")
    print("=" * 70)

    # 1. Device Setup
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        vram_mb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 2)
        print(f"Device: CUDA ({gpu_name} -- {vram_mb:.0f} MB VRAM)")
    else:
        print("Device: CPU (CUDA not available)")

    # 2. Load Dataset
    data, mappings, masks = load_vulnchain_dataset(
        graph_path=os.environ.get("GRAPH_FILE", "vulnchain_graph.json"),
        labels_path=os.environ.get("LABELS_FILE", "vpss_labels.json"),
        repo_split_path=os.environ.get("REPO_SPLIT_FILE", "repo_split_mapping.json"),
        train_ratio=0.8,
        val_ratio=0.1,
        test_ratio=0.1,
        seed=42
    )

    train_mask = masks["train_mask"].to(device)
    val_mask = masks["val_mask"].to(device)
    test_mask = masks["test_mask"].to(device)

    # 3. Instantiate Model & Loss
    print("\nInitializing VulnGAT (3-layer HAN, 128-dim hidden, separate edge matrices)...")
    model = VulnGAT(
        hidden_dim=128,
        num_layers=3,
        num_heads=4,
        dropout=0.3
    ).to(device)

    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total trainable parameters: {total_params:,} (~{total_params * 4 / 1024:.1f} KB)")

    criterion = VulnChainLoss(
        infonce_weight=0.1,
        edge_drop_rate=0.2,
        temperature=0.5
    )

    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    scheduler = ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=5, min_lr=1e-5)

    # 4. Training Loop with Early Stopping
    max_epochs = 100
    patience = 10
    best_val_loss = float("inf")
    patience_counter = 0
    best_model_state = None

    model_save_path = os.environ.get("MODEL_SAVE_PATH", "models/vulngat_trained.pt")
    os.makedirs(os.path.dirname(model_save_path) or ".", exist_ok=True)

    print("\n" + "-" * 70)
    print(f"{'Epoch':<8}{'Train Loss':<14}{'MSE':<12}{'InfoNCE':<12}{'Val Loss':<12}{'Val MAE':<10}{'LR':<10}")
    print("-" * 70)

    start_time = time.time()

    for epoch in range(1, max_epochs + 1):
        model.train()
        optimizer.zero_grad()

        # Prepare device tensors
        x_dict = {ntype: data[ntype].x.to(device) for ntype in data.node_types}
        edge_index_dict = {
            (src, rel, tgt): data[src, rel, tgt].edge_index.to(device)
            for src, rel, tgt in data.edge_types
        }
        train_labels = data["Package"].y.to(device)

        # Forward pass
        predictions = model(x_dict, edge_index_dict)

        # Compute Loss (MSE on train Package nodes + InfoNCE across graph)
        total_loss, mse_loss, infonce_loss = criterion(
            model=model,
            predictions=predictions,
            labels=train_labels,
            x_dict=x_dict,
            edge_index_dict=edge_index_dict,
            mask=train_mask
        )

        total_loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()

        # Validation Pass
        model.eval()
        with torch.no_grad():
            val_preds = model(x_dict, edge_index_dict)
            val_mse = torch.nn.functional.mse_loss(
                val_preds[val_mask], train_labels[val_mask]
            ).item()
            val_mae = torch.mean(
                torch.abs(val_preds[val_mask] - train_labels[val_mask])
            ).item()

        current_lr = optimizer.param_groups[0]["lr"]
        scheduler.step(val_mse)

        print(
            f"{epoch:<8}{total_loss.item():<14.5f}{mse_loss.item():<12.5f}"
            f"{infonce_loss.item():<12.5f}{val_mse:<12.5f}{val_mae:<10.4f}{current_lr:<10.2e}"
        )

        # Early Stopping Check
        if val_mse < best_val_loss:
            best_val_loss = val_mse
            patience_counter = 0
            best_model_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"\n[!] Early stopping triggered at epoch {epoch} (no val improvement for {patience} epochs).")
                break

    train_duration = time.time() - start_time
    print(f"\nTraining completed in {train_duration:.2f} seconds ({train_duration / 60:.2f} min).")

    # 5. Save Best Model
    if best_model_state is not None:
        torch.save(best_model_state, model_save_path)
        model.load_state_dict(best_model_state)
        print(f"Saved best model weights to: {model_save_path} (Val MSE: {best_val_loss:.5f})")

    # 6. Final Evaluation
    print("\n" + "=" * 70)
    print("Final Model Evaluation (CISA KEV Benchmark)")
    print("=" * 70)

    pkg_ids = [mappings["idx_to_pkg_id"][i] for i in range(len(mappings["idx_to_pkg_id"]))]

    train_eval = evaluate_model(model, data, masks["train_mask"], pkg_ids, device, k=10)
    val_eval = evaluate_model(model, data, masks["val_mask"], pkg_ids, device, k=10)
    test_eval = evaluate_model(model, data, masks["test_mask"], pkg_ids, device, k=10)

    print("\n| Metric              | Train Split | Val Split   | Test Split  |")
    print("|---------------------|-------------|-------------|-------------|")
    print(f"| MAE                 | {train_eval['mae']:<11.4f} | {val_eval['mae']:<11.4f} | {test_eval['mae']:<11.4f} |")
    print(f"| Spearman rho (r)    | {train_eval['spearman_rho']:<11.4f} | {val_eval['spearman_rho']:<11.4f} | {test_eval['spearman_rho']:<11.4f} |")
    print(f"| Ranking Accuracy    | {train_eval['ranking_accuracy'] * 100:<10.2f}% | {val_eval['ranking_accuracy'] * 100:<10.2f}% | {test_eval['ranking_accuracy'] * 100:<10.2f}% |")
    print(f"| Precision@10 (KEV)  | {train_eval['precision_at_k'] * 100:<10.2f}% | {val_eval['precision_at_k'] * 100:<10.2f}% | {test_eval['precision_at_k'] * 100:<10.2f}% |")

    print("\n" + "-" * 70)
    print("Top-10 Highest Risk Predictions on Test Split:")
    print("-" * 70)
    for res in test_eval["top_k_packages"]:
        kev_badge = " [CISA KEV] " if res["in_cisa_kev"] else "            "
        print(f"  #{res['rank']:<2} | Risk: {res['risk_score']:.4f} | {res['package']:<35}{kev_badge}")

    print("\n" + "=" * 70)
    print("[SUCCESS] Stage 5 Training Complete! vulngat_trained.pt is ready for deployment.")
    print("=" * 70)


if __name__ == "__main__":
    train()
