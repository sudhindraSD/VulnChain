"""
build_colab_package.py — Builds the Colab deliverable (Phase 4 worker)

1. colab/VULNCHAIN_PHASE4_COLAB.ipynb  — always built
2. vulnchain_phase4_colab.zip          — built only when phase4/vulnchain_graph.json
                                          and phase4/vpss_labels_51repo.json exist
                                          (i.e., after pipeline steps B4/B5)

The zip contains the model code, the 9-repo smoke artifacts, and the Phase-4
51-repo data artifacts. The notebook runs: Phase A smoke -> C1 training ->
non-zero-only metrics -> C2 masked-edge audit -> C3 NodeTestBench -> C4 MLP
baseline -> results download.
"""

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLAB_DIR = ROOT / "colab"

CELLS = []

def md(src):
    CELLS.append({"cell_type": "markdown", "metadata": {}, "source": src})

def code(src):
    CELLS.append({"cell_type": "code", "metadata": {}, "execution_count": None,
                  "outputs": [], "source": src})

md("""# VulnChain Phase 4 — Colab Training & Evaluation (GPU)

**Worker notebook** generated from `WORKER_ORDERS_PHASE4.md`. Run cells top-to-bottom.

1. **Runtime → Change runtime type → GPU** (T4 is fine).
2. Run the setup cell and upload `vulnchain_phase4_colab.zip` when prompted
   (or put the zip in Google Drive and mount/extract it instead).
3. **Phase A** is a SMOKE TEST (plumbing check, *not* a result).
   **Phase C** produces the real 51-repo numbers — report them honestly, no
   post-hoc threshold tuning (pre-registered caveat in `CURRENT_CONTEXT.md` §10.3).""")

code("""import os, subprocess, sys

if not os.path.exists("/content/vulnchain"):
    try:
        from google.colab import files
        print("Upload vulnchain_phase4_colab.zip:")
        up = files.upload()
        subprocess.run(["unzip", "-o", "-q", list(up.keys())[0], "-d", "/content/vulnchain"], check=True)
    except ModuleNotFoundError:
        raise RuntimeError("Not on Colab and /content/vulnchain missing — extract the zip manually.")
os.chdir("/content/vulnchain")
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "torch_geometric"], check=True)
import torch
assert torch.cuda.is_available(), "NO GPU — Runtime > Change runtime type > GPU, then rerun."
print("GPU:", torch.cuda.get_device_name(0), "| torch:", torch.__version__)""")

md("""## Phase A — 9-Repo Corrected-Split SMOKE RETRAIN

**SMOKE TEST, NOT A RESULT.** Verifies the corrected (leak-free) split plugs into the
training stack cleanly. Expected: Train 4,487 / Val 696 / Test 395, test vulnerable = 24,
0 dropped IDs. Metrics will be noisy (24 non-zero test labels) — that is expected and
must NOT be recorded as a held-out result anywhere.""")

code('''def run(cmd, env_extra=None, cwd=None, log_path=None):
    """Run a subprocess, capture output, persist log, print tail."""
    env = dict(os.environ, **(env_extra or {}))
    r = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True)
    out = r.stdout + ("\\n[STDERR]\\n" + r.stderr if r.stderr.strip() else "")
    if log_path:
        open(log_path, "w").write(out)
    print(out[-6000:])
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}) — see {log_path}")
    return out

assert not os.path.exists("TrainModel/epss_labels.json"), "EPSS trap file present — STOP (Hard Rule 2)."

log = run([sys.executable, "training/train.py"],
          env_extra={"REPO_SPLIT_FILE": "repo_split_mapping_corrected_9repo.json",
                     "MODEL_SAVE_PATH": "models/vulngat_smoke_9repo_corrected.pt"},
          cwd="TrainModel", log_path="phase4/phaseA_smoke_log.txt")

assert "0 dropped (train=4487, val=696, test=395)" in log, "Split counts mismatch — STOP."
assert "Test:  395 (Vulnerable: 24)" in log, "Test vulnerable count != 24 — STOP."
assert os.path.exists("TrainModel/models/vulngat_smoke_9repo_corrected.pt"), "Smoke model not saved."
print("\\n=== PHASE A SMOKE: PASS — plumbing verified. Numbers are NOT results. ===")''')

md("""## Phase C1 — VulnGAT Training on the 51-Repo Provenance-Clean Graph

Train 10,523 / Val (practica) 541 / Test (saleor-storefront) 1,341. The domain-shift
caveat for saleor-storefront (React/Next.js frontend vs. Express backend corpus) was
**pre-registered before this run** — do not re-pick test repos or thresholds post-hoc.""")

code('''log = run([sys.executable, "TrainModel/training/train.py"],
          env_extra={"GRAPH_FILE": "phase4/vulnchain_graph.json",
                     "LABELS_FILE": "phase4/vpss_labels_51repo.json",
                     "REPO_SPLIT_FILE": "phase4/repo_split_mapping_51repo.json",
                     "MODEL_SAVE_PATH": "phase4/models/vulngat_51repo.pt"},
          log_path="phase4/train_log_51repo.txt")

assert "0 dropped (train=10523, val=541, test=1341)" in log, "51-repo split mismatch — STOP."
assert os.path.exists("phase4/models/vulngat_51repo.pt"), "Model not saved."
print("\\n=== PHASE C1: TRAINING COMPLETE ===")''')

md("### C1b — Full metrics incl. non-zero-only Pearson/Spearman (statistically valid: n≈538)")

code('''import json, numpy as np, torch
sys.path.insert(0, "TrainModel")
from training.dataset import load_vulnchain_dataset
from core.model.vulngat import VulnGAT
from training.evaluate import compute_mae, compute_spearman_rho, compute_ranking_accuracy

data, mappings, masks = load_vulnchain_dataset(
    graph_path="phase4/vulnchain_graph.json",
    labels_path="phase4/vpss_labels_51repo.json",
    repo_split_path="phase4/repo_split_mapping_51repo.json")
model = VulnGAT()
model.load_state_dict(torch.load("phase4/models/vulngat_51repo.pt",
                                 map_location="cpu", weights_only=True))
model.eval()
with torch.no_grad():
    x_dict = {nt: data[nt].x for nt in data.node_types}
    ei_dict = {(s, r, t): data[s, r, t].edge_index for s, r, t in data.edge_types}
    preds = model(x_dict, ei_dict).numpy()
targs = data["Package"].y.numpy()

def pearson(a, b):
    return float(np.corrcoef(a, b)[0, 1]) if len(a) > 1 and np.std(a) > 0 and np.std(b) > 0 else 0.0

def metrics(mask):
    p, t = preds[mask.numpy()], targs[mask.numpy()]
    nz = t > 1e-9
    return {"n": int(mask.sum()), "n_nonzero": int(nz.sum()),
            "mae": compute_mae(p, t), "mse": float(np.mean((p - t) ** 2)),
            "pearson_nonzero": pearson(p[nz], t[nz]),
            "spearman_nonzero": compute_spearman_rho(p[nz], t[nz]),
            "spearman_all": compute_spearman_rho(p, t),
            "ranking_accuracy": compute_ranking_accuracy(p, t)}

out = {s: metrics(masks[s + "_mask"]) for s in ("train", "val", "test")}
json.dump(out, open("phase4/vulngat_51repo_metrics.json", "w"), indent=2)
json.dump({"pkg_ids": [mappings["idx_to_pkg_id"][i] for i in range(len(targs))],
           "predictions": preds.tolist(), "targets": targs.tolist()},
          open("phase4/test_predictions_51repo.json", "w"))
for s in ("train", "val", "test"):
    m = out[s]
    print(f"{s:>5}: MAE {m['mae']:.4f} | MSE {m['mse']:.4f} | "
          f"Pearson(nz) {m['pearson_nonzero']:.4f} (n={m['n_nonzero']}) | "
          f"Spearman(nz) {m['spearman_nonzero']:.4f} | RankAcc {m['ranking_accuracy']:.2%}")
print("\\nsaved: phase4/vulngat_51repo_metrics.json, phase4/test_predictions_51repo.json")''')

md("""## Phase C2 — Masked-Edge Robustness Audit

Package feature dim 6 (`has_known_cve_history`) is **zeroed for masked packages**
(Commandment 2 — the backdoor that invalidated the first audit is fixed in the
shipped script). Pre-registered success: model beats label propagation by **> 0.02 AUC**
at the 50% mask.""")

code('''log = run([sys.executable, "TrainModel/masked_edge_audit.py"],
          env_extra={"MODEL_PATH": "phase4/models/vulngat_51repo.pt",
                     "GRAPH_FILE": "phase4/vulnchain_graph.json",
                     "LABELS_FILE": "phase4/vpss_labels_51repo.json",
                     "REPO_SPLIT_FILE": "phase4/repo_split_mapping_51repo.json",
                     "AUDIT_OUT": "phase4/masked_edge_audit_51repo.json"},
          log_path="phase4/audit_log_51repo.txt")
print("\\n=== PHASE C2: AUDIT COMPLETE — read the OUTCOME section above ===")''')

md("""## Phase C3 — NodeTestBench OOD Benchmark (threshold LOCKED at ≥ 0.40)

Ground truth = packages with an OSV/KB-confirmed CVE (`cve` field non-null in the
inference output). **No threshold sweeps.** Report precision/recall at ≥ 0.40 only.""")

code('''import shutil, glob
os.makedirs("bench_run/models", exist_ok=True)
shutil.copy("TrainModel/analyze_project.py", "bench_run/")
shutil.copytree("TrainModel/core", "bench_run/core", dirs_exist_ok=True)  # analyze_project imports core.model
shutil.copy("phase4/vulnchain_graph.json", "bench_run/vulnchain_graph.json")
shutil.copy("phase4/models/vulngat_51repo.pt", "bench_run/models/vulngat_trained.pt")

if not os.path.exists("bench_run/NodeTestBench"):
    clone = subprocess.run(["git", "clone", "-q", "--depth", "1",
                            "https://github.com/contrast-security-oss/NodeTestBench",
                            "bench_run/NodeTestBench"])
    if clone.returncode != 0:
        print("CLONE FAILED — verify repo exists / is public")
locks = glob.glob("bench_run/NodeTestBench/**/package-lock.json", recursive=True)
print("lockfiles found:", locks)
assert locks, "No NodeTestBench lockfile found — report blocked, do not substitute another benchmark."

run([sys.executable, "analyze_project.py", os.path.abspath(locks[0]), "--json", "bench_results.json"],
    cwd="bench_run", log_path="phase4/bench_log_51repo.txt")
assert os.path.exists("bench_run/bench_results.json"), \
    "analyze_project produced no results — inspect phase4/bench_log_51repo.txt"

rows = json.load(open("bench_run/bench_results.json"))["packages"]
THR = 0.40  # pre-registered — do not sweep
tp = sum(1 for x in rows if x.get("cve") and x["risk_score"] >= THR)
fp = sum(1 for x in rows if not x.get("cve") and x["risk_score"] >= THR)
fn = sum(1 for x in rows if x.get("cve") and x["risk_score"] < THR)
prec = tp / (tp + fp) if (tp + fp) else 0.0
rec = tp / (tp + fn) if (tp + fn) else 0.0
print(f"N={len(rows)} | flagged >= {THR}: {tp + fp} | TP {tp} | FP {fp} | FN {fn}")
print(f"Precision@{THR}: {prec:.2%} | Recall@{THR}: {rec:.2%}")
json.dump({"threshold": THR, "n": len(rows), "tp": tp, "fp": fp, "fn": fn,
           "precision": prec, "recall": rec},
          open("phase4/nodetestbench_51repo.json", "w"), indent=2)
print("saved: phase4/nodetestbench_51repo.json")''')

md("""## Phase C4 — Feature-Only MLP Baseline (NO graph input)

The circularity kill-shot: VPSS ≈ f(depth, directness), and both are readable off the
10-dim features. If the MLP matches VulnGAT, headline claims must rest on C2/C3 —
that is a finding, not a failure. Same split, same labels, same optimizer/early-stopping.""")

code('''run([sys.executable, "phase4/mlp_baseline.py"],
    env_extra={"GRAPH_FILE": "phase4/vulnchain_graph.json",
               "LABELS_FILE": "phase4/vpss_labels_51repo.json",
               "REPO_SPLIT_FILE": "phase4/repo_split_mapping_51repo.json",
               "MLP_OUT": "phase4/mlp_baseline_results_51repo.json"},
    log_path="phase4/mlp_log_51repo.txt")

mlp = json.load(open("phase4/mlp_baseline_results_51repo.json"))
gnn = json.load(open("phase4/vulngat_51repo_metrics.json"))
print(f"{'metric (TEST split)':<24}{'VulnGAT':>12}{'MLP (no graph)':>16}")
for k, label in [("mae", "MAE"), ("mse", "MSE"), ("pearson_nonzero", "Pearson(nz)"),
                 ("spearman_nonzero", "Spearman(nz)"), ("ranking_accuracy", "RankAcc")]:
    print(f"{label:<24}{gnn['test'][k]:>12.4f}{mlp['test'][k]:>16.4f}")
print("\\nIf MLP ≈ GNN on these, the GNN's value must be argued from C2/C3, not VPSS fit.")''')

md("## Download all Phase-4 results")

code('''subprocess.run("zip -rq phase4_results.zip phase4 TrainModel/models/vulngat_smoke_9repo_corrected.pt -x *__pycache__*",
               shell=True, check=True)
from google.colab import files
files.download("phase4_results.zip")
print("Hand phase4_results.zip back to the Brain together with WORKER_REPORT_PHASE4.md updates.")''')


def build_notebook():
    COLAB_DIR.mkdir(exist_ok=True)
    nb = {
        "nbformat": 4, "nbformat_minor": 0,
        "metadata": {"colab": {"provenance": []},
                     "kernelspec": {"name": "python3", "display_name": "Python 3"},
                     "accelerator": "GPU"},
        "cells": CELLS,
    }
    out = COLAB_DIR / "VULNCHAIN_PHASE4_COLAB.ipynb"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1)
    print(f"wrote {out} ({len(CELLS)} cells)")


ZIP_CODE_FILES = [
    "TrainModel/core/__init__.py",
    "TrainModel/core/model/__init__.py",
    "TrainModel/core/model/vulngat.py",
    "TrainModel/core/model/layers.py",
    "TrainModel/core/model/loss.py",
    "TrainModel/training/__init__.py",
    "TrainModel/training/dataset.py",
    "TrainModel/training/train.py",
    "TrainModel/training/evaluate.py",
    "TrainModel/masked_edge_audit.py",
    "TrainModel/analyze_project.py",
    "TrainModel/vulnchain_graph.json",
    "TrainModel/vpss_labels.json",
    "TrainModel/repo_split_mapping_corrected_9repo.json",
    "phase4/repo_split_mapping_51repo.json",
    "phase4/vulnchain_graph.json",
    "phase4/vpss_labels_51repo.json",
    "phase4/mlp_baseline.py",
]

def build_zip():
    missing = [rel for rel in ZIP_CODE_FILES if not (ROOT / rel).exists()]
    if missing:
        print(f"zip SKIPPED — still missing (run B4/B5 first): {missing}")
        return
    out = ROOT / "vulnchain_phase4_colab.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.write(COLAB_DIR / "VULNCHAIN_PHASE4_COLAB.ipynb", "VULNCHAIN_PHASE4_COLAB.ipynb")
        for rel in ZIP_CODE_FILES:
            z.write(ROOT / rel, rel)
    print(f"wrote {out} ({out.stat().st_size / 1024 / 1024:.1f} MB)")


if __name__ == "__main__":
    build_notebook()
    build_zip()
