"""
Frozen advisory source + frozen model-score lookup for the proof CLI.

The advisory source is exactly what phase5/bench_run/analyze_project.py uses
offline: KB hasVulnerability edges + osv_cache.json cve_id entries.
No model is run here; see PROOF_PROTOCOL.md sections 0.1 and 1.1.
"""
from __future__ import annotations

import glob
import json
from collections import defaultdict
from pathlib import Path

KB_REL = "phase5/bench_run/vulnchain_graph.json"
CACHE_REL = "phase5/bench_run/osv_cache.json"
HYBRID_GATE_REL = "phase5/HYBRID_GATE.md"
CONFIRM_METRICS_REL = "phase5/confirm_metrics.json"


def offline_advisories(root: Path):
    """pid -> sorted list of advisory IDs (ADV_OFF). Empty entries omitted."""
    m = defaultdict(set)
    kb = json.loads((root / KB_REL).read_text(encoding="utf-8"))
    for edge in kb.get("edges", {}).get("hasVulnerability", []):
        src, tgt = edge.get("source"), edge.get("target")
        if src and tgt:
            m[src].add(tgt)
    cache = json.loads((root / CACHE_REL).read_text(encoding="utf-8"))
    for pid, entry in cache.items():
        cid = (entry or {}).get("cve_id")
        if cid:
            m[pid].add(cid)
    return {pid: sorted(ids) for pid, ids in m.items() if ids}


def frozen_report_files(root: Path):
    files = [root / "phase5/bench_run/bench_results_hr.json"]
    files += [Path(p) for p in sorted(glob.glob(str(root / "phase5/bench_run/hr_*_lock.json")))]
    files += [Path(p) for p in sorted(glob.glob(str(root / "phase5/demo/vc_*.json")))]
    return [p for p in files if p.exists()]


def model_scores(root: Path):
    """pid -> frozen VulnGAT-HR risk_score, first match in fixed file order wins."""
    scores = {}
    for p in frozen_report_files(root):
        data = json.loads(p.read_text(encoding="utf-8"))
        for row in data.get("packages", []) or []:
            pid, score = row.get("package"), row.get("risk_score")
            if pid and pid not in scores and isinstance(score, (int, float)):
                scores[pid] = float(score)
    return scores
