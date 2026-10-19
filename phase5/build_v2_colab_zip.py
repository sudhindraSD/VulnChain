"""
build_v2_colab_zip.py -- Packages all required data files for VulnGAT v2 Colab execution.
Produces phase5/vulngat_v2_colab_data.zip.
"""

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZIP_OUT = ROOT / "phase5" / "vulngat_v2_colab_data.zip"

FILES_TO_PACK = [
    ("phase5/bench_run/vulnchain_graph.json", "phase5/bench_run/vulnchain_graph.json"),
    ("phase5/epss_labels_51repo.json", "phase5/epss_labels_51repo.json"),
    ("phase4/vpss_labels_51repo.json", "phase4/vpss_labels_51repo.json"),
    ("phase4/repo_split_mapping_51repo.json", "phase4/repo_split_mapping_51repo.json"),
    (".osv_records_cache.json", ".osv_records_cache.json"),
]

print(f"Building {ZIP_OUT}...")
with zipfile.ZipFile(ZIP_OUT, "w", zipfile.ZIP_DEFLATED) as zf:
    for src_rel, arc_name in FILES_TO_PACK:
        src_path = ROOT / src_rel
        if not src_path.exists():
            raise FileNotFoundError(f"Missing required data file: {src_path}")
        print(f"  Adding {src_rel} -> {arc_name} ({src_path.stat().st_size / 1024 / 1024:.2f} MB)")
        zf.write(src_path, arc_name)

zip_size_mb = ZIP_OUT.stat().st_size / 1024 / 1024
print(f"[OK] Successfully built {ZIP_OUT} ({zip_size_mb:.2f} MB)")
