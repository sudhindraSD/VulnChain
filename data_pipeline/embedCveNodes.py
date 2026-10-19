"""
VulnChain — CVE node embedding generator
Reads cve_nodes.json (from osv_record_fetcher.py), runs each node's
text_for_embedding through SentenceBERT, and writes out CVE nodes with
the full 768-dim embedding attached — ready to merge into the graph.

Uses 'all-mpnet-base-v2' — 768-dim output, matches your locked architecture
(CVE node = 768-dim SentenceBERT, frozen). Model is frozen (no fine-tuning,
just inference) per your design.

Run locally:  pip install sentence-transformers
              python embed_cve_nodes.py
"""

import json
from sentence_transformers import SentenceTransformer

INPUT_FILE = "cve_nodes.json"
OUTPUT_FILE = "cve_nodes_embedded.json"
MODEL_NAME = "all-mpnet-base-v2"  # 768-dim output


def main():
    with open(INPUT_FILE) as f:
        nodes = json.load(f)

    print(f"Loaded {len(nodes)} CVE nodes")
    print(f"Loading {MODEL_NAME} (frozen, inference only)...")
    model = SentenceTransformer(MODEL_NAME)

    texts = [n["text_for_embedding"] or n["id"] for n in nodes]
    # fallback to the ID itself only in the pathological case text is empty —
    # you confirmed 0 vague IDs so this shouldn't trigger, just a safety net

    print(f"Encoding {len(texts)} texts...")
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)

    for node, emb in zip(nodes, embeddings):
        node["embedding"] = emb.tolist()  # 768-dim list, JSON-serializable

    with open(OUTPUT_FILE, "w") as f:
        json.dump(nodes, f)  # no indent — 326 x 768 floats is large, keep it compact

    dim = len(nodes[0]["embedding"])
    print()
    print("=== Done ===")
    print(f"Embedded {len(nodes)} CVE nodes, dim={dim}")
    print(f"-> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()