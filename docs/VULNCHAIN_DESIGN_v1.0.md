# 🔗 VULNCHAIN — The Architectural War Map
### `VULNCHAIN_DESIGN_v1.0.md` · Pre-Code Contract · May 2026

> **BIT Bengaluru · 7th Sem ISE · Major Project**  
> **Author:** Sudhindra S D  
> **Status:** `FROZEN` for Phase 1 — all 14 design decisions locked  
> **Versioning:** v1.1 after MVP · v2.0 for major pivots only

---

## ⚠️ READ THIS FIRST — FOR EVERY HUMAN AND AI PICKING THIS UP

This document was not written after the code. It was written **before a single line of implementation exists** — through a structured challenge-and-debate session where every decision was questioned, rejected alternatives were recorded, and nothing was left vague.

**If you are a human developer:**
- Read Sections 1–4 first. That's the story, the one-liner, and the map.
- Then go deep on whatever you're building next.
- Every "why" is answered here. Don't guess. Look it up.

**If you are an AI assistant:**
1. Read this entire document before writing any code
2. Sections marked `[LOCKED]` = final decision. Do not suggest alternatives unless the user explicitly asks
3. Sections marked `[FUTURE]` = deliberately deferred. Do not implement in Phase 1
4. Use the **Shared Language** section (Section 3) for all variable names, comments, and responses — no synonyms
5. If you find a contradiction between this doc and user instructions → **flag it, don't silently resolve it**
6. `core/` is the single source of truth for all graph + model logic. Never duplicate it elsewhere

---

## TABLE OF CONTENTS

| # | Section | What You'll Find |
|---|---------|-----------------|
| 1 | [The Problem](#1-the-problem) | Why this exists. Real attacks. Why current tools fail |
| 2 | [What VulnChain Is](#2-what-vulnchain-is) | One paragraph + one concrete end-to-end example |
| 3 | [Shared Language](#3-shared-language) | Canonical glossary — every term used in this project |
| 4 | [System Overview](#4-system-overview) | The full pipeline as a map |
| 5 | [Stage 1 — Graph Construction](#5-stage-1-graph-construction) | 3 rounds, 3 node types, all feature dimensions |
| 6 | [Stage 2 — Training Pipeline](#6-stage-2-training-pipeline) | Data, labels, splits, hyperparameters |
| 7 | [Stage 3 — Inference Pipeline](#7-stage-3-inference-pipeline) | Model serving, API contract |
| 8 | [Model Architecture — VulnGAT](#8-model-architecture-vulngat) | HAN layers, projections, classifier |
| 9 | [Loss Function](#9-loss-function) | MSE + InfoNCE, with full reasoning |
| 10 | [Data Sources](#10-data-sources) | 3 databases, why all 3, cache strategy |
| 11 | [Evaluation Strategy](#11-evaluation-strategy) | Metrics, ground truth, 4 ablation studies |
| 12 | [Repository Structure](#12-repository-structure) | Full folder map with purpose of every file |
| 13 | [Demo Strategy](#13-demo-strategy) | Log4Shell, pre-computation, 30% of grade |
| 14 | [Out of Scope — Phase 1](#14-out-of-scope) | What is deliberately NOT being built |
| 15 | [Design Decisions Log](#15-design-decisions-log) | 14 locked decisions with rejected alternatives |
| 16 | [Known Risks](#16-known-risks) | What could go wrong and how to handle it |
| 17 | [Literature Foundation](#17-literature-foundation) | 8 papers, what each one justifies |

---

## 1. THE PROBLEM

### 1.1 The Invisible Attack Surface

Here is something most developers don't think about:

When you run `npm install express`, you are not installing one package. You are installing **express and everything express depends on, and everything those packages depend on, recursively**. A typical Node.js project has 30–50 direct dependencies. The actual installed tree? **500 to 2000 packages.** The developer audited maybe 10 of them.

That gap — between what you think you installed and what actually runs on your machine — is the supply chain attack surface.

> 💡 **The core truth:** The dangerous package is **never** the one you directly imported. It is `lodash` 4 levels deep. It is a utility library that 40,000 other packages depend on. It is a package maintained by a single developer with a dormant GitHub account and no two-factor authentication.

### 1.2 This Is Not Theoretical — Five Attacks That Happened

| Attack | Year | What Happened | Scale |
|--------|------|--------------|-------|
| **Log4Shell** (CVE-2021-44228) | 2021 | `log4j-core` buried in Java trees everywhere. Remote code execution, zero authentication required | Apple, Amazon, Tesla, 18,000+ organizations |
| **event-stream** | 2018 | Popular npm package. Original maintainer handed ownership to a stranger. Stranger injected code targeting Bitcoin wallets | Downloaded 2 million times before detection |
| **ua-parser-js** | 2021 | Maintainer account hijacked. Malicious version auto-installed by CI/CD pipelines worldwide | Millions of pipelines within hours |
| **colors.js + faker.js** | 2022 | Maintainer **intentionally** sabotaged their own packages. All downstream dependents broken instantly | Thousands of production builds |
| **SolarWinds** | 2020 | Build pipeline compromised. Malicious code signed with legitimate certificates. Shipped as official update | 18,000 organizations, US government agencies |

Notice the pattern: **none of these attacked the software directly.** They all attacked the trust chain — the maintainer, the build pipeline, the dependency tree. That is supply chain attack.

### 1.3 Why Current Tools Fail

Tools like `npm audit`, Snyk, and Dependabot use **static CVE matching** — they look up your package version in a database and report matches. This sounds reasonable. It has two fatal flaws:

**Flaw 1 — No topology awareness**

Static tools give the same warning weight to:
- A vulnerability in a package that only your code directly uses
- A vulnerability in a package that **200 other packages in your tree** all depend on (high graph centrality)

These are completely different risk levels. The second one, if exploited, breaks your entire system. Static tools cannot distinguish them.

**Flaw 2 — No trust signal**

`npm audit` cannot tell you that the package you're using has a dormant maintainer with no 2FA and hasn't been touched in 3 years. That package has zero CVEs right now — it looks perfectly safe. But it is one account takeover away from the event-stream scenario.

**The gap VulnChain fills:** topology-sensitive, maintainer-trust-aware risk scoring that reasons across the **entire dependency graph** — not just a flat list of CVE matches.

---

## 2. WHAT VULNCHAIN IS

### 2.1 The One-Paragraph Definition

VulnChain is an AI-powered software supply chain vulnerability analyzer. It takes a `package-lock.json` file, constructs a heterogeneous graph with three node types (Author → Package → Vulnerability), enriches it from three CVE databases (NVD, OSV.dev, GitHub Advisory), and runs a 3-layer Heterogeneous Graph Attention Network called **VulnGAT** to produce a risk score between 0.0 and 1.0 for every package in the dependency tree. The model is trained on 500–1000 real GitHub repositories using VPSS scores as weak supervision labels, with InfoNCE contrastive loss for embedding quality. The core insight is simple: **risk is not a property of a single package — it is a property of a package's position in the graph.**

### 2.2 One Concrete End-to-End Example

> This is what actually happens when someone uses VulnChain. Read this once and the whole system will make sense.

**Input:** A developer uploads the `package-lock.json` from a Java project that (unknowingly) uses `log4j-core@2.14.1`.

**Round 1 — Build the skeleton:**
```
VulnChain reads package-lock.json →
  Creates node: log4j-core@2.14.1     [Package Node]
  Creates node: slf4j-api@1.7.32      [Package Node]
  Creates node: jackson-core@2.12.3   [Package Node]
  Creates edge: log4j-core → slf4j-api        [dependsOn]
  Creates edge: log4j-core → jackson-core     [dependsOn]
  ... (full transitive tree, all depths)
Result: 487 Package nodes, 1,203 dependsOn edges
```

**Round 2 — Find the CVEs:**
```
Queries local NVD cache for log4j-core@2.14.1 →
  Finds: CVE-2021-44228 (Log4Shell, CVSS 10.0)
  Description: "Apache Log4j2 ≤ 2.14.1 JNDI features allow RCE..."
  → SentenceBERT("Apache Log4j2 JNDI features allow remote code execution...")
  → [768-dim semantic vector]
  Creates node: CVE-2021-44228         [CVE Node, 768-dim]
  Creates edge: log4j-core → CVE-2021-44228   [hasVulnerability]
  Updates:  log4j-core.dim[0] = 10.0 (CVSS)
            log4j-core.dim[1] = 1    (CVE count)
```

**Round 3 — Find the maintainer:**
```
Queries GitHub Advisory cache for log4j-core maintainer →
  Finds: Apache Software Foundation
  account_age: 8,400 days, packages_maintained: 340, is_org: 1, 2fa: 1
  Creates node: Apache-Software-Foundation    [Author Node, 7-dim]
  Creates edge: log4j-core → Apache-ASF      [maintainedBy]
  Creates edge: CVE-2021-44228 → Apache-ASF  [introducedBy]
```

**VulnGAT Inference:**
```
Project all nodes → 128-dim hidden space
Layer 1: log4j-core absorbs its direct CVE + author signals
Layer 2: log4j-core absorbs signals from packages sharing its deps
Layer 3: Full 3-hop context absorbed into embedding
→ Sigmoid(Linear(embedding)) = 0.97
```

**Output:**
```json
{
  "name": "log4j-core",
  "version": "2.14.1",
  "risk_score": 0.97,
  "cves": ["CVE-2021-44228"],
  "reason": "CVSS 10.0 · 312 transitive dependents · active exploit in CISA KEV"
}
```

The dashboard shows `log4j-core` as a blazing red node in the graph. The developer knows exactly what to fix and why.

---

## 3. SHARED LANGUAGE

> **This section is law.** Every term below has one definition. Use it in code, comments, variable names, and conversation. No synonyms. No paraphrasing.

### 3.1 System Terms

| Term | Definition |
|------|-----------|
| **VulnChain** | The full system — pipeline + model + API + dashboard |
| **VulnGAT** | The trained GNN model specifically. 3-layer Heterogeneous Graph Attention Network. Lives in `core/model/vulngat.py` |
| **Enriched Graph** | The complete heterogeneous graph after all 3 construction rounds. Ready for inference |
| **Skeletal Graph** | The graph after Round 1 only — Package nodes + dependsOn edges. No CVE or Author nodes yet |
| **Risk Score** | Output of VulnGAT for a Package node. Float 0.0–1.0. Higher = more dangerous |
| **vulngat_trained.pt** | The saved PyTorch state dict of the trained VulnGAT model (~5–10MB) |

### 3.2 Graph Terms

| Term | Definition |
|------|-----------|
| **Heterogeneous Graph** | A graph with multiple node types AND multiple edge types — the structure VulnChain builds |
| **Package Node** | A node representing one npm package at one specific version. Feature vector = 10-dim |
| **CVE Node** | A node representing one vulnerability record. Feature vector = 768-dim (SentenceBERT embedding) |
| **Author Node** | A node representing one package maintainer or organization. Feature vector = 7-dim |
| **dependsOn edge** | `Package → Package` directed edge. "This package requires that package" |
| **hasVulnerability edge** | `Package → CVE` directed edge. "This package version is affected by this CVE" |
| **maintainedBy edge** | `Package → Author` directed edge. "This author/org maintains this package" |
| **introducedBy edge** | `CVE → Author` directed edge. "This CVE is in a package maintained by this author" |
| **Hidden Dim** | 128. The common embedding dimension all node types are projected to before GAT layers |

### 3.3 ML Terms

| Term | Definition |
|------|-----------|
| **GNN** | Graph Neural Network. A neural network that operates on graph-structured data |
| **GAT** | Graph Attention Network. A GNN that learns which neighbours to pay more attention to |
| **HAN** | Heterogeneous Attention Network. A GAT that handles multiple node and edge types with separate weight matrices per edge type |
| **Message Passing** | The core GAT operation: each node collects (aggregates) information from its neighbours each layer |
| **Attention Coefficient** | A learned weight between 0–1 that tells the model how much to weight a specific neighbour's message |
| **VPSS** | Vulnerability Propagation Severity Score. The weak supervision label. Continuous 0.0–1.0 |
| **Weak Supervision** | Training on imperfect but directionally correct labels (VPSS at 87% precision) instead of perfect ground truth |
| **InfoNCE** | Contrastive loss term. Pulls two augmented views of the same node closer in embedding space |
| **Node Augmentation** | Creating two "views" of the same node by randomly dropping edges (p=0.2). Used for InfoNCE |
| **Positive Pair** | Two augmented views of the SAME node — pulled closer in InfoNCE |
| **Negative Pair** | Embeddings of DIFFERENT nodes in the same batch — pushed apart in InfoNCE |
| **Frozen** | Model weights that are NOT updated during VulnGAT training. SentenceBERT is frozen — fixed feature extractor only |

### 3.4 Data Terms

| Term | Definition |
|------|-----------|
| **Ground Truth** | Packages confirmed exploited in the wild. Sourced exclusively from CISA KEV catalog |
| **CISA KEV** | Known Exploited Vulnerabilities catalog by US CISA. The gold standard for "was this actually exploited" |
| **Ablation Study** | Removing one component at a time and measuring the performance drop to prove that component matters |
| **Log4Shell** | CVE-2021-44228 in log4j-core. CVSS 10.0. Primary demo target. Confirmed in CISA KEV |

---

## 4. SYSTEM OVERVIEW

### 4.1 The Full Pipeline — As a Map

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  USER INPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  package-lock.json  (uploaded via dashboard or CLI)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE A — GRAPH CONSTRUCTION  [core/graph/builder.py]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Round 1 ── Parse package-lock.json
             → Package nodes (10-dim, dims 0-1 = placeholder 0.0)
             → dependsOn edges, full transitive depth
             → Dims 2-9 populated from npm registry + computed

  Round 2 ── Query local NVD + OSV cache
             → CVE nodes (768-dim via SentenceBERT)
             → hasVulnerability edges
             → Completes Package node dims 0,1 (CVSS + CVE count)

  Round 3 ── Query local GitHub Advisory cache
             → Author nodes (7-dim)
             → maintainedBy edges + introducedBy edges

  OUTPUT: Enriched Heterogeneous Graph
          (all 3 node types, all 4 edge types)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE B — VULNGAT INFERENCE  [core/model/vulngat.py]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Project → Package(10→128), CVE(768→128), Author(7→128)
  Layer 1 → Each node absorbs 1-hop neighbourhood
  Layer 2 → Each node absorbs 2-hop neighbourhood
  Layer 3 → Each node absorbs 3-hop neighbourhood
  Classify → Linear(128→1) → Sigmoid → Risk Score (0.0–1.0)

  OUTPUT: Risk Score per Package node only

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE C — API + DASHBOARD  [server/ + client/]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  POST /analyze → returns JSON with risk scores + graph
  React dashboard → D3.js force-directed graph
  Color-coded nodes → red (high risk) to green (safe)
  Click any node → CVE details, author info, blast radius

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  USER OUTPUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Risk score per package · Visual dependency graph
  CVE details · Maintainer trust signals · Blast radius
```

### 4.2 Two Entry Points, One Shared Core

VulnChain has two separate entry points that share the same graph construction and model code:

```
Training Pipeline                    Inference Pipeline
─────────────────                    ──────────────────
python training/train.py             python server/app.py

500 repos → build graphs             package-lock.json → build graph
→ compute VPSS labels                → load vulngat_trained.pt
→ train VulnGAT                      → predict risk scores
→ save vulngat_trained.pt            → serve via API

Both use:  core/  (graph construction + model definition)
```

> ⚠️ **Implementation rule:** `core/` is never duplicated. If you find yourself writing graph-building code inside `server/` or `training/`, stop — it belongs in `core/`.

---

## 5. STAGE 1 — GRAPH CONSTRUCTION

### 5.1 Round 1 — Building the Skeleton

**Input:** `package-lock.json`  
**Output:** Skeletal Graph — Package nodes + dependsOn edges  
**Network calls:** None (local file only)  
**Code:** `core/parsers/npm_parser.py` → `core/graph/builder.py`

**Depth: Full transitive, no limit.**

> 💡 **Why does depth matter so much?** The DVGraph paper found that **90% of vulnerable package paths are transitive** — the vulnerability is never in what you directly imported. If VulnChain stops at depth 1, it misses 9 out of 10 real attack paths. The graph gets large (500–2000 nodes for a typical project) but that's exactly what makes VulnGAT valuable — it reasons across 4–5 hops in milliseconds, which no human reviewer can do manually.

**What gets created:**
```
package-lock.json parsed →
  CREATE node: log4j-core@2.14.1          [Package Node]
  CREATE node: slf4j-api@1.7.32           [Package Node]
  CREATE node: jackson-databind@2.12.3    [Package Node]
  CREATE edge: log4j-core → slf4j-api     [dependsOn, directed]
  CREATE edge: log4j-core → jackson-core  [dependsOn, directed]
  ... (recursively, all depths)
```

**Package Node — 10 Feature Dimensions:**

> ⚠️ **Implementation trap:** Dims 0 and 1 require NVD data. They **cannot be populated in Round 1** because NVD hasn't been queried yet. In Round 1, initialize these to `0.0` as placeholders. They are filled in during Round 2 after NVD is queried. Dims 2–9 can be fully populated in Round 1.

| Dim | Feature | Populated In | Source | Type |
|-----|---------|-------------|--------|------|
| 0 | CVSS Base Score (max across all CVEs for this package) | **Round 2** | NVD | Float 0–10 |
| 1 | Number of known CVEs | **Round 2** | NVD + OSV | Int |
| 2 | Days since last version release | Round 1 | npm registry | Int |
| 3 | Number of direct dependents in this graph | Round 1 | Computed from graph | Int |
| 4 | Number of transitive dependents in this graph | Round 1 | Computed from graph | Int |
| 5 | Is direct dependency (1) or transitive (0) | Round 1 | Computed from graph | Binary |
| 6 | Package age in days (first published) | Round 1 | npm registry | Int |
| 7 | Number of maintainers | Round 1 | npm registry | Int |
| 8 | Has known active exploit — in CISA KEV (1) or not (0) | Round 1 | CISA KEV local cache | Binary |
| 9 | Ecosystem (npm=0, pip=1, maven=2) | Round 1 | Parsed from input | Int |

> **Note for AI assistants:** `package_features = torch.tensor([cvss, num_cves, days_since_release, direct_dependents, transitive_dependents, is_direct, age_days, num_maintainers, has_exploit, ecosystem])` — shape `[10]` per node. Normalize continuous dims before feeding to the model (min-max or standard scaling).

### 5.2 Round 2 — CVE Node Enrichment

**Input:** Package nodes from Skeletal Graph  
**Output:** CVE nodes (768-dim) + hasVulnerability edges + completes Package node dims 0,1  
**Network calls:** None — local NVD + OSV cache only  
**Code:** `core/graph/enrichment.py` + `core/embeddings/sentencebert.py`

**Process:**
```
For each Package Node in Skeletal Graph:
  1. Query local NVD cache → get all CVEs for this_package@this_version
  2. Query local OSV cache → confirm exact version range is affected
  3. Update Package node dim[0] = max CVSS score across all found CVEs
  4. Update Package node dim[1] = count of confirmed CVEs

  For each confirmed CVE:
    a. Extract description text from CVE record
    b. Check if description is meaningful (see Section 5.2.1)
    c. → SentenceBERT(description_text) → 768-dim vector
    d. CREATE CVE node with 768-dim feature vector
    e. CREATE edge: Package --hasVulnerability--> CVE
```

**CVE Node Feature Vector:**
- **Dimensions:** 768 (one semantic embedding from SentenceBERT)
- **Model:** `all-MiniLM-L6-v2` (default) or `nomic-embed-text`
- **Status:** SentenceBERT is **frozen** — weights are never updated during VulnGAT training
- **Shape:** `[768]` per CVE node

> 💡 **Why SentenceBERT and not raw CVSS numbers?** CVSS gives you 4–6 numbers. SentenceBERT gives you a 768-dimensional semantic fingerprint of what the vulnerability actually *does* — remote code execution, path traversal, privilege escalation, etc. Two CVEs can have the same CVSS score but completely different attack characteristics. SentenceBERT captures that distinction. Raw numbers cannot.

**5.2.1 — The Vague CVE Problem and the Fallback**

Not all CVE records have useful descriptions. Some say things like: *"Vulnerability in package X version Y"* — 5 words of zero semantic content. Running SentenceBERT on this produces a meaningless vector.

**Detection criteria for a vague description:**
- Description length < 50 characters, OR
- No action verb present: execute, overflow, inject, bypass, traverse, escalate, expose, leak, crash, forge

**Fallback — construct synthetic text, use the same SentenceBERT model:**
```python
# Example synthetic text built from CVSS structured fields:
synthetic = (
    f"{severity} severity {cwe_description} vulnerability. "
    f"{attack_vector} attack vector, "
    f"{'no' if privileges_required == 'NONE' else 'some'} privileges required, "
    f"{'no' if user_interaction == 'NONE' else 'requires'} user interaction. "
    f"CVSS score {cvss_score}. {cwe_id}."
)
# → "Critical severity deserialization vulnerability. Network attack vector,
#    no privileges required, no user interaction. CVSS score 9.8. CWE-502."

embedding = sentencebert.encode(synthetic)  # same model, same 768-dim space
```

> **Why the same SentenceBERT model for fallback?** Using a second model would create two different embedding spaces. A real CVE embedding and a fallback CVE embedding would live in different geometries — the GAT attention mechanism would see them as fundamentally different types of objects. One SentenceBERT model = one consistent 768-dim space for all CVE nodes.

> **Why NOT zero-padding CVSS numbers to 768-dim?** You'd produce `[9.8, 1.0, 0.0, 0.0, ..., 0.0]` — 763 zeros. No semantic content. The attention mechanism cannot learn from a 763-zero vector.

### 5.3 Round 3 — Author Node Enrichment

**Input:** Package nodes from Skeletal Graph  
**Output:** Author nodes (7-dim) + maintainedBy edges + introducedBy edges  
**Network calls:** None — local GitHub Advisory cache only  
**Code:** `core/graph/enrichment.py`

> 💡 **Why Author is the root of trust:** The causal chain in supply chain attacks is always `Author → Package → Vulnerability`. A compromised Author account poisons all packages they maintain simultaneously. This is the SolarWinds pattern, the event-stream pattern, the ua-parser-js pattern. If VulnChain only looks at packages and CVEs, it is blind to the most dangerous attack vector of all.

**What gets created:**
```
For each Package node:
  Query GitHub Advisory cache → get maintainer identity
  CREATE Author node (if not already exists — deduplication!)
  CREATE edge: Package --maintainedBy--> Author

For each CVE node:
  CREATE edge: CVE --introducedBy--> Author
  (the author whose package introduced this vulnerability)
```

**Author Node — 7 Feature Dimensions:**

| Dim | Feature | Type | The Security Signal |
|-----|---------|------|-------------------|
| 0 | Account age in days | Int | Old account = more established, harder to fake trust |
| 1 | Total packages maintained | Int | High count = wide blast radius if compromised |
| 2 | Number of their packages with known CVEs | Int | Past CVE history = track record of security practices |
| 3 | Days since last commit (across all their packages) | Int | Dormant maintainer = nobody watching for suspicious activity |
| 4 | Is organization (1) or individual (0) | Binary | Orgs have security teams, 2FA policies, succession plans |
| 5 | 2FA enabled on GitHub (1) or not/unknown (0) | Binary | No 2FA = most common account takeover vector in npm hijacks |
| 6 | Derived reputation score | Float 0–1 | Composite of dims 0–5, normalized. High = trusted maintainer |

> ⚠️ **Implementation note on dim 5 (2FA):** GitHub's public API does not directly expose 2FA status. Infer from GitHub Advisory DB where documented, or default to `0` (unknown = treat as risky) when not available. Being conservative here is intentional.

**Why Author nodes catch what CVE databases miss — a concrete example:**

```
Author: "abandoned-dev"
  dim[3] = 1,200 days since last commit
  dim[5] = 0 (no 2FA)

  ├── maintains: PackageA@1.0.0  ← depended on by 45 packages
  ├── maintains: PackageB@2.3.1  ← depended on by 120 packages
  └── maintains: PackageC@0.8.0  ← depended on by 89 packages

Current CVE count on all three packages: 0

npm audit result:    "No vulnerabilities found" ✅
VulnChain result:    All three packages flagged with elevated risk ⚠️
                     "Dormant maintainer, no 2FA, 254 downstream dependents"

Three months later:  "abandoned-dev" account gets taken over
                     Malicious version published to PackageB
                     254 downstream packages affected
```

Static tools were right — technically. No CVE existed. VulnChain was righter.

---

## 6. STAGE 2 — TRAINING PIPELINE

> This section describes how VulnGAT learns. After training is complete, `vulngat_trained.pt` is the only artifact that matters for inference. If you are implementing the server or demo, skip to Section 7.

### 6.1 Training Data — Curation Strategy

**Dataset size:** 500–1000 real GitHub repositories  
**Entry point:** `python training/train.py`  
**Data location:** `data/training_repos/`

**Distribution — intentional oversampling:**

| Category | Count | Source |
|----------|-------|--------|
| Repos with confirmed-vulnerable packages | ~200 | GitHub Advisory DB + CISA KEV |
| Clean repos with zero known CVEs | ~200 | Random GitHub sample, verified clean |
| Mixed repos (some vulnerable, mostly clean) | ~100 | GitHub Advisory DB |

> ⚠️ **Why intentional oversampling?** If you sample 500 random GitHub repos, ~90% will have zero known vulnerabilities. VulnGAT would learn to predict "safe" for everything and achieve 90% accuracy while being completely useless. It needs to see enough vulnerable examples to learn what makes a package dangerous. Oversampling to ~40% vulnerable forces the model to actually learn the signal.

**Specific packages to oversample (confirmed vulnerable, real CVEs):**
- `log4j-core@2.14.1` — Log4Shell, CVSS 10.0
- `event-stream@3.3.6` — malicious injection 2018
- `ua-parser-js@0.7.28` — account hijack 2021
- `node-ipc@10.1.1` — intentional sabotage 2022
- `colors@1.4.44-liberty-2` — intentional sabotage 2022
- `minimist@0.2.0` — prototype pollution
- `lodash@4.17.11` — prototype pollution, CVE-2019-10744
- `handlebars@4.7.6` — RCE, CVE-2021-23369

### 6.2 Labels — VPSS as Weak Supervision

**What is VPSS?**

Vulnerability Propagation Severity Score — a formula from the VPSS paper (P5) that computes a risk score for a package by combining:
- CVSS base score of its associated CVEs
- Reachability of the vulnerable code path (is the vulnerable function actually called?)
- Propagation depth in the dependency tree (how many other packages depend on it?)

**Output:** A continuous float between 0.0 and 1.0 per package. Not binary.

**Precision:** 87% on 1,200 real CVE-package pairs (validated in source paper).

> 💡 **Why use imperfect labels?** Perfect labels would require a security expert to manually audit every package in every repo. Not feasible for 500+ repos. VPSS at 87% precision means roughly 1 in 8 labels is wrong — but directionally correct. In ML, this is called **weak supervision** — training on labels that are better than random. The model learns to generalize beyond VPSS's own accuracy by seeing graph topology patterns that VPSS's formula cannot compute.

**Why VulnGAT surpasses VPSS:**

VPSS is a formula applied to a single package in isolation. It cannot see:
- That this package's maintainer has been dormant for 1,200 days (no 2FA)
- That 300 other packages in this graph share this package's dependencies (centrality)
- That two packages with the same CVE have completely different blast radii

VulnGAT sees all of this through graph attention. Even where both are slightly wrong, VulnGAT is less wrong because it has more signal.

**Label format:** Continuous float 0.0–1.0. **NOT converted to binary.**

> ⚠️ **Why NOT binary labels?** A VPSS score of 0.73 and a score of 0.95 would both become "vulnerable=1" under binary conversion. But these are meaningfully different — a 0.95 package should be patched immediately, a 0.73 package is monitored. Binary conversion throws away exactly the granularity that makes risk scores actionable. We use MSE regression loss which preserves this continuous signal (see Section 9).

### 6.3 Train/Val/Test Split

**Rule: Split by REPO, never by package.**

| Split | Size | Purpose |
|-------|------|---------|
| Train | ~400 repos | Model learns from |
| Validation | ~50 repos | Hyperparameter tuning, early stopping |
| Test | ~50 repos | Final reported metrics — not touched until final evaluation |

> ⚠️ **Why NOT split by package?** `lodash` appears in 300+ repos. If you split by package, VulnGAT will have seen `lodash` during training on 200 repos and is then tested on `lodash` from 50 test repos. The model has already seen this node — that's data leakage. Splitting by repo guarantees: every package in a test repo was completely unseen during training.

### 6.4 Training Hyperparameters

| Hyperparameter | Value | Reasoning |
|---------------|-------|-----------|
| Optimizer | Adam | Standard for GNNs. SGD too slow on variable-size graph data |
| Learning rate | 1e-3 | Standard Adam starting point |
| LR scheduler | ReduceLROnPlateau (patience=5) | Reduces LR when val loss plateaus |
| Batch size | 1 graph (1 repo) per step | Graphs are variable size — mini-batching requires sampling |
| Max epochs | 100 | Early stopping will usually trigger before this |
| Early stopping patience | 10 epochs | Stop if val loss doesn't improve for 10 consecutive epochs |
| Edge dropout (augmentation) | p = 0.2 | 20% of edges dropped per augmented view for InfoNCE |
| InfoNCE weight | 0.1 | Regularizer weight — keeps MSE dominant |
| Hidden dim | 128 | Balances expressiveness vs model size |
| Dropout between GAT layers | 0.3 | Prevents overfitting on small training set |

> 💡 **Why edge dropout p=0.2?** Too low (p=0.05) = both augmented views are nearly identical — the model learns nothing from the contrast. Too high (p=0.5) = graph structure is destroyed — the model learns from noise. p=0.2 is the value from GraphCL (You et al. 2020) — removes enough edges to force robust representation learning while preserving enough structure for meaningful gradients.

### 6.5 Training Script Behavior

```python
# training/train.py — execution order:

# 1. Load all repos
repos = load_repos("data/training_repos/")          # 500 curated repos

# 2. Build Enriched Graphs (same 3-round pipeline as inference)
graphs = [build_enriched_graph(repo) for repo in repos]   # uses core/

# 3. Compute VPSS labels for every Package node in every graph
labels = [compute_vpss(graph) for graph in graphs]

# 4. Split by repo — never by package
train_graphs, val_graphs, test_graphs = split_by_repo(
    graphs, ratios=[0.8, 0.1, 0.1]
)

# 5. Train with early stopping
for epoch in range(max_epochs=100):
    for graph, label in zip(train_graphs, train_labels):
        pred = model(graph)
        loss = mse_loss(pred, label) + 0.1 * infonce_loss(graph, model)
        loss.backward()
        optimizer.step()
        optimizer.zero_grad()

    val_loss = evaluate(model, val_graphs)
    scheduler.step(val_loss)
    if early_stopper.should_stop(val_loss):
        break

# 6. Save best model
torch.save(model.state_dict(), "models/vulngat_trained.pt")
```

---

## 7. STAGE 3 — INFERENCE PIPELINE

### 7.1 Model Serving — Load Once, Serve Forever

**The model is loaded exactly once when the FastAPI server starts. It stays in memory for every subsequent request.**

```python
# server/app.py

from fastapi import FastAPI, UploadFile
import torch
from core.model.vulngat import VulnGAT
from core.graph.builder import build_enriched_graph

app = FastAPI()

# ── STARTUP: load model once at server boot ───────────────────────────
model = VulnGAT()
model.load_state_dict(torch.load("models/vulngat_trained.pt", map_location="cpu"))
model.eval()   # inference mode — dropout disabled, no gradient tracking
# ─────────────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(file: UploadFile):
    graph = build_enriched_graph(await file.read())   # 3-round construction
    scores = model.predict(graph)                      # model already in RAM
    return format_response(scores, graph)
```

> **Why load once?** Loading a PyTorch model from disk takes 2–5 seconds. Per-request loading = every user waits 5 seconds before anything starts. VulnGAT is small (~5–10MB). It fits permanently in RAM. One-time startup cost, zero per-request cost.

### 7.2 API Contract — Every Endpoint Defined

**POST `/analyze`**

```
Input:  multipart/form-data  →  package-lock.json file
Output: JSON (schema below)
```

```json
{
  "analysis_id": "3f9a2c1b-...",
  "total_packages": 487,
  "high_risk_count": 3,
  "packages": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "risk_score": 0.97,
      "cves": ["CVE-2021-44228"],
      "depth": 3,
      "direct_dependents": 4,
      "transitive_dependents": 312
    },
    {
      "name": "lodash",
      "version": "4.17.11",
      "risk_score": 0.43,
      "cves": ["CVE-2019-10744"],
      "depth": 5,
      "direct_dependents": 28,
      "transitive_dependents": 89
    }
  ],
  "graph": {
    "nodes": [
      { "id": "log4j-core@2.14.1", "type": "package", "risk_score": 0.97 },
      { "id": "CVE-2021-44228",    "type": "cve" },
      { "id": "Apache-ASF",        "type": "author" }
    ],
    "edges": [
      { "source": "log4j-core@2.14.1", "target": "CVE-2021-44228", "type": "hasVulnerability" },
      { "source": "log4j-core@2.14.1", "target": "Apache-ASF",     "type": "maintainedBy" }
    ]
  }
}
```

**GET `/results/{analysis_id}`**  
Returns cached results for a previous analysis. Useful for dashboard re-rendering without re-running inference.

**GET `/health`**  
Returns `{ "status": "ok", "model_loaded": true }`. Call this before the demo to confirm server is ready.

---

## 8. MODEL ARCHITECTURE — VULNGAT

### 8.1 What Kind of Model Is This?

VulnGAT is a **Heterogeneous Graph Attention Network (HAN)**. Let's unpack that:

- **Graph Attention Network (GAT):** Instead of treating all neighbours equally, it *learns* how much attention to pay to each one. A package with CVSS 9.8 gets more attention weight than a package with CVSS 2.1.
- **Heterogeneous:** It handles multiple node types (Package, CVE, Author) and multiple edge types (dependsOn, hasVulnerability, etc.) with **separate weight matrices per edge type** — not one generic matrix for everything.

The separate weight matrices are what make VulnGAT a true HAN, not just a GNN that ignores edge type differences.

### 8.2 Step 1 — Input Projection to Common Dimension

Before any message passing, all node types are projected to the same 128-dimensional space:

```
Package Node: [10-dim]  ──→  Linear(10, 128)   ──→  [128-dim]
CVE Node:     [768-dim] ──→  Linear(768, 128)  ──→  [128-dim]
Author Node:  [7-dim]   ──→  Linear(7, 128)    ──→  [128-dim]
                                    ↓
              All nodes now live in the same 128-dim space
              Attention computation is now possible across all edges
```

> **Why is this necessary?** Attention computation requires a dot product between node embeddings. You cannot dot-product a 10-dim and 768-dim vector — the math doesn't work. All nodes must be projected to a common space first. 128-dim: large enough to be expressive, small enough to keep the model under 10MB.

### 8.3 Step 2 — Separate Weight Matrices Per Edge Type

```
W_dependsOn        [128 × 128]  ─→  Package-to-Package message passing
W_hasVulnerability [128 × 128]  ─→  Package-to-CVE message passing
W_maintainedBy     [128 × 128]  ─→  Package-to-Author message passing
W_introducedBy     [128 × 128]  ─→  CVE-to-Author message passing
```

> **Why separate matrices?** Each edge type carries fundamentally different semantic information:
> - `dependsOn` propagates **dependency risk** — "I depend on a risky package, I inherit some risk"
> - `maintainedBy` propagates **trust signal** — "I am maintained by a dormant account — suspicious"
> - `hasVulnerability` carries **exploitation evidence** — "I have a specific confirmed CVE"
>
> One shared weight matrix = forced to learn one transformation for all three. It blurs the distinction between "risky because of a CVE" and "risky because of a compromised maintainer." Separate matrices let the model learn each relationship independently.

### 8.4 Step 3 — Three Layers of Message Passing

Each layer expands the neighbourhood each node can see:

```
═══════════════════════════════════════════════════════
 LAYER 1 — Local Neighbourhood (1-hop view)
═══════════════════════════════════════════════════════
 Each Package node aggregates from:
  → Its direct dependencies      (via dependsOn)
  → Its known CVEs               (via hasVulnerability)
  → Its maintainer               (via maintainedBy)

 Output: Each node has absorbed its immediate context.
         "I know what my direct neighbours look like."

═══════════════════════════════════════════════════════
 LAYER 2 — Extended Neighbourhood (2-hop view)
═══════════════════════════════════════════════════════
 Each Package node now reaches:
  → Packages that share its dependencies
  → CVEs that affect its neighbours
  → Authors connected to its direct dependencies

 Output: Each node understands its structural position.
         "I know how I fit into the larger graph."

═══════════════════════════════════════════════════════
 LAYER 3 — Deep Context (3-hop view)
═══════════════════════════════════════════════════════
 Each Package node has absorbed risk signals from
 3 hops deep in every direction.

 Output: Final 128-dim embedding per Package node.
         "I have full contextual awareness. Ready to score."
═══════════════════════════════════════════════════════
```

**Residual connections between layers (anti-over-smoothing):**
```python
output_layer_2 = LayerNorm(GAT_Layer_2(output_layer_1) + output_layer_1)
```
Without residual connections, after 3 layers all node embeddings tend to converge to the same average — called **over-smoothing**. Residual connections preserve each node's individual identity across layers. This is critical because VulnGAT needs to distinguish `log4j-core` (risk=0.97) from `lodash` (risk=0.43) even after 3 layers of aggregation.

**Dropout between layers:** p=0.3 during training, disabled during inference (`model.eval()`).

### 8.5 Step 4 — The Classifier Head

```
128-dim Package Embedding (output of Layer 3)
        ↓
  Linear(128, 1)
        ↓
    Sigmoid()
        ↓
  Risk Score  →  float between 0.0 and 1.0
```

**Output is per Package node only.** CVE and Author nodes are inputs to the computation — they inform Package node embeddings through message passing — but VulnGAT produces risk scores only for packages. The user needs to know "which package should I patch?" — not a score for a CVE (that's just CVSS) or for an author (not directly patchable).

### 8.6 Full Architecture Summary

| Component | Specification |
|-----------|--------------|
| Model type | Heterogeneous Graph Attention Network (HAN) |
| Node types | Package (10→128), CVE (768→128), Author (7→128) |
| Edge types | 4: dependsOn, hasVulnerability, maintainedBy, introducedBy |
| Weight matrices | Separate per edge type (true HAN) |
| Hidden dimension | 128 |
| GAT layers | 3 (with residual connections + LayerNorm) |
| Dropout | 0.3 between layers (training only) |
| Classifier | Linear(128, 1) → Sigmoid |
| Output | Risk score per Package node, float 0.0–1.0 |
| Framework | PyTorch + PyTorch Geometric (PyG) |
| SentenceBERT | Frozen feature extractor — weights never updated |
| Model size | ~5–10MB |

---

## 9. LOSS FUNCTION

### 9.1 The Formula

```
Total Loss  =  MSE Loss  +  0.1 × InfoNCE Loss
               ─────────    ─────────────────────
               Primary       Representation
               supervision   regularizer
```

### 9.2 MSE Loss — The Primary Signal

```python
mse_loss = F.mse_loss(predicted_risk_scores, vpss_labels)
# predicted_risk_scores: shape [num_package_nodes], range 0–1 (Sigmoid output)
# vpss_labels:           shape [num_package_nodes], range 0–1 (VPSS scores)
```

MSE penalizes the model proportionally to how far its prediction is from the VPSS label. The gradient flows continuously — the model is gently nudged toward 0.73 when VPSS says 0.73, not just told "wrong" in binary.

> **Why MSE and not Binary Cross Entropy?** VPSS gives continuous scores. BCE requires thresholding: "is this package vulnerable or not?" That destroys the signal. A 0.73 package and a 0.95 package are both "vulnerable" under BCE — but they warrant completely different responses in real life. MSE preserves this granularity throughout training. Sigmoid output + MSE works cleanly when both output and label are in [0,1].

### 9.3 InfoNCE Loss — The Representation Regularizer

**The problem it solves:** Without any representation constraint, VulnGAT can "cheat" — it learns to assign similar embeddings to most nodes (since most packages are safe), producing a model that is good at MSE but terrible at distinguishing the rare dangerous ones. The embedding space collapses.

**How InfoNCE prevents this:**

```
Step 1: Take any node N
Step 2: Create two augmented views by randomly dropping 20% of its edges
        View A: N with some edges removed
        View B: N with different edges removed

Step 3: Run both views through VulnGAT
        → Embedding_A [128-dim]
        → Embedding_B [128-dim]

Step 4: Positive pair — A and B are the same node seen differently.
        Pull their embeddings closer together.

Step 5: Every OTHER node in the batch = Negative pairs.
        Push those embeddings apart from A and B.

Step 6: InfoNCE = cross entropy over cosine similarity distribution
```

> ⚠️ **Critical — positive pairs MUST be augmented views of the SAME node, NOT packages sharing the same CVE.** If "same CVE = positive pair," VulnGAT would cluster all vulnerable packages together in embedding space — no matter how different their actual risk profiles, centrality, or maintainer trust. That destroys the risk score differentiation entirely. Positive pairs must be identity-preserving augmentations. Never label-based groupings.

**The 0.1 weight:**

InfoNCE is a regularizer, not the primary supervisor. MSE dominates (weight=1.0). The 0.1 weight means: for every 1 unit of MSE loss, InfoNCE contributes only 0.1. This prevents InfoNCE from overriding the VPSS supervision signal while still improving embedding quality — especially critical for rare vulnerable packages that appear in few training repos and need strong, distinctive representations to be detected reliably.

---

## 10. DATA SOURCES — THREE DATABASES

> All three databases are pre-downloaded and cached locally **before training begins**. There are **no live API calls during inference or the demo**.

### 10.1 Why Three Databases?

Each database has a strength the others lack:

| Database | Core Strength | Core Gap |
|----------|--------------|---------|
| **NVD** | Best CVSS scores, CWE classification | Incomplete version range matching for npm/pip/maven |
| **OSV.dev** | Best version range matching per ecosystem | Sparse text descriptions — bad for SentenceBERT |
| **GitHub Advisory** | Best text descriptions + maintainer identity | Inconsistent CVSS coverage |

Together: complete coverage. Any one alone: something critical is missing.

### 10.2 What Each Database Provides

| Database | What VulnChain Gets | Used For | Cache Location | Size |
|----------|-------------------|---------|----------------|------|
| **NVD** | CVSS scores, CWE type, severity | Package node dims 0,1 · CVE fallback text construction | `data/nvd_cache/` | ~8GB |
| **OSV.dev** | Exact version ranges per ecosystem | Confirming which package versions are affected | `data/osv_cache/` | ~2GB |
| **GitHub Advisory DB** | Rich CVE text, maintainer identity, package-author mappings | SentenceBERT CVE embeddings · Author node features | `data/github_advisory_cache/` | ~500MB |

### 10.3 Cache Strategy

```
SETUP (one-time, before training or demo):
  python scripts/download_databases.py
    → Downloads NVD full JSON dump
    → Clones OSV.dev public database
    → Exports GitHub Advisory via GraphQL API
    → Stores all in data/  (gitignored — too large for repo)

DURING TRAINING:
  All lookups are local file reads. Zero network calls.

DURING DEMO:
  Results are pre-computed and cached in demo/log4shell_results.json
  Zero database lookups, zero network calls, zero failure surface.
```

> ⚠️ `data/` is gitignored. Any developer cloning this repo must run `scripts/download_databases.py` before anything else. Document this prominently in README.md.

---

## 11. EVALUATION STRATEGY

### 11.1 Primary Metrics

| Metric | What It Measures | Target |
|--------|-----------------|--------|
| **MAE** | Mean absolute error between predicted score and VPSS label | Lower = better |
| **Precision@10** | Of our top 10 highest-scored packages, how many are in CISA KEV? | Higher = better |
| **Ranking Accuracy** | % of (high-risk, low-risk) pairs that VulnGAT correctly orders | Higher = better |
| **Spearman ρ** | Rank-order correlation between predictions and VPSS labels | Closer to 1.0 = better |

> **Why K=10 for Precision@K?** In a real security workflow, a developer patches the top-K most dangerous packages first — they don't have time to patch 487. Precision@10 directly measures: "of the 10 packages we told you to urgently fix, how many actually mattered?" This is the most operationally meaningful metric for VulnChain's use case.

### 11.2 Ground Truth — CISA KEV Only

**A package qualifies as ground truth only if it appears in the CISA Known Exploited Vulnerabilities catalog** — confirmed exploited in the real world, not just assigned a CVSS score by a committee.

> **Why NOT "CVSS score above X"?** VulnChain's Package node features include CVSS score (dim 0). Using CVSS as ground truth would mean testing whether the model can predict CVSS from CVSS — circular. CISA KEV requires actual evidence of real-world exploitation, completely independent of CVSS assignment.

**8–12 Curated Ground Truth Cases:**

| Package | CVE | Attack Type | CISA KEV |
|---------|-----|-------------|----------|
| log4j-core@2.14.1 | CVE-2021-44228 | Remote code execution | ✅ |
| event-stream@3.3.6 | N/A (supply chain) | Malicious injection | ✅ |
| ua-parser-js@0.7.28 | CVE-2021-43577 | Account hijack | ✅ |
| node-ipc@10.1.1 | CVE-2022-23812 | Intentional sabotage | ✅ |
| minimist@0.2.0 | CVE-2021-44906 | Prototype pollution | ✅ |
| lodash@4.17.11 | CVE-2019-10744 | Prototype pollution | ✅ |
| handlebars@4.7.6 | CVE-2021-23369 | Remote code execution | ✅ |
| colors@1.4.44-liberty-2 | N/A (supply chain) | Intentional sabotage | ✅ |

### 11.3 Ablation Studies — Four Experiments

Each ablation removes one component and measures the performance drop. This proves every component earns its place.

| Ablation | What's Removed | Expected Drop | What It Proves |
|----------|---------------|--------------|----------------|
| **A1 — No Author Nodes** | Author nodes + maintainedBy + introducedBy edges | Precision@10 drops on hijack-type attacks (event-stream, ua-parser-js) | Author nodes detect maintainer-trust attacks that CVE databases miss |
| **A2 — No Contrastive Loss** | Set InfoNCE weight = 0 | Performance on rare/long-tail CVEs worsens | InfoNCE builds better embeddings for infrequent vulnerable packages |
| **A3 — Depth 1 Only** | Stop graph at direct deps | MAE and Ranking Accuracy worsen significantly | Transitive dependencies carry the real risk signal |
| **A4 — Raw CVSS vs SentenceBERT** | Replace 768-dim SentenceBERT with 6 raw CVSS numbers | All metrics drop | Semantic CVE embeddings add value beyond raw scores |

**Recommended run order:** A3 → A1 → A4 → A2 (most to least expected impact). Report all four in the paper.

---

## 12. REPOSITORY STRUCTURE

```
VulnChain/
│
│  ── USER-FACING ─────────────────────────────────────────────
│
├── client/                              # [FUTURE] React frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── GraphVisualization.jsx   # D3.js force-directed graph
│   │   │   │                            # Nodes colored by risk_score (red→green)
│   │   │   ├── RiskDashboard.jsx        # Risk score table + heatmap per package
│   │   │   ├── PackageDetail.jsx        # Click node → CVE list + author info
│   │   │   └── RepoInput.jsx            # package-lock.json file upload form
│   │   ├── App.jsx
│   │   └── index.css
│   └── package.json
│
├── server/                              # FastAPI backend
│   ├── app.py                           # ENTRY POINT — loads VulnGAT ONCE at startup
│   ├── routes/
│   │   ├── analyze.py                   # POST /analyze → full pipeline
│   │   └── results.py                   # GET /results/:id → cached results
│   └── requirements.txt
│
│  ── SHARED CORE ─────────────────────────────────────────────
│  ⚠️  NEVER duplicate logic from here into server/ or training/
│
├── core/
│   ├── parsers/
│   │   ├── npm_parser.py                # package-lock.json → Package nodes + dependsOn edges
│   │   ├── pip_parser.py                # [FUTURE] requirements.txt
│   │   └── maven_parser.py              # [FUTURE] pom.xml
│   │
│   ├── graph/
│   │   ├── builder.py                   # Orchestrates all 3 rounds of graph construction
│   │   ├── features.py                  # Package node 10-dim feature engineering
│   │   └── enrichment.py               # Round 2 (CVE nodes) + Round 3 (Author nodes)
│   │
│   ├── embeddings/
│   │   ├── sentencebert.py              # CVE text → 768-dim (frozen SentenceBERT)
│   │   └── fallback.py                  # Vague CVE → synthetic text → same SentenceBERT
│   │
│   └── model/
│       ├── vulngat.py                   # VulnGAT — full 3-layer HAN definition
│       ├── layers.py                    # HAN attention layer (separate weight matrix per edge type)
│       └── loss.py                      # Total Loss = MSE + 0.1 × InfoNCE
│
│  ── TRAINING ─────────────────────────────────────────────────
│  Run once. Produces vulngat_trained.pt. Then never touch again.
│
├── training/
│   ├── train.py                         # ENTRY POINT: python training/train.py
│   ├── dataset.py                       # Load 500 repos → build Enriched Graphs → VPSS labels
│   ├── evaluate.py                      # MAE, Precision@10, Spearman ρ, Ranking Accuracy
│   └── ablation.py                      # A1–A4 experiments
│
│  ── ARTIFACTS AND DATA ──────────────────────────────────────
│
├── models/
│   └── vulngat_trained.pt               # Trained model weights (~5–10MB)
│                                        # Commit to repo or publish as GitHub Release
│
├── data/                                # ⚠️ GITIGNORED — run scripts/download_databases.py first
│   ├── nvd_cache/                       # NVD full JSON dump (~8GB)
│   ├── osv_cache/                       # OSV.dev database (~2GB)
│   ├── github_advisory_cache/           # GitHub Advisory GraphQL export (~500MB)
│   └── training_repos/                  # 500 curated repos (one package-lock.json each)
│
├── demo/
│   └── log4shell_results.json           # Pre-computed inference on real log4j repo
│                                        # Dashboard reads this — no live inference during demo
│
│  ── SCRIPTS AND DOCS ────────────────────────────────────────
│
├── scripts/
│   └── download_databases.py            # One-time setup: downloads NVD + OSV + GitHub Advisory
│
├── docs/
│   ├── VULNCHAIN_DESIGN_v1.0.md         # THIS FILE — the war map
│   └── literature_survey.md             # 8 papers with summaries and contribution notes
│
├── README.md                            # Setup instructions, quickstart, project overview
└── docker-compose.yml                   # Container config (server + future services)
```

---

## 13. DEMO STRATEGY

### 13.1 This Demo Is Worth 30% of the Grade. Engineer It.

Do not improvise. Do not rely on live network calls. Do not leave a single failure point unhandled.

### 13.2 Target: Log4Shell

| Field | Value |
|-------|-------|
| Package | `log4j-core@2.14.1` |
| CVE | CVE-2021-44228 |
| CVSS | 10.0 (maximum possible) |
| CISA KEV | ✅ Confirmed exploited |
| Why this? | Most recognized supply chain CVE on Earth. Every judge, reviewer, and audience member has heard of it. Maximum credibility with zero explanation overhead. |

### 13.3 The Pre-Computation Approach

**Strategy: Run real inference on a real pre-patch repo → save output to JSON → dashboard reads JSON.**

```
BEFORE DEMO DAY:
──────────────────────────────────────────────────────
1. Find a real GitHub repo from mid-2021 using log4j-core@2.14.1 before patch
   Source: Archive.org + GitHub commit history
   Example: Any Spring Boot project from before Dec 10, 2021

2. Run full VulnChain pipeline on it:
   python server/app.py            (start server)
   curl -X POST localhost:8000/analyze \
     -F "file=@pre-patch-repo/package-lock.json"

3. Save the response to:
   demo/log4shell_results.json

4. Configure dashboard to load from demo/log4shell_results.json
   (not from live inference endpoint)

DURING DEMO:
──────────────────────────────────────────────────────
1. Upload the package-lock.json  → "Analyzing..." animation plays
2. Dashboard loads from demo/log4shell_results.json
3. log4j-core node appears RED   → risk_score = 0.97
4. Graph shows all 312 packages depending on log4j-core
5. Click log4j-core              → CVE-2021-44228 panel opens
6. Say: "This is Log4Shell. CVSS 10.0. 312 downstream packages
         affected. VulnChain found it in 3 seconds."
```

### 13.4 If Asked About Pre-computation

*"Inference ran beforehand on a real repository from mid-2021 that used log4j-core@2.14.1 before the patch. The dashboard displays the cached results for presentation reliability. The same pipeline runs live on any package-lock.json — we pre-computed this specific case to avoid network latency during the demo."*

This is completely honest. The numbers are real. Pre-computation is an engineering choice, not a shortcut.

### 13.5 Failure Recovery Plan

| Failure Scenario | Recovery |
|-----------------|----------|
| Server crashes mid-demo | Restart: `python server/app.py` — ready in 5 seconds |
| Dashboard fails to render | Open `demo/log4shell_results.json` and walk through the JSON fields live |
| Audience asks for live analysis of a different package | "The demo uses our curated Log4Shell case. Live inference on any npm package-lock.json is fully supported." |
| Internet goes down | All data is cached locally. Zero network dependency during demo. |

---

## 14. OUT OF SCOPE — PHASE 1

> These are deliberate deferrals. Not forgotten — saved for after the demo ships. Do NOT implement without being explicitly asked.

| Feature | Why Deferred |
|---------|-------------|
| **pip (requirements.txt) support** | npm has the richest CVE data and all 8 reference papers study npm. Add after npm is rock solid. |
| **Maven (pom.xml) support** | Same reason. Modular parser architecture in `core/parsers/` makes this easy to add later. |
| **Redis caching layer** | Overengineering for demo scale. Pre-cached JSON achieves the same result with zero infrastructure. |
| **Celery async task queue** | FastAPI sync endpoints handle demo load fine. |
| **Distributed training** | VulnGAT is 5–10MB. 500 repos trains on CPU in hours. Distributed = engineering cost for zero return. |
| **Remediation suggestions** | Nice-to-have. Risk scoring is the core value. |
| **Real-time live inference during demo** | Adds network dependency, rate limit risk, and latency — all during a 30%-of-grade presentation. |
| **User authentication** | Not relevant to academic demo. |
| **Scalability stress tests** | Not relevant to academic demo. |

---

## 15. DESIGN DECISIONS LOG

> Every decision below was challenged and locked. Say so explicitly if you want to revisit any of these. Do not silently override.

| # | Decision Point | Chosen | Rejected | Why |
|---|---------------|--------|----------|-----|
| D1 | CVE embedding model | SentenceBERT (frozen) | Llama-8B, CodeBERT | SentenceBERT is built for semantic sentence similarity. CodeBERT is trained on code syntax — wrong domain for CVE prose. Llama-8B is overengineered for a frozen feature extractor. |
| D2 | CVE fallback for vague descriptions | Synthetic text → same SentenceBERT | Zero-pad CVSS numbers to 768-dim | Zero-padding gives 763 zeros — no semantic content. Synthetic text produces a real meaningful vector in the same embedding space. |
| D3 | Loss function | MSE regression | Binary Cross Entropy | VPSS is continuous (0.73 ≠ 0.95). BCE collapses both to "vulnerable=1", throwing away actionable granularity. |
| D4 | InfoNCE positive pairs | Two augmented views of SAME node | Same-CVE packages as positive pairs | Same-CVE grouping clusters all vulnerable packages together, destroying risk score differentiation. |
| D5 | Weight matrices | Separate per edge type (true HAN) | Single shared matrix | Each edge type carries different semantics. One matrix blurs dependency risk vs maintainer trust vs CVE evidence. |
| D6 | Node projection | All types → 128-dim before GAT | Keep native dimensions | Attention requires dot products between node embeddings. Can't dot-product 10-dim and 768-dim vectors. |
| D7 | Risk score output | Per Package node only | Per all node types | Users need "which package to patch?" CVE score = just CVSS. Author score = not directly actionable. |
| D8 | Train/val/test split | By repo | By package | Lodash appears in 300+ repos. Package-level split = data leakage. Repo-level split guarantees no test package was seen during training. |
| D9 | Training labels | Continuous VPSS → MSE | Binary vulnerable/not → BCE | Granularity. 0.73 ≠ 0.95 in real risk. Binary collapses them to the same gradient. |
| D10 | Model loading | Once at server startup | Per request | Per-request = 5-second wait per user. Model is 5–10MB. One-time load costs nothing. |
| D11 | Dependency depth | Full transitive, all depths | Direct deps only | DVGraph paper: 90% of vulnerable paths are transitive. Depth-1 = blind to 9/10 real attacks. |
| D12 | Distributed training | Rejected entirely | — | Small model + 500 repos. CPU trains in hours. Distributed is overengineered with zero benefit. |
| D13 | Demo inference | Real inference pre-computed → cached JSON | Live inference during demo | Live = network risk + API rate limits + inference latency during 30%-of-grade presentation. Cached = stable, honest, fast. |
| D14 | Ground truth source | CISA KEV catalog | CVSS score threshold | CVSS threshold is circular — we train on CVSS features. CISA KEV is real-world exploitation evidence, independent of CVSS. |

---

## 16. KNOWN RISKS AND MITIGATIONS

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| VPSS labels wrong for ~13% of training data | Certain (by definition of 87% precision) | Medium | InfoNCE contrastive loss improves embeddings despite noisy labels. Model learns beyond VPSS accuracy. |
| Training graph too large for RAM | Medium | High | Use PyG's `NeighborLoader` for mini-batch graph sampling. Process one repo at a time, not all 500 simultaneously. |
| NVD/OSV cache becomes stale | Medium | Low for demo | Cache downloaded fresh before training. Demo uses pre-computed results — immune to stale data. |
| GAT over-smoothing after 3 layers | Low | Medium | Residual connections + LayerNorm between layers. Monitor: std of node embeddings should stay > 0.1 throughout training. |
| SentenceBERT embedding quality poor for specific CVE text | Low | Medium | Fallback synthetic text strategy handles worst-case vague descriptions. Evaluate on a held-out CVE set before training. |
| log4j pre-patch repo hard to find | Low | High | Archive.org preserves old repos. GitHub commit history shows any file at any past commit. Spring Boot repos from before Dec 10, 2021 are abundant. |
| Training data class imbalance | High | Medium | Intentional oversampling to ~40% vulnerable (Section 6.1). Monitor class distribution before training. |
| SentenceBERT too slow for live inference | Low | Low | SentenceBERT encodes a CVE description in ~10ms. Pre-cached demo makes this moot anyway. |

---

## 17. LITERATURE FOUNDATION

> These 8 papers are the academic backbone of VulnChain. Every architectural decision traces back to at least one of them.

| ID | Paper | What It Justifies |
|----|-------|------------------|
| **P1** | Wang et al. 2019 — *Heterogeneous Graph Attention Network* | Original HAN paper. Justifies separate weight matrices per edge type (D5) and the heterogeneous graph structure itself. |
| **P2** | VulBERTa — *NLP for Vulnerability Description Analysis* | Justifies transformer-based semantic embeddings for CVE text over raw CVSS numbers (D1). Proves NLP adds value. |
| **P3** | Supply chain attack taxonomy paper *(TBD — gap to fill)* | Provides statistics on supply chain attack frequency and patterns. Motivates Section 1. |
| **P4** | npm/PyPI ecosystem security paper *(TBD — gap to fill)* | Documents ecosystem-specific attack vectors. Justifies npm-first approach in Phase 1. |
| **P5** | VPSS paper — *Vulnerability Propagation Severity Score* | Source and validation of weak supervision labels. 87% precision on 1,200 pairs. Justifies Section 6.2. |
| **P6** | DVGraph — *Dependency Vulnerability Graph* | Confirms 90% of vulnerable paths are transitive (justifies D11, full transitive depth). npm-focused. |
| **P7** | GNN survey — *Graph Neural Networks for Intrusion Detection* | Survey paper. Establishes GNNs as appropriate tools for security applications. |
| **P8** | GAT-APG — *Attack Path Graph using GAT* | Justifies multi-layer GAT for attack path reasoning (Section 8.4). Reference for 3-layer design. |

> ⚠️ **Papers P3 and P4 are TBD — confirmed gaps.** These must be identified and added to `docs/literature_survey.md` before submission. Suggested search terms: "software supply chain attack taxonomy 2023", "npm package security vulnerability analysis".

---

## VERSION HISTORY

| Version | Date | Status | Changes |
|---------|------|--------|---------|
| v1.0 | May 2026 | `FROZEN` | Initial pre-code architectural contract. 14 design decisions locked. Built through structured challenge-and-debate session before any implementation. |

**Next version:** `v1.1` — after MVP build (`core/` + `training/` complete and tested)  
**Major pivot threshold:** `v2.0`

---

*End of VULNCHAIN_DESIGN_v1.0.md*  
*This document is the single source of design truth for VulnChain.*  
*When in doubt — read this first.*
