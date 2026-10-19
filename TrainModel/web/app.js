const app = document.querySelector("#app");
let report = null;
let auditData = null;
let selected = null;
let simulatedPatches = new Set();
let isAuditRunning = false;

let graphState = {
  canvas: null,
  ctx: null,
  nodes: [],
  edges: [],
  scale: 1,
  panX: 0,
  panY: 0,
  isDragging: false,
  dragNode: null,
  lastMouseX: 0,
  lastMouseY: 0,
  hoveredNode: null,
  selectedNode: null,
  animId: null,
};

// Plain English Risk Tier Helper
function getRiskInfo(score) {
  if (score >= 0.40) {
    return {
      tier: "critical",
      label: "Critical Risk",
      pct: Math.round(score * 100),
      desc: "Direct exploit or severe active advisory",
      color: "#f43f5e"
    };
  }
  if (score >= 0.20) {
    return {
      tier: "high",
      label: "High Risk",
      pct: Math.round(score * 100),
      desc: "Transitive exposure through 1-hop dependent",
      color: "#fb923c"
    };
  }
  if (score >= 0.08) {
    return {
      tier: "moderate",
      label: "Moderate Risk",
      pct: Math.round(score * 100),
      desc: "Shallow transitive exposure in dependency tree",
      color: "#facc15"
    };
  }
  return {
    tier: "safe",
    label: "Clean / Safe",
    pct: Math.round(score * 100),
    desc: "No known vulnerabilities or risky dependents",
    color: "#10b981"
  };
}

// Compute Project Health Grade (0-100)
function computeProjectHealth(rep) {
  if (!rep || !rep.packages || !rep.packages.length) return { score: 100, grade: "A", status: "Healthy" };
  
  // Calculate simulated reduction if patches are applied
  let simulatedDrop = 0;
  if (rep.remediations) {
    for (const r of rep.remediations) {
      if (simulatedPatches.has(r.package)) {
        simulatedDrop += r.simulated_risk_reduction_pct || 0;
      }
    }
  }
  simulatedDrop = Math.min(simulatedDrop, 90);

  const crit = rep.summary ? rep.summary.critical || 0 : 0;
  const high = rep.summary ? rep.summary.high || 0 : 0;
  const mod = rep.summary ? rep.summary.moderate || 0 : 0;

  let penalty = (crit * 15) + (high * 8) + (mod * 3);
  penalty = penalty * (1 - simulatedDrop / 100);
  const healthScore = Math.max(10, Math.min(100, Math.round(100 - penalty)));

  let grade = "A";
  let status = "Healthy Dependency Tree";
  if (healthScore < 50) { grade = "F"; status = "Critical Vulnerabilities Detected"; }
  else if (healthScore < 70) { grade = "C"; status = "Action Required (Transitive Risks)"; }
  else if (healthScore < 85) { grade = "B"; status = "Moderate Attention Needed"; }

  return { score: healthScore, grade, status, simulatedDrop };
}

const esc = (text) => String(text || "").replace(/[&<>\"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));

// API Fetchers
async function getSample() {
  if (!report) {
    report = await fetch("/api/sample").then(r => r.json()).catch(() => null);
  }
  return report;
}

async function getAudit() {
  if (!auditData) {
    auditData = await fetch("/api/audit").then(r => r.json()).catch(() => null);
  }
  return auditData;
}

function setRoute(path) {
  location.hash = `#${path}`;
}

function nav() {
  const current = route();
  document.querySelectorAll(".journey-step").forEach(a => {
    a.classList.toggle("active", a.dataset.route === current);
  });
}

function route() {
  return location.hash.replace("#", "") || "/";
}

// ═════════════════════════════════════════════════════════════════════════════
// SHARED PROJECT CONTEXT BANNER
// ═════════════════════════════════════════════════════════════════════════════
function renderHealthBanner() {
  if (!report) return "";
  const health = computeProjectHealth(report);
  const totalPkgs = report.total_packages || (report.packages ? report.packages.length : 0);
  const critCount = report.summary ? report.summary.critical || 0 : 0;
  const highCount = report.summary ? report.summary.high || 0 : 0;

  return `
    <div class="project-health-banner">
      <div class="health-left">
        <div class="health-gauge grade-${health.grade.toLowerCase()}">
          <span class="health-grade">${health.grade}</span>
          <span class="health-label">${health.score}/100</span>
        </div>
        <div class="health-details">
          <h2>Project Health: ${health.status}</h2>
          <p>Scanned <b>${totalPkgs} packages</b> across your dependency graph.</p>
          <div class="health-meta">
            <span class="meta-chip">🚨 ${critCount} Critical</span>
            <span class="meta-chip">⚠️ ${highCount} High Risk</span>
            ${health.simulatedDrop > 0 ? `<span class="meta-chip" style="color:var(--green);border-color:var(--green);">⚡ -${health.simulatedDrop.toFixed(0)}% Risk Simulated</span>` : ''}
          </div>
        </div>
      </div>
      <div class="health-right">
        <a href="#/scan" class="btn-secondary" style="font-size:12px;">Change Lockfile ↺</a>
      </div>
    </div>
  `;
}

// ═════════════════════════════════════════════════════════════════════════════
// STEP 1: INGESTION & LOCKFILE SCAN VIEW
// ═════════════════════════════════════════════════════════════════════════════
function scan() {
  app.innerHTML = `
    <div class="scan-container">
      <div class="journey-header">
        <span class="journey-step-tag">Step 1 of 5 · Ingestion</span>
        <h1>Select or Upload Your Project Lockfile</h1>
        <p>Choose an example project with real supply chain vulnerabilities, or upload your own npm <code class="mono">package-lock.json</code> to start the security triage.</p>
      </div>

      <!-- Quick Preset Selection -->
      <div class="preset-selection">
        <h3>Choose an Example Project</h3>
        <div class="preset-cards-grid">
          <div class="preset-card-item" data-preset="airtwin">
            <span class="badge">Recommended</span>
            <h4>Airtwin Backend</h4>
            <p>132 packages · Real-world tree with transitive CVEs in <code class="mono">axios</code>, <code class="mono">qs</code>, and <code class="mono">ws</code>.</p>
          </div>

          <div class="preset-card-item" data-preset="sample-app">
            <span class="badge">Minimal Test</span>
            <h4>Sample Test App</h4>
            <p>4 packages · Direct vulnerability sample with <code class="mono">express</code> and <code class="mono">lodash</code>.</p>
          </div>

          <div class="preset-card-item" data-preset="benchmark">
            <span class="badge">Evaluation Slice</span>
            <h4>Benchmark Pilot</h4>
            <p>113 packages · Verified test slice from repo-level held-out evaluation.</p>
          </div>
        </div>
      </div>

      <!-- File Dropzone -->
      <label class="dropzone-box" id="dropzone">
        <input id="lockfile" type="file" accept="application/json,.json">
        <div class="dropzone-icon">⇧</div>
        <h3>Drop your package-lock.json here</h3>
        <p>Supports npm lockfileVersion 1, 2, and 3 (All processed locally)</p>
        <button class="btn-cta" type="button">Browse Computer</button>
      </label>

      <!-- Live Stepper Progress -->
      <div class="scan-progress-box" id="scan-progress">
        <div class="progress-bar-wrap">
          <div class="progress-bar-fill"></div>
        </div>
        <div class="progress-step-text">Initializing VulnGAT environment…</div>
      </div>
    </div>
  `;

  const zone = document.querySelector("#dropzone");
  const input = document.querySelector("#lockfile");

  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("dragging"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragging"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    zone.classList.remove("dragging");
    if (e.dataTransfer.files.length) beginScan(e.dataTransfer.files[0]);
  });

  input.addEventListener("change", () => {
    if (input.files.length) beginScan(input.files[0]);
  });

  document.querySelectorAll("[data-preset]").forEach(card => {
    card.addEventListener("click", async () => {
      const presetId = card.dataset.preset;
      if (presetId === "benchmark") {
        await getSample();
        setRoute("/results");
        return;
      }
      try {
        const res = await fetch(`/api/preset/${presetId}`).then(r => r.json());
        if (res.content) {
          const blob = new Blob([res.content], { type: "application/json" });
          const file = new File([blob], res.filename, { type: "application/json" });
          beginScan(file);
        }
      } catch (err) {
        alert("Failed to load preset: " + err.message);
      }
    });
  });
}

async function beginScan(file) {
  if (!file) return;
  const progress = document.querySelector("#scan-progress");
  const bar = progress.querySelector(".progress-bar-fill");
  const text = progress.querySelector(".progress-step-text");
  progress.classList.add("show");

  const steps = [
    [20, "1/4 Parsing dependency hierarchy from lockfile…"],
    [45, "2/4 Resolving CVE advisories from OSV knowledge base…"],
    [70, "3/4 Building 10-dim package feature tensors and depth…"],
    [90, "4/4 Running 3-layer VulnGAT graph attention neural network…"]
  ];

  for (const [pct, msg] of steps) {
    bar.style.width = `${pct}%`;
    text.textContent = msg;
    await new Promise(r => setTimeout(r, 320));
  }

  try {
    const fileText = await file.text();
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: fileText
    });

    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "Analysis failed");

    report = json;
    selected = report.packages && report.packages.length ? report.packages[0] : null;

    bar.style.width = "100%";
    text.textContent = `Analysis complete · Scored ${report.total_packages} packages!`;
    await new Promise(r => setTimeout(r, 350));
    setRoute("/results");
  } catch (err) {
    bar.style.width = "0%";
    text.innerHTML = `<span style="color:var(--red)">Error: ${esc(err.message)}</span>`;
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// STEP 2: RISK TRIAGE VIEW
// ═════════════════════════════════════════════════════════════════════════════
function results() {
  getSample().then(data => {
    if (!data) {
      setRoute("/scan");
      return;
    }
    renderResultsView();
  });
  app.innerHTML = `<p class="section-sub">Loading dependency risk triage…</p>`;
}

function renderResultsView() {
  const items = (report && report.packages) || [];
  if (!selected && items.length) selected = items[0];

  const crit = report.summary ? report.summary.critical || 0 : 0;
  const high = report.summary ? report.summary.high || 0 : 0;
  const mod = report.summary ? report.summary.moderate || 0 : 0;
  const safe = report.summary ? report.summary.safe || 0 : 0;

  app.innerHTML = `
    <!-- Executive Health Banner -->
    ${renderHealthBanner()}

    <!-- 4 Triage Summary Cards -->
    <div class="summary-cards-row">
      <div class="risk-stat-card critical">
        <span class="card-title">Critical Risk</span>
        <span class="card-count">${crit}</span>
        <span class="card-desc">Direct exploits requiring immediate patch</span>
      </div>

      <div class="risk-stat-card high">
        <span class="card-title">High Risk</span>
        <span class="card-count">${high}</span>
        <span class="card-desc">Transitive risk propagated to direct parents</span>
      </div>

      <div class="risk-stat-card moderate">
        <span class="card-title">Moderate Risk</span>
        <span class="card-count">${mod}</span>
        <span class="card-desc">Shallow dependency exposure</span>
      </div>

      <div class="risk-stat-card safe">
        <span class="card-title">Clean / Safe</span>
        <span class="card-count">${safe}</span>
        <span class="card-desc">Healthy dependencies</span>
      </div>
    </div>

    <!-- Triage Table and Side Inspection -->
    <div class="triage-grid">
      <div class="triage-list-card">
        <div class="triage-filters">
          <input id="search-input" placeholder="Search by package name or CVE (e.g. axios, qs, express)…">
          <select id="tier-select">
            <option value="all">All Risk Levels</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="moderate">Moderate Only</option>
            <option value="safe">Clean Only</option>
          </select>
        </div>

        <div id="package-list-container">
          ${items.map(renderPackageRow).join("")}
        </div>
      </div>

      <!-- Detail Inspection Drawer -->
      <aside class="inspection-drawer" id="inspection-drawer">
        ${renderInspectionDrawer()}
      </aside>
    </div>

    <!-- Next Step Action Bar -->
    <div class="journey-action-bar">
      <div>
        <p>Finished reviewing vulnerabilities? Next, inspect how they propagate through your code.</p>
      </div>
      <a href="#/graph" class="btn-cta">Step 3: View Attack Chains →</a>
    </div>
  `;

  wireResultsInteractivity();
}

function renderPackageRow(pkg) {
  const info = getRiskInfo(pkg.risk_score);
  const isSelected = selected && selected.package === pkg.package;

  return `
    <div class="package-item-row ${isSelected ? 'selected' : ''}" data-pkg="${esc(pkg.package)}">
      <span class="risk-score-chip ${info.tier}">${info.pct}%</span>
      <div class="pkg-info-col">
        <div class="pkg-title">${esc(pkg.name)} <span>@${esc(pkg.version)}</span></div>
        <div class="pkg-risk-bar-track">
          <div class="pkg-risk-bar-fill ${info.tier}" style="width:${Math.max(info.pct, 2)}%"></div>
        </div>
        <div class="pkg-subtext">
          <span class="tag-badge ${pkg.is_direct ? '' : 'transitive'}">${pkg.is_direct ? 'Direct' : 'Transitive'}</span>
          ${pkg.cve ? `<span class="advisory-badge">Advisory: ${esc(pkg.cve)}</span>` : '<span style="color:var(--text-dim)">No direct advisory</span>'}
          <span>· ${pkg.dependents_count || 0} dependents</span>
        </div>
      </div>
      <span style="color:var(--text-dim);font-size:16px;">›</span>
    </div>
  `;
}

function renderInspectionDrawer() {
  if (!selected) return `<p style="color:var(--text-muted)">Select a package on the left to inspect details.</p>`;
  const s = selected;
  const info = getRiskInfo(s.risk_score);

  return `
    <div class="drawer-header">
      <div>
        <h3>${esc(s.name)}</h3>
        <span class="mono" style="font-size:12px;color:var(--text-muted)">Version ${esc(s.version)}</span>
      </div>
      <span class="risk-score-chip ${info.tier}">${info.label} (${info.pct}%)</span>
    </div>

    <div class="drawer-section">
      <label>Relationship in Project</label>
      <p>
        ${s.is_direct 
          ? '<b>Direct Dependency</b> (imported directly in your package.json).' 
          : '<b>Transitive Dependency</b> (imported indirectly by another package in your tree).'}
      </p>
    </div>

    <div class="drawer-section">
      <label>Advisory & Vulnerability</label>
      <p>
        ${s.cve 
          ? `<span class="advisory-badge" style="font-size:12px;">${esc(s.cve)}</span><br/><span style="margin-top:6px;display:inline-block;">Active vulnerability linked to this version.</span>` 
          : 'Clean node. No known vulnerability directly on this package.'}
      </p>
    </div>

    <div class="drawer-section">
      <label>Blast Radius & Dependents</label>
      <p>
        Used by <b>${s.dependents_count || 0} packages</b> in your dependency tree.
      </p>
    </div>

    <a href="#/graph" class="btn-secondary" style="width:100%;margin-top:10px;font-size:12px;">
      Trace Attack Path in Graph ◈
    </a>
  `;
}

function wireResultsInteractivity() {
  const search = document.querySelector("#search-input");
  const filter = document.querySelector("#tier-select");
  const container = document.querySelector("#package-list-container");

  const filterRows = () => {
    let copy = [...((report && report.packages) || [])];
    const q = search ? search.value.toLowerCase().trim() : "";
    const tierVal = filter ? filter.value : "all";

    copy = copy.filter(p => {
      const matchQ = !q || p.package.toLowerCase().includes(q) || (p.cve && p.cve.toLowerCase().includes(q));
      const matchTier = tierVal === "all" || getRiskInfo(p.risk_score).tier === tierVal;
      return matchQ && matchTier;
    });

    if (container) {
      container.innerHTML = copy.map(renderPackageRow).join("") || `<div style="padding:24px;text-align:center;color:var(--text-muted)">No packages match your search.</div>`;
      container.querySelectorAll("[data-pkg]").forEach(row => {
        row.addEventListener("click", () => {
          selected = (report.packages || []).find(p => p.package === row.dataset.pkg);
          document.querySelector("#inspection-drawer").innerHTML = renderInspectionDrawer();
          filterRows();
        });
      });
    }
  };

  if (search) search.addEventListener("input", filterRows);
  if (filter) filter.addEventListener("change", filterRows);
}

// ═════════════════════════════════════════════════════════════════════════════
// STEP 3: ATTACK CHAINS & BLAST RADIUS VIEW
// ═════════════════════════════════════════════════════════════════════════════
function graph() {
  getSample().then(data => {
    if (!data) {
      setRoute("/scan");
      return;
    }
    renderGraphView();
  });
  app.innerHTML = `<p class="section-sub">Loading supply chain attack graph…</p>`;
}

function renderGraphView() {
  const g = (report && report.graph) || { nodes: [], edges: [] };
  const attackPaths = (report && report.attack_paths) || [];

  app.innerHTML = `
    <!-- Executive Health Banner -->
    ${renderHealthBanner()}

    <div class="journey-header" style="text-align:left;margin:0 0 20px;">
      <span class="journey-step-tag">Step 3 of 5 · Attack Propagation</span>
      <h1>How Vulnerabilities Travel into Your Application</h1>
      <p>Transitive dependencies are packages you didn't install directly, but were installed by your dependencies. Attackers exploit deep transitive packages to compromise your root application.</p>
    </div>

    <!-- Visual Attack Chains Cards -->
    <div style="margin-bottom:30px;">
      <h3 style="font-size:16px;color:#fff;margin:0 0 12px;">Detected Transitive Attack Chains (${attackPaths.length})</h3>
      ${attackPaths.length ? attackPaths.map(p => `
        <div class="attack-chain-card">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
              <b style="font-size:15px;color:#fff;">${esc(p.cve)}</b>
              <span class="tag-badge" style="margin-left:8px;">${p.hops} Transitive Hops</span>
            </div>
            <span class="risk-score-chip critical">Sink Risk: ${Math.round(p.sink_risk * 100)}%</span>
          </div>

          <div class="chain-flow-row">
            ${p.chain.map((node, idx) => {
              const isRoot = idx === 0;
              const isSink = idx === p.chain.length - 1;
              return `
                <span class="chain-step-node ${isRoot ? 'root' : isSink ? 'sink' : ''}">
                  ${isRoot ? '📍 Your Direct App: ' : isSink ? '⚠️ Vulnerable Exploit: ' : '↳ '}<b>${esc(node)}</b>
                </span>
                ${idx < p.chain.length - 1 ? '<span style="color:var(--text-dim);font-weight:800;">→</span>' : ''}
              `;
            }).join("")}
          </div>

          <p style="font-size:13px;color:var(--text-muted);margin:0;">${esc(p.impact_summary)}</p>
        </div>
      `).join("") : `<div class="card"><p>No transitive attack chains detected in this project.</p></div>`}
    </div>

    <!-- Interactive Canvas Graph -->
    <div class="canvas-card-wrapper">
      <div class="canvas-controls-bar">
        <div class="canvas-btn-group">
          <button class="canvas-action-btn" id="btn-zoom-in" title="Zoom In">+</button>
          <button class="canvas-action-btn" id="btn-zoom-out" title="Zoom Out">−</button>
          <button class="canvas-action-btn" id="btn-reset-cam" title="Reset View">⊙</button>
        </div>
      </div>
      <canvas id="graph-canvas" class="graph-canvas-element"></canvas>
    </div>

    <!-- Next Step Action Bar -->
    <div class="journey-action-bar">
      <div>
        <p>Now that you know how the vulnerability reaches your app, let's fix it.</p>
      </div>
      <a href="#/remediation" class="btn-cta">Step 4: View Fix Roadmap →</a>
    </div>
  `;

  initCanvasVisualizer();
}

function initCanvasVisualizer() {
  const canvas = document.querySelector("#graph-canvas");
  if (!canvas) return;

  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * window.devicePixelRatio;
  canvas.height = rect.height * window.devicePixelRatio;

  const ctx = canvas.getContext("2d");
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  graphState.canvas = canvas;
  graphState.ctx = ctx;
  graphState.width = rect.width;
  graphState.height = rect.height;

  const g = (report && report.graph) || { nodes: [], edges: [] };
  const nodeMap = new Map();

  const numNodes = g.nodes.length || 1;
  const radius = Math.min(rect.width, rect.height) * 0.35;
  const cx = rect.width / 2;
  const cy = rect.height / 2;

  graphState.nodes = g.nodes.map((n, i) => {
    const angle = (i / numNodes) * 2 * Math.PI;
    const dist = (0.3 + 0.7 * Math.random()) * radius;
    const nodeObj = {
      ...n,
      x: cx + Math.cos(angle) * dist,
      y: cy + Math.sin(angle) * dist,
      radius: n.type === "CVE" ? 14 : n.is_direct ? 12 : 7,
      color: n.type === "CVE" ? "#f43f5e" : getRiskInfo(n.risk_score || 0).color
    };
    nodeMap.set(n.id, nodeObj);
    return nodeObj;
  });

  graphState.edges = g.edges.map(e => ({
    source: nodeMap.get(e.source),
    target: nodeMap.get(e.target),
    type: e.type
  })).filter(e => e.source && e.target);

  // Events
  canvas.addEventListener("mousedown", e => {
    const rect = canvas.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - graphState.panX) / graphState.scale;
    const mouseY = (e.clientY - rect.top - graphState.panY) / graphState.scale;

    for (const node of graphState.nodes) {
      if (Math.hypot(node.x - mouseX, node.y - mouseY) < node.radius + 6) {
        graphState.dragNode = node;
        graphState.selectedNode = node;
        break;
      }
    }
    graphState.isDragging = true;
    graphState.lastMouseX = e.clientX;
    graphState.lastMouseY = e.clientY;
  });

  window.addEventListener("mousemove", e => {
    if (!graphState.isDragging) return;
    const dx = e.clientX - graphState.lastMouseX;
    const dy = e.clientY - graphState.lastMouseY;
    if (graphState.dragNode) {
      graphState.dragNode.x += dx / graphState.scale;
      graphState.dragNode.y += dy / graphState.scale;
    } else {
      graphState.panX += dx;
      graphState.panY += dy;
    }
    graphState.lastMouseX = e.clientX;
    graphState.lastMouseY = e.clientY;
  });

  window.addEventListener("mouseup", () => {
    graphState.isDragging = false;
    graphState.dragNode = null;
  });

  canvas.addEventListener("wheel", e => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    graphState.scale = Math.min(Math.max(graphState.scale * factor, 0.4), 3.0);
  });

  document.querySelector("#btn-zoom-in").addEventListener("click", () => { graphState.scale = Math.min(graphState.scale * 1.2, 3.0); });
  document.querySelector("#btn-zoom-out").addEventListener("click", () => { graphState.scale = Math.max(graphState.scale / 1.2, 0.4); });
  document.querySelector("#btn-reset-cam").addEventListener("click", () => { graphState.scale = 1; graphState.panX = 0; graphState.panY = 0; });

  startCanvasTick();
}

function startCanvasTick() {
  if (graphState.animId) cancelAnimationFrame(graphState.animId);

  function tick() {
    const ctx = graphState.ctx;
    const w = graphState.width;
    const h = graphState.height;

    // Physics
    const nodes = graphState.nodes;
    const edges = graphState.edges;

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist = Math.hypot(dx, dy) || 1;
        if (dist < 140) {
          const force = (140 - dist) / dist * 0.08;
          if (nodes[i] !== graphState.dragNode) { nodes[i].x -= dx * force; nodes[i].y -= dy * force; }
          if (nodes[j] !== graphState.dragNode) { nodes[j].x += dx * force; nodes[j].y += dy * force; }
        }
      }
    }

    for (const e of edges) {
      const dx = e.target.x - e.source.x;
      const dy = e.target.y - e.source.y;
      const dist = Math.hypot(dx, dy) || 1;
      const force = (dist - 80) * 0.02;
      if (e.source !== graphState.dragNode) { e.source.x += dx / dist * force; e.source.y += dy / dist * force; }
      if (e.target !== graphState.dragNode) { e.target.x -= dx / dist * force; e.target.y -= dy / dist * force; }
    }

    // Render
    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(graphState.panX, graphState.panY);
    ctx.scale(graphState.scale, graphState.scale);

    for (const e of edges) {
      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);
      ctx.lineTo(e.target.x, e.target.y);
      ctx.strokeStyle = e.type === "hasVulnerability" ? "rgba(244, 63, 94, 0.7)" : "rgba(35, 56, 92, 0.4)";
      ctx.lineWidth = e.type === "hasVulnerability" ? 2 : 1;
      ctx.stroke();
    }

    for (const n of nodes) {
      if (n.type === "CVE") {
        ctx.save();
        ctx.translate(n.x, n.y);
        ctx.rotate(Math.PI / 4);
        ctx.fillStyle = "#f43f5e";
        ctx.fillRect(-n.radius / 1.4, -n.radius / 1.4, n.radius * 1.4, n.radius * 1.4);
        ctx.restore();
      } else {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
        ctx.fillStyle = n.color;
        ctx.fill();
      }

      if ((n.risk_score && n.risk_score >= 0.4) || n.type === "CVE") {
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.fillStyle = "#cbd5e1";
        ctx.fillText(n.name || n.id, n.x + n.radius + 4, n.y + 3);
      }
    }

    ctx.restore();
    graphState.animId = requestAnimationFrame(tick);
  }

  graphState.animId = requestAnimationFrame(tick);
}

// ═════════════════════════════════════════════════════════════════════════════
// STEP 4: ACTIONABLE FIX ROADMAP (Remediation)
// ═════════════════════════════════════════════════════════════════════════════
function remediation() {
  getSample().then(data => {
    if (!data) {
      setRoute("/scan");
      return;
    }
    renderRemediationView();
  });
  app.innerHTML = `<p class="section-sub">Loading fix roadmap…</p>`;
}

function renderRemediationView() {
  const remediations = (report && report.remediations) || [];
  const health = computeProjectHealth(report);

  app.innerHTML = `
    <!-- Executive Health Banner -->
    ${renderHealthBanner()}

    <div class="journey-header" style="text-align:left;margin:0 0 20px;">
      <span class="journey-step-tag">Step 4 of 5 · Remediation Roadmap</span>
      <h1>Prioritized Fixes & Patch Simulator</h1>
      <p>Fixing every transitive vulnerability is exhausting. VulnChain prioritizes fixes by <b>Risk Reduction ROI</b>: which upgrades remove the most attack blast radius with the fewest package changes.</p>
    </div>

    <!-- Fix Cards Grid -->
    <div class="remediation-card-grid">
      ${remediations.length ? remediations.map(r => {
        const isPatched = simulatedPatches.has(r.package);
        return `
          <div class="fix-card-item ${isPatched ? 'patched' : ''}">
            <div>
              <div class="fix-header">
                <div>
                  <b style="font-size:16px;color:#fff;display:block;">${esc(r.package)}</b>
                  <span class="advisory-badge" style="margin-top:4px;display:inline-block;">${esc(r.cve)}</span>
                </div>
                <span class="roi-badge">-${r.simulated_risk_reduction_pct}% Risk</span>
              </div>

              <p style="font-size:13px;color:var(--text-muted);margin:12px 0;line-height:1.5;">
                ${esc(r.recommended_action)}
              </p>

              <div style="font-size:12px;color:var(--text-dim);margin-bottom:16px;">
                Shields <b>${r.affected_dependents_count}</b> upstream packages from exploit.
              </div>
            </div>

            <button class="btn-cta ${isPatched ? '' : 'btn-secondary'}" data-patch="${esc(r.package)}" style="width:100%;">
              ${isPatched ? '✓ Patch Applied (Simulated)' : 'Simulate Patch & Upgrade'}
            </button>
          </div>
        `;
      }).join("") : `<div class="card"><p>No remediation targets detected in this project.</p></div>`}
    </div>

    <!-- Next Step Action Bar -->
    <div class="journey-action-bar">
      <div>
        <p>Want to see the scientific proof behind how VulnChain's AI works?</p>
      </div>
      <a href="#/audit" class="btn-cta">Step 5: View AI Model Proof →</a>
    </div>
  `;

  document.querySelectorAll("[data-patch]").forEach(btn => {
    btn.addEventListener("click", () => {
      const pkg = btn.dataset.patch;
      if (simulatedPatches.has(pkg)) simulatedPatches.delete(pkg);
      else simulatedPatches.add(pkg);
      renderRemediationView();
    });
  });
}

// ═════════════════════════════════════════════════════════════════════════════
// STEP 5: AI MODEL VERIFICATION & AUDIT (Plain English Scientific Proof)
// ═════════════════════════════════════════════════════════════════════════════
function audit() {
  getAudit().then(data => {
    if (!data) {
      app.innerHTML = `<p class="section-sub">Loading model verification audit…</p>`;
      return;
    }
    renderAuditView();
  });
  app.innerHTML = `<p class="section-sub">Loading model verification audit…</p>`;
}

function renderAuditView() {
  const projectAudit = (report && report.project_audit && report.project_audit.audit_rows) || [];

  app.innerHTML = `
    <!-- Executive Health Banner -->
    ${renderHealthBanner()}

    <div class="journey-header" style="text-align:left;margin:0 0 20px;">
      <span class="journey-step-tag">Step 5 of 5 · Scientific Verification</span>
      <h1>How Do We Know VulnChain AI Actually Works?</h1>
      <p>In software supply chain security, anyone can write a basic script to look up known CVEs. The critical question is: <b>What happens when vulnerability data is incomplete, delayed, or zero-day?</b></p>
    </div>

    <!-- Plain English Comparison Cards -->
    <div class="audit-explanation-card">
      <h3 style="font-size:18px;color:#fff;margin:0 0 8px;">The Masked-Edge Scientific Test</h3>
      <p style="font-size:14px;color:var(--text-muted);margin:0;line-height:1.6;">
        To prove the AI adds genuine value, we systematically deleted known vulnerability connections from 5,578 software packages and tested whether each system could still detect the hidden risk.
      </p>

      <div class="audit-comparison-row">
        <div class="comparison-box">
          <h4>1. Standard Rule-Based Script (BFS Floor)</h4>
          <span class="comparison-accuracy dim">51.9% Accuracy</span>
          <p class="comparison-desc">
            <b>Fails completely.</b> Because simple scripts only walk known direct edges, deleting the vulnerability connection drops detection accuracy to a coin toss (51.9%).
          </p>
        </div>

        <div class="comparison-box winner">
          <h4>2. VulnChain AI Graph Network (VulnGAT)</h4>
          <span class="comparison-accuracy green">76.4% Accuracy (+24.5% Win)</span>
          <p class="comparison-desc">
            <b>Succeeds.</b> VulnGAT analyzes multi-hop dependency structures to infer risk from neighboring package topology, maintaining 76.4% detection accuracy even when the direct advisory link is missing.
          </p>
        </div>
      </div>
    </div>

    <!-- Live Test On Your Currently Scanned Project -->
    ${projectAudit.length ? `
      <div class="triage-list-card" style="margin-bottom:26px;">
        <h3 style="font-size:16px;color:#fff;margin:0 0 6px;">Live Edge-Masking Test On Your Uploaded Project</h3>
        <p style="font-size:13px;color:var(--text-muted);margin:0 0 16px;">
          Here is what happens if we simulate deleting the advisory links on your project's vulnerable packages:
        </p>

        <table style="width:100%;border-collapse:collapse;font-size:13px;text-align:left;">
          <thead>
            <tr style="border-bottom:1px solid var(--panel-border);color:var(--text-muted);font-family:'JetBrains Mono',monospace;font-size:11px;">
              <th style="padding:10px;">Vulnerable Package</th>
              <th style="padding:10px;">Normal AI Score</th>
              <th style="padding:10px;">AI Score When Link Deleted</th>
              <th style="padding:10px;">Rule-Based Script Floor</th>
              <th style="padding:10px;">AI Advantage</th>
            </tr>
          </thead>
          <tbody>
            ${projectAudit.map(r => `
              <tr style="border-bottom:1px solid rgba(28,44,77,0.4);">
                <td style="padding:12px;font-family:'JetBrains Mono',monospace;color:#fff;">${esc(r.package)}</td>
                <td style="padding:12px;font-family:'JetBrains Mono',monospace;">${Math.round(r.unmasked_model_score * 100)}%</td>
                <td style="padding:12px;font-family:'JetBrains Mono',monospace;color:var(--cyan);font-weight:700;">${Math.round(r.masked_model_score * 100)}%</td>
                <td style="padding:12px;font-family:'JetBrains Mono',monospace;color:var(--text-dim);">${Math.round(r.masked_bfs_floor * 100)}%</td>
                <td style="padding:12px;"><span class="tag-badge" style="background:var(--green-bg);color:var(--green);border-color:var(--green-border);">${r.model_vs_bfs_gain}</span></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    ` : ''}

    <!-- Journey Completed Action Bar -->
    <div class="journey-action-bar">
      <div>
        <p>You have completed the full security journey! Ready to scan another project?</p>
      </div>
      <a href="#/scan" class="btn-cta">Start New Scan ↺</a>
    </div>
  `;
}

// ═════════════════════════════════════════════════════════════════════════════
// ROUTER & INITIALIZATION
// ═════════════════════════════════════════════════════════════════════════════
function render() {
  const current = route();
  nav();
  if (current === "/scan") return scan();
  if (current === "/results") return results();
  if (current === "/graph") return graph();
  if (current === "/remediation") return remediation();
  if (current === "/audit") return audit();
  scan(); // Default to scan flow
}

window.addEventListener("hashchange", render);
render();
