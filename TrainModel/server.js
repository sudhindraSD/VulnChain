const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFile } = require("child_process");
const { promisify } = require("util");

const root = __dirname;
const sample = JSON.parse(fs.readFileSync(path.join(root, "results.json"), "utf8"));
const runFile = promisify(execFile);
const python = fs.existsSync(path.join(root, "venv", "Scripts", "python.exe"))
  ? path.join(root, "venv", "Scripts", "python.exe")
  : "python";
const analyzer = path.join(root, "analyze_project.py");
const auditScript = path.join(root, "masked_edge_audit.py");
const auditResultsPath = path.join(root, "masked_edge_audit_results.json");

function send(res, status, body, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": `${type}; charset=utf-8`,
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}

async function analyzeWithVulnGAT(lockfile) {
  if (!fs.existsSync(analyzer)) throw new Error("The VulnGAT analyzer script is missing.");
  const jobDir = fs.mkdtempSync(path.join(os.tmpdir(), "vulnchain-"));
  const inputPath = path.join(jobDir, "package-lock.json");
  const outputPath = path.join(jobDir, "report.json");
  fs.writeFileSync(inputPath, lockfile, "utf8");
  try {
    await runFile(python, [analyzer, inputPath, "--json", outputPath], {
      cwd: root,
      timeout: 300_000,
      windowsHide: true,
      maxBuffer: 4 * 1024 * 1024,
    });
    const report = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    return { ...report, mode: "model-inference" };
  } finally {
    fs.rmSync(jobDir, { recursive: true, force: true });
  }
}

async function runLiveAudit() {
  if (!fs.existsSync(auditScript)) throw new Error("The masked_edge_audit.py script is missing.");
  await runFile(python, [auditScript], {
    cwd: root,
    timeout: 300_000,
    windowsHide: true,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (fs.existsSync(auditResultsPath)) {
    return JSON.parse(fs.readFileSync(auditResultsPath, "utf8"));
  }
  throw new Error("Audit finished but results file was not found.");
}

const types = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const server = http.createServer((req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    return res.end();
  }

  // Sample results endpoint
  if (req.method === "GET" && req.url === "/api/sample") {
    return send(res, 200, { ...sample, mode: "model-sample" });
  }

  // Presets list endpoint
  if (req.method === "GET" && req.url === "/api/presets") {
    const presets = [
      { id: "demo-test", name: "VulnChain Demo Test (17 pkgs, v3)", file: "target_package_lock.json" },
      { id: "airtwin", name: "Airtwin Backend (139 pkgs, v2)", file: "user_package_lock.json" },
      { id: "sample-app", name: "Sample Test App (5 pkgs, v2)", file: "sample_test_lock.json" },
      { id: "benchmark", name: "Default Benchmark Pilot (113 pkgs)", file: "results.json" },
    ];
    return send(res, 200, presets);
  }

  // Load preset content endpoint
  if (req.method === "GET" && req.url.startsWith("/api/preset/")) {
    const presetId = req.url.replace("/api/preset/", "").trim();
    let targetFile = null;
    if (presetId === "demo-test") targetFile = "target_package_lock.json";
    else if (presetId === "airtwin") targetFile = "user_package_lock.json";
    else if (presetId === "sample-app") targetFile = "sample_test_lock.json";

    if (targetFile && fs.existsSync(path.join(root, targetFile))) {
      const content = fs.readFileSync(path.join(root, targetFile), "utf8");
      return send(res, 200, { filename: targetFile, content });
    }
    return send(res, 404, { error: "Preset not found" });
  }

  // Audit results endpoint
  if (req.method === "GET" && req.url === "/api/audit") {
    if (fs.existsSync(auditResultsPath)) {
      try {
        const auditData = JSON.parse(fs.readFileSync(auditResultsPath, "utf8"));
        return send(res, 200, auditData);
      } catch (err) {
        return send(res, 500, { error: "Failed to parse audit results" });
      }
    }
    return send(res, 404, { error: "Audit results not found. Run the audit script first." });
  }

  // Trigger live audit endpoint
  if (req.method === "POST" && req.url === "/api/audit/run") {
    runLiveAudit()
      .then((data) => send(res, 200, data))
      .catch((err) => {
        console.error("Live audit failed:", err);
        send(res, 500, { error: err.message || "Live audit failed" });
      });
    return;
  }

  // Analyze package-lock.json endpoint
  if (req.method === "POST" && req.url === "/api/analyze") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 15_000_000) req.destroy();
    });
    req.on("end", async () => {
      try {
        JSON.parse(body);
        const result = await analyzeWithVulnGAT(body);
        return send(res, 200, result);
      } catch (error) {
        console.error("VulnGAT scan failed:", error.message, error.stderr || "");
        const detail = error.killed
          ? "Model inference exceeded the five-minute limit."
          : error.message || "The model could not analyze that lockfile.";
        return send(res, 400, { error: detail });
      }
    });
    return;
  }

  const requested = req.url === "/" ? "/web/index.html" : req.url;
  const file = path.normalize(path.join(root, requested));
  if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    return send(res, 404, "Not found", "text/plain");
  }
  send(res, 200, fs.readFileSync(file), types[path.extname(file)] || "application/octet-stream");
});

const PORT = 4173;
function startServer() {
  server.listen(PORT, () => console.log(`VulnChain is running at http://localhost:${PORT}`));
}
server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.log(`Port ${PORT} busy — killing old process...`);
    const { execSync } = require("child_process");
    try {
      execSync(`for /f "tokens=5" %a in ('netstat -aon ^| findstr :${PORT} ^| findstr LISTENING') do taskkill /F /PID %a`, { shell: "cmd.exe", stdio: "ignore" });
    } catch {}
    setTimeout(startServer, 500);
  } else throw err;
});
startServer();
