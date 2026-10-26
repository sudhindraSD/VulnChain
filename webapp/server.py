"""
VulnChain web backend — a thin FastAPI wrapper around phase5/bench_run/analyze_project.py.

One endpoint, POST /api/analyze:
  - accepts a multipart file upload
  - validates it is JSON and looks like an npm lockfile (lockfileVersion + packages/dependencies)
  - rejects yarn.lock / pnpm-lock.yaml explicitly
  - shells out to analyze_project.py (unchanged) via its --json output mode
  - returns the script's report verbatim plus a request id and timestamp

analyze_project.py's logic is NOT modified — it is invoked as a subprocess with its
own cwd (phase5/bench_run) so its relative paths (models/, vulnchain_graph.json) resolve.

Run:  python server.py   (serves API on :8000 and the built frontend from frontend/dist)
"""

import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENCH_RUN = PROJECT_ROOT / "phase5" / "bench_run"
ANALYZE_PY = BENCH_RUN / "analyze_project.py"
FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

# analyze_project.py performs live OSV lookups + GNN inference; on this machine torch
# is CPU-only (~60s for 132 packages). 120s matches the proven timeout in
# phase5/demo/demo_runner.py. Lower it if running with CUDA-enabled torch.
SCRIPT_TIMEOUT_S = 120
MAX_UPLOAD_BYTES = 15 * 1024 * 1024

# npm-only. Detected by filename before anything else so yarn/pnpm users get a
# pointed message instead of a confusing parse error.
UNSUPPORTED_LOCKFILES = {"yarn.lock": "Yarn", "pnpm-lock.yaml": "pnpm"}

app = FastAPI(title="VulnChain analyzer")


class ValidationError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)


def _looks_like_npm_lockfile(data) -> str | None:
    """Return a human-readable problem, or None if the JSON looks like an npm lockfile."""
    if not isinstance(data, dict):
        return "File is valid JSON but not an npm lockfile (expected a JSON object)."
    if "lockfileVersion" not in data:
        return "Missing \"lockfileVersion\" — this does not look like an npm package-lock.json."
    if not ("packages" in data or "dependencies" in data):
        return "Missing \"packages\"/\"dependencies\" — this does not look like an npm package-lock.json."
    return None


async def _run_analyzer(lock_path: Path, out_path: Path) -> dict:
    """Run analyze_project.py as a subprocess and return its parsed --json output."""
    cmd = [sys.executable, str(ANALYZE_PY), str(lock_path), "--json", str(out_path)]
    if os.environ.get("VULNCHAIN_OFFLINE") == "1":
        cmd.append("--offline")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(BENCH_RUN),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=SCRIPT_TIMEOUT_S)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise HTTPException(
            status_code=504,
            detail=f"Analysis timed out after {SCRIPT_TIMEOUT_S}s. The model may be busy — try again.",
        )

    if not out_path.exists():
        excerpt = (stderr or b"").decode("utf-8", "replace").strip()[-600:]
        raise HTTPException(
            status_code=502,
            detail="The analyzer failed to produce a report."
                   + (f" Script error: {excerpt}" if excerpt else ""),
        )

    try:
        with open(out_path, encoding="utf-8") as f:
            report = json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="The analyzer produced non-JSON output.")

    if not isinstance(report, dict) or "summary" not in report or "packages" not in report:
        raise HTTPException(status_code=502, detail="The analyzer output did not match the expected report schema.")
    return report


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    filename = (file.filename or "").strip().lower()

    # 1. Reject unsupported lockfile managers by name, before any parsing.
    for bad_name, manager in UNSUPPORTED_LOCKFILES.items():
        if bad_name in filename:
            raise ValidationError(
                f"\"{file.filename}\" is a {manager} lockfile. "
                "Only npm package-lock.json is supported — generate one with `npm install` in the project."
            )

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValidationError("File too large (over 15 MB).")
    if not raw:
        raise ValidationError("Uploaded file is empty.")

    # 2. Must be valid JSON.
    try:
        data = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(
            f"File is not valid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno}). "
            "package-lock.json must be a valid JSON file."
        )

    # 3. Must look like an npm lockfile, before spending time on the model.
    problem = _looks_like_npm_lockfile(data)
    if problem:
        raise ValidationError(problem)

    # 4. Run the untouched analyzer script.
    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnchain_"))
    lock_path = tmp_dir / "package-lock.json"
    out_path = tmp_dir / "report.json"
    try:
        lock_path.write_bytes(raw)
        report = await _run_analyzer(lock_path, out_path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return {
        "request_id": uuid.uuid4().hex[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **report,
    }


# --- Static frontend (production build) ---------------------------------------

if FRONTEND_DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/")
    async def index():
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.exception_handler(404)
    async def spa_fallback(request, exc):
        # SPA fallback so a refresh on a client route still serves the app.
        return FileResponse(FRONTEND_DIST / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
