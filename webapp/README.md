# VulnChain Web Frontend

Single-page web UI for the VulnChain supply-chain vulnerability analyzer.
A thin FastAPI wrapper (`server.py`) shells out to the **unchanged**
`phase5/bench_run/analyze_project.py` (VulnGAT model) and serves the built
React frontend from the same port.

## Run (presentation mode)

```bash
# one-time setup
pip install -r webapp/requirements.txt
cd webapp/frontend && npm install && npm run build && cd ../..

# start (Windows)
webapp\start.bat
# or:  python webapp/server.py
```

Open **http://127.0.0.1:8000**, drop a `package-lock.json`, wait for the
model (~1 min on this CPU-only machine for ~130 packages), explore results.

## API

`POST /api/analyze` — multipart file upload, field name `file`.

- Validates before running the model: JSON parse, `lockfileVersion` present,
  `packages`/`dependencies` present. Yarn/pnpm files are rejected by name.
- 400 = bad file · 502 = analyzer failure · 504 = timeout (120 s, matches
  the proven timeout in `phase5/demo/demo_runner.py`).
- Response = the analyzer's report **verbatim** (`total_packages`, `summary`,
  `packages[]`) plus `request_id` and `timestamp`.

## Files

| Path | Purpose |
|---|---|
| `server.py` | FastAPI wrapper: validation, subprocess, timeout, static hosting |
| `requirements.txt` | fastapi, uvicorn, python-multipart |
| `start.bat` / `start.sh` | one-command launch |
| `frontend/src/tiers.js` | tier cutoffs **mirrored verbatim** from the script (≥0.40 critical, ≥0.20 high, ≥0.08 moderate, else no known risk) |
| `frontend/src/api.js` | upload client + client-side pre-validation |
| `frontend/src/App.jsx` | phase machine: upload → loading → results / error |
| `frontend/src/components/` | UploadZone, LoadingView, ErrorPanel, SummaryBar, PackageTable, ResultsView |

## Design guarantees (per spec)

- `summary` counts and `risk_score` are displayed **verbatim** from the
  analyzer — the frontend never recomputes them. Row tiers use only the
  script's own cutoffs (see `tiers.js`).
- `has_vuln_descendant` shows "a downstream dependency is vulnerable" —
  no dependency path is invented (the backend provides none).
- `cap_applied` shows a note that the score was adjusted downward by the
  post-hoc calibration step.
- No caching, no history, no auth — upload → analyze → results only.
- Errors covered: non-JSON file, non-npm JSON, yarn/pnpm lockfiles, backend
  crash/timeout, server unreachable.
