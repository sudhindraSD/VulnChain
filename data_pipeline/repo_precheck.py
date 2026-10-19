"""
VulnChain Repo Pre-Check v2 — Lockfile Compatibility Scanner
--------------------------------------------------------------
Validates candidate GitHub repos BEFORE cloning by checking the GitHub
API for repo existence, identity, lockfile presence/format, and monorepo
risk signals.

v2 changes (vs v1):
  - Separates NOT_FOUND (repo 404) from NO_LOCKFILE (repo exists, no lockfile)
  - Verifies repo identity: shows description, language, fork status so
    wrong-owner inputs are visible, not silently folded into MISSING
  - Checks .gitignore for lockfile exclusion (checkable fact, not inference)
  - UNRESOLVED status for repos that can't be confidently categorized
  - Every status is backed by what was actually checked, not inferred

Stdlib only — no pip install required. Matches project convention.

Usage:
    python repo_precheck.py                      # uses built-in CANDIDATES list
    python repo_precheck.py candidates.txt       # one owner/repo per line
    python repo_precheck.py --json               # machine-readable JSON output

Environment:
    GITHUB_TOKEN  — set in .env or environment. Unauthenticated API allows
                    only 60 requests/hour; authenticated allows 5,000.

Status categories:
    OK          — Repo exists, has package-lock.json with parseable lockfileVersion,
                  no conflicting lockfiles.
    RISKY       — Repo exists, but has risk signals (yarn.lock, pnpm-lock.yaml,
                  workspaces, or unparseable lockfileVersion).
    NO_LOCKFILE — Repo exists, confirmed as a JS/TS project, but no
                  package-lock.json at root. .gitignore checked for cause.
    NOT_FOUND   — The owner/repo returned 404 from GitHub. Repo does not exist,
                  was deleted, is private, or the owner/name is wrong.
    UNRESOLVED  — Repo exists but identity can't be confirmed as a JS/TS project
                  (no package.json, language mismatch). May be wrong repo.
    ERROR       — API or network error during checks.
"""

import json
import os
import re
import sys
import time
import base64
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

# Fix Windows console encoding (cp1252 can't handle emoji/unicode)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"

# Rate-limit backoff settings
INITIAL_BACKOFF_SECONDS = 5
MAX_BACKOFF_SECONDS = 120
MAX_RETRIES = 4

# ---------------------------------------------------------------------------
# Default candidate list — edit this or pass a file as argv[1]
# ---------------------------------------------------------------------------
DEFAULT_CANDIDATES = []


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def load_github_token() -> str | None:
    """Load GITHUB_TOKEN from .env file or environment."""
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token.strip()

    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() == "GITHUB_TOKEN":
                return value.strip()
    return None


GITHUB_TOKEN = load_github_token()


def github_api_request(url: str, accept: str = "application/vnd.github.v3+json") -> dict | list | None:
    """
    Make a GitHub API request with token auth and rate-limit backoff.
    Returns parsed JSON (dict/list) or None on 404.
    Raises on unrecoverable errors.
    """
    headers = {"Accept": accept, "User-Agent": "VulnChain-PreCheck/2.0"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    backoff = INITIAL_BACKOFF_SECONDS
    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429):
                retry_after = e.headers.get("Retry-After")
                reset_time = e.headers.get("x-ratelimit-reset")

                if retry_after:
                    wait = int(retry_after) + 1
                elif reset_time:
                    wait = max(int(reset_time) - int(time.time()) + 1, backoff)
                else:
                    wait = backoff

                wait = min(wait, MAX_BACKOFF_SECONDS)
                remaining = e.headers.get("x-ratelimit-remaining", "?")
                print(f"  [rate-limit] remaining={remaining}, "
                      f"waiting {wait}s (attempt {attempt + 1}/{MAX_RETRIES + 1})...",
                      file=sys.stderr)
                time.sleep(wait)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue
            raise
        except urllib.error.URLError as e:
            if attempt < MAX_RETRIES:
                print(f"  [network error] {e.reason}. Retrying in {backoff}s...",
                      file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue
            raise

    raise RuntimeError(f"Exhausted {MAX_RETRIES + 1} attempts for {url}")


def get_file_content(owner: str, repo: str, path: str) -> bytes | None:
    """
    Fetch file content from GitHub via the Contents API.
    Returns raw bytes or None if the file doesn't exist.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    result = github_api_request(url)

    if result is None:
        return None
    if not isinstance(result, dict):
        return None

    encoding = result.get("encoding")
    content = result.get("content")

    if encoding == "base64" and content:
        return base64.b64decode(content)

    # For files > 1 MB, content is null — use download_url
    download_url = result.get("download_url")
    if download_url:
        headers = {"User-Agent": "VulnChain-PreCheck/2.0"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"
        req = urllib.request.Request(download_url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError):
            return None

    return None


# ---------------------------------------------------------------------------
# Repo metadata
# ---------------------------------------------------------------------------

def get_repo_metadata(owner: str, repo: str) -> dict | None:
    """
    Fetch repo metadata from GET /repos/{owner}/{repo}.
    Returns dict with identity fields or None if repo doesn't exist (404).
    """
    url = f"https://api.github.com/repos/{owner}/{repo}"
    raw = github_api_request(url)
    if raw is None or not isinstance(raw, dict):
        return None

    return {
        "full_name": raw.get("full_name", f"{owner}/{repo}"),
        "description": raw.get("description") or "",
        "language": raw.get("language"),
        "topics": raw.get("topics", []),
        "is_fork": raw.get("fork", False),
        "parent_full_name": (raw.get("parent") or {}).get("full_name"),
        "is_archived": raw.get("archived", False),
        "default_branch": raw.get("default_branch"),
        "stargazers_count": raw.get("stargazers_count", 0),
        "pushed_at": raw.get("pushed_at"),
    }


# ---------------------------------------------------------------------------
# File analysis helpers
# ---------------------------------------------------------------------------

def extract_lockfile_version(raw: bytes) -> int | None:
    """
    Extract lockfileVersion from package-lock.json content.
    Returns int (1, 2, or 3) or None if unparseable.
    """
    try:
        data = json.loads(raw)
        v = data.get("lockfileVersion")
        if v is not None:
            return int(v)
        # lockfileVersion absent → npm v5 era, effectively version 1
        return 1
    except (json.JSONDecodeError, ValueError):
        pass

    # JSON may be truncated (large files via download_url). Regex fallback.
    text = raw.decode("utf-8", errors="replace")[:4096]
    m = re.search(r'"lockfileVersion"\s*:\s*(\d+)', text)
    if m:
        return int(m.group(1))

    if text.lstrip().startswith("{"):
        return 1

    return None


def detect_yarn_berry(raw: bytes) -> bool:
    """
    Detect if a yarn.lock is Yarn Berry (v2+) format.
    Checked: presence of '__metadata:' key in first 4KB of yarn.lock.
    Classic Yarn v1 starts with '# yarn lockfile v1'.
    """
    text = raw.decode("utf-8", errors="replace")[:4096]
    if "__metadata:" in text:
        return True
    return False


def check_gitignore_for_lockfile(owner: str, repo: str) -> bool | None:
    """
    Check if .gitignore excludes package-lock.json.
    Returns:
      True  — .gitignore exists and contains a line matching package-lock
      False — .gitignore exists but does not exclude package-lock
      None  — no .gitignore at repo root
    Checked: substring 'package-lock' in non-comment lines of .gitignore.
    """
    raw = get_file_content(owner, repo, ".gitignore")
    if raw is None:
        return None
    text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if "package-lock" in line:
            return True
    return False


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class RepoCheckResult:
    """Result of checking a single repo."""

    def __init__(self, owner_repo: str):
        self.owner_repo = owner_repo
        self.status = "UNKNOWN"

        # Repo identity (from GET /repos/{owner}/{repo})
        self.repo_exists = False
        self.repo_description = None
        self.repo_language = None
        self.repo_topics = []
        self.repo_is_fork = False
        self.repo_parent = None          # "owner/repo" of fork parent
        self.repo_is_archived = False
        self.repo_stars = None
        self.repo_default_branch = None
        self.repo_pushed_at = None

        # File check results
        self.has_package_json = False
        self.has_package_lock = False
        self.lockfile_version = None
        self.has_yarn_lock = False
        self.yarn_is_berry = None        # True/False/None
        self.has_pnpm_lock = False
        self.has_workspaces = False
        self.workspaces_value = None
        self.gitignore_excludes_lockfile = None  # True/False/None

        # Diagnostics
        self.risk_reasons = []
        self.notes = []                  # factual observations
        self.evidence = []               # what was checked to support each conclusion
        self.error = None

    def to_dict(self) -> dict:
        d = {
            "repo": self.owner_repo,
            "status": self.status,
            "repo_exists": self.repo_exists,
            "repo_description": self.repo_description,
            "repo_language": self.repo_language,
            "repo_is_fork": self.repo_is_fork,
            "repo_parent": self.repo_parent,
            "repo_is_archived": self.repo_is_archived,
            "repo_stars": self.repo_stars,
            "lockfileVersion": self.lockfile_version,
            "has_package_json": self.has_package_json,
            "has_package_lock": self.has_package_lock,
            "has_yarn_lock": self.has_yarn_lock,
            "yarn_is_berry": self.yarn_is_berry,
            "has_pnpm_lock": self.has_pnpm_lock,
            "has_workspaces": self.has_workspaces,
            "gitignore_excludes_lockfile": self.gitignore_excludes_lockfile,
            "risk_reasons": self.risk_reasons,
            "notes": self.notes,
            "evidence": self.evidence,
        }
        if self.error:
            d["error"] = self.error
        return d


# ---------------------------------------------------------------------------
# Core check logic
# ---------------------------------------------------------------------------

def check_repo(owner_repo: str) -> RepoCheckResult:
    """
    Run all pre-checks on a single repo.

    Check order:
    1. Validate input format
    2. Check repo existence via GET /repos/{owner}/{repo} (NOT_FOUND if 404)
    3. Store repo metadata for identity verification
    4. Check package.json (confirms JS/TS project)
    5. Check package-lock.json (+ extract lockfileVersion)
    6. Check yarn.lock (+ detect Berry vs Classic)
    7. Check pnpm-lock.yaml
    8. If no lockfile found, check .gitignore for exclusion patterns
    9. Determine status from collected evidence
    """
    result = RepoCheckResult(owner_repo)

    try:
        owner, repo = owner_repo.strip().split("/", 1)
    except ValueError:
        result.status = "ERROR"
        result.error = f"Invalid format: expected 'owner/repo', got '{owner_repo}'"
        return result

    try:
        # ----- Step 1: Repo existence -----
        meta = get_repo_metadata(owner, repo)
        if meta is None:
            result.status = "NOT_FOUND"
            result.repo_exists = False
            result.evidence.append(
                f"GET /repos/{owner}/{repo} returned 404 — repo does not exist, "
                f"is private, or owner/name is wrong"
            )
            return result

        # Store identity for verification
        result.repo_exists = True
        result.repo_description = meta["description"]
        result.repo_language = meta["language"]
        result.repo_topics = meta["topics"]
        result.repo_is_fork = meta["is_fork"]
        result.repo_parent = meta["parent_full_name"]
        result.repo_is_archived = meta["is_archived"]
        result.repo_stars = meta["stargazers_count"]
        result.repo_default_branch = meta["default_branch"]
        result.repo_pushed_at = meta["pushed_at"]

        result.evidence.append(
            f"Repo exists: language={meta['language']}, "
            f"stars={meta['stargazers_count']}, "
            f"fork={meta['is_fork']}, "
            f"archived={meta['is_archived']}"
        )

        if result.repo_is_fork:
            result.notes.append(f"Fork of {result.repo_parent}")

        if result.repo_is_archived:
            result.notes.append("Repository is archived")

        # ----- Step 2: package.json -----
        pkg_json_raw = get_file_content(owner, repo, "package.json")
        if pkg_json_raw is not None:
            result.has_package_json = True
            result.evidence.append("Checked: GET /repos/.../contents/package.json → exists")
            try:
                pkg_data = json.loads(pkg_json_raw)
                workspaces = pkg_data.get("workspaces")
                if workspaces:
                    result.has_workspaces = True
                    if isinstance(workspaces, dict):
                        ws_display = workspaces.get("packages", workspaces)
                    else:
                        ws_display = workspaces
                    result.workspaces_value = ws_display
                    ws_count = len(ws_display) if isinstance(ws_display, list) else "?"
                    result.risk_reasons.append(
                        f"workspaces field in package.json ({ws_count} patterns) "
                        f"— monorepo; root lockfile may not cover all packages"
                    )
                    result.evidence.append(
                        f"Checked: package.json parsed, 'workspaces' key present with {ws_count} entries"
                    )
            except json.JSONDecodeError:
                result.notes.append("package.json exists but is not valid JSON")
        else:
            result.evidence.append("Checked: GET /repos/.../contents/package.json → 404 (not found)")

        # ----- Step 3: package-lock.json -----
        lockfile_raw = get_file_content(owner, repo, "package-lock.json")
        if lockfile_raw is not None:
            result.has_package_lock = True
            result.lockfile_version = extract_lockfile_version(lockfile_raw)
            result.evidence.append(
                f"Checked: GET /repos/.../contents/package-lock.json → exists, "
                f"lockfileVersion={result.lockfile_version}"
            )
            if result.lockfile_version is None:
                result.risk_reasons.append(
                    "package-lock.json exists but lockfileVersion could not be parsed"
                )
        else:
            result.evidence.append("Checked: GET /repos/.../contents/package-lock.json → 404 (not found)")

        # ----- Step 4: yarn.lock -----
        yarn_raw = get_file_content(owner, repo, "yarn.lock")
        if yarn_raw is not None:
            result.has_yarn_lock = True
            result.yarn_is_berry = detect_yarn_berry(yarn_raw)
            if result.yarn_is_berry:
                result.risk_reasons.append(
                    "yarn.lock is Yarn Berry (v2+) format — parser incompatible "
                    "(checked: '__metadata:' found in first 4KB of yarn.lock)"
                )
            else:
                result.risk_reasons.append(
                    "yarn.lock present (Yarn Classic v1) — parser expects package-lock.json"
                )
            result.evidence.append(
                f"Checked: GET /repos/.../contents/yarn.lock → exists, "
                f"berry={'yes (__metadata: found)' if result.yarn_is_berry else 'no'}"
            )
        else:
            result.evidence.append("Checked: GET /repos/.../contents/yarn.lock → 404 (not found)")

        # ----- Step 5: pnpm-lock.yaml -----
        pnpm_raw = get_file_content(owner, repo, "pnpm-lock.yaml")
        if pnpm_raw is not None:
            result.has_pnpm_lock = True
            result.risk_reasons.append("pnpm-lock.yaml present — parser incompatible")
            result.evidence.append("Checked: GET /repos/.../contents/pnpm-lock.yaml → exists")
        else:
            result.evidence.append("Checked: GET /repos/.../contents/pnpm-lock.yaml → 404 (not found)")

        # ----- Step 6: .gitignore check (only if no package-lock.json) -----
        if not result.has_package_lock:
            gi_result = check_gitignore_for_lockfile(owner, repo)
            result.gitignore_excludes_lockfile = gi_result
            if gi_result is True:
                result.evidence.append(
                    "Checked: .gitignore contains a line matching 'package-lock' — "
                    "lockfile is actively excluded from version control"
                )
                result.notes.append(
                    "package-lock.json is gitignored (verified: .gitignore contains "
                    "'package-lock' pattern). Running 'npm install' after clone would "
                    "generate one locally."
                )
            elif gi_result is False:
                result.evidence.append(
                    "Checked: .gitignore exists but does NOT contain 'package-lock' — "
                    "lockfile absence is not due to gitignore"
                )
            else:
                result.evidence.append(
                    "Checked: no .gitignore at repo root — cannot determine if "
                    "lockfile is excluded by policy"
                )

        # ----- Step 7: Determine status -----
        if result.error:
            result.status = "ERROR"

        elif not result.has_package_json:
            # Repo exists but no package.json → can't confirm it's a JS/TS project
            js_languages = {"JavaScript", "TypeScript", "CoffeeScript"}
            if result.repo_language in js_languages:
                # Language says JS/TS but no package.json at root — unusual
                result.status = "UNRESOLVED"
                result.notes.append(
                    f"Repo language is '{result.repo_language}' but no package.json at root. "
                    f"May be a non-npm JS project, or package.json is in a subdirectory."
                )
            else:
                result.status = "UNRESOLVED"
                result.notes.append(
                    f"No package.json at root and repo language is "
                    f"'{result.repo_language or 'null'}'. "
                    f"Cannot confirm this is an npm/Node.js project — may be wrong repo."
                )

        elif result.has_package_lock and result.lockfile_version is not None and not result.risk_reasons:
            result.status = "OK"

        elif result.risk_reasons:
            result.status = "RISKY"

        elif not result.has_package_lock:
            result.status = "NO_LOCKFILE"

        else:
            result.status = "UNRESOLVED"
            result.notes.append("Could not confidently categorize this repo")

    except Exception as e:
        result.status = "ERROR"
        result.error = str(e)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

STATUS_ICONS = {
    "OK":          "  OK       ",
    "NO_LOCKFILE": "  NO_LOCK  ",
    "RISKY":       "  RISKY    ",
    "NOT_FOUND":   "  NOT_FOUND",
    "UNRESOLVED":  "  UNRESOLVD",
    "ERROR":       "  ERROR    ",
    "UNKNOWN":     "  UNKNOWN  ",
}

STATUS_MARKERS = {
    "OK":          "[+]",
    "NO_LOCKFILE": "[-]",
    "RISKY":       "[!]",
    "NOT_FOUND":   "[X]",
    "UNRESOLVED":  "[?]",
    "ERROR":       "[E]",
    "UNKNOWN":     "[?]",
}


def truncate(s: str, maxlen: int) -> str:
    if not s:
        return ""
    if len(s) <= maxlen:
        return s
    return s[:maxlen - 3] + "..."


def print_table(results: list[RepoCheckResult]) -> None:
    """Print formatted results with identity verification info."""
    max_repo = max((len(r.owner_repo) for r in results), default=20)
    max_repo = max(max_repo, 15)
    desc_width = 45

    # Header
    print()
    print("=" * (max_repo + 100))
    print(f"  VulnChain Repo Pre-Check v2 — {len(results)} repos scanned")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Auth: {'token (5,000 req/hr)' if GITHUB_TOKEN else 'NONE (60 req/hr)'}")
    print("=" * (max_repo + 100))

    # Summary counts
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    parts = []
    for s in ["OK", "RISKY", "NO_LOCKFILE", "NOT_FOUND", "UNRESOLVED", "ERROR"]:
        if counts.get(s, 0) > 0:
            parts.append(f"{counts[s]} {s}")
    print(f"  Summary: {' | '.join(parts)}")
    print()

    # Table header
    hdr = (f"  {'Repo':<{max_repo}}  {'Status':<12} {'LkV':>3} "
           f" {'Lang':<12} {'Description':<{desc_width}} {'Flags'}")
    print(hdr)
    print(f"  {'─' * max_repo}  {'─' * 12} {'─' * 3} "
          f" {'─' * 12} {'─' * desc_width} {'─' * 30}")

    # Rows
    for r in results:
        marker = STATUS_MARKERS.get(r.status, "[?]")
        icon = STATUS_ICONS.get(r.status, r.status)
        lockver = str(r.lockfile_version) if r.lockfile_version is not None else " —"
        lang = (r.repo_language or "—")[:12]
        desc = truncate(r.repo_description or "", desc_width)

        flags = []
        if r.has_yarn_lock:
            berry_tag = "Berry" if r.yarn_is_berry else "Classic"
            flags.append(f"yarn({berry_tag})")
        if r.has_pnpm_lock:
            flags.append("pnpm")
        if r.has_workspaces:
            ws_count = len(r.workspaces_value) if isinstance(r.workspaces_value, list) else "?"
            flags.append(f"ws({ws_count})")
        if r.repo_is_fork:
            flags.append("fork")
        if r.repo_is_archived:
            flags.append("archived")
        if r.gitignore_excludes_lockfile:
            flags.append("gitignored")
        if r.error:
            flags.append(f"ERR:{r.error[:25]}")

        flag_str = ", ".join(flags) if flags else ""
        print(f"{marker}{r.owner_repo:<{max_repo}}  {icon} {lockver:>3} "
              f" {lang:<12} {desc:<{desc_width}} {flag_str}")

    print()

    # ---- NOT_FOUND detail ----
    not_found = [r for r in results if r.status == "NOT_FOUND"]
    if not_found:
        print("─" * (max_repo + 100))
        print("  [X] NOT_FOUND — These repos returned 404. They do not exist, are private,")
        print("      or the owner/repo name is wrong. No file checks were performed.")
        print()
        for r in not_found:
            print(f"  {r.owner_repo}")
            for ev in r.evidence:
                print(f"    Evidence: {ev}")
            print()

    # ---- RISKY detail ----
    risky = [r for r in results if r.status == "RISKY"]
    if risky:
        print("─" * (max_repo + 100))
        print("  [!] RISKY — These repos have risk signals that may cause parser failure:")
        print()
        for r in risky:
            desc_line = f' — "{r.repo_description}"' if r.repo_description else ""
            print(f"  {r.owner_repo}{desc_line}")
            for reason in r.risk_reasons:
                print(f"    Risk: {reason}")
            for note in r.notes:
                print(f"    Note: {note}")
            print()

    # ---- NO_LOCKFILE detail ----
    no_lock = [r for r in results if r.status == "NO_LOCKFILE"]
    if no_lock:
        print("─" * (max_repo + 100))
        print("  [-] NO_LOCKFILE — Repo exists and has package.json, but no package-lock.json:")
        print()
        for r in no_lock:
            desc_line = f' — "{r.repo_description}"' if r.repo_description else ""
            print(f"  {r.owner_repo}{desc_line}")
            if r.gitignore_excludes_lockfile is True:
                print(f"    Cause: package-lock.json is gitignored (verified in .gitignore)")
            elif r.gitignore_excludes_lockfile is False:
                print(f"    Cause: .gitignore exists but does NOT exclude package-lock — "
                      f"lockfile may never have existed or was removed")
            else:
                print(f"    Cause: no .gitignore found — cannot determine exclusion policy")
            for note in r.notes:
                print(f"    Note: {note}")
            print()

    # ---- UNRESOLVED detail ----
    unresolved = [r for r in results if r.status == "UNRESOLVED"]
    if unresolved:
        print("─" * (max_repo + 100))
        print("  [?] UNRESOLVED — Cannot confirm these are usable npm/Node.js projects:")
        print()
        for r in unresolved:
            desc_line = f' — "{r.repo_description}"' if r.repo_description else ""
            print(f"  {r.owner_repo}{desc_line}")
            for note in r.notes:
                print(f"    Reason: {note}")
            print()

    # ---- Evidence dump for all checked repos ----
    print("─" * (max_repo + 100))
    print("  Evidence log (what was actually checked per repo):")
    print()
    for r in results:
        print(f"  {r.owner_repo} [{r.status}]:")
        for ev in r.evidence:
            print(f"    {ev}")
        print()


def print_json(results: list[RepoCheckResult]) -> None:
    """Print machine-readable JSON output."""
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "tool_version": "2.0",
        "total": len(results),
        "summary": counts,
        "results": [r.to_dict() for r in results],
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_candidates(filepath: str) -> list[str]:
    """Load owner/repo list from a text file (one per line, # comments allowed)."""
    candidates = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                candidates.append(line)
    return candidates


def main():
    json_mode = "--json" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if args:
        candidates = load_candidates(args[0])
    else:
        candidates = DEFAULT_CANDIDATES

    if not candidates:
        print("No candidates to check. Either:")
        print("  1. Edit DEFAULT_CANDIDATES in this script, or")
        print("  2. Pass a file:  python repo_precheck.py candidates.txt")
        print()
        print("File format: one owner/repo per line (e.g., 'expressjs/express')")
        sys.exit(1)

    if not json_mode:
        print(f"\nVulnChain Pre-Check v2: scanning {len(candidates)} repos...")
        if not GITHUB_TOKEN:
            print("WARNING: No GITHUB_TOKEN found — rate limit is 60 requests/hour.")
            print("   Set GITHUB_TOKEN in .env or environment for 5,000 req/hr.\n")
        # Estimate API calls: ~6 per repo (metadata + 4 files + maybe gitignore)
        est_calls = len(candidates) * 6
        print(f"  Estimated API calls: ~{est_calls} "
              f"(rate limit: {'5,000' if GITHUB_TOKEN else '60'}/hr)\n")

    results = []
    for i, candidate in enumerate(candidates):
        if not json_mode:
            print(f"  [{i + 1}/{len(candidates)}] {candidate}...", end=" ", flush=True)

        result = check_repo(candidate)
        results.append(result)

        if not json_mode:
            print(result.status)

        # Small delay to be polite to the API
        if i < len(candidates) - 1:
            time.sleep(0.3)

    if json_mode:
        print_json(results)
    else:
        print_table(results)


if __name__ == "__main__":
    main()
