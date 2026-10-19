"""
VulnChain Batch 2 — Deep Repo Finder
--------------------------------------
Searches for candidate repos across 3 tiers using:
  - You.com Search API (web search for vulnerable apps, supply chain incidents)
  - GitHub Search API (topics, code search, advisory DB)
  - OSV.dev API (npm vulnerability ecosystem data)

Then runs each candidate through the precheck pipeline to verify lockfile
status.

Usage:
    python find_repos.py                    # run all searches + precheck
    python find_repos.py --search-only      # search only, skip precheck
    python find_repos.py --precheck-only    # precheck candidates_batch2.txt

Output: candidates_batch2.txt + tiered results in console
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

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"

# Already used repos — exclude these and near-duplicates
EXCLUDED_REPOS = {
    "owasp/nodegoat", "juice-shop/juice-shop", "appsecco/dvna",
    "snyk-labs/nodejs-goof", "expressjs/express", "strapi/strapi",
    "tryghost/ghost", "webpack/webpack", "nestjs/nest", "npm/cli",
}

# ---------------------------------------------------------------------------
# Token / key loading
# ---------------------------------------------------------------------------

def load_env() -> dict:
    """Load all key=value pairs from .env file."""
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env

ENV = load_env()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or ENV.get("GITHUB_TOKEN")
YOU_API_KEY = os.environ.get("YOU_API_KEY") or ENV.get("YOU_API_KEY")


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def github_api(url: str) -> dict | list | None:
    """GitHub API request with auth and rate-limit backoff."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "VulnChain-RepoFinder/1.0"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    for attempt in range(4):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429, 422):
                wait = 10 * (attempt + 1)
                remaining = e.headers.get("x-ratelimit-remaining", "?")
                print(f"    [rate-limit] {e.code}, remaining={remaining}, "
                      f"waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            print(f"    [github error] {e.code} for {url}", file=sys.stderr)
            return None
        except urllib.error.URLError as e:
            print(f"    [network error] {e.reason}", file=sys.stderr)
            time.sleep(5)
            continue
    return None


def you_search(query: str, max_results: int = 15) -> list[dict]:
    """
    Search via You.com Search API.
    Returns list of {title, url, snippet} dicts.
    """
    if not YOU_API_KEY:
        print("  [warn] No YOU_API_KEY, skipping You.com search", file=sys.stderr)
        return []

    url = "https://ydc-index.io/v1/search"
    payload = json.dumps({
        "query": query,
    }).encode("utf-8")
    headers = {
        "X-API-Key": YOU_API_KEY,
        "Content-Type": "application/json",
        "User-Agent": "VulnChain-RepoFinder/1.0",
    }

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            raw_hits = []
            if isinstance(data, dict):
                res_obj = data.get("results")
                if isinstance(res_obj, dict):
                    raw_hits = res_obj.get("web", [])
                elif isinstance(res_obj, list):
                    raw_hits = res_obj
                elif "hits" in data and isinstance(data["hits"], list):
                    raw_hits = data["hits"]
                elif "web" in data and isinstance(data["web"], list):
                    raw_hits = data["web"]

            results = []
            for hit in raw_hits:
                if isinstance(hit, dict):
                    snippets = hit.get("snippets", [])
                    snippet_str = " ".join(snippets) if isinstance(snippets, list) else str(snippets)
                    desc = hit.get("description", "")
                    combined_snippet = f"{desc} {snippet_str}".strip()
                    results.append({
                        "title": hit.get("title", ""),
                        "url": hit.get("url", ""),
                        "snippet": combined_snippet,
                    })
            return results[:max_results]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:200]
        print(f"  [you.com error] {e.code}: {body}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"  [you.com error] {e}", file=sys.stderr)
        return []


def osv_query(ecosystem: str = "npm", package: str = None) -> list[dict]:
    """Query OSV.dev for vulnerabilities in a specific package or ecosystem."""
    url = "https://api.osv.dev/v1/query"
    if package:
        payload = {"package": {"name": package, "ecosystem": ecosystem}}
    else:
        return []

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("vulns", [])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# GitHub search strategies
# ---------------------------------------------------------------------------

def extract_repos_from_search(data: dict) -> list[dict]:
    """Extract owner/repo + metadata from GitHub search API response."""
    repos = []
    if not data or "items" not in data:
        return repos
    for item in data["items"]:
        full_name = item.get("full_name", "")
        if full_name.lower() in EXCLUDED_REPOS:
            continue
        repos.append({
            "repo": full_name,
            "description": item.get("description", ""),
            "language": item.get("language", ""),
            "stars": item.get("stargazers_count", 0),
            "pushed_at": item.get("pushed_at", ""),
            "archived": item.get("archived", False),
            "topics": item.get("topics", []),
        })
    return repos


def search_github_repos(query: str, sort: str = "stars", per_page: int = 30) -> list[dict]:
    """Search GitHub repos with the given query."""
    encoded_q = urllib.request.quote(query)
    url = (f"https://api.github.com/search/repositories"
           f"?q={encoded_q}&sort={sort}&per_page={per_page}")
    print(f"  [github] Searching: {query[:80]}...")
    data = github_api(url)
    time.sleep(2)  # GitHub search rate limit: 10 req/min
    return extract_repos_from_search(data)


def extract_github_urls(text: str) -> list[str]:
    """Extract GitHub owner/repo patterns from text."""
    pattern = r'github\.com/([a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)'
    matches = re.findall(pattern, text)
    non_repo_prefixes = {
        "features", "topics", "search", "orgs", "marketplace", "pricing",
        "about", "security", "enterprise", "site", "explore", "trending",
        "collections", "events", "readme", "settings", "pulls", "issues"
    }
    cleaned = []
    for m in matches:
        m = m.rstrip("/").replace(".git", "")
        if "/" in m:
            parts = m.split("/")
            if len(parts) == 2 and parts[0].lower() not in non_repo_prefixes:
                if m.lower() not in EXCLUDED_REPOS:
                    cleaned.append(m)
    return list(set(cleaned))


# ---------------------------------------------------------------------------
# Tier 1: Deliberately vulnerable Node.js apps
# ---------------------------------------------------------------------------

def search_tier1() -> list[dict]:
    """Find deliberately vulnerable Node.js applications."""
    print("\n" + "=" * 70)
    print("TIER 1: Deliberately Vulnerable Node.js Apps")
    print("=" * 70)

    all_repos = {}

    # Strategy 1: GitHub topic searches
    topic_queries = [
        "topic:vulnerable-application language:JavaScript",
        "topic:vulnerable-application language:TypeScript",
        "topic:owasp language:JavaScript",
        "topic:intentionally-vulnerable language:JavaScript",
        "topic:security-training language:JavaScript",
        "topic:ctf language:JavaScript vulnerable",
        "topic:vulnerable-web-application language:JavaScript",
        "topic:dvna OR topic:nodegoat OR topic:juice-shop language:JavaScript",
        "vulnerable nodejs application OWASP training in:name,description language:JavaScript",
        "damn vulnerable node in:name,description language:JavaScript",
        "intentionally insecure nodejs in:name,description",
        "vulnerable express application in:name,description language:JavaScript",
        "security training nodejs vulnerable in:description language:JavaScript",
        "pentest nodejs practice in:description language:JavaScript",
    ]

    for q in topic_queries:
        results = search_github_repos(q)
        for r in results:
            key = r["repo"].lower()
            if key not in all_repos:
                all_repos[key] = r
                r["search_query"] = q

    # Strategy 2: You.com web search for lists of vulnerable Node.js apps
    you_queries = [
        "list of deliberately vulnerable Node.js applications github OWASP 2024",
        "intentionally insecure Node.js apps for security training github",
        "vulnerable nodejs application CTF practice github repository",
        "OWASP vulnerable nodejs projects github list",
        "damn vulnerable node application alternatives github",
    ]

    you_repos = set()
    for q in you_queries:
        print(f"  [you.com] Searching: {q[:70]}...")
        results = you_search(q)
        for r in results:
            urls = extract_github_urls(r.get("url", "") + " " + r.get("snippet", ""))
            you_repos.update(urls)
        time.sleep(1)

    # Add You.com-found repos to the list
    for repo_name in you_repos:
        key = repo_name.lower()
        if key not in all_repos and key not in EXCLUDED_REPOS:
            all_repos[key] = {
                "repo": repo_name,
                "description": "",
                "language": "",
                "stars": 0,
                "pushed_at": "",
                "search_query": "you.com web search",
            }

    print(f"\n  Tier 1 candidates found: {len(all_repos)}")
    return list(all_repos.values())


# ---------------------------------------------------------------------------
# Tier 2: Notorious/deprecated npm packages with CVE history
# ---------------------------------------------------------------------------

def search_tier2() -> list[dict]:
    """Find repos of notorious/deprecated npm packages with supply chain history."""
    print("\n" + "=" * 70)
    print("TIER 2: Notorious/Deprecated npm Packages")
    print("=" * 70)

    all_repos = {}

    # Known notorious packages to find repos for
    notorious_packages = [
        # Sabotage/protestware (from web search results)
        "colors", "faker", "node-ipc",
        # Historically compromised
        "event-stream", "ua-parser-js", "coa", "rc",
        # Deprecated but widely used
        "request", "querystring", "nomnom", "optimist",
        "node-uuid", "github", "jade", "istanbul",
        # Known CVE-heavy packages
        "minimist", "qs", "lodash", "handlebars",
        "serialize-javascript", "kind-of", "set-value",
        "mixin-deep", "mem", "braces", "marked",
        "node-fetch", "tar", "glob-parent", "trim",
        "trim-newlines", "json-schema", "y18n",
        "hosted-git-info", "ssri", "ini", "elliptic",
    ]

    # Strategy 1: Find GitHub repos for notorious packages via npm registry
    for pkg in notorious_packages:
        print(f"  [npm] Looking up: {pkg}...")
        npm_url = f"https://registry.npmjs.org/{pkg}"
        try:
            req = urllib.request.Request(npm_url, headers={"User-Agent": "VulnChain"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                # Get repo URL from package.json metadata
                repo_info = data.get("repository", {})
                if isinstance(repo_info, str):
                    repo_url = repo_info
                elif isinstance(repo_info, dict):
                    repo_url = repo_info.get("url", "")
                else:
                    repo_url = ""

                # Extract GitHub owner/repo
                gh_urls = extract_github_urls(repo_url)
                if gh_urls:
                    repo_name = gh_urls[0]
                    key = repo_name.lower()
                    if key not in all_repos and key not in EXCLUDED_REPOS:
                        # Check if deprecated
                        latest = data.get("dist-tags", {}).get("latest", "")
                        latest_data = data.get("versions", {}).get(latest, {})
                        deprecated = latest_data.get("deprecated") or data.get("deprecated")

                        all_repos[key] = {
                            "repo": repo_name,
                            "description": data.get("description", "")[:100],
                            "language": "JavaScript",
                            "stars": 0,
                            "pushed_at": "",
                            "npm_package": pkg,
                            "deprecated": bool(deprecated),
                            "search_query": f"npm registry lookup: {pkg}",
                        }
        except Exception as e:
            print(f"    [error] {pkg}: {e}")
        time.sleep(0.3)

    # Strategy 2: GitHub Advisory DB search for npm
    print("\n  [github] Searching advisory DB for npm ecosystem...")
    advisory_url = ("https://api.github.com/advisories"
                    "?ecosystem=npm&severity=critical&per_page=50")
    advisories = github_api(advisory_url)
    if advisories and isinstance(advisories, list):
        for adv in advisories:
            # Get affected package source repos
            for vuln in adv.get("vulnerabilities", []):
                pkg_name = vuln.get("package", {}).get("name", "")
                if pkg_name and pkg_name not in notorious_packages:
                    notorious_packages.append(pkg_name)
    time.sleep(2)

    # Strategy 3: You.com search for supply chain incident repos
    you_queries = [
        "colors.js faker.js sabotage npm supply chain attack github repository",
        "event-stream npm hack bitcoin malicious dependency github",
        "node-ipc protestware npm supply chain github repository",
        "ua-parser-js npm compromised cryptominer github",
        "npm deprecated packages still widely used vulnerable CVE github",
        "most vulnerable npm packages CVE history github repository 2023 2024",
    ]

    for q in you_queries:
        print(f"  [you.com] Searching: {q[:70]}...")
        results = you_search(q)
        for r in results:
            urls = extract_github_urls(r.get("url", "") + " " + r.get("snippet", ""))
            for repo_name in urls:
                key = repo_name.lower()
                if key not in all_repos and key not in EXCLUDED_REPOS:
                    all_repos[key] = {
                        "repo": repo_name,
                        "description": "",
                        "language": "",
                        "stars": 0,
                        "pushed_at": "",
                        "search_query": f"you.com: {q[:50]}",
                    }
        time.sleep(1)

    print(f"\n  Tier 2 candidates found: {len(all_repos)}")
    return list(all_repos.values())


# ---------------------------------------------------------------------------
# Tier 3: Stale production repos with lockfiles
# ---------------------------------------------------------------------------

def search_tier3() -> list[dict]:
    """Find stale production Node.js repos (last commit 2+ years ago)."""
    print("\n" + "=" * 70)
    print("TIER 3: Stale Production Repos (last push 2+ years ago)")
    print("=" * 70)

    all_repos = {}

    # Strategy 1: GitHub search for stale Node.js apps with lockfiles
    # pushed:<2024-01-01 means last push before 2024
    stale_queries = [
        "filename:package-lock.json language:JavaScript pushed:<2024-01-01 stars:>50",
        "filename:package-lock.json language:JavaScript pushed:<2023-01-01 stars:>100",
        "nodejs application in:description pushed:<2024-01-01 stars:>50 language:JavaScript",
        "express app in:description pushed:<2024-01-01 stars:>30 language:JavaScript",
        "node server in:description pushed:<2023-06-01 stars:>50 language:JavaScript",
        "REST API nodejs in:description pushed:<2024-01-01 stars:>40 language:JavaScript",
        "web application nodejs in:description pushed:<2023-01-01 stars:>50 language:JavaScript",
    ]

    for q in stale_queries:
        results = search_github_repos(q, sort="stars", per_page=20)
        for r in results:
            key = r["repo"].lower()
            # Only include if actually stale (pushed_at before 2024)
            pushed = r.get("pushed_at", "")
            if pushed and pushed < "2024-06-01":
                if key not in all_repos:
                    all_repos[key] = r
                    r["search_query"] = q

    # Strategy 2: You.com search for abandoned Node.js projects
    you_queries = [
        "abandoned Node.js application github stars unmaintained 2022 2023",
        "stale Node.js project github outdated dependencies production use",
        "unmaintained express application github vulnerable dependencies",
    ]

    for q in you_queries:
        print(f"  [you.com] Searching: {q[:70]}...")
        results = you_search(q)
        for r in results:
            urls = extract_github_urls(r.get("url", "") + " " + r.get("snippet", ""))
            for repo_name in urls:
                key = repo_name.lower()
                if key not in all_repos and key not in EXCLUDED_REPOS:
                    all_repos[key] = {
                        "repo": repo_name,
                        "description": "",
                        "language": "",
                        "stars": 0,
                        "pushed_at": "",
                        "search_query": f"you.com: {q[:50]}",
                    }
        time.sleep(1)

    print(f"\n  Tier 3 candidates found: {len(all_repos)}")
    return list(all_repos.values())


# ---------------------------------------------------------------------------
# Verify repos via GitHub API (existence + metadata)
# ---------------------------------------------------------------------------

def verify_repo(repo_name: str) -> dict | None:
    """
    Verify a repo exists and get its metadata.
    Returns dict with metadata or None if repo doesn't exist.
    """
    owner, name = repo_name.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{name}"
    data = github_api(url)
    if not data or not isinstance(data, dict):
        return None

    return {
        "full_name": data.get("full_name", repo_name),
        "description": (data.get("description") or "")[:100],
        "language": data.get("language"),
        "stars": data.get("stargazers_count", 0),
        "pushed_at": data.get("pushed_at", ""),
        "archived": data.get("archived", False),
        "fork": data.get("fork", False),
        "parent": (data.get("parent") or {}).get("full_name"),
        "topics": data.get("topics", []),
    }


def check_lockfile(repo_name: str) -> dict:
    """Check lockfile status for a repo. Returns status dict."""
    owner, name = repo_name.split("/", 1)

    result = {
        "has_package_json": False,
        "has_package_lock": False,
        "lockfile_version": None,
        "has_yarn_lock": False,
        "yarn_is_berry": None,
        "has_pnpm_lock": False,
        "gitignore_excludes_lockfile": None,
        "status": "UNKNOWN",
    }

    # Check package.json
    pkg_url = f"https://api.github.com/repos/{owner}/{name}/contents/package.json"
    pkg_data = github_api(pkg_url)
    if pkg_data and isinstance(pkg_data, dict):
        result["has_package_json"] = True

    # Check package-lock.json
    lock_url = f"https://api.github.com/repos/{owner}/{name}/contents/package-lock.json"
    lock_data = github_api(lock_url)
    if lock_data and isinstance(lock_data, dict):
        result["has_package_lock"] = True
        content = lock_data.get("content", "")
        if content:
            try:
                raw = base64.b64decode(content)
                text = raw.decode("utf-8", errors="replace")[:4096]
                m = re.search(r'"lockfileVersion"\s*:\s*(\d+)', text)
                if m:
                    result["lockfile_version"] = int(m.group(1))
                else:
                    result["lockfile_version"] = 1
            except Exception:
                pass

    # Check yarn.lock
    yarn_url = f"https://api.github.com/repos/{owner}/{name}/contents/yarn.lock"
    yarn_data = github_api(yarn_url)
    if yarn_data and isinstance(yarn_data, dict):
        result["has_yarn_lock"] = True
        content = yarn_data.get("content", "")
        if content:
            try:
                raw = base64.b64decode(content)
                text = raw.decode("utf-8", errors="replace")[:4096]
                result["yarn_is_berry"] = "__metadata:" in text
            except Exception:
                pass

    # Check pnpm-lock.yaml
    pnpm_url = f"https://api.github.com/repos/{owner}/{name}/contents/pnpm-lock.yaml"
    pnpm_data = github_api(pnpm_url)
    if pnpm_data and isinstance(pnpm_data, dict):
        result["has_pnpm_lock"] = True

    # If no lockfile, check .gitignore
    if not result["has_package_lock"]:
        gi_url = f"https://api.github.com/repos/{owner}/{name}/contents/.gitignore"
        gi_data = github_api(gi_url)
        if gi_data and isinstance(gi_data, dict):
            content = gi_data.get("content", "")
            if content:
                try:
                    text = base64.b64decode(content).decode("utf-8", errors="replace")
                    result["gitignore_excludes_lockfile"] = "package-lock" in text
                except Exception:
                    pass

    # Determine status
    if result["has_package_lock"] and result["lockfile_version"]:
        if result["has_yarn_lock"] or result["has_pnpm_lock"]:
            result["status"] = "RISKY"
        else:
            result["status"] = "OK"
    elif result["has_yarn_lock"] or result["has_pnpm_lock"]:
        result["status"] = "RISKY"
    elif result["has_package_json"]:
        result["status"] = "NO_LOCKFILE"
    else:
        result["status"] = "UNRESOLVED"

    return result


def format_lockfile_status(lf: dict) -> str:
    """Format lockfile check result as a concise string."""
    parts = []
    if lf["has_package_lock"]:
        parts.append(f"package-lock.json v{lf['lockfile_version'] or '?'}")
    if lf["has_yarn_lock"]:
        berry = "Berry" if lf["yarn_is_berry"] else "Classic"
        parts.append(f"yarn.lock ({berry})")
    if lf["has_pnpm_lock"]:
        parts.append("pnpm-lock.yaml")
    if not lf["has_package_lock"] and not lf["has_yarn_lock"] and not lf["has_pnpm_lock"]:
        if lf["gitignore_excludes_lockfile"]:
            parts.append("NO lockfile (gitignored)")
        elif lf["has_package_json"]:
            parts.append("NO lockfile (unknown cause)")
        else:
            parts.append("NO package.json")
    return " + ".join(parts) if parts else "unknown"


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main():
    search_only = "--search-only" in sys.argv
    precheck_only = "--precheck-only" in sys.argv

    print(f"\nVulnChain Batch 2 Deep Repo Finder")
    print(f"  GitHub token: {'present' if GITHUB_TOKEN else 'MISSING'}")
    print(f"  You.com key:  {'present' if YOU_API_KEY else 'MISSING'}")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    if precheck_only:
        # Load from existing file
        candidates_file = SCRIPT_DIR / "candidates_batch2.txt"
        if not candidates_file.exists():
            print("No candidates_batch2.txt found. Run without --precheck-only first.")
            sys.exit(1)
        all_candidates = []
        for line in candidates_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "/" in line:
                all_candidates.append({"repo": line, "tier": "?", "search_query": "file"})
    else:
        # Run all searches
        tier1 = search_tier1()
        tier2 = search_tier2()
        tier3 = search_tier3()

        # Tag tiers
        for r in tier1:
            r["tier"] = "1"
        for r in tier2:
            r["tier"] = "2"
        for r in tier3:
            r["tier"] = "3"

        # Deduplicate across tiers (tier 1 wins)
        seen = set()
        all_candidates = []
        for r in tier1 + tier2 + tier3:
            key = r["repo"].lower()
            if key not in seen and key not in EXCLUDED_REPOS:
                seen.add(key)
                all_candidates.append(r)

        print(f"\n{'=' * 70}")
        print(f"Total unique candidates: {len(all_candidates)}")
        print(f"  Tier 1 (vulnerable apps): {len(tier1)}")
        print(f"  Tier 2 (notorious/deprecated): {len(tier2)}")
        print(f"  Tier 3 (stale production): {len(tier3)}")
        print(f"  After dedup: {len(all_candidates)}")

        # Save candidates list
        candidates_file = SCRIPT_DIR / "candidates_batch2.txt"
        with open(candidates_file, "w") as f:
            f.write("# VulnChain Batch 2 — Auto-discovered candidates\n")
            f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Total: {len(all_candidates)}\n\n")
            for r in all_candidates:
                f.write(f"{r['repo']}\n")
        print(f"\nSaved candidate list to: {candidates_file}")

    if search_only:
        print("\n--search-only: skipping verification. Run precheck separately.")
        return

    # Verify each candidate
    print(f"\n{'=' * 70}")
    print(f"Verifying {len(all_candidates)} candidates...")
    print(f"  (~5 API calls per repo, estimated total: ~{len(all_candidates) * 5} calls)")
    print(f"{'=' * 70}")

    verified = []
    not_found = []
    errors = []

    for i, cand in enumerate(all_candidates):
        repo_name = cand["repo"]
        print(f"  [{i + 1}/{len(all_candidates)}] {repo_name}...", end=" ", flush=True)

        try:
            # Check if valid format
            if "/" not in repo_name:
                print("INVALID FORMAT")
                errors.append({"repo": repo_name, "error": "invalid format"})
                continue

            # Verify existence
            meta = verify_repo(repo_name)
            if meta is None:
                print("NOT_FOUND")
                not_found.append({"repo": repo_name, "tier": cand.get("tier", "?")})
                time.sleep(0.5)
                continue

            # Check lockfile
            lf = check_lockfile(repo_name)
            status = lf["status"]
            print(f"{status} (v{lf['lockfile_version'] or '-'})")

            verified.append({
                **cand,
                **meta,
                "lockfile": lf,
                "lockfile_status": format_lockfile_status(lf),
                "check_status": status,
            })

        except Exception as e:
            print(f"ERROR: {e}")
            errors.append({"repo": repo_name, "error": str(e)})

        time.sleep(0.5)

    # Output results
    print(f"\n\n{'=' * 100}")
    print(f"RESULTS: {len(verified)} verified | {len(not_found)} not found | {len(errors)} errors")
    print(f"{'=' * 100}")

    # Group by tier
    for tier_name, tier_label in [("1", "TIER 1: Vulnerable Apps"),
                                   ("2", "TIER 2: Notorious/Deprecated"),
                                   ("3", "TIER 3: Stale Production")]:
        tier_repos = [v for v in verified if v.get("tier") == tier_name]
        if not tier_repos:
            print(f"\n--- {tier_label}: 0 repos ---")
            continue

        print(f"\n--- {tier_label}: {len(tier_repos)} repos ---")
        print(f"{'Repo':<45} {'Lock Status':<35} {'Status':<12} {'Evidence'}")
        print(f"{'─' * 45} {'─' * 35} {'─' * 12} {'─' * 40}")

        for v in tier_repos:
            evidence = v.get("search_query", "")[:40]
            print(f"{v['full_name']:<45} {v['lockfile_status']:<35} "
                  f"{v['check_status']:<12} {evidence}")

    # NOT_FOUND repos
    if not_found:
        print(f"\n--- NOT FOUND ({len(not_found)} repos) ---")
        for nf in not_found:
            print(f"  {nf['repo']} (tier {nf.get('tier', '?')})")

    # Save JSON results
    results_file = SCRIPT_DIR / "batch2_results.json"
    with open(results_file, "w") as f:
        json.dump({
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "verified": [
                {
                    "repo": v["full_name"],
                    "tier": v.get("tier", "?"),
                    "description": v.get("description", ""),
                    "language": v.get("language", ""),
                    "stars": v.get("stars", 0),
                    "pushed_at": v.get("pushed_at", ""),
                    "lockfile_status": v.get("lockfile_status", ""),
                    "check_status": v.get("check_status", ""),
                    "search_query": v.get("search_query", ""),
                } for v in verified
            ],
            "not_found": not_found,
            "errors": errors,
        }, f, indent=2)
    print(f"\nFull results saved to: {results_file}")


if __name__ == "__main__":
    main()
