"""
VulnChain — Author node extractor (Round 3), v2
Reads package_graph.json + hasVulnerability_edges.json, resolves Author
identity via npm registry's `repository` field (the actual GitHub repo
that owns the package source) rather than guessing npm-username ==
GitHub-username. Builds:
  - author_nodes.json           : Author nodes with 7-dim features
  - maintainedBy_edges.json     : Package -> Author edges
  - introducedBy_edges.json     : CVE -> Author edges

DEFINITIONAL NOTE (flagged, not silently changed — confirmed with user):
  "Author" = the GitHub org/user that owns the package's source repository,
  resolved from npm registry's `repository.url` field. This is a shift from
  the design doc's literal "npm maintainer username" — chosen because it's
  resolvable with certainty (no guessing) and better matches the doc's own
  threat model (SolarWinds/event-stream = compromise of the entity
  controlling the actual source, not the npm listing).

  Packages with no repository field, or a repository field pointing
  somewhere other than github.com, fall back to using the first npm
  maintainer name as a best-effort Author id — flagged in output via
  "resolution": "repo_owner" vs "resolution": "npm_maintainer_fallback".

REQUIRES A GITHUB TOKEN — unauthenticated GitHub API is 60 req/hr.
Put it in a .env file in this folder:
  GITHUB_TOKEN=ghp_xxxxxxxxxxxx
(and make sure .env is in your .gitignore)

REMAINING KNOWN LIMITATION:
  - Dim 5 (2FA) has no public API for individual users, and is only
    visible for orgs you're an authenticated member of — not available
    for arbitrary third-party orgs either. Always defaults to 0
    (unknown = treat as risky), exactly as the design doc instructs.
    This is a hard external limit, not something we can resolve.

Run locally:  pip install requests python-dotenv
              python author_extractor.py
"""

import json
import time
import re
import requests
from pathlib import Path
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

load_dotenv()

PACKAGE_GRAPH_FILE = "package_graph.json"
HASVULN_EDGES_FILE = "hasVulnerability_edges.json"

NPM_CACHE_FILE = ".npm_registry_cache.json"          # package name -> {maintainers, repository}
GH_REPO_CACHE_FILE = ".github_repo_cache.json"       # "owner/repo" -> {owner_login, owner_type, latest_commit_date}
GH_USER_CACHE_FILE = ".github_user_cache.json"       # username -> {created_at, type}
MAINT_COUNT_CACHE_FILE = ".npm_maintainer_count_cache.json"

AUTHOR_NODES_OUT = "author_nodes.json"
MAINTAINEDBY_EDGES_OUT = "maintainedBy_edges.json"
INTRODUCEDBY_EDGES_OUT = "introducedBy_edges.json"

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GH_HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

if not GITHUB_TOKEN:
    print("WARNING: no GITHUB_TOKEN found (check your .env file). You will hit")
    print("the 60 req/hr limit almost immediately. Continuing anyway so you can")
    print("see how far unauthenticated gets you.")
    print()

GITHUB_REPO_URL_RE = re.compile(r"github\.com[:/]+([^/]+)/([^/.]+?)(?:\.git)?/?$")


def load_json(path, default):
    if Path(path).exists():
        with open(path) as f:
            return json.load(f)
    return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def get_unique_package_names(package_graph):
    return sorted({n["name"] for n in package_graph["nodes"]})


def parse_github_owner_repo(repository_field):
    if not repository_field:
        return None
    url = repository_field.get("url", "") if isinstance(repository_field, dict) else str(repository_field)
    m = GITHUB_REPO_URL_RE.search(url)
    if not m:
        return None
    return m.group(1), m.group(2)


def fetch_npm_package(name, cache):
    if name in cache:
        return cache[name]
    try:
        resp = requests.get(f"https://registry.npmjs.org/{requests.utils.quote(name, safe='')}", timeout=15)
        if resp.status_code != 200:
            cache[name] = None
            return None
        data = resp.json()
        result = {
            "maintainers": data.get("maintainers", []),
            "repository": data.get("repository"),
        }
        cache[name] = result
        return result
    except requests.exceptions.RequestException:
        cache[name] = None
        return None


def fetch_github_repo(owner, repo, cache):
    key = f"{owner}/{repo}"
    if key in cache:
        return cache[key]
    try:
        # repo metadata (gives owner type directly)
        resp = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers=GH_HEADERS, timeout=15)
        if resp.status_code != 200:
            cache[key] = None
            return None
        repo_data = resp.json()
        owner_login = repo_data.get("owner", {}).get("login")
        owner_type = repo_data.get("owner", {}).get("type")  # "User" or "Organization"

        # latest commit date
        commit_resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits",
            headers=GH_HEADERS, params={"per_page": 1}, timeout=15,
        )
        latest_commit_date = None
        if commit_resp.status_code == 200:
            commits = commit_resp.json()
            if commits:
                latest_commit_date = commits[0].get("commit", {}).get("author", {}).get("date")

        result = {
            "owner_login": owner_login,
            "owner_type": owner_type,
            "latest_commit_date": latest_commit_date,
        }
        cache[key] = result
        return result
    except requests.exceptions.RequestException:
        cache[key] = None
        return None


def fetch_github_user(username, cache):
    if username in cache:
        return cache[username]
    try:
        resp = requests.get(f"https://api.github.com/users/{username}", headers=GH_HEADERS, timeout=15)
        if resp.status_code != 200:
            cache[username] = None
            return None
        data = resp.json()
        result = {"created_at": data.get("created_at"), "type": data.get("type")}
        cache[username] = result
        return result
    except requests.exceptions.RequestException:
        cache[username] = None
        return None


def fetch_npm_maintainer_count(username, cache):
    if username in cache:
        return cache[username]
    try:
        resp = requests.get(
            "https://registry.npmjs.org/-/v1/search",
            params={"text": f"maintainer:{username}", "size": 1}, timeout=15,
        )
        if resp.status_code != 200:
            cache[username] = None
            return None
        total = resp.json().get("total")
        cache[username] = total
        return total
    except requests.exceptions.RequestException:
        cache[username] = None
        return None


def days_since(iso_date_str):
    if not iso_date_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


def main():
    with open(PACKAGE_GRAPH_FILE) as f:
        package_graph = json.load(f)
    hasvuln_edges = load_json(HASVULN_EDGES_FILE, [])

    names = get_unique_package_names(package_graph)
    print(f"{len(names)} unique package names")

    # ---- Step 1: npm registry -> maintainers + repository per package ----
    npm_cache = load_json(NPM_CACHE_FILE, {})
    todo = [n for n in names if n not in npm_cache]
    print(f"Fetching npm registry data: {len(todo)} left ({len(npm_cache)} cached)")
    for i, name in enumerate(todo, 1):
        fetch_npm_package(name, npm_cache)
        if i % 100 == 0 or i == len(todo):
            save_json(NPM_CACHE_FILE, npm_cache)
            print(f"  npm: {i}/{len(todo)}")
        time.sleep(0.05)
    save_json(NPM_CACHE_FILE, npm_cache)

    # ---- Step 2: resolve Author identity per package ----
    # package_name -> (author_id, resolution_method)
    package_to_author = {}
    github_repos_needed = set()  # (owner, repo)

    for name in names:
        entry = npm_cache.get(name)
        owner_repo = parse_github_owner_repo(entry.get("repository")) if entry else None
        if owner_repo:
            package_to_author[name] = (f"{owner_repo[0]}/{owner_repo[1]}", "repo_owner")
            github_repos_needed.add(owner_repo)
        elif entry and entry.get("maintainers"):
            first_maintainer = entry["maintainers"][0].get("name")
            if first_maintainer:
                package_to_author[name] = (first_maintainer, "npm_maintainer_fallback")
            else:
                package_to_author[name] = (None, None)
        else:
            package_to_author[name] = (None, None)

    resolved_via_repo = sum(1 for _, m in package_to_author.values() if m == "repo_owner")
    resolved_via_fallback = sum(1 for _, m in package_to_author.values() if m == "npm_maintainer_fallback")
    print(f"Author resolution: {resolved_via_repo} via GitHub repo owner, "
          f"{resolved_via_fallback} via npm maintainer fallback, "
          f"{len(names) - resolved_via_repo - resolved_via_fallback} unresolved")

    # ---- Step 3: fetch GitHub repo data (owner type + real last commit) ----
    gh_repo_cache = load_json(GH_REPO_CACHE_FILE, {})
    todo = [r for r in github_repos_needed if f"{r[0]}/{r[1]}" not in gh_repo_cache]
    print(f"Fetching GitHub repo data: {len(todo)} left ({len(gh_repo_cache)} cached)")
    for i, (owner, repo) in enumerate(todo, 1):
        fetch_github_repo(owner, repo, gh_repo_cache)
        if i % 25 == 0 or i == len(todo):
            save_json(GH_REPO_CACHE_FILE, gh_repo_cache)
            print(f"  github repos: {i}/{len(todo)}")
        time.sleep(0.1 if GITHUB_TOKEN else 1.0)
    save_json(GH_REPO_CACHE_FILE, gh_repo_cache)

    # ---- Step 4: fetch GitHub user data for the resolved owner_login (repo-based)
    #      and for npm_maintainer_fallback authors ----
    owner_logins_needed = set()
    for owner, repo in github_repos_needed:
        r = gh_repo_cache.get(f"{owner}/{repo}")
        if r and r.get("owner_login"):
            owner_logins_needed.add(r["owner_login"])
    fallback_usernames = {a for a, m in package_to_author.values() if m == "npm_maintainer_fallback"}
    all_usernames_for_gh_user = owner_logins_needed | fallback_usernames

    gh_user_cache = load_json(GH_USER_CACHE_FILE, {})
    todo = [u for u in all_usernames_for_gh_user if u not in gh_user_cache]
    print(f"Fetching GitHub user account data: {len(todo)} left ({len(gh_user_cache)} cached)")
    for i, username in enumerate(todo, 1):
        fetch_github_user(username, gh_user_cache)
        if i % 25 == 0 or i == len(todo):
            save_json(GH_USER_CACHE_FILE, gh_user_cache)
            print(f"  github users: {i}/{len(todo)}")
        time.sleep(0.1 if GITHUB_TOKEN else 1.0)
    save_json(GH_USER_CACHE_FILE, gh_user_cache)

    # ---- Step 5: npm global maintained-package count (only meaningful for
    #      npm_maintainer_fallback authors; repo-owner authors get an
    #      in-graph count instead since "packages maintained" doesn't map
    #      cleanly onto an org/repo identity) ----
    count_cache = load_json(MAINT_COUNT_CACHE_FILE, {})
    todo = [u for u in fallback_usernames if u not in count_cache]
    print(f"Fetching npm maintainer package counts: {len(todo)} left ({len(count_cache)} cached)")
    for i, username in enumerate(todo, 1):
        fetch_npm_maintainer_count(username, count_cache)
        if i % 100 == 0 or i == len(todo):
            save_json(MAINT_COUNT_CACHE_FILE, count_cache)
            print(f"  maintainer counts: {i}/{len(todo)}")
        time.sleep(0.05)
    save_json(MAINT_COUNT_CACHE_FILE, count_cache)

    # ---- Step 6: which packages (in-graph) have CVEs, for dim 2 ----
    packages_with_cve = set()
    for edge in hasvuln_edges:
        pkg_name = edge["source"].rsplit("@", 1)[0]
        packages_with_cve.add(pkg_name)

    # ---- Step 7: build final author_id -> list of package names map ----
    author_to_packages = {}
    author_resolution = {}  # author_id -> "repo_owner" | "npm_maintainer_fallback"
    for name, (author_id, method) in package_to_author.items():
        if author_id:
            author_to_packages.setdefault(author_id, []).append(name)
            author_resolution[author_id] = method

    print(f"{len(author_to_packages)} unique Author identities")

    # ---- Step 8: build Author nodes ----
    author_nodes = []
    maintainedby_edges = []

    for author_id, maintained_packages in sorted(author_to_packages.items()):
        method = author_resolution[author_id]

        if method == "repo_owner":
            owner, repo = author_id.split("/", 1)
            repo_data = gh_repo_cache.get(author_id)
            owner_login = repo_data.get("owner_login") if repo_data else None
            owner_type = repo_data.get("owner_type") if repo_data else None
            latest_commit_date = repo_data.get("latest_commit_date") if repo_data else None
            user_data = gh_user_cache.get(owner_login) if owner_login else None
            account_age_days = days_since(user_data["created_at"]) if user_data else None
            is_org = 1 if owner_type == "Organization" else 0
            days_since_last_activity = days_since(latest_commit_date)
            total_maintained = len(maintained_packages)  # graph-scoped for repo-owner identities
        else:  # npm_maintainer_fallback
            user_data = gh_user_cache.get(author_id)
            account_age_days = days_since(user_data["created_at"]) if user_data else None
            is_org = 1 if (user_data and user_data.get("type") == "Organization") else 0
            days_since_last_activity = None  # no repo resolved, no commit data available
            total_maintained = count_cache.get(author_id) or len(maintained_packages)

        cves_in_their_packages = sum(1 for p in maintained_packages if p in packages_with_cve)
        has_2fa = 0  # hard external limit, see module docstring

        age_score = min((account_age_days or 0) / 3650, 1.0)
        activity_score = 1.0 - min((days_since_last_activity if days_since_last_activity is not None else 3650) / 1825, 1.0)
        cve_penalty = 1.0 - min(cves_in_their_packages / 5, 1.0)
        reputation = round((age_score * 0.3 + activity_score * 0.3 + cve_penalty * 0.3 + is_org * 0.1), 3)

        node = {
            "id": author_id,
            "resolution": method,
            "features": {
                "account_age_days": account_age_days,
                "total_packages_maintained": total_maintained,
                "packages_with_known_cves": cves_in_their_packages,
                "days_since_last_commit": days_since_last_activity,
                "is_organization": is_org,
                "has_2fa": has_2fa,
                "reputation_score": reputation,
            }
        }
        author_nodes.append(node)

        for pkg_name in maintained_packages:
            for graph_node in package_graph["nodes"]:
                if graph_node["name"] == pkg_name:
                    maintainedby_edges.append({
                        "source": graph_node["id"],
                        "target": author_id,
                        "type": "maintainedBy"
                    })

    # ---- Step 9: introducedBy edges (CVE -> Author) ----
    pkg_id_to_authors = {}
    for e in maintainedby_edges:
        pkg_id_to_authors.setdefault(e["source"], []).append(e["target"])

    introducedby_edges = []
    for edge in hasvuln_edges:
        pkg_id = edge["source"]
        cve_id = edge["target"]
        for author in pkg_id_to_authors.get(pkg_id, []):
            introducedby_edges.append({
                "source": cve_id,
                "target": author,
                "type": "introducedBy"
            })

    save_json(AUTHOR_NODES_OUT, author_nodes)
    save_json(MAINTAINEDBY_EDGES_OUT, maintainedby_edges)
    save_json(INTRODUCEDBY_EDGES_OUT, introducedby_edges)

    print()
    print("=== Done ===")
    print(f"Author nodes: {len(author_nodes)}")
    print(f"  resolved via GitHub repo owner: {sum(1 for a in author_nodes if a['resolution'] == 'repo_owner')}")
    print(f"  resolved via npm maintainer fallback: {sum(1 for a in author_nodes if a['resolution'] == 'npm_maintainer_fallback')}")
    print(f"  with real account age data: {sum(1 for a in author_nodes if a['features']['account_age_days'] is not None)}")
    print(f"  with real last-commit data: {sum(1 for a in author_nodes if a['features']['days_since_last_commit'] is not None)}")
    print(f"maintainedBy edges: {len(maintainedby_edges)}")
    print(f"introducedBy edges: {len(introducedby_edges)}")
    print(f"-> {AUTHOR_NODES_OUT}")
    print(f"-> {MAINTAINEDBY_EDGES_OUT}")
    print(f"-> {INTRODUCEDBY_EDGES_OUT}")


if __name__ == "__main__":
    main()