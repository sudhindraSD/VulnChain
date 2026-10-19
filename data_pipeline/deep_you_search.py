"""
Clean You.com deep search verification.
Only verifies hand-curated high-value repos from the 404 candidates.
Filters out: gist hashes, awesome-* lists, non-Node repos, advisory links,
writeup repos, and obvious noise.
"""
import json, os, sys, time, urllib.request, urllib.error

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

env_path = r"c:\Users\Admin\Desktop\Major VulnChain\.env"
with open(env_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

EXCLUDED = {
    "owasp/nodegoat", "juice-shop/juice-shop", "appsecco/dvna",
    "snyk-labs/nodejs-goof", "expressjs/express", "strapi/strapi",
    "tryghost/ghost", "webpack/webpack", "nestjs/nest", "npm/cli",
}

# Hand-curated from the 404 harvested candidates — only repos that are
# likely Node.js apps/packages with package-lock.json potential.
# Excluded: gist hashes, awesome-* lists, advisories/, non-JS repos,
# writeup repos, tool repos (arachni, zod, axios, etc.)
CANDIDATES = [
    # Tier 1: Intentionally Vulnerable Node.js Apps
    "xuezzou/Vulnerable-nodejs",
    "SirAppSec/vuln-node.js-express.js-app",
    "VitthalS/ivna",
    "cr0hn/vulnerable-node",
    "kaakaww/vuln_node_express",
    "djadmin/vulnerable-app",
    "samoylenko/vulnerable-app-nodejs-express",
    "sethsec/Nodejs-SSRF-App",
    "clarkio/vulnerable-app",
    "stypr/vulnerable-nodejs-express-mysql",
    "acc4pentester/vulnerable-app-javascript",
    "vst212/vulnerable-app-js",
    "Charlie-belmer/vulnerable-node-app",
    "payatu/vuln-nodejs-app",
    "snoopysecurity/dvws-node",
    "dsolaborg/vulnerable-node",
    "asecurityguru/vulnerablenodejsapplication",
    "MendDemoOrg/VulnerableJS",
    "shieldfy/vulnerable-nodejs-project",
    "nawien-sharma/dvna-sqlite",
    "isp1r0/DVNA",
    "Tim-Demo/dvna-js",
    "ajinabraham/dvna",
    "invicticoreteam/dvna",
    "sudo-vin/vulnerable-node-2",
    "CassandraGoose/Fortified-NodeGoat",
    "aabashkin/nosql-injection-vulnapp",
    "NketiahGodfred/EJS-ssti-exploit",
    "GPUkiller/ZipSlipNodeJS",
    "rodolfomarianocy/nodeserial",
    "C0oki3s/ssrf",
    "sethsec/Nodejs-SSRF-App",
    "m6a-UdS/ssrf-lab",
    "Captain-K-101/Ssrf-labs",

    # Tier 1: Prototype pollution / deserialization demos
    "dubniczky/Prototype-Pollution",
    "HoLyVieR/prototype-pollution-nsec18",
    "kimmobrunfeldt/lodash-merge-pollution-example",
    "fredrik-stigsson/prototype-pollution-rce-api",
    "brettgervasoni/pollute_api",
    "Serhatcck/server-side-prototype-pollution",
    "klezVirus/deser-node",
    "clevernyyyy/zip-slip-poc",
    "Serhatcck/zip-slip",
    "KTH-LangSec/server-side-prototype-pollution",
    "Jake-Schoellkopf/Server-Side_Prototype_Pollution",
    "fatihsoysalcom/nodejs-prototype-pollution-example",

    # Tier 1: CTF / Security Lab
    "ashnehete/ctf-nodejs",
    "gluckzhang/ctf-jwt-token",
    "Tusabras/nodejs-ctf",
    "omega-coder/Nosql-ctf-challenge",
    "ericjiang97/node-ctf",
    "blairsec/ctfjs",
    "easyctf/JS-CTF-Platform",
    "kOaDT/oss-oopssec-store",
    "mcibique/express-security",
    "NLHPNS/Web-Security-Lab",

    # Tier 2: Supply chain incident repos & real packages
    "dominictarr/event-stream",
    "RIAEvangelist/node-ipc",
    "faisalman/ua-parser-js",
    "OpenZeppelin/damn-vulnerable-defi",
    "cthackers/adm-zip",
    "richardgirges/express-fileupload",
    "mde/ejs",
    "luin/serialize",
    "commenthol/serialize-to-js",
    "auth0/node-jsonwebtoken",
    "kentcdodds/cross-env",
    "hugeglass/flatmap-stream",
    "achrinza/node-ipc",
    "snyk-labs/node-ipc-goof",
    "substack/safe-regex",
    "jagracey/RegEx-DoS",
    "tjenkinson/redos-detector",
    "micromatch/micromatch",
    "y-mehta/ssrf-req-filter",
    "welefen/ssrf-agent",
    "davisjam/vuln-regex-detector",
    "nodejs/is-my-node-vulnerable",
    "snyk/zip-slip-vulnerability",
    "lirantal/dependency-confusion-demo",
    "snyk-schmidtty/dependency-confusion-npm",
    "JeppW/npm-dependency-confusion-poc",
    "moment/moment",

    # Tier 3: Stale production / boilerplates / real apps
    "bradtraversy/vanilla-node-rest-api",
    "adnanrahic/nodejs-restful-api",
    "storyblok/storyblok-express-boilerplate",
    "hagopj13/node-express-boilerplate",
    "mdn/express-locallibrary-tutorial",
    "codeship-library/node-express-basic",
    "ExpressGateway/express-gateway",
    "NomicFoundation/hardhat-boilerplate",
    "sandorTuranszky/production-ready-expressjs-server",
    "libeyondea/backend-node-express",
    "rwieruch/node-express-server",
    "afteracademy/nodejs-backend-architecture-typescript",
    "jamj2000/tiendabackend",
    "benc-uk/nodejs-demoapp",
    "vercel/pkg",
    "vercel/serve",
    "microsoft/TypeScript-Node-Starter",
    "IBM/nodejs-web-app",
    "IBM/nodejs-backend-for-frontend",
    "web-push-libs/web-push",
    "sendgrid/sendgrid-nodejs",
    "mercadopago/sdk-nodejs",
    "twray/hotel-bookings-rest-api",
    "fernandobd42/testable-api-nodejs",
    "cypress-io/cypress",
    "nodemailer/nodemailer",
    "yakyak/yakyak",
    "saleor/saleor-storefront",
    "GoogleChromeLabs/squoosh",
    "pnp/sp-dev-fx-webparts",
    "chartjs/Chart.js",
    "s-yadav/react-number-format",
    "uber-archive/node-flame",
    "practicajs/practica",
    "makenew/nodejs-app",
    "payatu/DVAPI",
]

def github_api(url):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "VulnChain-Clean/2.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            remaining = resp.headers.get("X-RateLimit-Remaining", "?")
            if remaining != "?" and int(remaining) < 50:
                print(f"  [rate-limit] {remaining} remaining, sleeping 30s...")
                time.sleep(30)
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  [rate-limit] 403, sleeping 60s...")
            time.sleep(60)
        return None
    except Exception:
        return None

def check_file(repo, path):
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    data = github_api(url)
    if data and isinstance(data, dict):
        return True, data.get("download_url")
    return False, None

# Deduplicate
candidates = list(dict.fromkeys(c for c in CANDIDATES if c.lower() not in EXCLUDED))
print(f"=== Verifying {len(candidates)} curated You.com candidates ===\n")

ok_repos = []
no_lock = []
not_found = []

for idx, repo in enumerate(candidates, 1):
    print(f"[{idx}/{len(candidates)}] {repo}...", end=" ", flush=True)

    meta = github_api(f"https://api.github.com/repos/{repo}")
    if not meta or not isinstance(meta, dict) or "id" not in meta:
        print("NOT_FOUND")
        not_found.append(repo)
        time.sleep(0.3)
        continue

    has_pkg, _ = check_file(repo, "package.json")
    if not has_pkg:
        print("NO package.json")
        time.sleep(0.3)
        continue

    has_lock, lock_url = check_file(repo, "package-lock.json")
    has_yarn, _ = check_file(repo, "yarn.lock")
    has_pnpm, _ = check_file(repo, "pnpm-lock.yaml")

    lock_version = None
    if has_lock and lock_url:
        try:
            req = urllib.request.Request(lock_url, headers={"User-Agent": "VulnChain"})
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read(500)  # Only need first 500 bytes to get lockfileVersion
                lock_data = json.loads(raw.decode("utf-8", errors="replace") + "}")
                lock_version = lock_data.get("lockfileVersion")
        except Exception:
            # If partial JSON fails, try full read
            try:
                req2 = urllib.request.Request(lock_url, headers={"User-Agent": "VulnChain"})
                with urllib.request.urlopen(req2, timeout=15) as r2:
                    lock_data = json.loads(r2.read().decode("utf-8", errors="replace"))
                    lock_version = lock_data.get("lockfileVersion")
            except Exception:
                pass

    if has_lock:
        conflict = ""
        if has_yarn:
            conflict += " +yarn.lock"
        if has_pnpm:
            conflict += " +pnpm-lock.yaml"
        status = "RISKY" if conflict else "OK"
        entry = {
            "repo": meta.get("full_name", repo),
            "status": status,
            "stars": meta.get("stargazers_count", 0),
            "language": meta.get("language"),
            "lockfile_version": lock_version,
            "has_yarn": has_yarn,
            "has_pnpm": has_pnpm,
            "pushed_at": meta.get("pushed_at", ""),
            "archived": meta.get("archived", False),
            "description": (meta.get("description") or "")[:120],
        }
        ok_repos.append(entry)
        print(f"{status} (stars: {entry['stars']}, lockV: {lock_version}{conflict})")
    else:
        no_lock.append({
            "repo": meta.get("full_name", repo),
            "stars": meta.get("stargazers_count", 0),
        })
        print(f"NO_LOCKFILE (stars: {meta.get('stargazers_count', 0)})")

    time.sleep(0.3)

# Summary
print(f"\n{'='*60}")
print(f"VERIFICATION COMPLETE")
print(f"{'='*60}")
print(f"Total checked:   {len(candidates)}")
print(f"OK (lock):       {len([r for r in ok_repos if r['status'] == 'OK'])}")
print(f"RISKY (lock+yarn/pnpm): {len([r for r in ok_repos if r['status'] == 'RISKY'])}")
print(f"NO_LOCKFILE:     {len(no_lock)}")
print(f"NOT_FOUND:       {len(not_found)}")

# Save clean output
out = r"c:\Users\Admin\Desktop\Major VulnChain\you_deep_verified_ok.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump({
        "source": "You.com Deep Search (30 queries x 20 results)",
        "total_harvested": 404,
        "curated_checked": len(candidates),
        "ok_count": len([r for r in ok_repos if r["status"] == "OK"]),
        "risky_count": len([r for r in ok_repos if r["status"] == "RISKY"]),
        "ok_repos": [r for r in ok_repos if r["status"] == "OK"],
        "risky_repos": [r for r in ok_repos if r["status"] == "RISKY"],
        "no_lockfile": no_lock,
        "not_found": not_found,
    }, f, indent=2)
print(f"\nSaved to {out}")
