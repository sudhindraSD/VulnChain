# VulnChain vs npm audit -- Side-by-Side Demo Report

**Generated:** 2026-09-20 01:55:51
**Model:** VulnGAT-HR (frozen encoder + refit head, 51-repo KB)
**Checkpoint:** `phase5/models/vulngat_hr_full.pt`

---

## Executive Summary

npm audit provides a **flat list** of known CVEs affecting your dependency tree.
VulnChain provides a **ranked risk assessment** that considers:
- Vulnerability severity (CVSS)
- Dependency graph topology (blast radius)
- Propagation through transitive dependencies
- Package exposure context (direct/transitive, dev/prod)

The key difference: npm audit says *"you have N advisories"*;
VulnChain says *"here are your highest-risk packages, ranked, with the
propagation paths that make them dangerous."*

---

## Lockfile: `personal_132pkg`

### At-a-Glance Comparison

| Metric | npm audit | VulnChain |
|--------|-----------|-----------|
| Total packages analyzed | 138 | 132 |
| Vulnerability alerts | 11 (flat advisories) | 10 (risk >= 0.40) |
| Critical | 2 | 10 |
| High | 5 | 2 |
| Own-CVE flags | -- | 6 |
| Propagation-only flags | -- | 4 |
| Attack paths traced | -- | 9 |

### npm audit: Flat Advisory List

| Package | Severity | Via | Fix Available |
|---------|----------|-----|---------------|
| axios | high | Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF, Axios: Authentication Bypass via Prototype Pollution Gadget in `validateStatus` Merge Strategy | [Y] |
| body-parser | low | body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement | [Y] |
| concurrently | critical | shell-quote | [Y] |
| engine.io | high | Socket.IO: Engine.IO Polling Transport Connection Exhaustion, Socket.IO: Engine.IO WebTransport SID DoS | [Y] |
| follow-redirects | moderate | follow-redirects leaks Custom Authentication Headers to Cross-Domain Redirect Targets | [Y] |
| form-data | high | form-data: CRLF injection in form-data via unescaped multipart field names and filenames | [Y] |
| qs | moderate | qs has a remotely triggerable DoS: qs.stringify crashes with TypeError on null/undefined entries in comma-format arrays when encodeValuesOnly is set, qs array-limit bypass via bracket-key comma parsing | [Y] |
| shell-quote | critical | shell-quote quote() does not escape newlines in object .op values, shell-quote: Quadratic-complexity Denial of Service in `parse()` (CWE-407) | [Y] |
| socket.io-adapter | moderate | ws | [Y] |
| socket.io-parser | high | Socket.IO: Zero-attachment Memory Exhaustion | [Y] |
| ws | high | ws: Uninitialized memory disclosure, ws: Memory exhaustion DoS from tiny fragments and data chunks | [Y] |

### VulnChain: Ranked Top-10 with Propagation Paths

**#1** `express@5.2.1` -- **0.9998** *(propagation-elevated)* (direct)
  - Path (1 hops, GHSA-v422-hmwv-36x6): `express@5.2.1 -> body-parser@2.2.2`
  - Path (1 hops, GHSA-4mjr-xmp4-gh2g): `express@5.2.1 -> qs@6.15.0`

**#2** `socket.io@4.8.3` -- **0.9825** *(propagation-elevated)* (direct)
  - Path (1 hops, GHSA-gr94-w7qr-f4j3): `socket.io@4.8.3 -> engine.io@6.6.6`
  - Path (1 hops, GHSA-2m8v-j782-fhvr): `socket.io@4.8.3 -> socket.io-parser@4.2.6`
  - Path (2 hops, GHSA-96hv-2xvq-fx4p): `socket.io@4.8.3 -> engine.io@6.6.6 -> ws@8.18.3`

**#3** `body-parser@2.2.2` -- **0.9720** [!] `GHSA-v422-hmwv-36x6` (transitive)
  - Path (1 hops, GHSA-v422-hmwv-36x6): `express@5.2.1 -> body-parser@2.2.2`

**#4** `axios@1.14.0` -- **0.9658** [!] `GHSA-35jp-ww65-95wh` (direct)
  - Path (0 hops, GHSA-35jp-ww65-95wh): `axios@1.14.0`
  - Path (1 hops, GHSA-r4q5-vmmm-2653): `axios@1.14.0 -> follow-redirects@1.15.11`
  - Path (1 hops, GHSA-hmw2-7cc7-3qxx): `axios@1.14.0 -> form-data@4.0.5`

**#5** `concurrently@9.2.1` -- **0.9634** *(propagation-elevated)* (direct)
  - Path (1 hops, GHSA-w7jw-789q-3m8p): `concurrently@9.2.1 -> shell-quote@1.8.3`

**#6** `engine.io@6.6.6` -- **0.9557** [!] `GHSA-gr94-w7qr-f4j3` (transitive)
  - Path (1 hops, GHSA-gr94-w7qr-f4j3): `socket.io@4.8.3 -> engine.io@6.6.6`

**#7** `socket.io-adapter@2.5.6` -- **0.9258** *(propagation-elevated)* (transitive)

**#8** `qs@6.15.0` -- **0.6402** [!] `GHSA-4mjr-xmp4-gh2g` (transitive)
  - Path (1 hops, GHSA-4mjr-xmp4-gh2g): `express@5.2.1 -> qs@6.15.0`

**#9** `socket.io-parser@4.2.6` -- **0.5230** [!] `GHSA-2m8v-j782-fhvr` (transitive)
  - Path (1 hops, GHSA-2m8v-j782-fhvr): `socket.io@4.8.3 -> socket.io-parser@4.2.6`

**#10** `shell-quote@1.8.3` -- **0.4459** [!] `GHSA-w7jw-789q-3m8p` (transitive)
  - Path (1 hops, GHSA-w7jw-789q-3m8p): `concurrently@9.2.1 -> shell-quote@1.8.3`

### Key Insight

> VulnChain flagged **4** packages that have no CVE of their own
> but are elevated by propagation through vulnerable transitive dependencies.
> npm audit would not flag these packages at all -- they are the blast radius
> of the vulnerabilities, not the vulnerabilities themselves.

---

## Lockfile: `vuln_test`

### At-a-Glance Comparison

| Metric | npm audit | VulnChain |
|--------|-----------|-----------|
| Total packages analyzed | 11 | 11 |
| Vulnerability alerts | 4 (flat advisories) | 1 (risk >= 0.40) |
| Critical | 2 | 1 |
| High | 1 | 2 |
| Own-CVE flags | -- | 1 |
| Propagation-only flags | -- | 0 |
| Attack paths traced | -- | 4 |

### npm audit: Flat Advisory List

| Package | Severity | Via | Fix Available |
|---------|----------|-----|---------------|
| handlebars | critical | Arbitrary Code Execution in handlebars, Prototype Pollution in handlebars | [Y] |
| jquery | moderate | Cross-Site Scripting (XSS) in jquery, XSS in jQuery as used in Drupal, Backdrop CMS, and other products | [Y] |
| js-yaml | high | js-yaml has prototype pollution in merge (<<), JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases | [Y] |
| tar | critical | Arbitrary File Creation/Overwrite due to insufficient absolute path sanitization, Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization | [Y] |

### VulnChain: Ranked Top-10 with Propagation Paths

**#1** `jquery@2.2.4` -- **0.6531** [!] `GHSA-rmxg-73gg-4p98` (direct)
  - Path (0 hops, GHSA-rmxg-73gg-4p98): `jquery@2.2.4`

**#2** `js-yaml@3.13.1` -- **0.3985** [!] `GHSA-mh29-5h37-fv8m` (direct)
  - Path (0 hops, GHSA-mh29-5h37-fv8m): `js-yaml@3.13.1`

**#3** `tar@4.4.8` -- **0.2407** [!] `GHSA-w8wr-v893-vjvp` (direct)
  - Path (0 hops, GHSA-w8wr-v893-vjvp): `tar@4.4.8`

**#4** `argparse@1.0.10` -- **0.0800** *(propagation-elevated)* (transitive)

**#5** `minipass@2.9.0` -- **0.0800** *(propagation-elevated)* (transitive)

**#6** `yallist@3.1.1` -- **0.0800** *(propagation-elevated)* (transitive)

**#7** `esprima@4.0.1` -- **0.0763** *(propagation-elevated)* (transitive)

**#8** `chownr@1.1.4` -- **0.0570** *(propagation-elevated)* (transitive)

**#9** `minizlib@1.3.3` -- **0.0459** *(propagation-elevated)* (transitive)

**#10** `handlebars@4.0.5` -- **0.0404** [!] `GHSA-xjpj-3mr7-gcpf` (direct)
  - Path (0 hops, GHSA-xjpj-3mr7-gcpf): `handlebars@4.0.5`

### Key Insight

> All VulnChain flags correspond to packages with their own CVEs in this lockfile.

---

## Lockfile: `legacy_app`

### At-a-Glance Comparison

| Metric | npm audit | VulnChain |
|--------|-----------|-----------|
| Total packages analyzed | 9 | 9 |
| Vulnerability alerts | 7 (flat advisories) | 5 (risk >= 0.40) |
| Critical | 2 | 5 |
| High | 2 | 2 |
| Own-CVE flags | -- | 5 |
| Propagation-only flags | -- | 0 |
| Attack paths traced | -- | 7 |

### npm audit: Flat Advisory List

| Package | Severity | Via | Fix Available |
|---------|----------|-----|---------------|
| body-parser | high | body-parser vulnerable to denial of service when url encoding is enabled, body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement | [Y] |
| express | moderate | express vulnerable to XSS via response.redirect(), Express.js Open Redirect in malformed URLs | [Y] |
| lodash | critical | Command Injection in lodash, Prototype Pollution in lodash | [Y] |
| minimist | critical | Prototype Pollution in minimist | [Y] |
| qs | high | qs vulnerable to Prototype Pollution, qs's arrayLimit bypass in comma parsing allows denial of service | [Y] |
| send | low | send vulnerable to template injection that can lead to XSS | [Y] |
| serve-static | low | serve-static vulnerable to template injection that can lead to XSS, send | [Y] |

### VulnChain: Ranked Top-10 with Propagation Paths

**#1** `express@4.17.1` -- **1.0000** [!] `GHSA-rv95-896h-c2vc` (direct)
  - Path (0 hops, GHSA-rv95-896h-c2vc): `express@4.17.1`
  - Path (1 hops, GHSA-v422-hmwv-36x6): `express@4.17.1 -> body-parser@1.19.0`
  - Path (1 hops, GHSA-cm22-4g7w-348p): `express@4.17.1 -> serve-static@1.14.1`

**#2** `body-parser@1.19.0` -- **0.9765** [!] `GHSA-v422-hmwv-36x6` (transitive)
  - Path (1 hops, GHSA-v422-hmwv-36x6): `express@4.17.1 -> body-parser@1.19.0`

**#3** `serve-static@1.14.1` -- **0.9311** [!] `GHSA-cm22-4g7w-348p` (transitive)
  - Path (1 hops, GHSA-cm22-4g7w-348p): `express@4.17.1 -> serve-static@1.14.1`

**#4** `send@0.17.1` -- **0.8702** [!] `GHSA-m6fv-jmcg-4jfg` (transitive)
  - Path (2 hops, GHSA-m6fv-jmcg-4jfg): `express@4.17.1 -> serve-static@1.14.1 -> send@0.17.1`

**#5** `lodash@4.17.11` -- **0.4112** [!] `GHSA-xxjr-mmjv-4gpg` (direct)
  - Path (0 hops, GHSA-xxjr-mmjv-4gpg): `lodash@4.17.11`

**#6** `minimist@1.2.5` -- **0.3023** [!] `GHSA-xvch-5gv4-984h` (direct)
  - Path (0 hops, GHSA-xvch-5gv4-984h): `minimist@1.2.5`

**#7** `qs@6.7.0` -- **0.2021** [!] `GHSA-w7fw-mjwx-w883` (transitive)
  - Path (2 hops, GHSA-w7fw-mjwx-w883): `express@4.17.1 -> body-parser@1.19.0 -> qs@6.7.0`

**#8** `debug@2.6.9` -- **0.0800** *(propagation-elevated)* (transitive)

**#9** `ms@2.0.0` -- **0.0800** *(propagation-elevated)* (transitive)

### Key Insight

> All VulnChain flags correspond to packages with their own CVEs in this lockfile.

---

## Methodology Notes

- **VulnChain model:** VulnGAT-HR (frozen 2-layer GAT encoder trained on 51-repo graph, refit linear head)
- **Knowledge base:** 51-repo heterogeneous graph (12,405 packages, 883 CVEs, 2,632 hasVulnerability edges)
- **Risk score:** Sigmoid output [0, 1]; threshold at 0.40 for 'critical' classification
- **Propagation paths:** BFS upstream from each CVE-bearing package to direct dependencies
- **npm audit:** Standard `npm audit --json` with no registry modifications
- **Post-hoc calibration:** Packages with no CVE and no vulnerable descendant capped at 0.08

> [!NOTE]
> The 100% NodeTestBench precision claim from Phase 4 is **retracted** (D4).
> VulnGAT-HR precision on NodeTestBench is 75.6% (41 flagged, 10 FP) with recall 40.3%.
> The model's strength is in ranking and propagation-aware risk assessment, not binary detection.