import json
with open("cve_seed_ids.json") as f:
    ids = json.load(f)
cve = [i for i in ids if i.startswith("CVE-")]
ghsa = [i for i in ids if i.startswith("GHSA-")]
other = [i for i in ids if not i.startswith("CVE-") and not i.startswith("GHSA-")]
print(f"CVE-prefixed: {len(cve)}")
print(f"GHSA-only: {len(ghsa)}")
print(f"Other: {len(other)} -> {other[:10]}")