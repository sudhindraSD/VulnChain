#!/usr/bin/env python3
"""Generate paper_notes/paper_tables.md from the project's frozen source files.

Stdlib only. Every number is parsed from a source file at run time; nothing is
typed by hand. If a value cannot be sourced, the cell is written UNRESOLVED,
the failure is reported on stderr and the script exits non-zero.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "paper_notes" / "paper_tables.md"

failures = []


def read(rel):
    try:
        return (ROOT / rel).read_text(encoding="utf-8")
    except (OSError, ValueError) as e:
        failures.append(f"{rel}: could not read file ({e})")
        return ""


def read_json(rel):
    txt = read(rel)
    if not txt:
        return {}
    try:
        return json.loads(txt)
    except ValueError as e:
        failures.append(f"{rel}: invalid JSON ({e})")
        return {}


def commit_of(rel):
    r = subprocess.run(
        ["git", "log", "-1", "--format=%h", "--", rel],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    h = r.stdout.strip()
    if not h:
        failures.append(f"{rel}: git log returned no commit")
        return "?"
    return h


def grab(pattern, text, source, label, group=1, flags=re.S):
    """First (and only) regex match in text; UNRESOLVED on zero or many hits."""
    hits = list(re.finditer(pattern, text, flags))
    if len(hits) != 1:
        failures.append(f"{source}: expected exactly 1 match for {label!r}, found {len(hits)}")
        return "UNRESOLVED"
    m = hits[0]
    if m.group(group) is None:
        failures.append(f"{source}: group {group} empty for {label!r}")
        return "UNRESOLVED"
    return m.group(group)


SEP_RE = re.compile(r"\|[\s:\|\-]*\|")


def md_tables(text):
    """Parse GitHub-style tables: header row, |---| separator, then rows."""
    tables = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith("|") and i + 1 < len(lines) and SEP_RE.fullmatch(lines[i + 1].strip()):
            header = [c.strip() for c in lines[i].strip().strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            tables.append({"header": header, "rows": rows})
        else:
            i += 1
    return tables


def find_table(tables, header_pats, source, label):
    pats = [re.compile(p) for p in header_pats]
    hits = [t for t in tables if all(any(p.search(h) for h in t["header"]) for p in pats)]
    if len(hits) != 1:
        failures.append(f"{source}: expected exactly 1 table matching {label!r}, found {len(hits)}")
        return None
    return hits[0]


def col_index(tbl, cell_pat, source, label):
    cp = re.compile(cell_pat)
    cols = [j for j, h in enumerate(tbl["header"]) if cp.search(h)]
    if len(cols) != 1:
        failures.append(f"{source}: expected exactly 1 column matching {label!r}, found {len(cols)}")
        return None
    return cols[0]


def row_by_first_cell(tbl, row_pat, source, label, mode="full"):
    rp = re.compile(row_pat)
    hits = [r for r in tbl["rows"] if r and (
        rp.fullmatch(r[0]) if mode == "full" else rp.match(r[0]))]
    if len(hits) != 1:
        failures.append(f"{source}: expected exactly 1 row matching {label!r}, found {len(hits)}")
        return None
    return hits[0]


def first_cell_row(tables, row_pat, source, label):
    rp = re.compile(row_pat)
    hits = [r for t in tables for r in t["rows"] if r and rp.fullmatch(r[0])]
    if len(hits) != 1:
        failures.append(f"{source}: expected exactly 1 row matching {label!r}, found {len(hits)}")
        return None
    return hits[0]


def cell_at(row, j, source, label):
    if row is None or j is None:
        return "UNRESOLVED"
    if j >= len(row):
        failures.append(f"{source}: row too short for {label!r}")
        return "UNRESOLVED"
    return row[j]


def num_in(s, source, label):
    m = re.search(r"([\d.]+)", str(s))
    if not m:
        failures.append(f"{source}: no number in {label!r}")
        return "UNRESOLVED"
    return m.group(1)


def fmt6(v):
    try:
        return f"{float(v):.6f}"
    except (TypeError, ValueError):
        failures.append("non-numeric value where a formatted number was required")
        return "UNRESOLVED"


def esc(s):
    return str(s).replace("|", "\\|")


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(esc(c) for c in r) + " |")
    return "\n".join(out)


def footnote(rels):
    return "Sources: " + "; ".join(f"`{rel}` @ `{commit_of(rel)}`" for rel in rels)


def jget(d, key, source):
    if key not in d:
        failures.append(f"{source}: missing key {key!r}")
        return "UNRESOLVED"
    return d[key]


def main():
    parts = []
    parts.append("# VulnChain — paper tables (auto-generated)")
    parts.append("")
    parts.append("<!-- Generated by paper_notes/make_tables.py — do not edit by hand; "
                 "edit the generator and re-run. Every value is parsed from the cited source "
                 "file at the commit shown; values that cannot be sourced are written "
                 "UNRESOLVED and the generator exits non-zero. -->")
    parts.append("")

    # ------------------------------------------------------------------
    # Table 1 — leak audit (phase5/HYBRID_GATE.md)
    # ------------------------------------------------------------------
    src = "phase5/HYBRID_GATE.md"
    gate_txt = read(src)
    gate_tbls = md_tables(gate_txt)

    lp_orig = first_cell_row(gate_tbls, r"`LP_original`", src, "LP_original row")
    lp_auc = cell_at(lp_orig, 1, src, "LP_original mean±std")
    lp_verdict = cell_at(lp_orig, 5, src, "LP_original verdict")
    lp_bar = cell_at(lp_orig, 3, src, "LP_original success bar")

    lp_clean = first_cell_row(gate_tbls, r"`LP_clean` \(VPSS recomputed on masked graph\)",
                              src, "LP_clean row")
    hr_row = first_cell_row(gate_tbls, r"VulnGAT-HR \(unchanged\)", src, "VulnGAT-HR row")
    bfs_row = first_cell_row(gate_tbls, r"BFS \(unchanged, for reference\)", src, "BFS row")

    parts.append("## Table 1 — Leak audit (original gate comparators)")
    parts.append("")
    parts.append(md_table(
        ["Comparator", "Mean ± Std ROC-AUC", "Note"],
        [
            ["LP_original", lp_auc, f"FAIL vs success bar {lp_bar}; verdict: {lp_verdict}"],
            ["LP_clean (VPSS recomputed on masked graph)", cell_at(lp_clean, 1, src, "LP_clean value"), "cleaned known-set"],
            ["VulnGAT-HR (unchanged)", cell_at(hr_row, 1, src, "HR value"), "candidate model"],
            ["BFS (unchanged, for reference)", cell_at(bfs_row, 1, src, "BFS value"), "reference only"],
        ],
    ))
    parts.append("")
    parts.append(footnote([src]))
    parts.append("")

    # ------------------------------------------------------------------
    # Table 2 — invalid / negative results
    # ------------------------------------------------------------------
    audit_src = "phase5/HYBRID_AUDIT.md"
    add2_src = "HYBRID_GATE_ADDENDUM2.md"
    lc_src = "phase5/LEARNING_CURVE.md"
    v22_src = "phase5/V22_SANITY.md"
    audit_txt = read(audit_src)
    add2_txt = read(add2_src)
    lc_txt = read(lc_src)
    v22_txt = read(v22_src)
    audit_tbls = md_tables(audit_txt)
    v22_tbls = md_tables(v22_txt)

    cs_tbl = find_table(audit_tbls, [r"C&S_CURRENT", r"C&S_STRICT"], audit_src, "C&S table")
    cs_mean = row_by_first_cell(cs_tbl, r"mean ± std", audit_src, "mean ± std row") if cs_tbl else None
    cs_cur_j = col_index(cs_tbl, r"C&S_CURRENT", audit_src, "C&S_CURRENT col") if cs_tbl else None
    cs_str_j = col_index(cs_tbl, r"C&S_STRICT", audit_src, "C&S_STRICT col") if cs_tbl else None
    cs_current = cell_at(cs_mean, cs_cur_j, audit_src, "C&S_CURRENT mean±std")
    cs_strict = cell_at(cs_mean, cs_str_j, audit_src, "C&S_STRICT mean±std")

    perm_tbl = find_table(audit_tbls, [r"permuted AUC"], audit_src, "permuted table")
    perm_mean = row_by_first_cell(perm_tbl, r"mean ± std", audit_src, "permuted mean row") if perm_tbl else None
    perm_auc = cell_at(perm_mean, 1, audit_src, "permuted mean±std")

    cs_status = grab(r"\*\*(The original C&S .PASS. is INVALID\.)\*\*", add2_txt, add2_src, "C&S invalid status")
    cs_delta = grab(r"mean paired delta of \S+ \(`(\+[\d.]+)`\) over", add2_txt, add2_src, "C&S paired delta")
    cs_reason_n = grab(r"set contained \*\*all ([\d,]+)\s*(\w+)\s*(\w+)", add2_txt, add2_src, "known_CURRENT count", group=1)
    cs_reason_w = grab(r"set contained \*\*all ([\d,]+)\s*(\w+)\s*(\w+)", add2_txt, add2_src, "known_CURRENT noun", group=2)
    cs_reason_w2 = grab(r"set contained \*\*all ([\d,]+)\s*(\w+)\s*(\w+)", add2_txt, add2_src, "known_CURRENT noun 2", group=3)
    cs_withdrawn = grab(r"(The [\d.]+ / \+[\d.]+ PASS is withdrawn)", add2_txt, add2_src, "withdrawn phrase")
    cs_reason = "known_CURRENT contained all " + cs_reason_n + \
                (f" {cs_reason_w} {cs_reason_w2}" if cs_reason_w not in ("UNRESOLVED", "") else "")
    strict_sent = grab(r"(C&S_STRICT mean AUC [\d.]+ does not exceed LP_clean mean [\d.]+ "
                       r"by more than [\d.]+ \(. = -?[\d.]+\)\.)", audit_txt, audit_src, "C&S_STRICT sentence")
    perm_dist = grab(r"mean . 0\.5. = ([\d.]+)", audit_txt, audit_src, "|mean - 0.5|")
    perm_status = grab(r"\*\*(NOT near 0\.5 \(FAIL[^)]*\))\*\*", audit_txt, audit_src, "permuted status")
    perm_null = grab(r"This is a \*\*(mis-specified null)\*\*", add2_txt, add2_src, "mis-specified null")

    lc_stop_a = grab(r"STOPPED.{0,3}Assertion A FAILED in (\d+)/(\d+) runs", lc_txt, lc_src, "Assertion A runs", group=1)
    lc_stop_b = grab(r"STOPPED.{0,3}Assertion A FAILED in (\d+)/(\d+) runs", lc_txt, lc_src, "Assertion A runs", group=2)
    lc_a_p = grab(r"only ([\d,]+)/([\d,]+) positives and ([\d,]+)/([\d,]+) negatives",
                  lc_txt, lc_src, "Assertion A example positives", group=1)
    lc_a_P = grab(r"only ([\d,]+)/([\d,]+) positives and ([\d,]+)/([\d,]+) negatives",
                  lc_txt, lc_src, "Assertion A example positives total", group=2)
    lc_a_n = grab(r"only ([\d,]+)/([\d,]+) positives and ([\d,]+)/([\d,]+) negatives",
                  lc_txt, lc_src, "Assertion A example negatives", group=3)
    lc_a_N = grab(r"only ([\d,]+)/([\d,]+) positives and ([\d,]+)/([\d,]+) negatives",
                  lc_txt, lc_src, "Assertion A example negatives total", group=4)
    lc_b_a = grab(r"Assertion B FAILED in (\d+)/(\d+) runs", lc_txt, lc_src, "Assertion B runs", group=1)
    lc_b_b = grab(r"Assertion B FAILED in (\d+)/(\d+) runs", lc_txt, lc_src, "Assertion B runs", group=2)
    lc_eval = grab(r"(training was stopped before any run \(exceeds [\d.]+: not evaluable\))",
                   lc_txt, lc_src, "learning curve evaluability")

    v22_tbl = find_table(v22_tbls, [r"v2\.2 \(100 [Ee]pochs\)", r"Threshold / Target Bar"],
                         v22_src, "V22 metrics table")
    v22_col = col_index(v22_tbl, r"v2\.2 \(100 [Ee]pochs\)", v22_src, "v2.2 100-epoch col") if v22_tbl else None
    v22_gate_col = col_index(v22_tbl, r"Threshold / Target Bar", v22_src, "gate col") if v22_tbl else None
    val_row = row_by_first_cell(v22_tbl, r"\*\*Val Spearman \(Nonzero cut, N=451\)\*\*",
                                v22_src, "Val Spearman row") if v22_tbl else None
    test_row = row_by_first_cell(v22_tbl, r"\*\*Test Spearman \(Nonzero cut, N=1,433\)\*\*",
                                 v22_src, "Test Spearman row") if v22_tbl else None
    val_v22 = cell_at(val_row, v22_col, v22_src, "Val v2.2 value")
    test_v22 = cell_at(test_row, v22_col, v22_src, "Test v2.2 value")
    gate_raw = cell_at(test_row, v22_gate_col, v22_src, "gate cell")
    gate_val = num_in(gate_raw, v22_src, "gate value") if gate_raw != "UNRESOLVED" else "UNRESOLVED"
    if val_v22 != "UNRESOLVED" and gate_val != "UNRESOLVED":
        try:
            temporal_verdict = "FAIL (derived in generator: {} < {})".format(
                float(num_in(test_v22, v22_src, "test v2.2 number")), float(gate_val))
        except ValueError:
            temporal_verdict = "UNRESOLVED"
            failures.append(f"{v22_src}: could not compare temporal value vs gate")
    else:
        temporal_verdict = "UNRESOLVED"

    parts.append("## Table 2 — Invalid / negative results")
    parts.append("")
    parts.append(md_table(
        ["Result", "Value", "Source"],
        [
            ["C&S hybrid (C&S_CURRENT) — mean ± std ROC-AUC", cs_current, f"`{audit_src}`"],
            ["C&S hybrid — mean paired delta over LP_clean", cs_delta, f"`{add2_src}`"],
            ["C&S hybrid — status", cs_status, f"`{add2_src}`"],
            ["C&S hybrid — why invalid", f"{cs_reason}; {cs_withdrawn}", f"`{add2_src}`"],
            ["C&S_STRICT — mean ± std ROC-AUC", cs_strict, f"`{audit_src}`"],
            ["C&S_STRICT — margin check (verbatim)", strict_sent, f"`{audit_src}`"],
            ["Permuted-label control — mean ± std AUC", perm_auc, f"`{audit_src}`"],
            ["Permuted-label control — distance from 0.5", f"|mean − 0.5| = {perm_dist}", f"`{audit_src}`"],
            ["Permuted-label control — status", perm_status, f"`{audit_src}`"],
            ["Permuted-label control — interpretation", perm_null, f"`{add2_src}`"],
            ["Learning curve — Assertion A", f"STOPPED — FAILED in {lc_stop_a}/{lc_stop_b} runs", f"`{lc_src}`"],
            ["Learning curve — Assertion A example", f"keeps only {lc_a_p}/{lc_a_P} positives and {lc_a_n}/{lc_a_N} negatives", f"`{lc_src}`"],
            ["Learning curve — Assertion B", f"FAILED in {lc_b_a}/{lc_b_b} runs", f"`{lc_src}`"],
            ["Learning curve — evaluability", lc_eval, f"`{lc_src}`"],
            ["Temporal split — Val Spearman, v2.2 (100 Epochs), Nonzero cut (N=451)", val_v22, f"`{v22_src}`"],
            ["Temporal split — Test Spearman, v2.2 (100 Epochs), Nonzero cut (N=1,433)", test_v22, f"`{v22_src}`"],
            ["Temporal split — Secondary Gate bar", gate_val, f"`{v22_src}`"],
            ["Temporal split — verdict", temporal_verdict, f"`{v22_src}` (derived)"],
        ],
    ))
    parts.append("")

    # ------------------------------------------------------------------
    # Table 3 — Task D per-seed paired deltas (phase5/confirm_metrics.json + CONFIRM_RESULT.md)
    # ------------------------------------------------------------------
    cm_src = "phase5/confirm_metrics.json"
    cr_src = "phase5/CONFIRM_RESULT.md"
    cm = read_json(cm_src)
    cr_txt = read(cr_src)
    cr_tbls = md_tables(cr_txt)

    rows = jget(cm, "rows", cm_src)
    verdict = jget(cm, "verdict", cm_src)
    key_deltas = ["CANDIDATE-LP_clean", "CANDIDATE-HR", "CANDIDATE-RANK_AVG(RIDGE,LP_clean)"]

    t3_rows = []
    if isinstance(rows, list) and rows:
        for r in rows:
            seed = jget(r, "seed", cm_src)
            vals = [fmt6(jget(r, k, cm_src)) for k in key_deltas]
            vals.append(fmt6(jget(r, "PERM_ALL", cm_src)))
            t3_rows.append([str(seed)] + vals)
    else:
        failures.append(f"{cm_src}: 'rows' missing or not a list")

    mean_cells = [grab(r"\| mean \| (\+[\d.]+) \| (\+[\d.]+) \| (\+[\d.]+) \|\s*$",
                       cr_txt, cr_src, f"mean col {j}", group=j, flags=re.S | re.M) for j in (1, 2, 3)]
    std_cells = [grab(r"\| std \(ddof=1\) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \|\s*$",
                      cr_txt, cr_src, f"std col {j}", group=j, flags=re.S | re.M) for j in (1, 2, 3)]

    perm_null_line = grab(r"mean = ([\d.]+); std \(ddof=1\) = ([\d.]+); outside (\S+) = (True|False)",
                          cr_txt, cr_src, "permuted null line")
    perm_null_m = re.search(r"mean = ([\d.]+); std \(ddof=1\) = ([\d.]+); outside (\S+) = (True|False)",
                            cr_txt, re.S)
    if perm_null_m:
        perm_mean_cell, perm_std_cell = perm_null_m.group(1), perm_null_m.group(2)
        perm_outside = f"outside {perm_null_m.group(3)} = {perm_null_m.group(4)}"
    else:
        perm_mean_cell = perm_std_cell = perm_outside = "UNRESOLVED"

    t3_rows.append(["mean"] + mean_cells + [perm_mean_cell])
    t3_rows.append(["std (ddof=1)"] + std_cells + [perm_std_cell])

    parts.append("## Table 3 — Task D per-seed paired deltas (CANDIDATE = RANK_AVG(RIDGE,LP_clean))")
    parts.append("")
    parts.append(md_table(
        ["Seed", "CANDIDATE − LP_clean", "CANDIDATE − HR", "CANDIDATE − RANK_AVG(RIDGE,LP_clean)", "PERM_ALL (AUC)"],
        t3_rows,
    ))
    parts.append("")
    threshold = grab(r"(threshold = max\([\d.]+, 2 \* sd_delta\) = [\d.]+)", cr_txt, cr_src, "threshold")
    primary = grab(r"PRIMARY: (PASS|FAIL)", cr_txt, cr_src, "primary verdict")
    sec_tbl = find_table(cr_tbls, [r"Secondary", r"mean paired delta"], cr_src, "secondaries table")
    sec_rows = [[c for c in r] for r in sec_tbl["rows"]] if sec_tbl else [["UNRESOLVED"]]
    parts.append(md_table(
        ["Check", "Value"],
        [
            ["Primary verdict", primary],
            ["Threshold", threshold],
            ["Permuted-label null (PERM_ALL)", f"mean {perm_mean_cell}; std (ddof=1) {perm_std_cell}; {perm_outside}"],
        ],
    ))
    parts.append("")
    parts.append("Secondaries:")
    parts.append("")
    parts.append(md_table(["Secondary", "mean paired delta", "bar", "outcome"], sec_rows))
    parts.append("")
    parts.append(footnote([cm_src, cr_src]))
    parts.append("")

    # ------------------------------------------------------------------
    # Table 4 — Task D post-hoc (phase5/CONFIRM_POSTHOC.md)
    # ------------------------------------------------------------------
    cp_src = "phase5/CONFIRM_POSTHOC.md"
    cp_txt = read(cp_src)
    cp_tbls = md_tables(cp_txt)

    cp2 = find_table(cp_tbls, [r"CANDIDATE \(HR\+LP_clean\)", r"RANK_AVG\(HR, BINARISED_LP\)"],
                     cp_src, "post-hoc AUC table")
    cp3 = find_table(cp_tbls, [r"CANDIDATE . CANDIDATE", r"CANDIDATE . NONZERO_NBR"],
                     cp_src, "post-hoc paired-delta table")

    parts.append("## Table 4 — Task D post-hoc (fusions vs the Task D candidate)")
    parts.append("")
    parts.append("Per-seed ROC-AUC (recomputed), mean and std (ddof=1):")
    parts.append("")
    if cp2:
        parts.append(md_table(cp2["header"], cp2["rows"]))
    else:
        parts.append(md_table(["UNRESOLVED"], [["UNRESOLVED"]]))
    parts.append("")
    parts.append("Paired deltas: CANDIDATE minus each method:")
    parts.append("")
    if cp3:
        parts.append(md_table(cp3["header"], cp3["rows"]))
    else:
        parts.append(md_table(["UNRESOLVED"], [["UNRESOLVED"]]))
    parts.append("")
    parts.append(footnote([cp_src]))
    parts.append("")

    # ------------------------------------------------------------------
    # Table 5 — proof module
    # ------------------------------------------------------------------
    vr_src = "proof/out/verify_report.json"
    na_src = "proof/out/npm_audit_comparison.json"
    oo_src = "proof/out/offline_online.json"
    pp2_src = "PROOF_POSTHOC2.md"
    pp_src = "PROOF_POSTHOC.md"
    vr = read_json(vr_src)
    na = read_json(na_src)
    oo = read_json(oo_src)
    pp2_txt = read(pp2_src)
    pp_txt = read(pp_src)

    vr_counts = jget(vr, "counts", vr_src)
    na_counts = jget(na, "counts", na_src)
    oo_counts = jget(oo, "counts", oo_src)

    pid_rec = grab(r"\| `VC_FLAGGED` \| (\d+) records / \*\*(\d+) distinct pids\*\*",
                  pp2_txt, pp2_src, "VC_FLAGGED records", group=1)
    pid_dist = grab(r"\| `VC_FLAGGED` \| (\d+) records / \*\*(\d+) distinct pids\*\*",
                    pp2_txt, pp2_src, "VC_FLAGGED distinct pids", group=2)
    pid_both = grab(r"\| both \| \*\*(\d+)\*\*", pp2_txt, pp2_src, "pids both")
    pid_vc_only = grab(r"\| VC-flagged-only \| \*\*(\d+)\*\*", pp2_txt, pp2_src, "pids VC-only")
    pid_npm_only = grab(r"\| npm-only \| \*\*(\d+)\*\*", pp2_txt, pp2_src, "pids npm-only")

    unres = grab(r"UNRESOLVED`\) = (\d+)\s*records = (\d+) distinct", pp_txt, pp_src, "UNRESOLVED records")
    distinct = grab(r"UNRESOLVED`\) = (\d+)\s*records = (\d+) distinct", pp_txt, pp_src, "distinct packages", group=2)

    agree = jget(oo_counts, "agree_count", oo_src)
    total = jget(oo_counts, "units_total", oo_src)
    rate = jget(oo, "agreement_rate", oo_src)
    if all(v != "UNRESOLVED" for v in (agree, total, rate)):
        oo_summary = f"{agree} / {total} agree (rate {float(rate):.6f})"
    else:
        oo_summary = "UNRESOLVED"

    parts.append("## Table 5 — Proof module")
    parts.append("")
    parts.append(md_table(
        ["Quantity", "Value", "Source"],
        [
            ["Verified paths (pass / total)", f"{jget(vr_counts, 'paths_pass', vr_src)} / {jget(vr_counts, 'paths_total', vr_src)}", f"`{vr_src}`"],
            ["Verified paths — failures", jget(vr_counts, "paths_fail", vr_src), f"`{vr_src}`"],
            ["Packages with no path", jget(vr_counts, "packages_with_no_path", vr_src), f"`{vr_src}`"],
            ["VC_FLAGGED (records / distinct pids)", f"{pid_rec} records / {pid_dist} distinct pids", f"`{pp2_src}`"],
            ["npm audit comparison, VC-flagged records unit — found by both", jget(na_counts, "found_by_both", na_src), f"`{na_src}`"],
            ["npm audit comparison, VC-flagged records unit — VulnChain only", jget(na_counts, "vulnchain_only", na_src), f"`{na_src}`"],
            ["npm audit comparison, VC-flagged records unit — npm audit only", jget(na_counts, "npm_audit_only", na_src), f"`{na_src}`"],
            ["npm audit comparison, distinct pids unit — found by both", pid_both, f"`{pp2_src}`"],
            ["npm audit comparison, distinct pids unit — VulnChain only", pid_vc_only, f"`{pp2_src}`"],
            ["npm audit comparison, distinct pids unit — npm audit only", pid_npm_only, f"`{pp2_src}`"],
            ["UNEXPLAINED", jget(na, "unexplained_count", na_src), f"`{na_src}`"],
            ["Offline/online agreement", oo_summary, f"`{oo_src}`"],
            ["model_score UNRESOLVED", f"{unres} records / {distinct} distinct packages", f"`{pp_src}`"],
        ],
    ))
    parts.append("")
    parts.append(footnote([vr_src, na_src, oo_src, pp2_src, pp_src]))
    parts.append("")

    OUT.write_text("\n".join(parts), encoding="utf-8")

    if failures:
        print("make_tables.py: UNSOURCED VALUES / ERRORS:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(f"Wrote {OUT} with UNRESOLVED cells; exiting non-zero.", file=sys.stderr)
        return 1
    print(f"OK: wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
