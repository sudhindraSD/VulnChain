// Tier cutoffs mirrored EXACTLY from analyze_project.py's summary computation
// (phase5/bench_run/analyze_project.py, critical_count/high_count/... block):
//   critical: risk_score >= 0.40
//   high:     0.20 <= risk_score < 0.40
//   moderate: 0.08 <= risk_score < 0.20
//   no_known_risk: risk_score < 0.08
// The summary counts come from the backend verbatim; this function only derives
// a per-row tier label using those same cutoffs, as required. Do not change one
// without the other.
export const TIER_CUTOFFS = {
  critical: 0.40,
  high: 0.20,
  moderate: 0.08,
};

export const TIER_LABELS = {
  critical: 'Critical',
  high: 'High',
  moderate: 'Moderate',
  no_known_risk: 'No known risk',
  safe: 'No known risk',
};

export function tierOf(riskScore) {
  if (riskScore >= TIER_CUTOFFS.critical) return 'critical';
  if (riskScore >= TIER_CUTOFFS.high) return 'high';
  if (riskScore >= TIER_CUTOFFS.moderate) return 'moderate';
  return 'no_known_risk';
}

export const TIER_ORDER = ['critical', 'high', 'moderate', 'no_known_risk'];

export const TIER_RANK = { critical: 0, high: 1, moderate: 2, no_known_risk: 3, safe: 3 };

// Compare version strings numerically per segment ("2.2.2" < "10.0.0").
export function compareVersions(a, b) {
  const pa = String(a).split('.');
  const pb = String(b).split('.');
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = parseInt(pa[i] || '0', 10);
    const nb = parseInt(pb[i] || '0', 10);
    if (na !== nb) return na - nb;
    const sa = pa[i] || '';
    const sb = pb[i] || '';
    if (sa !== sb) return sa < sb ? -1 : 1;
  }
  return 0;
}

export function formatRisk(score) {
  return `${(score * 100).toFixed(2)}%`;
}
