import React from 'react';
import { TIER_ORDER } from '../tiers.js';

// Renders report.summary VERBATIM — counts come straight from analyze_project.py,
// never recomputed on the frontend.
export default function SummaryBar({ summary, totalPackages }) {
  return (
    <section className="summary" aria-label="Risk summary">
      {TIER_ORDER.map((tier) => {
        const count = summary[tier] ?? 0;
        const share = totalPackages > 0 ? Math.round((count / totalPackages) * 100) : 0;
        return (
          <div key={tier} className={`summary-card tier-${tier} ${count === 0 ? 'is-zero' : ''}`}>
            <span className="summary-count">{count}</span>
            <span className="summary-label">{tier}</span>
            <div className="summary-track" aria-hidden="true">
              <div className="summary-fill" style={{ width: `${share}%` }} />
            </div>
          </div>
        );
      })}
    </section>
  );
}
