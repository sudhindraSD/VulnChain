import React, { useMemo, useState } from 'react';
import { tierOf, TIER_ORDER, TIER_RANK, TIER_LABELS, compareVersions, formatRisk } from '../tiers.js';

const COLUMNS = [
  { id: 'name', label: 'Package', sortable: true },
  { id: 'version', label: 'Version', sortable: true },
  { id: 'risk', label: 'Risk', sortable: true },
  { id: 'tier', label: 'Tier', sortable: true },
  { id: 'dep', label: 'Dependency', sortable: true },
];

function advisoryUrl(cveId) {
  if (!cveId) return null;
  if (cveId.startsWith('GHSA-')) return `https://github.com/advisories/${cveId}`;
  if (cveId.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${cveId}`;
  return null;
}

function sortRows(rows, sort) {
  const sorted = [...rows];
  const dir = sort.dir === 'asc' ? 1 : -1;
  sorted.sort((a, b) => {
    let cmp = 0;
    switch (sort.key) {
      case 'name':
        cmp = a.name.localeCompare(b.name);
        break;
      case 'version':
        cmp = compareVersions(a.version, b.version);
        break;
      case 'risk':
        cmp = a.risk_score - b.risk_score;
        break;
      case 'tier':
        cmp = TIER_RANK[tierOf(a.risk_score)] - TIER_RANK[tierOf(b.risk_score)];
        break;
      case 'dep':
        cmp = (a.is_direct ? 0 : 1) - (b.is_direct ? 0 : 1);
        break;
      default:
        cmp = 0;
    }
    if (cmp === 0) cmp = a.risk_score - b.risk_score; // stable tiebreak on risk
    return cmp * dir;
  });
  return sorted;
}

function ExpandedDetail({ pkg }) {
  let statusClass, statusIcon, statusText;
  if (pkg.has_own_cve) {
    statusClass = 'own-cve';
    statusIcon = '!';
    statusText = (
      <>
        This package has a known vulnerability&nbsp;—&nbsp;
        {advisoryUrl(pkg.cve) ? (
          <a className="cve-link" href={advisoryUrl(pkg.cve)} target="_blank" rel="noreferrer">
            {pkg.cve}
          </a>
        ) : (
          <span className="cve-link">{pkg.cve}</span>
        )}
      </>
    );
  } else if (pkg.has_vuln_descendant) {
    statusClass = 'descendant';
    statusIcon = '↑';
    statusText = 'A downstream dependency is vulnerable.';
  } else {
    statusClass = 'clean';
    statusIcon = '✓';
    statusText = 'No known vulnerability in this package or its dependencies.';
  }

  return (
    <div className="row-detail">
      <p className={`detail-status ${statusClass}`}>
        <span className="detail-badge" aria-hidden="true">{statusIcon}</span>
        {statusText}
      </p>
      <div className="detail-meta">
        {pkg.cap_applied && (
          <span className="detail-chip cap-note" title="Post-hoc calibration">
            score adjusted downward by the post-hoc calibration step
          </span>
        )}
        <span className="detail-chip">
          depended on by {pkg.dependents_count} package{pkg.dependents_count === 1 ? '' : 's'}
        </span>
        <span className="detail-chip">{pkg.is_direct ? 'direct' : 'transitive'} dependency</span>
      </div>
    </div>
  );
}

export default function PackageTable({ packages, summary, totalPackages }) {
  const [sort, setSort] = useState({ key: 'risk', dir: 'desc' });
  const [tierFilter, setTierFilter] = useState('all');
  const [depFilter, setDepFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [expanded, setExpanded] = useState(() => new Set());

  const toggleSort = (key) => {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' }));
  };

  const toggleExpanded = (pkgId) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(pkgId)) next.delete(pkgId);
      else next.add(pkgId);
      return next;
    });
  };

  const rows = useMemo(() => {
    let filtered = packages;
    if (tierFilter !== 'all') {
      filtered = filtered.filter((p) => tierOf(p.risk_score) === tierFilter);
    }
    if (depFilter !== 'all') {
      filtered = filtered.filter((p) => (depFilter === 'direct' ? p.is_direct : !p.is_direct));
    }
    const q = query.trim().toLowerCase();
    if (q) {
      filtered = filtered.filter((p) => p.name.toLowerCase().includes(q));
    }
    return sortRows(filtered, sort);
  }, [packages, tierFilter, depFilter, query, sort]);

  return (
    <section className="table-section">
      <div className="controls">
        <div className="chip-row" role="group" aria-label="Filter by tier">
          <button
            className={`chip ${tierFilter === 'all' ? 'active' : ''}`}
            onClick={() => setTierFilter('all')}
          >
            All <span className="chip-count">{totalPackages}</span>
          </button>
          {TIER_ORDER.map((tier) => (
            <button
              key={tier}
              className={`chip tier-chip-${tier} ${tierFilter === tier ? 'active' : ''}`}
              onClick={() => setTierFilter(tierFilter === tier ? 'all' : tier)}
            >
              {TIER_LABELS[tier] || (tier[0].toUpperCase() + tier.slice(1))} <span className="chip-count">{(summary[tier] ?? (tier === 'no_known_risk' ? summary.safe : 0)) ?? 0}</span>
            </button>
          ))}
        </div>
        <div className="chip-row" role="group" aria-label="Filter by dependency type">
          {['all', 'direct', 'transitive'].map((d) => (
            <button
              key={d}
              className={`chip ${depFilter === d ? 'active' : ''}`}
              onClick={() => setDepFilter(d)}
            >
              {d === 'all' ? 'All deps' : d[0].toUpperCase() + d.slice(1)}
            </button>
          ))}
        </div>
        <input
          className="search"
          type="search"
          placeholder="Filter packages…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter packages by name"
        />
      </div>

      <div className="table-scroll">
        <table className="pkg-table">
          <thead>
            <tr>
              <th className="chevron-col" aria-hidden="true" />
              {COLUMNS.map((col) => (
                <th key={col.id}>
                  {col.sortable ? (
                    <button className="th-sort" onClick={() => toggleSort(col.id)}>
                      {col.label}
                      <span className={`sort-arrow ${sort.key === col.id ? 'visible' : ''}`}>
                        {sort.key === col.id && sort.dir === 'asc' ? '▲' : '▼'}
                      </span>
                    </button>
                  ) : (
                    col.label
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr className="no-match">
                <td colSpan={6}>No packages match the current filters.</td>
              </tr>
            )}
            {rows.map((pkg) => {
              const tier = tierOf(pkg.risk_score);
              const isOpen = expanded.has(pkg.package);
              return (
                <React.Fragment key={pkg.package}>
                  <tr
                    className={`pkg-row tier-row-${tier} ${isOpen ? 'open' : ''}`}
                    onClick={() => toggleExpanded(pkg.package)}
                  >
                    <td className="chevron-col" aria-hidden="true">
                      <span className={`chevron ${isOpen ? 'rotated' : ''}`}>▸</span>
                    </td>
                    <td className="cell-name">{pkg.name}</td>
                    <td className="cell-version">{pkg.version}</td>
                    <td className="cell-risk">
                      <span className={`risk-value tier-text-${tier}`}>{formatRisk(pkg.risk_score)}</span>
                      <span className="risk-track" aria-hidden="true">
                        <span className={`risk-fill tier-bg-${tier}`} style={{ width: `${Math.min(pkg.risk_score * 100, 100)}%` }} />
                      </span>
                    </td>
                    <td className="cell-tier">
                      <span className={`tier-badge tier-badge-${tier}`}>{TIER_LABELS[tier] || tier}</span>
                    </td>
                    <td className="cell-dep">
                      <span className={`dep-label ${pkg.is_direct ? 'direct' : ''}`}>
                        {pkg.is_direct ? 'Direct' : 'Transitive'}
                      </span>
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="detail-row">
                      <td colSpan={6}>
                        <ExpandedDetail pkg={pkg} />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="table-count">
        Showing {rows.length} of {totalPackages} packages
      </p>
    </section>
  );
}
