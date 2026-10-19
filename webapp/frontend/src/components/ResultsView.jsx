import React from 'react';
import SummaryBar from './SummaryBar.jsx';
import PackageTable from './PackageTable.jsx';

export default function ResultsView({ report, fileName, onReset }) {
  return (
    <div className="results">
      <div className="results-header">
        <div>
          <h1 className="results-title">Risk report</h1>
          <p className="results-file">
            <span className="mono">{fileName}</span> · {report.total_packages} packages analyzed
          </p>
        </div>
        <button className="btn btn-ghost" onClick={onReset}>Analyze another lockfile</button>
      </div>

      <SummaryBar summary={report.summary} totalPackages={report.total_packages} />
      <PackageTable packages={report.packages} summary={report.summary} totalPackages={report.total_packages} />
    </div>
  );
}
