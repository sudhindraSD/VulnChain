import React, { useCallback, useRef, useState } from 'react';
import UploadZone from './components/UploadZone.jsx';
import LoadingView from './components/LoadingView.jsx';
import ErrorPanel from './components/ErrorPanel.jsx';
import ResultsView from './components/ResultsView.jsx';
import { analyzeLockfile, preflightError, AnalyzeError } from './api.js';

export default function App() {
  const [phase, setPhase] = useState('idle'); // idle | loading | results | error
  const [fileName, setFileName] = useState('');
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const lastFileRef = useRef(null);

  const runAnalysis = useCallback(async (file) => {
    lastFileRef.current = file;
    setFileName(file.name);

    const problem = await preflightError(file);
    if (problem) {
      setError(new AnalyzeError('Unsupported file', problem));
      setPhase('error');
      return;
    }

    setPhase('loading');
    const controller = new AbortController();
    // Hard client cap, slightly above the backend's own 120s script timeout —
    // the UI must never hang silently.
    const timer = setTimeout(() => controller.abort(), 150_000);
    try {
      const result = await analyzeLockfile(file, controller.signal);
      setReport(result);
      setPhase('results');
    } catch (err) {
      setError(err instanceof AnalyzeError ? err : new AnalyzeError('Unexpected error', String(err)));
      setPhase('error');
    } finally {
      clearTimeout(timer);
    }
  }, []);

  const reset = useCallback(() => {
    setPhase('idle');
    setReport(null);
    setError(null);
    setFileName('');
    lastFileRef.current = null;
  }, []);

  return (
    <div className="shell">
      <header className="masthead">
        <div className="brand">
          <svg className="brand-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round">
            <path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z" />
          </svg>
          <span>VulnChain</span>
        </div>
        <span className="masthead-sub">GNN-powered dependency risk analysis</span>
      </header>

      <main>
        {phase === 'idle' && <UploadZone onFile={runAnalysis} />}
        {phase === 'loading' && <LoadingView fileName={fileName} />}
        {phase === 'error' && (
          <ErrorPanel
            error={error}
            canRetry={!!lastFileRef.current}
            onRetry={() => lastFileRef.current && runAnalysis(lastFileRef.current)}
            onReset={reset}
          />
        )}
        {phase === 'results' && <ResultsView report={report} fileName={fileName} onReset={reset} />}
      </main>

      <footer className="footer">
        <span>Risk tiers use the analyzer&rsquo;s own cutoffs&nbsp;· ≥40% critical&nbsp;· ≥20% high&nbsp;· ≥8% moderate</span>
        {report && (
          <span className="footer-meta">
            request {report.request_id} · {new Date(report.timestamp).toLocaleTimeString()}
          </span>
        )}
      </footer>
    </div>
  );
}
