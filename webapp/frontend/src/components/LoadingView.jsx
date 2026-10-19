import React, { useEffect, useState } from 'react';

export default function LoadingView({ fileName }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const started = Date.now();
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="loading">
      <div className="spinner" aria-hidden="true" />
      <h1 className="loading-title">Analyzing dependency graph<span className="ellipsis">…</span></h1>
      <p className="loading-file">{fileName}</p>
      <p className="loading-timer">{elapsed}s</p>
      <p className="loading-note">
        Building the dependency graph and running VulnGAT inference.
        <br />
        This can take up to a minute on larger lockfiles.
      </p>
    </div>
  );
}
