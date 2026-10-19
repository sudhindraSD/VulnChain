import React from 'react';

export default function ErrorPanel({ error, canRetry, onRetry, onReset }) {
  return (
    <div className="error-panel" role="alert">
      <svg className="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
      <h1 className="error-title">{error.title}</h1>
      <p className="error-detail">{error.detail}</p>
      <div className="error-actions">
        {canRetry && (
          <button className="btn" onClick={onRetry}>Try again</button>
        )}
        <button className="btn btn-ghost" onClick={onReset}>Choose another file</button>
      </div>
    </div>
  );
}
