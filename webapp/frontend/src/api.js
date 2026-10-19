// Client for the VulnChain backend (POST /api/analyze).
// Client-side checks mirror the backend's validation for instant feedback on
// obviously-bad files; the backend remains the authority for everything.

const UNSUPPORTED = [
  { match: 'yarn.lock', manager: 'Yarn' },
  { match: 'pnpm-lock.yaml', manager: 'pnpm' },
];

// Returns an error message string, or null if the file passes pre-flight checks.
export async function preflightError(file) {
  const name = (file.name || '').toLowerCase();
  for (const { match, manager } of UNSUPPORTED) {
    if (name.includes(match)) {
      return `"${file.name}" is a ${manager} lockfile. Only npm package-lock.json is supported — generate one with \`npm install\` in the project.`;
    }
  }
  let text;
  try {
    text = await file.text();
  } catch {
    return 'Could not read the file. Please try again.';
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return 'File is not valid JSON. package-lock.json must be a valid JSON file.';
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return 'File is valid JSON but not an npm lockfile (expected a JSON object).';
  }
  if (!('lockfileVersion' in data)) {
    return 'Missing "lockfileVersion" — this does not look like an npm package-lock.json.';
  }
  if (!('packages' in data) && !('dependencies' in data)) {
    return 'Missing "packages"/"dependencies" — this does not look like an npm package-lock.json.';
  }
  return null;
}

export class AnalyzeError extends Error {
  constructor(title, detail) {
    super(detail);
    this.title = title;
    this.detail = detail;
  }
}

function titleForStatus(status) {
  if (status === 400) return 'Unsupported file';
  if (status === 422) return 'No file received';
  if (status === 504) return 'Analysis timed out';
  if (status === 502) return 'Analyzer failure';
  return `Request failed (${status})`;
}

export async function analyzeLockfile(file, signal) {
  const form = new FormData();
  form.append('file', file, file.name);

  let resp;
  try {
    resp = await fetch('/api/analyze', { method: 'POST', body: form, signal });
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new AnalyzeError('Analysis timed out', 'The model took too long to respond. Please try again.');
    }
    throw new AnalyzeError(
      'Cannot reach the VulnChain server',
      'Is the backend running? Start it with: python webapp/server.py'
    );
  }

  const data = await resp.json().catch(() => null);
  if (!resp.ok) {
    throw new AnalyzeError(titleForStatus(resp.status), data?.detail || 'The request failed.');
  }
  return data;
}
