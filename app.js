/**
 * UI for JWT Peek. All decoding and checking lives in core.js.
 *
 * Deliberately absent: any fetch, any analytics, any storage of the token.
 * The textarea is the only place it exists.
 */
import { TIME_CLAIMS, claimToDate, decode, inspect, relativeTime, verifyHmac } from './core.js';

const el = {
  token: document.getElementById('token'),
  parseError: document.getElementById('parse-error'),
  sample: document.getElementById('sample'),
  clear: document.getElementById('clear'),
  findingsSection: document.getElementById('findings-section'),
  findings: document.getElementById('findings'),
  audience: document.getElementById('audience'),
  issuer: document.getElementById('issuer'),
  leeway: document.getElementById('leeway'),
  verifySection: document.getElementById('verify-section'),
  secret: document.getElementById('secret'),
  alg: document.getElementById('alg'),
  verify: document.getElementById('verify'),
  verifyResult: document.getElementById('verify-result'),
  decodedSection: document.getElementById('decoded-section'),
  header: document.getElementById('header'),
  payload: document.getElementById('payload'),
  times: document.querySelector('#times tbody'),
  timesTable: document.getElementById('times'),
  noTimes: document.getElementById('no-times'),
};

/** The sample is signed with the secret "secret" so Verify has something to do. */
const SAMPLE = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsImlhdCI6MTc5MzUwMDAwMCwiZXhwIjoxOTAwMDAwMDAwLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJhcGkifQ',
  'yzxlFKuLX8oPPlG1iQpYl0HvAR5E0aD-H1L1VVCdD8A',
].join('.');

function render() {
  const raw = el.token.value.trim();
  const show = (hidden) => {
    el.findingsSection.hidden = hidden;
    el.verifySection.hidden = hidden;
    el.decodedSection.hidden = hidden;
  };

  if (!raw) {
    el.parseError.textContent = '';
    show(true);
    return;
  }

  let decoded;
  try {
    decoded = decode(raw);
  } catch (error) {
    el.parseError.textContent = error.message;
    show(true);
    return;
  }

  el.parseError.textContent = '';
  show(false);

  el.header.textContent = JSON.stringify(decoded.header, null, 2);
  el.payload.textContent = JSON.stringify(decoded.payload, null, 2);

  renderFindings(decoded);
  renderTimes(decoded);
  el.verifyResult.textContent = '';
  el.verifyResult.className = '';
}

function renderFindings(decoded) {
  const findings = inspect(decoded, {
    leewaySeconds: Number(el.leeway.value) || 0,
    audience: el.audience.value.trim() || undefined,
    issuer: el.issuer.value.trim() || undefined,
  });

  el.findings.replaceChildren(...findings.map((finding) => {
    const li = document.createElement('li');
    li.className = finding.level;
    const claim = document.createElement('code');
    claim.textContent = finding.claim;
    li.append(claim, document.createTextNode(' ' + finding.message));
    return li;
  }));

  if (!findings.length) {
    const li = document.createElement('li');
    li.className = 'ok';
    li.textContent = 'Nothing to flag.';
    el.findings.append(li);
  }
}

function renderTimes(decoded) {
  const now = new Date();
  const rows = TIME_CLAIMS
    .filter((claim) => decoded.payload[claim] !== undefined)
    .map((claim) => ({ claim, parsed: claimToDate(decoded.payload[claim]) }))
    .filter((row) => row.parsed);

  el.timesTable.hidden = rows.length === 0;
  el.noTimes.hidden = rows.length > 0;

  el.times.replaceChildren(...rows.map(({ claim, parsed }) => {
    const tr = document.createElement('tr');
    const name = document.createElement('th');
    name.scope = 'row';
    name.textContent = claim + (parsed.suspectMilliseconds ? ' (ms?)' : '');

    const absolute = document.createElement('td');
    absolute.textContent = parsed.date.toLocaleString();

    const relative = document.createElement('td');
    relative.textContent = relativeTime(parsed.date, now);

    tr.append(name, absolute, relative);
    return tr;
  }));
}

el.token.addEventListener('input', render);
for (const input of [el.audience, el.issuer, el.leeway]) {
  input.addEventListener('input', render);
}

el.sample.addEventListener('click', () => {
  el.token.value = SAMPLE;
  el.secret.value = 'secret';
  render();
});

el.clear.addEventListener('click', () => {
  el.token.value = '';
  el.secret.value = '';
  render();
  el.token.focus();
});

el.verify.addEventListener('click', async () => {
  el.verifyResult.textContent = 'Checking…';
  el.verifyResult.className = 'muted';
  try {
    const result = await verifyHmac(el.token.value, el.secret.value, el.alg.value);
    el.verifyResult.textContent = result.valid
      ? `Signature is valid for ${el.alg.value}.`
      : result.reason;
    el.verifyResult.className = result.valid ? 'ok-text' : 'error';
  } catch (error) {
    el.verifyResult.textContent = error.message;
    el.verifyResult.className = 'error';
  }
});

render();
