#!/usr/bin/env node
'use strict';

const fs = require('fs');
const core = require('../src/core.js');
const VERSION = require('../package.json').version;

// ----- tiny color helpers (no dep) -----
const useColor = process.stdout.isTTY && !process.env.NO_COLOR && !process.argv.includes('--no-color');
const col = (c, s) => (useColor ? `\x1b[${c}m${s}\x1b[0m` : s);
const red = (s) => col('31', s), green = (s) => col('32', s), yellow = (s) => col('33', s),
  dim = (s) => col('2', s), bold = (s) => col('1', s), cyan = (s) => col('36', s);

const HELP = `${bold('jwtpeek')} — decode & inspect a JWT in your terminal. Decodes only, never verifies.

${bold('Usage')}
  jwtpeek <token>            Decode a token and show header, payload & expiry
  jwtpeek <token> --json     Machine-readable {header, payload, signature, ...}
  jwtpeek <token> --header   Print only the decoded header (JSON)
  jwtpeek <token> --payload  Print only the decoded payload (JSON)
  pbpaste | jwtpeek          Read the token from stdin (pipe)
  echo "$AUTH" | jwtpeek     "Bearer "/"Authorization:" prefixes are stripped

${bold('Options')}
  --json        Full structure as JSON (stdout stays pure; notes go to stderr)
  --header      Only the header object
  --payload     Only the payload object
  --no-color    Disable ANSI colors
  -v, --version
  -h, --help

${bold('Exit')}  0 valid (or no exp) · 1 expired · 2 decode error
`;

function fail(msg) {
  process.stderr.write(red(`jwtpeek: ${msg}\n`));
  process.exit(2);
}

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}

// "2018-01-18T02:30:22.000Z" -> "2018-01-18 02:30:22 UTC"
function isoUTC(ms) {
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '') + ' UTC';
}

function indentJSON(obj) {
  return JSON.stringify(obj, null, 2).split('\n').map((l) => '  ' + l).join('\n');
}

function claimVerdict(key, ms, exp, nowMs) {
  if (key === 'exp') {
    return exp.expired
      ? red(`EXPIRED ${core.formatDuration(nowMs - ms)} ago`)
      : green(`expires in ${core.formatDuration(ms - nowMs)}`);
  }
  if (key === 'nbf') {
    return nowMs < ms
      ? yellow(`not valid for ${core.formatDuration(ms - nowMs)}`)
      : dim(`valid since ${core.formatDuration(nowMs - ms)} ago`);
  }
  return ms <= nowMs
    ? dim(`${core.formatDuration(nowMs - ms)} ago`)
    : dim(`in ${core.formatDuration(ms - nowMs)}`);
}

function printHuman(decoded, exp, nowMs) {
  const out = [bold('Header'), indentJSON(decoded.header), '',
    bold('Payload'), indentJSON(decoded.payload)];

  const rows = [];
  for (const [key, label] of core.TIME_CLAIMS) {
    if (!(key in decoded.payload)) continue;
    const ms = core.normalizeEpochMs(decoded.payload[key]);
    if (ms == null) continue;
    rows.push({ key, label, ms });
  }
  if (rows.length) {
    out.push('', bold('Claims'));
    const w = Math.max(...rows.map((r) => r.label.length));
    for (const r of rows) {
      out.push(`  ${cyan(r.label.padEnd(w))}  ${dim(isoUTC(r.ms))}  ${claimVerdict(r.key, r.ms, exp, nowMs)}`);
    }
  }
  process.stdout.write(out.join('\n') + '\n');
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('-h') || argv.includes('--help')) { process.stdout.write(HELP); process.exit(0); }
  if (argv.includes('-v') || argv.includes('--version')) { process.stdout.write(VERSION + '\n'); process.exit(0); }
  if (argv.length === 0 && process.stdin.isTTY) { process.stdout.write(HELP); process.exit(0); }

  const flags = new Set(argv.filter((a) => a.startsWith('-')));
  const positional = argv.filter((a) => !a.startsWith('-'));

  let raw = positional[0];
  if (!raw) {
    if (process.stdin.isTTY) fail('no token given (pass it as an argument or pipe it in)');
    raw = readStdin();
  }
  const token = core.stripToken(raw);
  if (!token) fail('no token given (pass it as an argument or pipe it in)');

  let decoded;
  try { decoded = core.decodeJwt(token); }
  catch (e) { fail(e.message); }

  const nowMs = Date.now();
  const exp = core.evaluateExpiry(decoded.payload, nowMs);

  if (flags.has('--header')) {
    process.stdout.write(JSON.stringify(decoded.header, null, 2) + '\n');
  } else if (flags.has('--payload')) {
    process.stdout.write(JSON.stringify(decoded.payload, null, 2) + '\n');
  } else if (flags.has('--json')) {
    process.stdout.write(JSON.stringify({
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature,
      expired: exp.expired,
      notYetValid: exp.notYetValid,
    }, null, 2) + '\n');
  } else {
    printHuman(decoded, exp, nowMs);
  }

  // Safety note always to stderr so it never pollutes stdout / pipes.
  process.stderr.write(dim('note: signature NOT verified — jwtpeek decodes only\n'));
  if (exp.notYetValid) process.stderr.write(yellow('warning: token is not valid yet (nbf is in the future)\n'));

  process.exit(exp.expired ? 1 : 0);
}

main();
