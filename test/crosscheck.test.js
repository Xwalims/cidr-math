'use strict';

/**
 * Contract tests for scripts/crosscheck.py.
 *
 * The suite elsewhere in this package derives every expectation from the code
 * under test. scripts/crosscheck.py is the one piece of evidence that does not:
 * it compares against Python's `ipaddress`, an independent implementation.
 *
 * That only holds while the harness is actually runnable and actually compares
 * what it claims to. A harness nobody executes is decoration, and a README that
 * cites its results is a lie the moment it stops running -- which is exactly
 * what happened once already: cidr-math/README.md claimed a cross-check against
 * `ipaddress` over 800+ randomised cases, and no such script existed anywhere on
 * disk or in any commit.
 *
 * So these tests assert the harness's SHAPE, not its arithmetic results:
 * - it exists, parses, and is runnable;
 * - it can distinguish agreeing from disagreeing input, i.e. a comparison that
 *   silently passes everything would fail here;
 * - its generator produces each operation it claims to cover, at the mix it
 *   claims;
 * - it documents the ground truth each operation compares against.
 *
 * The numeric comparison itself is exercised for real in the 'run()' case below
 * via child_process, since a passing mock proves nothing about agreement.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const HARNESS = path.join(ROOT, 'scripts', 'crosscheck.py');
const WORKER = path.join(ROOT, 'scripts', 'crosscheck-worker.js');

function run(args) {
  return execFileSync('python3', [HARNESS, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

test('the cross-check harness and its worker are present', () => {
  assert.ok(fs.existsSync(HARNESS), 'scripts/crosscheck.py is missing');
  assert.ok(fs.existsSync(WORKER), 'scripts/crosscheck-worker.js is missing');
});

test('the harness compiles and runs, agreeing with python ipaddress', () => {
  const out = run(['200']);
  assert.match(out, /crosscheck: 200\/200 cases agree with python ipaddress/);
});

test('the harness is deterministic for a fixed seed', () => {
  const first = run(['150', '--seed', '4242']);
  const second = run(['150', '--seed', '4242']);
  assert.equal(first, second);
});

test('a different seed changes the generated cases', () => {
  // A harness whose output does not depend on the seed is not random, and a
  // harness that is not random covers one fixed corner of the input space.
  //
  // The echoed seed must be stripped before comparing. The summary line
  // prints `seed=<arg>` regardless of what the generator actually did, so a
  // harness hard-wired to one seed still produces two different-looking
  // strings and this test would pass on a generator that ignores its input.
  const breakdown = (out) => out.replace(/seed=\d+/g, 'seed=X').trim();
  const a = breakdown(run(['200', '--seed', '1']));
  const b = breakdown(run(['200', '--seed', '2']));
  assert.notEqual(a, b);
});

test('the harness covers every operation it advertises', () => {
  const out = run(['300']);
  for (const op of ['parse', 'summarise', 'subnets', 'difference', 'intersect', 'supernet', 'count']) {
    assert.match(out, new RegExp(`\\b${op}=\\d+`), `${op} never appears in the breakdown`);
  }
});

test('the harness rejects a case it cannot verify, instead of passing it', () => {
  // Corrupt the worker so it returns a wrong answer for every case. A harness
  // that reports success here would be certifying agreement with itself.
  const backup = fs.readFileSync(WORKER, 'utf8');
  try {
    fs.writeFileSync(
      WORKER,
      backup.replace(
        'function run(c) {\n  switch (c.op) {',
        'function run(c) {\n  if (c) return { net: [4, 0, 0], blocks: [[4, 0, 0]], count: "1" };\n  switch (c.op) {'
      )
    );
    assert.throws(() => run(['100']), /disagree|worker failed/);
  } finally {
    fs.writeFileSync(WORKER, backup);
  }
});

test('the worker round-trips every block it reports', () => {
  // verifyRoundTrip() cannot fail for a correct library: formatCidr() output is
  // re-parsed to the same numbers by construction, so mutating that guard into
  // a no-op is an equivalent mutant, not a hole. Assert the guard is present
  // and actually called, so its removal is at least visible in a diff review
  // rather than silently reducing the harness to a number comparator.
  const worker = fs.readFileSync(WORKER, 'utf8');
  assert.match(worker, /function verifyRoundTrip\(nets\)/, 'the round-trip guard must exist');
  const calls = worker.match(/verifyRoundTrip\(/g) || [];
  // One definition plus one call per operation that reports blocks.
  assert.ok(calls.length >= 6, `expected the guard on every reporting op, found ${calls.length - 1} call sites`);
  assert.match(worker, /round-trip mismatch/, 'the guard must name its failure');
});

test('the harness does not run as part of node --test or ship to npm', () => {
  // It needs Python and an external implementation; it is a development tool.
  // Wiring it into `npm test` would make the package's own suite depend on a
  // language the package does not use.
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.test, 'node --test');
  assert.ok(!pkg.files.some((entry) => entry.startsWith('scripts')), 'scripts/ must stay out of the published files');
});

test('the harness documents the ground truth and its own blind spots', () => {
  const doc = fs.readFileSync(HARNESS, 'utf8');
  // Ground truth per operation: an independent call, not a reimplementation.
  for (const call of [
    'summarize_address_range',
    'subnets(',
    'supernet(',
  ]) {
    assert.ok(doc.includes(call), `harness must cite ${call} as ground truth`);
  }
  // And it must say out loud where it is NOT an oracle, so the README cannot
  // quietly grow into a claim it does not support. Each blind spot is named
  // separately: a section that survives deleting one of them is not evidence
  // of honesty, and a single regex on a heading checked nothing but the
  // heading.
  // Slice out the module docstring properly: the first `"""` opens it and the
  // second closes it. Taking doc.slice(0, doc.indexOf('"""', 20)) instead
  // returns just the shebang, which makes every assertion below pass on an
  // empty string -- a test that cannot fail.
  const open = doc.indexOf('"""');
  const close = doc.indexOf('"""', open + 3);
  assert.ok(open !== -1 && close !== -1, 'the harness must have a module docstring');
  const docstring = doc.slice(open, close);
  assert.match(docstring, /does NOT cover/i, 'the blind-spot note must be in the module docstring');
  for (const blindSpot of ['input rejection', 'text formatting', 'node --test']) {
    assert.ok(
      docstring.toLowerCase().includes(blindSpot.toLowerCase()),
      `the blind-spot note must name ${blindSpot}`
    );
  }
  // The note must also survive in the README, since that is where a reader
  // meets the claim.
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(
    readme,
    /does not (cover|check|verify)/i,
    'README must state what the cross-check does not cover'
  );
});