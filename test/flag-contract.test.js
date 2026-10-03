'use strict';

/**
 * Flag/help contract.
 *
 * A flag the parser accepts but `--help` never mentions is a working feature
 * nobody can discover: the user has to read the source to find it. That is the
 * same class of dishonesty as a dead badge or an invented `--flag` in the help,
 * and it is invisible to the functional tests — every test in this suite passes
 * while a working flag stays hidden.
 *
 * The parser is a `switch` over the flag name, so `case '--x':` is the ground
 * truth for what it accepts. Anything it accepts must appear in the real
 * `--help` output of the real binary.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SRC = path.join(__dirname, '..', 'src', 'cli.js');
const BIN = path.join(__dirname, '..', 'bin', 'cidr.js');

/** Every flag name the argument parser's switch statement handles. */
function parserFlags() {
  const source = fs.readFileSync(SRC, 'utf8');
  const flags = new Set();
  for (const m of source.matchAll(/case '(--[a-z][a-z0-9-]*)'/g)) flags.add(m[1]);
  return [...flags].sort();
}

const help = spawnSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' }).stdout;

test('the scanner finds the parser flags it claims to', () => {
  // A scanner that matches nothing would make the test below vacuous.
  const flags = parserFlags();
  assert.ok(flags.length >= 6, `expected to find the parser's flags, got ${JSON.stringify(flags)}`);
  for (const known of ['--json', '--expand', '--help', '--version']) {
    assert.ok(flags.includes(known), `scanner should find ${known}`);
  }
});

test('every flag the parser accepts is documented in --help', () => {
  const undocumented = parserFlags().filter((flag) => !help.includes(flag));
  assert.deepEqual(undocumented, [], `undocumented but accepted: ${undocumented.join(' ')}`);
});

test('the reverse direction holds: every flag in --help parses', () => {
  // Guards against a help entry for a flag the parser rejects.
  const inHelp = [...help.matchAll(/(--[a-z][a-z0-9-]*)/g)].map((m) => m[1]);
  const known = new Set(parserFlags());
  known.add('-h');
  known.add('-v');
  const phantom = [...new Set(inHelp)].filter((flag) => !known.has(flag));
  assert.deepEqual(phantom, [], `documented but not accepted: ${phantom.join(' ')}`);
});

test('the value-taking flags are documented with their placeholder', () => {
  // `--new-prefix <n>` not `--new-prefix`, so the reader learns it needs a value.
  for (const flag of ['--new-prefix', '--prefix', '--expand-limit']) {
    assert.ok(help.includes(`${flag} <n>`), `${flag} should be documented with a value`);
  }
});

test('every documented flag is actually accepted by the real binary', () => {
  // Run the binary with each documented flag and require the parser not to
  // reject it. Values are supplied for the ones that need one.
  const cases = {
    '--json': ['info', '10.0.0.0/24', '--json'],
    '--no-color': ['info', '10.0.0.0/24', '--no-color'],
    '--color': ['info', '10.0.0.0/24', '--color'],
    '--colour': ['info', '10.0.0.0/24', '--colour'],
    '--no-colour': ['info', '10.0.0.0/24', '--no-colour'],
    '--expand': ['info', '10.0.0.0/30', '--expand'],
    '--expand-limit': ['info', '10.0.0.0/30', '--expand-limit', '4'],
    '--new-prefix': ['split', '10.0.0.0/24', '--new-prefix', '26'],
    '--prefix': ['supernet', '10.1.2.3/24', '--prefix', '16'],
    '-h': ['-h'],
    '-v': ['-v'],
  };
  for (const [flag, args] of Object.entries(cases)) {
    const result = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
    assert.notEqual(
      result.stderr,
      `cidr: unknown option "${flag}"`,
      `${flag} is documented but the parser rejects it`,
    );
  }
});

test('--new-prefix and --prefix are equivalent to the positional form', () => {
  const run = (args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
  assert.equal(
    run(['split', '10.0.0.0/24', '26']).stdout,
    run(['split', '10.0.0.0/24', '--new-prefix', '26']).stdout,
  );
  assert.equal(
    run(['supernet', '10.1.2.3/24', '16']).stdout,
    run(['supernet', '10.1.2.3/24', '--prefix', '16']).stdout,
  );
});
