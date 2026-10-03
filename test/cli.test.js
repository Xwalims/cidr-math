'use strict';

/**
 * End-to-end tests: spawn the real bin/cidr.js and assert real exit codes.
 *
 * Nothing here stubs the CLI or calls main() directly, so the argv parsing,
 * stream handling and process exit codes are all exercised for real.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const BIN = path.join(__dirname, '..', 'bin', 'cidr.js');

/** Run the CLI and return {status, stdout, stderr}. */
function run(args, options = {}) {
  const result = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    input: options.input === undefined ? '' : options.input,
    env: { ...process.env, NO_COLOR: '1' },
    ...options,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function lines(text) {
  return text.trimEnd().split('\n');
}

test('the binary exists and is executable', () => {
  const fs = require('node:fs');
  assert.ok(fs.existsSync(BIN), `${BIN} should exist`);
  // eslint-disable-next-line no-bitwise
  assert.ok(fs.statSync(BIN).mode & 0o111, `${BIN} should have the executable bit`);
});

test('--help exits 0 and lists the commands', () => {
  const result = run(['--help']);
  assert.equal(result.status, 0);
  for (const command of ['info', 'split', 'summarise', 'contains', 'diff', 'sort', 'supernet']) {
    assert.match(result.stdout, new RegExp(`\\b${command}\\b`), `help should mention ${command}`);
  }
  assert.match(result.stdout, /--json/);
  assert.match(result.stdout, /--expand/);
});

test('--version prints the package version', () => {
  const result = run(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), require('../package.json').version);
});

test('no arguments prints usage and exits 0', () => {
  const result = run([]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage:/);
});

test('info prints the network details and exits 0', () => {
  const result = run(['info', '10.0.0.0/24']);
  assert.equal(result.status, 0);
  const out = result.stdout;
  assert.match(out, /network:\s+10\.0\.0\.0/);
  assert.match(out, /last:\s+10\.0\.0\.255/);
  assert.match(out, /usable range:\s+10\.0\.0\.1 - 10\.0\.0\.254/);
  assert.match(out, /total addresses:\s+256 \(2\^8\)/);
  assert.match(out, /host bits/);
});

test('info reports the exact 2^32 count of 0.0.0.0/0 as a decimal string', () => {
  const result = run(['info', '0.0.0.0/0', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.count, '4294967296');
  assert.equal(data.countHex, '0x100000000');
  assert.equal(data.network, '0.0.0.0');
  assert.equal(data.last, '255.255.255.255');
});

test('info reports the exact 2^128 count of ::/0 as a decimal string', () => {
  const result = run(['info', '::/0', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.count, '340282366920938463463374607431768211456');
  assert.equal(data.countHex, '0x1' + '0'.repeat(32));
});

test('info on an IPv6 /64 shows the exact 2^64 count', () => {
  const result = run(['info', '2001:db8::/64', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.count, '18446744073709551616');
  assert.equal(data.network, '2001:db8::');
  assert.equal(data.last, '2001:db8::ffff:ffff:ffff:ffff');
});

test('info normalises the same IPv6 address written three ways identically', () => {
  const spellings = ['2001:db8::1/32', '2001:0db8:0000::1/32', '2001:DB8:0:0:0:0:0:1/32'];
  const results = spellings.map((spelling) => run(['info', spelling, '--json']));
  for (const result of results) assert.equal(result.status, 0);

  // Everything except the echoed input must be byte-identical, and the input
  // echo is the only thing allowed to differ.
  const parsed = results.map((result) => JSON.parse(result.stdout));
  assert.equal(parsed[0].cidr, '2001:db8::/32');
  assert.equal(parsed[0].network, '2001:db8::');
  assert.equal(parsed[0].prefix, 32);
  assert.equal(parsed[0].count, parsed[1].count);
  assert.equal(parsed[0].count, parsed[2].count);
  assert.deepEqual(parsed.map((p) => p.input), spellings);
  for (const data of parsed) {
    const { input, ...rest } = data;
    assert.deepEqual(rest, (({ input: _ignored, ...r }) => r)(parsed[0]));
  }
});

test('info notes when host bits were set', () => {
  const result = run(['info', '10.0.0.5/24']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /host bits set/);
  assert.match(result.stdout, /10\.0\.0\.0\/24/);
});

test('split prints four blocks for a /24 into /26', () => {
  const result = run(['split', '10.0.0.0/24', '26']);
  assert.equal(result.status, 0);
  const body = lines(result.stdout).slice(1);
  assert.deepEqual(body, ['10.0.0.0/26', '10.0.0.64/26', '10.0.0.128/26', '10.0.0.192/26']);
});

test('split works on an IPv6 block', () => {
  const result = run(['split', '2001:db8::/62', '64', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.count, 4);
  assert.deepEqual(data.subnets, [
    '2001:db8::/64',
    '2001:db8:0:1::/64',
    '2001:db8:0:2::/64',
    '2001:db8:0:3::/64',
  ]);
});

test('split accepts a slash-prefixed argument', () => {
  const withSlash = run(['split', '10.0.0.0/24', '/26', '--json']);
  const withoutSlash = run(['split', '10.0.0.0/24', '26', '--json']);
  assert.equal(withSlash.status, 0);
  assert.equal(withSlash.stdout, withoutSlash.stdout);
});

test('summarise merges two adjacent /24s into a /23', () => {
  const result = run(['summarise', '10.0.0.0/24', '10.0.1.0/24', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout).minimal, ['10.0.0.0/23']);
});

test('summarise leaves a lone /24 alone', () => {
  const result = run(['summarise', '10.0.1.0/24', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout).minimal, ['10.0.1.0/24']);
});

test('summarise reads a list from standard input', () => {
  const result = run(['summarise', '--json'], {
    input: '10.0.0.0/25\n10.0.0.128/25\n2001:db8::/32\n',
  });
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.deepEqual(data.minimal, ['10.0.0.0/24', '2001:db8::/32']);
});

test('summarise handles a mixed IPv4/IPv6 list', () => {
  const result = run(['summarise', '2001:db8::1', '10.0.0.1', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout).minimal, ['10.0.0.1/32', '2001:db8::1/128']);
});

test('contains exits 0 when the first block contains the second', () => {
  const result = run(['contains', '10.0.0.0/8', '10.1.2.0/24']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /yes/);
});

test('contains exits 1 when it does not, so shell conditionals work', () => {
  const result = run(['contains', '10.0.0.0/24', '10.0.1.0/24']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /no/);
});

test('contains is false across address families and exits 1', () => {
  const result = run(['contains', '::/0', '10.0.0.1']);
  assert.equal(result.status, 1);
  const reverse = run(['contains', '0.0.0.0/0', '2001:db8::/32']);
  assert.equal(reverse.status, 1);
});

test('contains accepts a bare address on the right-hand side', () => {
  assert.equal(run(['contains', '10.0.0.0/8', '10.1.2.3']).status, 0);
  assert.equal(run(['contains', '10.0.0.0/8', '11.1.2.3']).status, 1);
});

test('contains --json reports the boolean as well as the exit code', () => {
  const yes = run(['contains', '10.0.0.0/8', '10.1.2.0/24', '--json']);
  assert.equal(yes.status, 0);
  assert.equal(JSON.parse(yes.stdout).contains, true);
  const no = run(['contains', '10.0.0.0/8', '11.0.0.0/8', '--json']);
  assert.equal(no.status, 1);
  assert.equal(JSON.parse(no.stdout).contains, false);
});

test('diff prints the blocks in A that are not in B', () => {
  const result = run(['diff', '10.0.0.0/22', '10.0.0.128/25', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout).difference, [
    '10.0.0.0/25',
    '10.0.1.0/24',
    '10.0.2.0/23',
  ]);
});

test('diff of identical blocks is empty', () => {
  const result = run(['diff', '10.0.0.0/24', '10.0.0.0/24', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout).difference, []);
});

test('sort orders IPv4 before IPv6 and numerically within a family', () => {
  const result = run(['sort', '2001:db8::1', '10.0.0.10', '10.0.0.9', '::1', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout).sorted, [
    '10.0.0.9/32',
    '10.0.0.10/32',
    '::1/128',
    '2001:db8::1/128',
  ]);
});

test('supernet returns the enclosing block', () => {
  const result = run(['supernet', '10.1.2.3/24', '16', '--json']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).supernet, '10.1.0.0/16');
});

test('supernet works in IPv6 space', () => {
  const result = run(['supernet', '2001:db8:1:2:3:4:5:6/128', '64', '--json']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).supernet, '2001:db8:1:2::/64');
});

test('--expand lists every address of a small block', () => {
  const result = run(['info', '10.0.0.0/30', '--expand']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /10\.0\.0\.0 167772160/);
  assert.match(result.stdout, /10\.0\.0\.3 167772163/);
});

test('--expand refuses a block larger than the limit, exiting 3', () => {
  const result = run(['info', '10.0.0.0/8', '--expand']);
  assert.equal(result.status, 3);
  assert.match(result.stderr, /refusing to expand/);
  assert.match(result.stderr, /--expand-limit/);
});

test('--expand-limit can be lowered, and a custom limit is honoured', () => {
  const tooBig = run(['info', '10.0.0.0/20', '--expand', '--expand-limit', '16']);
  assert.equal(tooBig.status, 3);
  const ok = run(['info', '10.0.0.0/24', '--expand', '--expand-limit=1024']);
  assert.equal(ok.status, 0);
  // 10.0.0.0/25 is 128 addresses: over a 64 limit, under a 256 one.
  assert.equal(run(['info', '10.0.0.0/25', '--expand-limit', '64', '--expand']).status, 3);
  assert.equal(run(['info', '10.0.0.0/25', '--expand-limit', '256', '--expand']).status, 0);
});

test('--expand never tries to materialise 2^64 addresses', () => {
  const result = run(['info', '2001:db8::/64', '--expand']);
  assert.equal(result.status, 3);
  assert.match(result.stderr, /18446744073709551616/);
});

test('an invalid CIDR exits 2 with a message on stderr', () => {
  const result = run(['info', '10.0.0.256/24']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /out of range 0-255/);
  assert.equal(result.stdout, '');
});

test('an invalid IPv6 address exits 2 with a message on stderr', () => {
  const result = run(['info', '2001:db8:::1']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /:::/);
});

test('an out-of-range prefix length exits 2', () => {
  assert.equal(run(['info', '10.0.0.0/33']).status, 2);
  assert.equal(run(['info', '2001:db8::/129']).status, 2);
});

test('an unknown command exits 2 and suggests the valid ones', () => {
  const result = run(['frobnicate', '10.0.0.0/24']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown command "frobnicate"/);
  assert.match(result.stderr, /info, split, summarise/);
});

test('an unknown option exits 2', () => {
  const result = run(['info', '10.0.0.0/24', '--nope']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown option "--nope"/);
});

test('a missing argument exits 2', () => {
  assert.equal(run(['info']).status, 2);
  assert.equal(run(['split', '10.0.0.0/24']).status, 2);
  assert.equal(run(['contains', '10.0.0.0/8']).status, 2);
  assert.equal(run(['diff', '10.0.0.0/8']).status, 2);
});

test('summarise with no arguments and no stdin exits 2', () => {
  const result = run(['summarise']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /no CIDRs given/);
});

test('--no-color output contains no ANSI escapes', () => {
  const result = run(['info', '10.0.0.0/24', '--no-color']);
  assert.equal(result.status, 0);
  // eslint-disable-next-line no-control-regex
  assert.equal(/\[/.test(result.stdout), false, 'no ANSI escapes expected');
});

test('output is deterministic across repeated runs', () => {
  const first = run(['summarise', '10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24']);
  const second = run(['summarise', '10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24']);
  assert.equal(first.stdout, second.stdout);
  assert.equal(first.status, second.status);
});

test('a zone identifier is accepted and preserved', () => {
  const result = run(['info', 'fe80::/64%eth0', '--json']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).zone, 'eth0');
});

// RFC 3021: a /31 keeps both of its addresses (a point-to-point link) and a /32
// keeps its single one. The general rule (drop base and last) would print an
// empty range for both, so these pin the two special cases in usableRange().
test('info on a /31 keeps both addresses rather than dropping the endpoints', () => {
  const result = run(['info', '192.168.1.0/31', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.usableKind, 'point-to-point');
  assert.equal(data.usableFirst, '192.168.1.0');
  assert.equal(data.usableLast, '192.168.1.1');
  assert.equal(data.usableCount, '2');
});

test('info on a /32 keeps its single address rather than dropping it', () => {
  const result = run(['info', '192.168.1.7/32', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.usableKind, 'single');
  assert.equal(data.usableFirst, '192.168.1.7');
  assert.equal(data.usableLast, '192.168.1.7');
  assert.equal(data.usableCount, '1');
});

test('info on an IPv6 /127 keeps both addresses, like the IPv4 /31', () => {
  const result = run(['info', '2001:db8::/127', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.usableKind, 'point-to-point');
  assert.equal(data.usableCount, '2');
});

test('info on the IPv6 /128 host route keeps its single address', () => {
  const result = run(['info', '::1/128', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.usableKind, 'single');
  assert.equal(data.usableCount, '1');
});

test('a /31 is printed with its whole range in the text output too', () => {
  const result = run(['info', '192.168.1.0/31']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /usable range:\s+192\.168\.1\.0 - 192\.168\.1\.1/);
  assert.match(result.stdout, /usable count:\s+2 addresses/);
});

test('a /32 counts one usable address in the singular', () => {
  const result = run(['info', '192.168.1.7/32']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /usable count:\s+1 address$/m);
  assert.doesNotMatch(result.stdout, /1 addresses/);
});

test('the usual rule still drops base and last for a /30', () => {
  const result = run(['info', '10.0.0.0/30', '--json']);
  assert.equal(result.status, 0);
  const data = JSON.parse(result.stdout);
  assert.equal(data.usableKind, 'first-last');
  assert.equal(data.usableFirst, '10.0.0.1');
  assert.equal(data.usableLast, '10.0.0.2');
  assert.equal(data.usableCount, '2');
});