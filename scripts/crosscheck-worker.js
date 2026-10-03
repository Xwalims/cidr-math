'use strict';

/**
 * Cross-check worker: reads a JSON array of cases on stdin, writes JSON results.
 *
 * Spawned once by scripts/crosscheck.py with every case in a single batch —
 * one process per case would dominate the runtime and make the harness slower
 * than the code it verifies.
 *
 * Every result is reported as numeric [family, base, last] triples rather than
 * text, so a difference is always an arithmetic difference and never a
 * formatting preference (Python's str(IPv6Address) writes the IPv4-mapped form
 * as `::ffff:102:304`, RFC 5952 canonical text here writes `::ffff:1.2.3.4`).
 *
 * Each emitted block is also parsed back with the package's own parser and
 * compared against the block it came from, so a formatter bug in a *result*
 * cannot hide behind the numeric comparison.
 */

const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const lib = require(path.join(ROOT, 'src', 'index.js'));
const { parseCidr } = require(path.join(ROOT, 'src', 'address.js'));

/** BigInt-safe JSON: addresses go out as decimal strings. */
function triples(nets) {
  return nets.map(triple);
}

/** One block as [family, base, last], with addresses as decimal strings. */
function triple(net) {
  return [net.family, net.base.toString(10), net.last.toString(10)];
}

/**
 * Re-parse every block we are about to report and confirm the text round-trips
 * to the same numbers. Throws on the first mismatch, which surfaces as a
 * non-zero exit from the harness instead of a silently wrong comparison.
 */
function verifyRoundTrip(nets) {
  for (const net of nets) {
    const back = parseCidr(net.text);
    if (back.family !== net.family || back.base !== net.base || back.last !== net.last) {
      throw new Error(
        `round-trip mismatch: ${net.text} parsed back as ` +
          `${back.family} ${back.base}..${back.last}, expected ` +
          `${net.family} ${net.base}..${net.last}`
      );
    }
  }
}

function run(c) {
  switch (c.op) {
    case 'parse': {
      const net = parseCidr(c.cidr);
      verifyRoundTrip([net]);
      return { net: triple(net), text: net.text, hostBitsSet: net.hostBitsSet };
    }
    case 'summarise': {
      const nets = lib.summarise(c.cidrs);
      verifyRoundTrip(nets);
      return { blocks: triples(nets) };
    }
    case 'subnets': {
      const nets = lib.subnets(c.cidr, c.newPrefix);
      verifyRoundTrip(nets);
      return { blocks: triples(nets) };
    }
    case 'difference': {
      const nets = lib.difference(c.a, c.b);
      verifyRoundTrip(nets);
      return { blocks: triples(nets) };
    }
    case 'intersect': {
      const net = lib.intersect(c.a, c.b);
      if (net === null) return { net: null };
      verifyRoundTrip([net]);
      return { net: triple(net) };
    }
    case 'supernet': {
      const net = lib.supernetOf(c.cidr, c.prefix);
      verifyRoundTrip([net]);
      return { net: triple(net) };
    }
    case 'count': {
      const net = parseCidr(c.cidr);
      return { count: lib.count(net).toString(10) };
    }
    default:
      throw new Error(`unknown op ${JSON.stringify(c.op)}`);
  }
}

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  raw += chunk;
});
process.stdin.on('end', () => {
  const cases = JSON.parse(raw);
  const results = cases.map((c) => {
    try {
      return { ok: true, value: run(c) };
    } catch (err) {
      return { ok: false, error: String(err && err.message ? err.message : err) };
    }
  });
  process.stdout.write(JSON.stringify(results));
});