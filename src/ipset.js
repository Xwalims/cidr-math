'use strict';

/**
 * Core set arithmetic over IP networks, computed with BigInt masks.
 *
 * Every network is represented as a closed range [base, last] of BigInt
 * addresses within a family (bits 32 or 128). Numeric adjacency of ranges is
 * the only notion of "contiguous" used here: two blocks are never merged
 * because their prefixes happen to be neighbours.
 */

const { CidrError, formatCidr, parseAddress, parseCidr } = require('./address.js');

function fail(message, input) {
  throw new CidrError(message, input);
}

/**
 * Accept either an already-parsed network record or a CIDR string.
 * A parsed bare address (from parseAddress) is treated as a host route, so
 * callers may mix both record types in one call.
 */
function asNet(value, label) {
  if (value && typeof value === 'object') {
    if (typeof value.base === 'bigint') return value;
    if (typeof value.value === 'bigint') {
      const prefix = value.family === 4 ? 32 : 128;
      return makeNetwork(value.family, prefix, value.value, value.zone);
    }
  }
  if (typeof value === 'string') return parseCidr(value);
  fail(`${label} must be a CIDR string or a parsed network record`, value);
}

/** Mask of the leading `prefix` bits of a `bits`-wide address. */
function prefixMask(prefix, bits) {
  if (prefix < 0 || prefix > bits) {
    fail(`prefix length /${prefix} is out of range for a ${bits}-bit address`);
  }
  if (prefix === 0) return 0n;
  return ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
}

/** Build a network record from a raw (already masked) base value. */
function makeNetwork(family, prefix, value, zone = null) {
  const bits = family === 4 ? 32 : 128;
  const shift = BigInt(bits - prefix);
  const base = (value >> shift) << shift;
  const net = {
    family,
    bits,
    prefix,
    base,
    last: base + ((1n << shift) - 1n),
    zone,
    hostBitsSet: false,
    text: '',
  };
  net.text = formatCidr(net);
  return net;
}

/** Number of addresses in a block (BigInt). 2^32 and 2^128 are exact here. */
function count(net) {
  return 1n << BigInt(net.bits - net.prefix);
}

/** Number of host bits below the prefix. */
function hostBits(net) {
  return net.bits - net.prefix;
}

/**
 * The subnetting calculator: every subnet of length `newPrefix` inside `net`.
 *
 * 10.0.0.0/24 split at /26 yields exactly four blocks.
 */
function subnets(input, newPrefix) {
  const net = asNet(input, 'network');
  if (!Number.isInteger(newPrefix)) {
    fail(`new prefix length must be an integer, got ${JSON.stringify(newPrefix)}`);
  }
  if (newPrefix > net.bits) {
    fail(
      `new prefix length /${newPrefix} exceeds ${net.bits} for IPv${net.family}`
    );
  }
  if (newPrefix < net.prefix) {
    fail(
      `cannot split ${net.text} into /${newPrefix}: that block is larger than the source ` +
        `(prefixes must be ${net.prefix} or longer)`
    );
  }

  const step = 1n << BigInt(net.bits - newPrefix);
  const total = 1n << BigInt(newPrefix - net.prefix);
  const out = [];
  for (let i = 0n; i < total; i += 1n) {
    out.push(makeNetwork(net.family, newPrefix, net.base + i * step, net.zone));
  }
  return out;
}

/** Every subnet of length `newPrefix` inside `net`, as canonical strings. */
function subnetTexts(input, newPrefix) {
  return subnets(input, newPrefix).map((net) => net.text);
}

/**
 * Cover a closed range with the fewest aligned CIDR blocks (greedy: always take
 * the largest block that is aligned at `start` and still fits in the range).
 * This is what makes 10.0.0.64-10.0.3.255 collapse to three blocks rather than
 * hundreds of /32s.
 */
function coverRange(start, end, bits, family, zone = null) {
  const out = [];
  let cursor = start;
  while (cursor <= end) {
    // Largest power-of-two block aligned at `cursor`.
    let size = cursor === 0n ? 1n << BigInt(bits) : cursor & -cursor;
    const remaining = end - cursor + 1n;
    while (size > remaining) size >>= 1n;
    let prefix = bits;
    for (let step = size; step > 1n; step >>= 1n) prefix -= 1;
    out.push(makeNetwork(family, prefix, cursor, zone));
    cursor += size;
  }
  return out;
}

/** Merge sorted [start, end] ranges that overlap or touch numerically. */
function mergeRanges(ranges) {
  const out = [];
  for (const range of ranges) {
    const last = out[out.length - 1];
    if (last && range.start <= last.end + 1n) {
      if (range.end > last.end) last.end = range.end;
    } else {
      out.push({ start: range.start, end: range.end });
    }
  }
  return out;
}

/**
 * True when two zone identifiers denote the same zone.
 *
 * RFC 4007 makes the zone part of an address's identity: "two different
 * physical links may each contain a node with the link-local address
 * fe80::1" (section 3.2), and a node "requires an internal means to identify
 * to which zone a non-global address belongs" (section 6). So fe80::/64%eth0
 * and fe80::/64%eth1 are two disjoint sets of addresses, not two halves of
 * one block that happens to share a numeric range.
 *
 * A null zone means "no zone given", i.e. the statement is about every zone.
 * It therefore matches any zone, but - see summarise() - it never absorbs a
 * zoned block, because doing so would widen a scoped set into a global one.
 */
function sameZone(a, b) {
  return a === b;
}

/**
 * Order zone identifiers for output: no zone first, then alphabetical.
 * A Map keyed by zone iterates in insertion order, so summarise() sorts with
 * this to keep its output a function of its input rather than of argument
 * order.
 */
function zoneOrder(a, b) {
  if (a === null) return b === null ? 0 : -1;
  if (b === null) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Collapse networks/addresses into the minimal set of CIDR blocks covering
 * exactly the same addresses.
 *
 * 10.0.0.0/24 + 10.0.1.0/24 -> 10.0.0.0/23
 * 10.0.1.0/24 alone       -> 10.0.1.0/24
 *
 * Mixed families are summarised independently; IPv4 output comes first.
 *
 * Blocks are grouped by zone as well as by family, so a zoned block never
 * merges with a different zone or with an unzoned one. Collapsing
 * ["fe80::/64%eth0", "fe80:0:0:1::/64%eth1"] into a single "fe80::%eth0/63"
 * would claim the second half of eth0 - addresses that were not in the input
 * - and silently drop the eth1 half.
 */
function summarise(entries) {
  const list = Array.isArray(entries) ? entries : [entries];

  // Family first, then zone, so output order stays deterministic and IPv4
  // still comes before IPv6. Keyed by family then zone rather than a joined
  // string, so no separator can collide with a zone name.
  const groups = new Map();
  for (const entry of list) {
    const net = asNet(entry, 'entry');
    if (!groups.has(net.family)) groups.set(net.family, new Map());
    const byZone = groups.get(net.family);
    if (!byZone.has(net.zone)) byZone.set(net.zone, []);
    byZone.get(net.zone).push(net);
  }

  const out = [];
  for (const family of [4, 6]) {
    const byZone = groups.get(family);
    if (!byZone) continue;
    const bits = family === 4 ? 32 : 128;
    for (const zone of [...byZone.keys()].sort(zoneOrder)) {
      const ranges = byZone
        .get(zone)
        .map((net) => ({ start: net.base, end: net.last }))
        .sort((x, y) => (x.start < y.start ? -1 : x.start > y.start ? 1 : 0));
      for (const range of mergeRanges(ranges)) {
        out.push(...coverRange(range.start, range.end, bits, family, zone));
      }
    }
  }
  return out;
}

/** Same as summarise(), returning canonical strings. */
function summariseTexts(entries) {
  return summarise(entries).map((net) => net.text);
}

/** Longest common prefix length of two addresses. */
function commonPrefixLength(a, b, bits) {
  let diff = a ^ b;
  let prefix = bits;
  while (diff !== 0n) {
    diff >>= 1n;
    prefix -= 1;
  }
  return prefix;
}

/**
 * The common part of two networks, or null when they are disjoint.
 * Different families are disjoint, not an error: intersect("10.0.0.0/8",
 * "2001:db8::/32") === null.
 *
 * Blocks in different zones are also disjoint - they share no address - so
 * intersect("fe80::/64%eth0", "fe80::/64%eth1") === null. An unzoned block is
 * zone-agnostic and does intersect a zoned one, taking the zoned spelling.
 */
function intersect(a, b) {
  const left = asNet(a, 'first network');
  const right = asNet(b, 'second network');
  if (left.family !== right.family) return null;
  if (left.zone !== null && right.zone !== null && !sameZone(left.zone, right.zone)) {
    return null;
  }
  const start = left.base > right.base ? left.base : right.base;
  const end = left.last < right.last ? left.last : right.last;
  if (start > end) return null;
  return makeNetwork(
    left.family,
    commonPrefixLength(start, end, left.bits),
    start,
    left.zone || right.zone
  );
}

/** True when `container` covers every address of `inner`. */
function contains(container, inner) {
  const outer = asNet(container, 'container');
  const probe = asNet(inner, 'inner network');
  if (outer.family !== probe.family) return false;
  // A container scoped to a zone only contains blocks in that zone. An
  // unzoned container is unscoped, so it contains any zone.
  if (outer.zone !== null && !sameZone(outer.zone, probe.zone)) return false;
  return outer.base <= probe.base && outer.last >= probe.last;
}

/** True when a bare address falls inside a block. */
function containsAddress(container, address) {
  const outer = asNet(container, 'container');
  const probe = parseAddress(address);
  if (outer.family !== probe.family) return false;
  if (outer.zone !== null && !sameZone(outer.zone, probe.zone)) return false;
  return outer.base <= probe.value && probe.value <= outer.last;
}

/** True when two blocks share at least one address. */
function overlaps(a, b) {
  return intersect(a, b) !== null;
}

/**
 * Blocks that are in `a` but not in `b` (b may be a single CIDR or a list).
 *
 * Subtracting a block can leave the remainder splittable into several pieces,
 * each of which is then covered minimally, so the result is a list.
 */
function difference(a, b) {
  const outer = asNet(a, 'first network');
  const others = (Array.isArray(b) ? b : [b]).map((entry) => asNet(entry, 'network'));

  let pieces = [outer];
  for (const hole of others) {
    if (hole.family !== outer.family) continue;
    // A hole in another zone removes nothing: those addresses are not in the
    // outer block to begin with.
    if (outer.zone !== null && hole.zone !== null && !sameZone(outer.zone, hole.zone)) {
      continue;
    }
    if (hole.last < outer.base || hole.base > outer.last) continue;

    const next = [];
    for (const piece of pieces) {
      if (hole.last < piece.base || hole.base > piece.last) {
        next.push(piece);
        continue;
      }
      if (piece.base < hole.base) {
        next.push(...coverRange(piece.base, hole.base - 1n, piece.bits, piece.family, piece.zone));
      }
      if (hole.last < piece.last) {
        next.push(...coverRange(hole.last + 1n, piece.last, piece.bits, piece.family, piece.zone));
      }
    }
    pieces = next;
  }

  const deduped = new Map();
  for (const piece of pieces) {
    if (!deduped.has(piece.text)) deduped.set(piece.text, piece);
  }
  return [...deduped.values()].sort((x, y) =>
    x.family !== y.family ? x.family - y.family : x.base < y.base ? -1 : x.base > y.base ? 1 : 0
  );
}

/** Same as difference(), returning canonical strings. */
function differenceTexts(a, b) {
  return difference(a, b).map((net) => net.text);
}

/** The enclosing block of prefix length `prefix` around `input`. */
function supernetOf(input, prefix) {
  const net = asNet(input, 'network');
  if (!Number.isInteger(prefix)) {
    fail(`supernet prefix length must be an integer, got ${JSON.stringify(prefix)}`);
  }
  if (prefix > net.bits) {
    fail(`supernet prefix /${prefix} exceeds ${net.bits} for IPv${net.family}`);
  }
  if (prefix > net.prefix) {
    fail(
      `cannot aggregate ${net.text} to /${prefix}: that block is smaller than the source ` +
        `(prefixes must be ${net.prefix} or shorter)`
    );
  }
  return makeNetwork(
    net.family,
    prefix,
    net.base & prefixMask(prefix, net.bits),
    net.zone
  );
}

/** Every address in a block, as BigInt values. Callers must bound the size. */
function expand(input) {
  const net = asNet(input, 'network');
  const out = [];
  for (let value = net.base; value <= net.last; value += 1n) out.push(value);
  return out;
}

module.exports = {
  count,
  coverRange,
  difference,
  differenceTexts,
  expand,
  hostBits,
  intersect,
  contains,
  containsAddress,
  makeNetwork,
  mergeRanges,
  overlaps,
  prefixMask,
  subnetTexts,
  subnets,
  supernetOf,
  summarise,
  summariseTexts,
  // exported for internal composition and tests
  asNet,
  commonPrefixLength,
  sameZone,
};