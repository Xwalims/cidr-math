'use strict';

/**
 * Property tests: invariants that must hold for arbitrary inputs.
 *
 * The deterministic RNG keeps failures reproducible - a property test that
 * fails only sometimes is worse than useless.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { formatAddress, parseAddress, parseCidr } = require('../src/address.js');
const {
  contains,
  count,
  difference,
  expand,
  intersect,
  overlaps,
  subnetTexts,
  subnets,
  supernetOf,
  summariseTexts,
} = require('../src/ipset.js');
const { sortCidrs } = require('../src/sort.js');

/** xorshift32: deterministic, dependency-free, seedable. */
function makeRng(seed) {
  let state = seed >>> 0 || 0x9e3779b9;
  return function next() {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
}

const rng = makeRng(20261002);

function randomInt(maxExclusive) {
  return rng() % maxExclusive;
}

function randomIPv4String() {
  const parts = [];
  for (let i = 0; i < 4; i += 1) parts.push(randomInt(256));
  return parts.join('.');
}

function randomIPv4Network(minPrefix = 0, maxPrefix = 32) {
  return parseCidr(`${randomIPv4String()}/${minPrefix + randomInt(maxPrefix - minPrefix + 1)}`);
}

function randomIPv6Network(minPrefix = 0, maxPrefix = 128) {
  const hextets = [];
  for (let i = 0; i < 8; i += 1) hextets.push(randomInt(65536).toString(16));
  return parseCidr(`${hextets.join(':')}/${minPrefix + randomInt(maxPrefix - minPrefix + 1)}`);
}

/** Total addresses covered by a list of blocks, as a BigInt. */
function totalSize(texts) {
  return texts.reduce((sum, text) => sum + count(parseCidr(text)), 0n);
}

test('property: every /24 summarises back to itself from all 256 addresses', () => {
  for (let trial = 0; trial < 25; trial += 1) {
    const prefix = `10.${randomInt(256)}.${randomInt(256)}.0`;
    const addresses = [];
    for (let i = 0; i < 256; i += 1) addresses.push(`${prefix.replace('.0', `.${i}`)}`);
    assert.deepEqual(summariseTexts(addresses), [`${prefix}/24`], `block ${prefix}`);
  }
});

test('property: splitting a block in half and diffing reassembles it', () => {
  for (let trial = 0; trial < 200; trial += 1) {
    const net = randomIPv4Network(8, 30);
    const [upperPrefix, lowerPrefix] = [net.prefix + 1, net.prefix];
    const halves = subnets(net, upperPrefix);
    assert.equal(halves.length, 2);

    const [first, second] = halves;
    // first minus second is the part of first beyond the shared boundary.
    const left = difference(first, second);
    const right = difference(second, first);
    // Together they must cover the whole parent exactly.
    assert.deepEqual(summariseTexts([...left, ...right]), [net.text], `net ${net.text}`);

    // And the union of the halves must be the parent.
    assert.deepEqual(summariseTexts(halves.map((n) => n.text)), [net.text]);
  }
});

test('property: difference and summarise are consistent', () => {
  for (let trial = 0; trial < 200; trial += 1) {
    const outer = randomIPv4Network(8, 28);
    // Derive the hole from the outer block so that it is guaranteed to sit
    // inside it; an unrelated random block would mostly be disjoint, which
    // makes the interesting assertions vacuous.
    const extraBits = randomInt(Math.min(6, 32 - outer.prefix) + 1);
    const candidates = subnets(outer, outer.prefix + extraBits);
    const inner = candidates[randomInt(candidates.length)];
    const rest = difference(outer, inner);
    // The remainder plus the hole must rebuild the outer block exactly.
    assert.deepEqual(summariseTexts([...rest, inner.text]), [outer.text], `net ${outer.text}`);
    // Every remainder block stays inside the outer block.
    for (const block of rest) {
      assert.ok(contains(outer, block), `${block.text} escaped ${outer.text}`);
      // ...and outside the hole.
      assert.equal(overlaps(block, inner), false, `${block.text} overlaps ${inner.text}`);
    }
    // Sizes add up.
    assert.equal(totalSize(rest.map((n) => n.text)) + count(inner), count(outer));
  }
});

test('property: intersect is symmetric and idempotent', () => {
  for (let trial = 0; trial < 200; trial += 1) {
    const a = randomIPv4Network(8, 32);
    const b = randomIPv4Network(8, 32);
    const ab = intersect(a, b);
    const ba = intersect(b, a);
    assert.equal(ab === null ? null : ab.text, ba === null ? null : ba.text);
    if (ab === null) {
      assert.equal(overlaps(a, b), false);
      continue;
    }
    // The intersection is inside both inputs, and intersecting it with
    // either input again changes nothing.
    assert.ok(contains(a, ab));
    assert.ok(contains(b, ab));
    assert.deepEqual(intersect(ab, a).text, ab.text);
    assert.deepEqual(intersect(ab, b).text, ab.text);
  }
});

test('property: contains is a partial order', () => {
  for (let trial = 0; trial < 150; trial += 1) {
    const a = randomIPv4Network(8, 32);
    const b = randomIPv4Network(8, 32);
    if (contains(a, b)) {
      assert.ok(contains(b, a), 'containment is not antisymmetric');
      // Reflexive and transitive with a common parent.
      assert.ok(contains(a, a));
      assert.ok(intersect(a, b) !== null);
    }
    // Same size and mutually containing implies identity.
    if (contains(a, b) && contains(b, a) && count(a) === count(b)) {
      assert.equal(a.text, b.text);
    }
  }
});

test('property: summarise is idempotent and its output is minimal', () => {
  for (let trial = 0; trial < 200; trial += 1) {
    const entries = [];
    const count_ = 1 + randomInt(8);
    for (let i = 0; i < count_; i += 1) entries.push(randomIPv4Network(0, 32).text);
    const once = summariseTexts(entries);
    // Summarising the output changes nothing.
    assert.deepEqual(summariseTexts(once), once, `input ${entries.join(' ')}`);
    // Size is preserved: the cover spans exactly the same addresses.
    assert.equal(totalSize(once), totalSize(summariseTexts(entries)));
    // No two output blocks overlap, or they would have merged.
    for (let i = 0; i + 1 < once.length; i += 1) {
      const left = parseCidr(once[i]);
      const right = parseCidr(once[i + 1]);
      assert.ok(right.base > left.last, `${left.text} and ${right.text} overlap`);
    }
    // Adjacent blocks need not be mergeable: 64.0.0.0/2 and 128.0.0.0/1 touch
    // (127.255.255.255 is followed by 128.0.0.0) but no single block covers
    // 64.0.0.0-255.255.255.255, so the cover is already minimal.
  }
});

test('property: summarise never loses or invents an address', () => {
  for (let trial = 0; trial < 60; trial += 1) {
    const base = randomIPv4Network(16, 24);
    const entries = [base.text];
    for (let i = 0; i < randomInt(4); i += 1) {
      entries.push(randomIPv4Network(16, 32).text);
    }
    const covered = summariseTexts(entries);
    // Every input block is contained in exactly one output block.
    for (const input of entries) {
      const holders = covered.filter((out) => contains(out, input));
      assert.ok(holders.length >= 1, `${input} not covered by ${covered.join(' ')}`);
      for (const holder of holders) assert.ok(contains(holder, input));
    }
  }
});

test('property: subnetting a block tiles it exactly', () => {
  for (let trial = 0; trial < 60; trial += 1) {
    const net = randomIPv4Network(8, 24);
    const newPrefix = net.prefix + 1 + randomInt(Math.min(6, 32 - net.prefix));
    const children = subnets(net, newPrefix);
    assert.equal(children.length, 2 ** (newPrefix - net.prefix));
    // Children are in ascending order, contiguous, non-overlapping.
    for (let i = 0; i + 1 < children.length; i += 1) {
      assert.equal(children[i].last + 1n, children[i + 1].base);
    }
    assert.equal(children[0].base, net.base);
    assert.equal(children[children.length - 1].last, net.last);
    // Every child holds the same number of addresses.
    for (const child of children) assert.equal(count(child), count(children[0]));
    // And they reassemble into the parent.
    assert.deepEqual(summariseTexts(children.map((c) => c.text)), [net.text]);
  }
});

test('property: supernet_of encloses its input', () => {
  for (let trial = 0; trial < 150; trial += 1) {
    const net = randomIPv4Network(4, 32);
    const prefix = randomInt(net.prefix + 1);
    const enclosing = supernetOf(net, prefix);
    assert.ok(contains(enclosing, net));
    assert.equal(enclosing.prefix, prefix);
    assert.equal(enclosing.family, net.family);
  }
});

test('property: IPv4 and IPv6 are never equal or overlapping', () => {
  for (let trial = 0; trial < 100; trial += 1) {
    const v4 = randomIPv4Network(0, 32);
    const v6 = randomIPv6Network(16, 128);
    assert.equal(intersect(v4, v6), null);
    assert.equal(overlaps(v4, v6), false);
    assert.equal(contains(v4, v6), false);
    assert.equal(contains(v6, v4), false);
    // The IPv4 block is returned untouched by a mixed-family difference.
    assert.deepEqual(difference(v4, v6).map((n) => n.text), [v4.text]);
    // And a mixed list summarises into the two independent minimal covers.
    assert.deepEqual(summariseTexts([v6.text, v4.text]), [v4.text, v6.text]);
  }
});

test('property: sorting a set is deterministic and total', () => {
  for (let trial = 0; trial < 100; trial += 1) {
    const entries = [];
    for (let i = 0; i < 1 + randomInt(6); i += 1) {
      entries.push(
        randomInt(2) === 0
          ? randomIPv4Network(0, 32).text
          : randomIPv6Network(16, 128).text
      );
    }
    const once = sortCidrs(entries);
    assert.deepEqual(sortCidrs([...entries].reverse()), once, 'permutation changed the order');
    // IPv4 blocks all precede IPv6 blocks.
    const firstV6 = once.findIndex((text) => text.includes(':'));
    if (firstV6 !== -1) {
      for (let i = firstV6; i < once.length; i += 1) assert.ok(once[i].includes(':'));
    }
  }
});

test('property: expand and count agree for small blocks', () => {
  for (let trial = 0; trial < 60; trial += 1) {
    const net = randomIPv4Network(24, 30);
    const addresses = expand(net);
    assert.equal(addresses.length, Number(count(net)));
    assert.equal(addresses[0], net.base);
    assert.equal(addresses[addresses.length - 1], net.last);
    // A full block summarised from its own addresses is itself. The addresses
    // are formatted with formatAddress, since a decimal literal is not a CIDR.
    assert.deepEqual(
      summariseTexts(addresses.map((value) => formatAddress({ family: net.family, value, zone: null }))),
      [net.text]
    );
  }
});

test('property: BigInt counts are exact for every prefix length', () => {
  for (let prefix = 0; prefix <= 32; prefix += 1) {
    assert.equal(count(parseCidr(`0.0.0.0/${prefix}`)), 1n << BigInt(32 - prefix));
    assert.equal(count(parseCidr(`::/${prefix}`)), 1n << BigInt(128 - prefix));
  }
  // Spot-check the awkward ones as exact decimal strings.
  assert.equal(count(parseCidr('0.0.0.0/0')).toString(10), '4294967296');
  assert.equal(count(parseCidr('::/0')).toString(10), '340282366920938463463374607431768211456');
  assert.equal(count(parseCidr('2001:db8::/64')).toString(10), '18446744073709551616');
});

test('property: parsing is idempotent through formatting', () => {
  for (let trial = 0; trial < 150; trial += 1) {
    const net = randomIPv4Network(0, 32);
    // Formatting the parsed block and re-parsing yields the same block.
    const again = parseCidr(net.text);
    assert.equal(again.text, net.text);
    assert.equal(again.base, net.base);
    assert.equal(again.last, net.last);
  }
});