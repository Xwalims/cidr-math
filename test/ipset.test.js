'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  contains,
  containsAddress,
  count,
  difference,
  differenceTexts,
  expand,
  hostBits,
  intersect,
  overlaps,
  subnetTexts,
  subnets,
  supernetOf,
  summarise,
  summariseTexts,
} = require('../src/ipset.js');
const { parseAddress, parseCidr } = require('../src/address.js');

test('counts are exact BigInt powers of two', () => {
  assert.equal(count(parseCidr('10.0.0.0/24')).toString(10), '256');
  assert.equal(count(parseCidr('10.0.0.0/32')).toString(10), '1');
  assert.equal(count(parseCidr('10.0.0.0/31')).toString(10), '2');
  assert.equal(count(parseCidr('10.0.0.0/0')).toString(10), '4294967296');
  assert.equal(count(parseCidr('2001:db8::/32')).toString(10), '79228162514264337593543950336');
  assert.equal(count(parseCidr('::/0')).toString(10), '340282366920938463463374607431768211456');
  assert.equal(count(parseCidr('2001:db8::/128')).toString(10), '1');
});

test('the IPv4 and IPv6 default routes count 2^32 and 2^128 exactly', () => {
  // The classic Number-based bug: 2^32 and 2^128 are not representable as doubles.
  const v4 = count(parseCidr('0.0.0.0/0'));
  const v6 = count(parseCidr('::/0'));
  assert.equal(typeof v4, 'bigint');
  assert.equal(v4, 1n << 32n);
  assert.equal(v6, 1n << 128n);
  assert.equal(v6.toString(10).length, 39);
});

test('an IPv6 /64 count matches the documented 2^64 value', () => {
  assert.equal(
    count(parseCidr('2001:db8::/64')).toString(10),
    '18446744073709551616'
  );
});

test('hostBits reports the number of bits below the prefix', () => {
  assert.equal(hostBits(parseCidr('10.0.0.0/24')), 8);
  assert.equal(hostBits(parseCidr('10.0.0.0/32')), 0);
  assert.equal(hostBits(parseCidr('::/0')), 128);
});

test('splitting a /24 into /26 gives exactly four blocks', () => {
  const blocks = subnets('10.0.0.0/24', 26);
  assert.equal(blocks.length, 4);
  assert.deepEqual(subnetTexts('10.0.0.0/24', 26), [
    '10.0.0.0/26',
    '10.0.0.64/26',
    '10.0.0.128/26',
    '10.0.0.192/26',
  ]);
  // The children tile the parent exactly.
  assert.deepEqual(summariseTexts(blocks), ['10.0.0.0/24']);
});

test('splitting into a shorter prefix is rejected', () => {
  assert.throws(() => subnets('10.0.0.0/24', 22), /larger than the source/);
  assert.throws(() => subnets('10.0.0.0/24', 33), /exceeds 32 for IPv4/);
  assert.throws(() => subnets('10.0.0.0/24', 'twenty'), /must be an integer/);
});

test('splitting a /22 into /24 yields four blocks ending at 10.0.3.0/24', () => {
  const blocks = subnetTexts('10.0.0.0/22', 24);
  assert.equal(blocks.length, 4);
  assert.equal(blocks[0], '10.0.0.0/24');
  assert.equal(blocks[3], '10.0.3.0/24');
  assert.deepEqual(summariseTexts(blocks), ['10.0.0.0/22']);
});

test('splitting an IPv6 /64 into /68 yields sixteen blocks', () => {
  const blocks = subnets('2001:db8::/64', 68);
  assert.equal(blocks.length, 16);
  assert.equal(blocks[0].text, '2001:db8::/68');
  assert.equal(blocks[15].text, '2001:db8:0:0:f000::/68');
  assert.deepEqual(summariseTexts(blocks), ['2001:db8::/64']);
});

test('splitting a /0 halves the address space without losing precision', () => {
  // The BigInt payoff: 2^31 addresses per half, exact to the last digit.
  assert.deepEqual(subnetTexts('0.0.0.0/0', 1), ['0.0.0.0/1', '128.0.0.0/1']);
  assert.deepEqual(subnetTexts('0.0.0.0/0', 2), [
    '0.0.0.0/2',
    '64.0.0.0/2',
    '128.0.0.0/2',
    '192.0.0.0/2',
  ]);
  assert.deepEqual(subnetTexts('::/0', 1), ['::/1', '8000::/1']);
  for (const net of subnets('0.0.0.0/0', 1)) {
    assert.equal(count(net).toString(10), '2147483648');
  }
});

test('splitting a /16 into /24 yields 256 blocks ending at 10.0.255.0/24', () => {
  const blocks = subnetTexts('10.0.0.0/16', 24);
  assert.equal(blocks.length, 256);
  assert.equal(blocks[0], '10.0.0.0/24');
  assert.equal(blocks[255], '10.0.255.0/24');
  assert.deepEqual(summariseTexts(blocks), ['10.0.0.0/16']);
});

test('adjacent /24s summarise to a single /23', () => {
  assert.deepEqual(summariseTexts(['10.0.0.0/24', '10.0.1.0/24']), ['10.0.0.0/23']);
  assert.deepEqual(summariseTexts(['10.0.1.0/24']), ['10.0.1.0/24']);
  assert.deepEqual(summariseTexts(['10.0.0.0/24']), ['10.0.0.0/24']);
});

test('two identical entries collapse to one block', () => {
  assert.deepEqual(summariseTexts(['10.0.0.0/24', '10.0.0.0/24']), ['10.0.0.0/24']);
  assert.deepEqual(summariseTexts(['10.0.0.1', '10.0.0.1']), ['10.0.0.1/32']);
});

test('a /25 pair collapses to its /24', () => {
  assert.deepEqual(summariseTexts(['10.0.0.0/25', '10.0.0.128/25']), ['10.0.0.0/24']);
  assert.deepEqual(summariseTexts(['10.0.0.0/25', '10.0.0.128/25', '10.0.1.0/24']), [
    '10.0.0.0/23',
  ]);
});

test('prefix adjacency is not numeric adjacency: distant /31s must not merge', () => {
  // 10.0.0.3/31 is a misaligned CIDR: it normalises to 10.0.0.2/31, whose
  // neighbour 10.0.0.0/31 makes the pair a perfect /30. Verified against
  // Python ipaddress, which resolves 10.0.0.3/31 to 10.0.0.2/31.
  assert.deepEqual(summariseTexts(['10.0.0.0/31', '10.0.0.2/31']), ['10.0.0.0/30']);
  assert.deepEqual(summariseTexts(['10.0.0.0/31', '10.0.0.3/31']), ['10.0.0.0/30']);
  assert.deepEqual(summariseTexts(['192.168.0.0/31', '192.168.2.0/31']), [
    '192.168.0.0/31',
    '192.168.2.0/31',
  ]);
  // 10.0.0.0/30 and 10.0.0.4/30 really are contiguous (0-7), so they do
  // merge into a /29. Verified against Python ipaddress.
  assert.deepEqual(summariseTexts(['10.0.0.0/30', '10.0.0.4/30']), ['10.0.0.0/29']);
  // 10.0.0.5/30 is a misaligned CIDR: it normalises to 10.0.0.4/30, which is
  // contiguous with 10.0.0.0/30, so the pair merges to a /29. Verified against
  // Python ipaddress, which resolves 10.0.0.5/30 to 10.0.0.4/30.
  assert.deepEqual(summariseTexts(['10.0.0.0/30', '10.0.0.5/30']), ['10.0.0.0/29']);
  // A single address inside an existing block changes nothing: the union is
  // still the /24. Verified against Python ipaddress.
  assert.deepEqual(summariseTexts(['10.0.0.0/24', '10.0.0.1']), ['10.0.0.0/24']);
  // A single address outside it extends the cover to the /23 that contains
  // both, because 10.0.0.0/24 and 10.0.1.0/32 do not fill the /23.
  assert.deepEqual(summariseTexts(['10.0.0.0/24', '10.0.1.5']), [
    '10.0.0.0/24',
    '10.0.1.5/32',
  ]);
  // Numerically adjacent /31s merge, because the addresses really do touch.
  assert.deepEqual(summariseTexts(['10.0.0.0/31', '10.0.0.1/31']), ['10.0.0.0/31']);
});

test('four contiguous /24s collapse all the way to a /22', () => {
  const entries = ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24'];
  assert.deepEqual(summariseTexts(entries), ['10.0.0.0/22']);
  // Remove one and the minimal cover is no longer a single block.
  assert.deepEqual(summariseTexts(entries.slice(0, 3)), [
    '10.0.0.0/23',
    '10.0.2.0/24',
  ]);
});

test('a minimal cover of a /22 plus one /26 collapses to the /22', () => {
  // Adding a block inside an existing one changes nothing: the union is
  // still the /22. Verified against Python ipaddress.
  assert.deepEqual(summariseTexts(['10.0.0.0/22', '10.0.0.0/26']), ['10.0.0.0/22']);
});

test('a minimal cover of three /24s is a /23 plus a /24', () => {
  // The union of 10.0.0.0/24, 10.0.1.0/24 and 10.0.2.0/24 cannot be a single
  // block: 10.0.3.0/24 is missing. Verified against Python ipaddress.
  assert.deepEqual(summariseTexts(['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24']), [
    '10.0.0.0/23',
    '10.0.2.0/24',
  ]);
});

test('summarise merges three contiguous /24s two at a time', () => {
  const entries = ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24'];
  assert.deepEqual(summariseTexts([...entries, '10.0.3.0/24']), ['10.0.0.0/22']);
});

test('a whole /24 of individual addresses summarises back to the /24', () => {
  const entries = [];
  for (let i = 0; i < 256; i += 1) entries.push(`10.0.0.${i}`);
  assert.deepEqual(summariseTexts(entries), ['10.0.0.0/24']);
});

test('summarise keeps families separate and returns IPv4 first', () => {
  assert.deepEqual(summariseTexts(['2001:db8::1', '10.0.0.1', '2001:db8::/32']), [
    '10.0.0.1/32',
    '2001:db8::/32',
  ]);
});

test('summarise of the whole IPv4 range is NOT 0.0.0.0/0', () => {
  // Only the two endpoints were given, so the middle is missing and no
  // smaller-than-/0 block can cover both. Verified against Python ipaddress.
  assert.deepEqual(summariseTexts(['0.0.0.0', '255.255.255.255']), [
    '0.0.0.0/32',
    '255.255.255.255/32',
  ]);
});

test('summarise of a tiled /12 rebuilds the /12', () => {
  // Every /24 in the /12, listed explicitly (a bare address would be a /32).
  const entries = [];
  for (let i = 0; i < 16; i += 1) {
    for (let j = 0; j < 256; j += 1) entries.push(`10.${i}.${j}.0/24`);
  }
  assert.equal(entries.length, 4096);
  assert.deepEqual(summariseTexts(entries), ['10.0.0.0/12']);
});

test('summarise of every /24 in a /16 gives back the /16', () => {
  // A full /16 is 2^24 addresses; too many records for a unit test. Cover it
  // with the smallest entry set that still tiles it: one /24 per entry.
  const entries = [];
  for (let i = 0; i < 256; i += 1) entries.push(`10.0.${i}.0/24`);
  assert.equal(entries.length, 256);
  assert.deepEqual(summariseTexts(entries), ['10.0.0.0/16']);

  // Half a /16 is a /17, not the /16: 10.0.128.0 onwards is missing.
  assert.deepEqual(summariseTexts(entries.slice(0, 128)), ['10.0.0.0/17']);
});

test('summarise of a full IPv6 range is not ::/0', () => {
  // Same reasoning: the endpoints alone leave the middle uncovered.
  assert.deepEqual(summariseTexts(['::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']), [
    '::/128',
    'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128',
  ]);
});

test('summarise of an empty list is empty', () => {
  assert.deepEqual(summariseTexts([]), []);
});

test('intersect across address families is null, never an error', () => {
  assert.equal(intersect('10.0.0.0/8', '2001:db8::/32'), null);
  assert.equal(intersect('::/0', '0.0.0.0/0'), null);
  assert.equal(intersect('::ffff:1.2.3.4', '1.2.3.4'), null);
  assert.equal(intersect('0.0.0.0/0', '::/0'), null);
});

test('intersect finds the common part', () => {
  assert.equal(intersect('10.0.0.0/24', '10.0.0.0/24').text, '10.0.0.0/24');
  assert.equal(intersect('10.0.0.0/22', '10.0.2.0/24').text, '10.0.2.0/24');
  assert.equal(intersect('10.1.2.0/23', '10.1.2.128/25').text, '10.1.2.128/25');
  assert.equal(intersect('10.0.0.0/23', '10.0.1.0/24').text, '10.0.1.0/24');
  assert.equal(intersect('2001:db8::/32', '2001:db8::/48').text, '2001:db8::/48');
  assert.equal(intersect('::/0', '2001:db8::/32').text, '2001:db8::/32');
  assert.equal(intersect('10.0.0.0/8', '10.1.2.0/24').text, '10.1.2.0/24');
  // 2001:db8::/48 and 2001:db8:1::/48 are disjoint: their /47 is not covered
  // by either input. Verified against Python ipaddress.
  assert.equal(intersect('2001:db8::/48', '2001:db8:1::/48'), null);
});

test('intersect returns null for disjoint networks, it does not throw', () => {
  assert.equal(intersect('10.0.0.0/24', '10.0.1.0/24'), null);
  assert.equal(intersect('192.168.0.0/24', '172.16.0.0/12'), null);
  assert.equal(intersect('2001:db8::/32', '2001:db9::/32'), null);
  assert.equal(intersect('2001:db8::/48', '2001:db8:1::/48'), null);
});

test('intersect across address families is null, never an error', () => {
  assert.equal(intersect('10.0.0.0/8', '2001:db8::/32'), null);
  assert.equal(intersect('::/0', '0.0.0.0/0'), null);
  assert.equal(intersect('::ffff:1.2.3.4', '1.2.3.4'), null);
  assert.equal(intersect('0.0.0.0/0', '::/0'), null);
});

test('intersect of the IPv4-mapped IPv6 range with an IPv4 /32', () => {
  // ::ffff:0:0/96 and 1.2.3.4/32 share no addresses: they are different families.
  assert.equal(intersect('::ffff:0:0/96', '1.2.3.0/24'), null);
  assert.equal(intersect('::ffff:0:0/96', '::ffff:1.2.3.0/120').text, '::ffff:1.2.3.0/120');
});

test('contains is true only for full containment', () => {
  assert.equal(contains('10.0.0.0/8', '10.1.2.0/24'), true);
  assert.equal(contains('10.0.0.0/8', '10.0.0.0/8'), true);
  assert.equal(contains('10.0.0.0/24', '10.0.0.0/25'), true);
  assert.equal(contains('10.0.0.0/25', '10.0.0.0/24'), false);
  assert.equal(contains('10.0.0.0/8', '11.0.0.0/8'), false);
  assert.equal(contains('10.0.0.0/25', '10.0.0.128/25'), false);
});

test('contains is false across address families and never throws', () => {
  assert.equal(contains('::/0', '10.0.0.1'), false);
  assert.equal(contains('0.0.0.0/0', '::1'), false);
  assert.equal(contains('::/0', '2001:db8::/32'), true);
});

test('containsAddress checks single addresses', () => {
  assert.equal(containsAddress('10.0.0.0/24', '10.0.0.42'), true);
  assert.equal(containsAddress('10.0.0.0/24', '10.0.1.42'), false);
  assert.equal(containsAddress('10.0.0.0/24', '::1'), false);
  assert.equal(containsAddress('2001:db8::/32', '2001:db8::1'), true);
});

test('overlaps is true when the blocks share an address', () => {
  assert.equal(overlaps('10.0.0.0/24', '10.0.0.128/25'), true);
  assert.equal(overlaps('10.0.0.0/24', '10.0.1.0/24'), false);
  assert.equal(overlaps('10.0.0.0/8', '2001:db8::/32'), false);
});

test('difference with a non-overlapping block is the whole block', () => {
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.1.0/24'), ['10.0.0.0/24']);
  assert.deepEqual(differenceTexts('10.0.0.0/24', '2001:db8::/32'), ['10.0.0.0/24']);
});

test('difference yielding zero blocks when the inner block covers the outer', () => {
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.0.0/24'), []);
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.0.0/8'), []);
  assert.deepEqual(differenceTexts('10.0.0.0/24', '0.0.0.0/0'), []);
});

test('difference yielding one block when the hole is flush with an edge', () => {
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.0.0/25'), ['10.0.0.128/25']);
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.0.128/25'), ['10.0.0.0/25']);
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.0.0/26'), [
    '10.0.0.64/26',
    '10.0.0.128/25',
  ]);
});

test('difference yielding two blocks when the hole is strictly inside', () => {
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.0.64/26'), [
    '10.0.0.0/26',
    '10.0.0.128/25',
  ]);
  assert.deepEqual(differenceTexts('10.0.0.0/22', '10.0.1.0/24'), [
    '10.0.0.0/24',
    '10.0.2.0/23',
  ]);
  assert.deepEqual(differenceTexts('10.0.0.0/30', '10.0.0.1/32'), [
    '10.0.0.0/32',
    '10.0.0.2/31',
  ]);
});

test('difference yielding three blocks from a single interior hole', () => {
  // The classic three-block case: the remainder needs one block below the hole,
  // and the tail above it splits in two. Verified against Python ipaddress.
  assert.deepEqual(differenceTexts('10.0.0.0/22', '10.0.0.128/25'), [
    '10.0.0.0/25',
    '10.0.1.0/24',
    '10.0.2.0/23',
  ]);
  // Same shape, shifted so the three blocks have different sizes.
  assert.deepEqual(differenceTexts('172.16.0.0/12', '172.16.128.0/17'), [
    '172.16.0.0/17',
    '172.17.0.0/16',
    '172.18.0.0/15',
    '172.20.0.0/14',
    '172.24.0.0/13',
  ]);
});

test('difference yielding four blocks from one small hole in a big block', () => {
  assert.deepEqual(differenceTexts('10.0.0.0/22', '10.0.0.64/26'), [
    '10.0.0.0/26',
    '10.0.0.128/25',
    '10.0.1.0/24',
    '10.0.2.0/23',
  ]);
  assert.deepEqual(differenceTexts('10.0.0.0/21', '10.0.0.128/25'), [
    '10.0.0.0/25',
    '10.0.1.0/24',
    '10.0.2.0/23',
    '10.0.4.0/22',
  ]);
});

test('difference of a /22 minus a hole flush with its top edge', () => {
  assert.deepEqual(differenceTexts('10.0.0.0/22', '10.0.3.192/26'), [
    '10.0.0.0/23',
    '10.0.2.0/24',
    '10.0.3.0/25',
    '10.0.3.128/26',
  ]);
});

test('difference accepts a list of blocks to remove', () => {
  assert.deepEqual(differenceTexts('10.0.0.0/24', ['10.0.0.0/26', '10.0.0.128/25']), [
    '10.0.0.64/26',
  ]);
  assert.deepEqual(differenceTexts('10.0.0.0/24', ['10.0.0.64/26', '10.0.0.192/26']), [
    '10.0.0.0/26',
    '10.0.0.128/26',
  ]);
});

test('difference from the IPv4 default route stays exact in BigInt', () => {
  // 0.0.0.0/0 minus 10.0.0.0/24: the tail after the hole decomposes into a
  // long run of ever-larger blocks. Verified against Python ipaddress.
  assert.deepEqual(differenceTexts('0.0.0.0/0', '10.0.0.0/24'), [
    '0.0.0.0/5',
    '8.0.0.0/7',
    '10.0.1.0/24',
    '10.0.2.0/23',
    '10.0.4.0/22',
    '10.0.8.0/21',
    '10.0.16.0/20',
    '10.0.32.0/19',
    '10.0.64.0/18',
    '10.0.128.0/17',
    '10.1.0.0/16',
    '10.2.0.0/15',
    '10.4.0.0/14',
    '10.8.0.0/13',
    '10.16.0.0/12',
    '10.32.0.0/11',
    '10.64.0.0/10',
    '10.128.0.0/9',
    '11.0.0.0/8',
    '12.0.0.0/6',
    '16.0.0.0/4',
    '32.0.0.0/3',
    '64.0.0.0/2',
    '128.0.0.0/1',
  ]);
});

test('difference from the IPv6 default route stays exact in BigInt', () => {
  const blocks = differenceTexts('::/0', '2001:db8::/32');
  // The hole is removed; head and tail are covered minimally.
  assert.equal(blocks[0], '::/3');
  assert.equal(blocks[1], '2000::/16');
  assert.ok(blocks.includes('2001:db9::/32'));
  assert.equal(blocks[blocks.length - 1], '8000::/1');
  // Re-adding the hole must rebuild exactly the default route.
  assert.deepEqual(summariseTexts([...blocks, '2001:db8::/32']), ['::/0']);
});

test('difference from a /0 in either family stays exact', () => {
  assert.deepEqual(differenceTexts('0.0.0.0/0', '0.0.0.0/1'), ['128.0.0.0/1']);
  assert.deepEqual(differenceTexts('0.0.0.0/0', '128.0.0.0/1'), ['0.0.0.0/1']);
  assert.deepEqual(differenceTexts('::/1', '::/2'), ['4000::/2']);
  assert.deepEqual(differenceTexts('8000::/1', '8000::/2'), ['c000::/2']);
});

test('difference in IPv6 space works on a /126', () => {
  assert.deepEqual(differenceTexts('2001:db8::/126', '2001:db8::2/128'), [
    '2001:db8::/127',
    '2001:db8::3/128',
  ]);
  assert.deepEqual(differenceTexts('2001:db8::/126', '2001:db8::/127'), ['2001:db8::2/127']);
});

test('supernet_of returns the enclosing block', () => {
  assert.equal(supernetOf('10.1.2.3/24', 16).text, '10.1.0.0/16');
  assert.equal(supernetOf('10.1.2.3/24', 8).text, '10.0.0.0/8');
  assert.equal(supernetOf('10.1.2.3/24', 24).text, '10.1.2.0/24');
  assert.equal(supernetOf('2001:db8:1:2:3:4:5:6/128', 64).text, '2001:db8:1:2::/64');
  assert.equal(supernetOf('192.168.1.1', 16).text, '192.168.0.0/16');
});

test('supernet_of rejects a prefix shorter than the source block', () => {
  assert.throws(() => supernetOf('10.0.0.0/16', 24), /smaller than the source/);
  assert.throws(() => supernetOf('10.0.0.0/16', 33), /exceeds 32 for IPv4/);
  assert.throws(() => supernetOf('10.0.0.0/16', 8.5), /must be an integer/);
});

test('expand lists every address of a small block', () => {
  const values = expand('10.0.0.0/30');
  assert.equal(values.length, 4);
  assert.equal(values[0].toString(10), '167772160');
  assert.equal(values[3].toString(10), '167772163');
});

test('summarise accepts parsed records as well as strings', () => {
  const parsed = [parseCidr('10.0.0.0/25'), parseAddress('10.0.0.128')];
  // A /25 plus a single /32 is NOT a /24: 10.0.0.129-10.0.0.255 is missing,
  // so no block covers the pair. Both expected outputs verified against
  // Python ipaddress.
  assert.deepEqual(summarise(parsed).map((net) => net.text), [
    '10.0.0.0/25',
    '10.0.0.128/32',
  ]);
  assert.deepEqual(summariseTexts([parseCidr('10.0.0.0/25'), '10.0.0.255']), [
    '10.0.0.0/25',
    '10.0.0.255/32',
  ]);
  // Two consecutive /32s do merge into a /31.
  assert.deepEqual(
    summariseTexts([parseCidr('10.0.0.0/25'), '10.0.0.128', '10.0.0.129']),
    ['10.0.0.0/25', '10.0.0.128/31']
  );
  // The true partner of the /25 completes it.
  assert.deepEqual(summariseTexts([parseCidr('10.0.0.0/25'), '10.0.0.128/25']), [
    '10.0.0.0/24',
  ]);
});

test('summarise output is minimal: no two output blocks can be merged', () => {
  const output = summariseTexts([
    '10.0.0.0/25',
    '10.0.0.128/25',
    '10.0.1.0/25',
    '10.0.1.128/25',
    '10.0.2.0/25',
  ]);
  assert.deepEqual(output, ['10.0.0.0/23', '10.0.2.0/25']);
  // Summarising the output again is a no-op.
  assert.deepEqual(summariseTexts(output), output);
});
// ---------------------------------------------------------------------------
// Zone identifiers are part of an address's identity (RFC 4007 section 3.2:
// "two different physical links may each contain a node with the link-local
// address fe80::1"). Blocks on different interfaces share a numeric range but
// no addresses, so they must never be merged, intersected or subtracted as if
// they did. These came out of a differential run against Python's ipaddress.
// ---------------------------------------------------------------------------

test('blocks in different zones never collapse into one', () => {
  // Both halves of fe80::/63 are present, but on different links, so the
  // result is two /64s - not one /63 stamped with the first zone seen.
  assert.deepEqual(
    summariseTexts(['fe80::/64%eth0', 'fe80:0:0:1::/64%eth1']),
    ['fe80::%eth0/64', 'fe80:0:0:1::%eth1/64']
  );
});

test('a zoned block does not merge with an unzoned one', () => {
  assert.deepEqual(
    summariseTexts(['fe80::/64%eth0', 'fe80:0:0:1::/64']),
    ['fe80:0:0:1::/64', 'fe80::%eth0/64']
  );
});

test('blocks sharing a zone still collapse', () => {
  assert.deepEqual(
    summariseTexts(['fe80::/64%eth0', 'fe80:0:0:1::/64%eth0']),
    ['fe80::%eth0/63']
  );
});

test('blocks in different zones are disjoint', () => {
  assert.equal(intersect('fe80::/64%eth0', 'fe80::/64%eth1'), null);
  assert.equal(overlaps('fe80::/64%eth0', 'fe80::/64%eth1'), false);
  assert.equal(contains('fe80::/63%eth0', 'fe80::/64%eth1'), false);
  assert.equal(containsAddress('fe80::/63%eth0', 'fe80::1%eth1'), false);
});

test('an unzoned block intersects and contains any zone', () => {
  // No zone given means the statement holds in every zone.
  const hit = intersect('fe80::/63', 'fe80::/64%eth0');
  assert.equal(hit.text, 'fe80::%eth0/64');
  assert.equal(hit.zone, 'eth0');
  assert.equal(contains('fe80::/63', 'fe80::/64%eth0'), true);
  assert.equal(containsAddress('fe80::/63', 'fe80::1%eth0'), true);
});

test('subtracting a hole in another zone removes nothing', () => {
  assert.deepEqual(
    differenceTexts('fe80::/63%eth0', 'fe80::/64%eth1'),
    ['fe80::%eth0/63']
  );
  // The same hole on the same interface does remove.
  assert.deepEqual(
    differenceTexts('fe80::/63%eth0', 'fe80::/64%eth0'),
    ['fe80:0:0:1::%eth0/64']
  );
});

test('subtracting from an UNZONED block only removes that zone', () => {
  // The reverse direction of the test above, and the one that was wrong.
  //
  // An unzoned block is not "a block with no interface" -- per sameZone() it is
  // the statement "these addresses, in every zone". So fe80::/64 minus
  // fe80::/64%eth0 removes eth0's copy and leaves every OTHER zone's copy
  // intact. Returning [] claims the unscoped block is now empty, which drops
  // every address on every interface other than eth0.
  assert.deepEqual(
    differenceTexts('fe80::/64', 'fe80::/64%eth0'),
    ['fe80::/64']
  );
  // A PARTIAL zoned hole cannot narrow an unzoned block either, and the
  // reason is not an oversight. "Every zone" minus "eth0's lower half" is not
  // expressible: the vocabulary has no block meaning "every zone except
  // eth0". So the block is returned intact -- an over-approximation, which is
  // the safe direction for a "what is still uncovered" question. Understating
  // it (the old behaviour) was the dangerous one.
  assert.deepEqual(
    differenceTexts('fe80::/64', 'fe80::/65%eth0'),
    ['fe80::/64']
  );
  // An unzoned hole still removes from an unzoned outer, exactly as before --
  // subtracting a zone-agnostic statement from a zone-agnostic statement.
  assert.deepEqual(
    differenceTexts('fe80::/64', 'fe80::/64'),
    []
  );
  // And a zoned hole in a DIFFERENT zone than an unzoned outer must not
  // empty it either -- same reason, spelled the other way round.
  assert.deepEqual(
    differenceTexts('fe80::/63', 'fe80::/64%eth1'),
    ['fe80::/63']
  );
  // IPv4 cannot carry a zone, so the unzoned path there is unaffected.
  assert.deepEqual(differenceTexts('10.0.0.0/24', '10.0.0.0/25'), ['10.0.0.128/25']);
});

test('zone is a total sort tie-break', () => {
  const sorted = summariseTexts(['fe80:0:0:1::/64%eth1', 'fe80::/64%eth0']);
  assert.deepEqual(sorted, ['fe80::%eth0/64', 'fe80:0:0:1::%eth1/64']);
  assert.deepEqual(summariseTexts(sorted), sorted);
});
