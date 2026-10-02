'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { parseAddress, parseCidr } = require('../src/address.js');
const { contains } = require('../src/ipset.js');
const { compareAddresses, compareNets, sortAddresses, sortCidrs, sortNets } = require('../src/sort.js');

test('sorts IPv4 numerically, not lexicographically', () => {
  // As strings "10.0.0.10" < "10.0.0.9"; numerically it is the other way.
  assert.deepEqual(sortCidrs(['10.0.0.10', '10.0.0.9', '10.0.0.1']), [
    '10.0.0.1/32',
    '10.0.0.9/32',
    '10.0.0.10/32',
  ]);
  assert.deepEqual(sortCidrs(['9.0.0.0', '100.0.0.0', '20.0.0.0']), [
    '9.0.0.0/32',
    '20.0.0.0/32',
    '100.0.0.0/32',
  ]);
});

test('sorts IPv6 numerically too', () => {
  assert.deepEqual(sortCidrs(['2001:db8::10', '2001:db8::9', '2001:db8::2']), [
    '2001:db8::2/128',
    '2001:db8::9/128',
    '2001:db8::10/128',
  ]);
});

test('all IPv4 comes before all IPv6', () => {
  const input = ['2001:db8::1', '::1', '10.0.0.1', '255.255.255.255', '2001:db8::'];
  assert.deepEqual(sortCidrs(input), [
    '10.0.0.1/32',
    '255.255.255.255/32',
    '::1/128',
    '2001:db8::/128',
    '2001:db8::1/128',
  ]);
});

test('sorts by network base, not by prefix length', () => {
  // 10.0.0.0/16 and 10.0.0.0/32 share a base, so the longer prefix wins.
  assert.deepEqual(sortCidrs(['10.0.1.0/24', '10.0.0.0/16', '10.0.0.0/32']), [
    '10.0.0.0/32',
    '10.0.0.0/16',
    '10.0.1.0/24',
  ]);
});

test('ties on base are broken by longer prefix first', () => {
  // Same network base, different prefixes: the more specific block first.
  assert.deepEqual(sortCidrs(['10.0.0.0/24', '10.0.0.0/8', '10.0.0.0/16']), [
    '10.0.0.0/24',
    '10.0.0.0/16',
    '10.0.0.0/8',
  ]);
});

test('sorting is a no-op on already sorted input', () => {
  const sorted = ['10.0.0.0/8', '10.0.1.0/24', '172.16.0.0/12', '::/0', '2001:db8::/32'];
  assert.deepEqual(sortCidrs(sorted), sorted);
  assert.deepEqual(sortCidrs([...sorted].reverse()), sorted);
});

test('sorting is deterministic and idempotent', () => {
  const input = ['2001:db8::5', '10.0.0.2', '10.0.0.10', '::', '192.168.0.0/16', '10.0.0.2'];
  const once = sortCidrs(input);
  assert.deepEqual(sortCidrs(once), once);
  // A different permutation of the same input sorts identically.
  assert.deepEqual(sortCidrs([...input].reverse()), once);
});

test('sortCidrs does not mutate its input', () => {
  const input = ['10.0.0.2', '10.0.0.1'];
  const copy = [...input];
  sortCidrs(input);
  assert.deepEqual(input, copy);
});

test('sorts parsed records as well as strings', () => {
  const records = [parseCidr('2001:db8::1'), parseCidr('10.0.0.1')];
  assert.deepEqual(sortNets(records).map((net) => net.text), ['10.0.0.1/32', '2001:db8::1/128']);
});

test('sorts bare addresses', () => {
  assert.deepEqual(sortAddresses(['::1', '10.0.0.9', '10.0.0.10']).map((a) => a.text), [
    '10.0.0.9',
    '10.0.0.10',
    '::1',
  ]);
});

test('comparators return 0 for identical values', () => {
  assert.equal(compareNets(parseCidr('10.0.0.0/24'), parseCidr('10.0.0.0/24')), 0);
  assert.equal(compareAddresses(parseAddress('10.0.0.1'), parseAddress('10.0.0.1')), 0);
});

test('an IPv4 and an IPv6 address are never equal and never overlap', () => {
  // ::a00:1 is 0x0a000001 - numerically the *same* BigInt as 10.0.0.1. They are
  // still different addresses, because the family is checked separately.
  const v4 = parseCidr('10.0.0.1/32');
  const v6 = parseCidr('::a00:1/128');
  assert.equal(v6.base, v4.base);
  assert.equal(v6.base, 167772161n);
  assert.notEqual(v6.family, v4.family);
  assert.notEqual(v6.bits, v4.bits);
  assert.notEqual(v6.text, v4.text);
  assert.equal(v6.text, '::a00:1/128');
  assert.equal(v4.text, '10.0.0.1/32');
  // Despite sharing a numeric value, neither contains the other.
  assert.equal(contains(v4, v6), false);
  assert.equal(contains(v6, v4), false);
  // ::ffff:10.0.0.1 is the mapped form of 10.0.0.1 but stays IPv6.
  const mapped = parseCidr('::ffff:10.0.0.1/128');
  assert.equal(mapped.family, 6);
  assert.notEqual(mapped.base, v4.base);
  assert.equal(mapped.text, '::ffff:10.0.0.1/128');
});

test('sorting a single mixed set yields a stable, reproducible order', () => {
  const input = ['::ffff:10.0.0.1', '10.0.0.1', '0.0.0.0/0', '::/0'];
  assert.deepEqual(sortCidrs(input), [
    '0.0.0.0/0',
    '10.0.0.1/32',
    '::/0',
    '::ffff:10.0.0.1/128',
  ]);
});