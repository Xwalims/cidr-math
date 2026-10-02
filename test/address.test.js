'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  CidrError,
  formatAddress,
  formatCidr,
  parseAddress,
  parseCidr,
  splitCidr,
} = require('../src/address.js');

test('parses IPv4 addresses into BigInt values', () => {
  assert.equal(parseAddress('0.0.0.0').value, 0n);
  assert.equal(parseAddress('255.255.255.255').value, 4294967295n);
  assert.equal(parseAddress('10.0.0.1').value, 167772161n);
  assert.equal(parseAddress('192.168.1.1').family, 4);
  assert.equal(parseAddress('192.168.1.1').bits, 32);
});

test('rejects malformed IPv4 with a message naming the problem', () => {
  const cases = [
    ['10.0.0', /expected 4 dot-separated octets, got 3/],
    ['10.0.0.256', /octet 4 \("256"\) is out of range 0-255/],
    ['10.0.0.-1', /octet 4 \("-1"\) is not 1 to 3 decimal digits/],
    ['10.0.0.a', /octet 4 \("a"\) is not 1 to 3 decimal digits/],
    ['10.0.0.1.2', /expected 4 dot-separated octets, got 5/],
    ['10..0.1', /octet 2 \(""\) is not 1 to 3 decimal digits/],
  ];
  for (const [input, pattern] of cases) {
    assert.throws(() => parseAddress(input), (error) => {
      assert.ok(error instanceof CidrError, `${input} should raise CidrError`);
      assert.match(error.message, pattern);
      assert.equal(error.input, input);
      return true;
    }, `expected ${input} to be rejected`);
  }
});

test('parses IPv6 including shorthand and mixed notation', () => {
  assert.equal(parseAddress('::1').value, 1n);
  assert.equal(parseAddress('::').value, 0n);
  assert.equal(parseAddress('::ffff:1.2.3.4').value, 281470698652420n);
  assert.equal(parseAddress('2001:db8::1').value, 42540766411282592856903984951653826561n);
  assert.equal(parseAddress('2001:db8::1').family, 6);
  assert.equal(parseAddress('2001:db8::1').bits, 128);
  assert.equal(parseAddress('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').value, (1n << 128n) - 1n);
});

test('the same IPv6 address written three ways parses identically', () => {
  const spellings = [
    '2001:db8::1',
    '2001:0db8:0000:0000:0000:0000:0000:0001',
    '2001:DB8:0:0:0:0:0:1',
  ];
  const values = spellings.map((text) => parseAddress(text).value);
  const rendered = spellings.map((text) => formatAddress(parseAddress(text)));
  for (const value of values) assert.equal(value, values[0]);
  for (const text of rendered) assert.equal(text, '2001:db8::1');
  // 010.0.0.1 and 10.0.0.1 are also the same IPv4 address.
  assert.equal(formatAddress(parseAddress('010.0.0.1')), formatAddress(parseAddress('10.0.0.1')));
});

test('formats IPv6 in canonical RFC 5952 form', () => {
  const cases = [
    ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
    ['0:0:0:0:0:0:0:1', '::1'],
    ['2001:DB8:0:0:8:800:200C:417A', '2001:db8::8:800:200c:417a'],
    ['fe80:0:0:0:0:0:0:0', 'fe80::'],
    ['::ffff:1.2.3.4', '::ffff:1.2.3.4'],
    ['0:1:0:0:1:0:0:1', '0:1::1:0:0:1'],
    ['1:0:0:1:0:0:0:1', '1:0:0:1::1'],
  ];
  for (const [input, expected] of cases) {
    assert.equal(formatAddress(parseAddress(input)), expected, input);
  }
});

test('RFC 5952: the leftmost longest zero run is compressed', () => {
  // Both runs are 3 groups; RFC 5952 4.2.3 says choose the leftmost.
  assert.equal(formatAddress(parseAddress('1:0:0:0:2:0:0:3')), '1::2:0:0:3');
  // A single zero group is never compressed.
  assert.equal(formatAddress(parseAddress('1:2:3:4:5:6:0:8')), '1:2:3:4:5:6:0:8');
});

test('rejects malformed IPv6 with a message naming the problem', () => {
  const cases = [
    ['2001:db8:::1', /":::" is not allowed/],
    ['2001::db8::1', /"::" may appear at most once/],
    ['1:2:3:4:5:6:7', /expected 8 groups without "::", got 7/],
    ['1:2:3:4:5:6:7:8:9', /expected 8 groups without "::", got 9/],
    ['1:2:3:4:5:6:7:8:9::', /must stand for at least one zero group/],
    ['12345::', /group "12345" is not 1 to 4 hexadecimal digits/],
    ['gggg::1', /group "gggg" is not 1 to 4 hexadecimal digits/],
    ['', /empty address/],
    ['10.0.0.1 10.0.0.2', /contains whitespace/],
  ];
  for (const [input, pattern] of cases) {
    assert.throws(() => parseAddress(input), (error) => {
      assert.ok(error instanceof CidrError);
      assert.match(error.message, pattern);
      return true;
    }, `expected ${JSON.stringify(input)} to be rejected`);
  }
});

test('accepts IPv6 zone identifiers and keeps them on output', () => {
  const parsed = parseAddress('fe80::1%eth0');
  assert.equal(parsed.value, parseAddress('fe80::1').value);
  assert.equal(parsed.zone, 'eth0');
  assert.equal(formatAddress(parsed), 'fe80::1%eth0');
  assert.equal(formatAddress(parseAddress('fe80::1%3')), 'fe80::1%3');
  assert.equal(parseCidr('fe80::/64%eth0').zone, 'eth0');
  assert.equal(formatCidr(parseCidr('fe80::/64%eth0')), 'fe80::%eth0/64');
});

test('rejects invalid and misplaced zone identifiers', () => {
  assert.throws(() => parseAddress('fe80::1%'), /empty zone identifier/);
  assert.throws(() => parseAddress('fe80::1%eth0%x'), /more than one "%" zone separator/);
  assert.throws(() => parseAddress('fe80::1%eth/0'), /invalid zone identifier/);
  assert.throws(() => parseAddress('fe80::1%eth 0'), /contains whitespace/);
  assert.throws(() => parseAddress('10.0.0.1%eth0'), /IPv4 addresses cannot carry a zone identifier/);
});

test('splitCidr separates the address and prefix', () => {
  assert.deepEqual(splitCidr('10.0.0.0/24'), { address: '10.0.0.0', prefix: 24 });
  assert.deepEqual(splitCidr('2001:db8::/32'), { address: '2001:db8::', prefix: 32 });
  assert.deepEqual(splitCidr('10.0.0.1'), { address: '10.0.0.1', prefix: null });
});

test('splitCidr rejects malformed suffixes', () => {
  const cases = [
    ['10.0.0.0/24/8', /more than one "\/" separator/],
    ['/24', /missing address before "\/"/],
    ['10.0.0.0/', /prefix length "\/" is not a decimal number/],
    ['10.0.0.0/twenty', /prefix length "\/twenty" is not a decimal number/],
    ['10.0.0.0/33', /prefix length \/33 exceeds 32 for IPv4/],
    ['2001:db8::/129', /prefix length \/129 exceeds 128 for IPv6/],
  ];
  for (const [input, pattern] of cases) {
    assert.throws(() => splitCidr(input), pattern, input);
  }
});

test('parseCidr defaults a bare address to a host route', () => {
  assert.equal(parseCidr('10.0.0.7').text, '10.0.0.7/32');
  assert.equal(parseCidr('2001:db8::5').text, '2001:db8::5/128');
});

test('parseCidr clears host bits and reports that it did', () => {
  const net = parseCidr('10.0.0.5/24');
  assert.equal(net.text, '10.0.0.0/24');
  assert.equal(net.base, parseCidr('10.0.0.0/24').base);
  assert.equal(net.hostBitsSet, true);
  assert.equal(parseCidr('10.0.0.0/24').hostBitsSet, false);
  assert.equal(parseCidr('2001:db8::dead:beef/64').text, '2001:db8::/64');
});

test('IPv4 /32 is a single address and IPv6 /128 is a single address', () => {
  const v4 = parseCidr('10.0.0.1/32');
  assert.equal(v4.base, v4.last);
  assert.equal(v4.base.toString(10), '167772161');
  const v6 = parseCidr('2001:db8::1/128');
  assert.equal(v6.base, v6.last);
  assert.equal(v6.prefix, 128);
});

test('IPv4 /31 holds exactly two addresses (RFC 3021)', () => {
  const net = parseCidr('10.0.0.0/31');
  assert.equal(net.last - net.base, 1n);
  assert.equal(net.last.toString(10), '167772161');
  assert.equal(parseCidr('10.0.0.0/31').text, '10.0.0.0/31');
  const v6 = parseCidr('2001:db8::/127');
  assert.equal(v6.last - v6.base, 1n);
});