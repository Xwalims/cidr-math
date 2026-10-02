'use strict';

/**
 * Address and CIDR parsing/formatting for IPv4 and IPv6.
 *
 * All address arithmetic in this package is done with BigInt. A 64-bit IPv6
 * address does not fit in a JavaScript double, so a Number-based implementation
 * silently loses precision above 2^53 - which is precisely where real IPv6
 * documentation, allocation and operational traffic lives.
 */

const IPV4_BITS = 32;
const IPV6_BITS = 128;

/** RFC 4007 zone identifiers are either an interface name or a numeric index. */
const ZONE_RE = /^[0-9A-Za-z_.~-]+$/;

class CidrError extends Error {
  constructor(message, input) {
    super(message);
    this.name = 'CidrError';
    this.code = 'ECIDR';
    if (input !== undefined) this.input = input;
  }
}

function fail(message, input) {
  throw new CidrError(message, input);
}

/**
 * Split a trailing "%zone" off an address string.
 * Zone identifiers are accepted for IPv6 (RFC 4007) and rejected for IPv4.
 */
function splitZone(text) {
  const pct = text.indexOf('%');
  if (pct === -1) return { body: text, zone: null };
  if (text.indexOf('%', pct + 1) !== -1) {
    fail(`address "${text}" contains more than one "%" zone separator`, text);
  }
  const zone = text.slice(pct + 1);
  const body = text.slice(0, pct);
  if (zone === '') fail(`address "${text}" has an empty zone identifier after "%"`, text);
  if (!ZONE_RE.test(zone)) {
    fail(
      `address "${text}" has an invalid zone identifier "%${zone}" ` +
        '(expected an interface name or a numeric index)',
      text
    );
  }
  return { body, zone };
}

function parseIPv4(text, original) {
  const parts = text.split('.');
  if (parts.length !== 4) {
    fail(
      `invalid IPv4 address "${original}": expected 4 dot-separated octets, got ${parts.length}`,
      original
    );
  }
  let value = 0n;
  for (let i = 0; i < 4; i += 1) {
    const part = parts[i];
    if (!/^[0-9]{1,3}$/.test(part)) {
      fail(
        `invalid IPv4 address "${original}": octet ${i + 1} ("${part}") is not 1 to 3 decimal digits`,
        original
      );
    }
    const octet = Number(part);
    if (octet > 255) {
      fail(
        `invalid IPv4 address "${original}": octet ${i + 1} ("${part}") is out of range 0-255`,
        original
      );
    }
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function hextets(text, original) {
  return text.split(':').map((group) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      fail(
        `invalid IPv6 address "${original}": group "${group}" is not 1 to 4 hexadecimal digits`,
        original
      );
    }
    return Number.parseInt(group, 16);
  });
}

function parseIPv6(text, original) {
  let body = text;

  // A trailing dotted quad occupies the low 32 bits. Rewrite it as two hextets
  // while leaving the text before it (including any "::") untouched.
  if (body.includes('.')) {
    const v4 = body.slice(body.lastIndexOf(':') + 1);
    let v4Value;
    try {
      v4Value = parseIPv4(v4, original);
    } catch {
      fail(
        `invalid IPv6 address "${original}": embedded IPv4 part "${v4}" is not a dotted quad`,
        original
      );
    }
    const hi = (v4Value >> 16n) & 0xffffn;
    const lo = v4Value & 0xffffn;
    body = `${body.slice(0, body.length - v4.length)}${hi.toString(16)}:${lo.toString(16)}`;
  }

  // ":::" is checked first: the double-colon scan would otherwise report
  // "2001:db8:::1" as two separate "::" occurrences.
  if (body.includes(':::')) {
    fail(`invalid IPv6 address "${original}": ":::" is not allowed`, original);
  }

  const doubleColon = body.indexOf('::');
  let headText;
  let tailText;
  if (doubleColon === -1) {
    headText = body;
    tailText = '';
  } else {
    if (body.indexOf('::', doubleColon + 1) !== -1) {
      fail(`invalid IPv6 address "${original}": "::" may appear at most once`, original);
    }
    headText = body.slice(0, doubleColon);
    tailText = body.slice(doubleColon + 2);
  }

  const head = headText === '' ? [] : hextets(headText, original);
  const tail = tailText === '' ? [] : hextets(tailText, original);
  const explicit = head.length + tail.length;

  if (doubleColon === -1) {
    if (explicit !== 8) {
      fail(
        `invalid IPv6 address "${original}": expected 8 groups without "::", got ${explicit}`,
        original
      );
    }
  } else if (explicit > 7) {
    fail(
      `invalid IPv6 address "${original}": "::" must stand for at least one zero group ` +
        `(found ${explicit} groups besides it, at most 7 are allowed)`,
      original
    );
  }

  let value = 0n;
  for (const group of head) value = (value << 16n) | BigInt(group);
  value <<= BigInt(16 * (8 - explicit));
  for (const group of tail) value = (value << 16n) | BigInt(group);
  return value;
}

/**
 * Parse a bare IP address (no prefix length).
 *
 * Accepts every common spelling: "::1", "2001:db8::/32"-style blocks via
 * parseCidr(), mixed notation such as "::ffff:1.2.3.4", leading zeros
 * ("2001:0db8::1", "010.0.0.1"), and IPv6 zone identifiers ("fe80::1%eth0").
 *
 * @returns {{family: 4|6, bits: number, value: bigint, zone: string|null}}
 */
function parseAddress(input) {
  if (typeof input !== 'string') {
    fail(`expected an address string, got ${typeof input}`, input);
  }
  const trimmed = input.trim();
  if (trimmed === '') fail('empty address', input);
  if (/\s/.test(trimmed)) {
    fail(`invalid address "${input}": contains whitespace`, input);
  }

  const { body, zone } = splitZone(trimmed);
  const family = body.includes(':') ? 6 : 4;

  if (family === 6) {
    const record = makeAddressRecord(6, parseIPv6(body, trimmed), zone);
    record.text = formatAddress(record);
    return record;
  }
  if (zone !== null) {
    fail(`invalid address "${input}": IPv4 addresses cannot carry a zone identifier`, input);
  }
  if (!body.includes('.')) {
    fail(
      `invalid address "${input}": not a recognisable IP address ` +
        '(IPv4 needs 4 dot-separated octets, IPv6 needs colon-separated groups)',
      input
    );
  }
  const record = makeAddressRecord(4, parseIPv4(body, trimmed), null);
  record.text = formatAddress(record);
  return record;
}

/**
 * Build a parsed-address record. A bare address defaults to a host route
 * (/32 or /128), and the record carries both `prefix` and `text`, so it can
 * stand in for a network record anywhere one is accepted.
 */
function makeAddressRecord(family, value, zone) {
  const bits = family === 4 ? IPV4_BITS : IPV6_BITS;
  return {
    family,
    bits,
    value,
    prefix: bits,
    base: value,
    last: value,
    zone,
    hostBitsSet: false,
    text: '',
  };
}

function isIPv4Mapped(value) {
  return value >> 32n === 0xffffn;
}

function formatIPv4(value) {
  const octets = [(value >> 24n) & 0xffn, (value >> 16n) & 0xffn, (value >> 8n) & 0xffn, value & 0xffn];
  return octets.map((octet) => octet.toString(10)).join('.');
}

/**
 * Canonical IPv6 text form, following RFC 5952:
 * lowercase hex, no leading zeros, "::" replaces the longest run of two or
 * more zero groups (leftmost run on a tie), and the IPv4-mapped prefix is
 * written in mixed notation.
 */
function formatIPv6(value) {
  const groups = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) {
    groups.push(Number((value >> shift) & 0xffffn));
  }

  if (isIPv4Mapped(value)) {
    return `::ffff:${formatIPv4(value & 0xffffffffn)}`;
  }

  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  let runLength = 0;
  for (let i = 0; i < 8; i += 1) {
    if (groups[i] === 0) {
      if (runStart === -1) {
        runStart = i;
        runLength = 1;
      } else {
        runLength += 1;
      }
      if (runLength > bestLength) {
        bestLength = runLength;
        bestStart = runStart;
      }
    } else {
      runStart = -1;
      runLength = 0;
    }
  }

  const hex = groups.map((group) => group.toString(16));
  if (bestLength < 2) return hex.join(':');

  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

/** Format a parsed address (from parseAddress) as canonical text. */
function formatAddress(address) {
  if (address.family === 4) return formatIPv4(address.value);
  const text = formatIPv6(address.value);
  return address.zone === null ? text : `${text}%${address.zone}`;
}

/**
 * Detect and strip a CIDR suffix.
 *
 * @returns {{address: string, prefix: number|null}} prefix is null when the
 * input carried no "/" suffix. Throws CidrError on a malformed suffix.
 */
function splitCidr(input) {
  if (typeof input !== 'string') {
    fail(`expected a CIDR string, got ${typeof input}`, input);
  }
  const trimmed = input.trim();
  if (trimmed === '') fail('empty CIDR', input);

  const slash = trimmed.indexOf('/');
  if (slash === -1) return { address: trimmed, prefix: null };
  if (trimmed.indexOf('/', slash + 1) !== -1) {
    fail(`invalid CIDR "${input}": more than one "/" separator`, input);
  }

  let addressText = trimmed.slice(0, slash);
  let prefixText = trimmed.slice(slash + 1);

  // Some tools write the zone after the prefix ("fe80::/64%eth0") rather than
  // on the address ("fe80::%eth0/64"). Accept both and normalise the zone onto
  // the address, where RFC 4007 puts it.
  if (prefixText.includes('%')) {
    const cut = prefixText.indexOf('%');
    const moved = prefixText.slice(cut + 1);
    prefixText = prefixText.slice(0, cut);
    addressText = `${addressText}%${moved}`;
  }

  if (addressText === '') {
    fail(`invalid CIDR "${input}": missing address before "/"`, input);
  }
  if (!/^\d{1,3}$/.test(prefixText)) {
    fail(
      `invalid CIDR "${input}": prefix length "/${prefixText}" is not a decimal number`,
      input
    );
  }

  const address = parseAddress(addressText);
  const prefix = Number(prefixText);
  const max = address.family === 4 ? IPV4_BITS : IPV6_BITS;
  if (prefix > max) {
    fail(
      `invalid CIDR "${input}": prefix length /${prefix} exceeds ${max} for IPv${address.family}`,
      input
    );
  }
  return { address: addressText, prefix };
}

/**
 * Parse "address" or "address/prefix" into a network record.
 *
 * Host bits below the prefix are cleared, so "10.0.0.5/24" and "10.0.0.0/24"
 * are the same network; `hostBitsSet` records that they differed.
 *
 * @returns {{family: 4|6, bits: number, prefix: number, base: bigint,
 *            last: bigint, zone: string|null, hostBitsSet: boolean,
 *            text: string}}
 */
function parseCidr(input) {
  const { address: addressText, prefix: explicitPrefix } = splitCidr(input);
  const address = parseAddress(addressText);
  const prefix = explicitPrefix === null ? address.bits : explicitPrefix;

  const shift = BigInt(address.bits - prefix);
  const base = (address.value >> shift) << shift;
  const last = base + ((1n << shift) - 1n);

  const net = {
    family: address.family,
    bits: address.bits,
    prefix,
    base,
    last,
    zone: address.zone,
    hostBitsSet: base !== address.value,
    text: '',
  };
  net.text = formatCidr(net);
  return net;
}

/** Canonical "address/prefix" text for a network record. */
function formatCidr(net) {
  const base = { family: net.family, value: net.base, zone: net.zone };
  return `${formatAddress(base)}/${net.prefix}`;
}

module.exports = {
  IPV4_BITS,
  IPV6_BITS,
  CidrError,
  formatAddress,
  formatCidr,
  formatIPv4,
  formatIPv6,
  isIPv4Mapped,
  parseAddress,
  parseCidr,
  splitCidr,
  splitZone,
};