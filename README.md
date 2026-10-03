# cidr-math

IP subnet arithmetic for IPv4 and IPv6 — split, summarise, intersect, contain
and difference — with **exact** address counts.

Zero dependencies. Node 20+. Every address calculation uses `BigInt`, because a
64-bit IPv6 address does not fit in a JavaScript `Number`: above 2^53 a double
silently loses precision, which is exactly where real IPv6 allocations live.
`2001:db8::/64` has 18446744073709551616 addresses, and this library counts them
without losing a digit.

Every example below is real captured output from the committed code.

## Install

```sh
git clone https://github.com/Xwalims/cidr-math.git
cd cidr-math
node bin/cidr.js info 10.0.0.0/24
```

To use the CLI by name, link it into your `PATH`:

```sh
npm link        # then: cidr info 10.0.0.0/24
```

## Command line

```sh
cidr <command> [args] [flags]
```

| Command | What it does |
| --- | --- |
| `cidr info <cidr>` | Network, first/last address, usable range, host bits, total count |
| `cidr split <cidr> <new-prefix>` | Subdivide a block into equal subnets |
| `cidr summarise [<cidr>...]` | The minimal set of CIDR blocks covering the same addresses |
| `cidr contains <container> <inner>` | Exit 0 if the first block contains the second, else 1 |
| `cidr diff <a> <b>` | The blocks in `a` that are not in `b` |
| `cidr sort [<cidr>...]` | Deterministic order: IPv4 first, then numeric |
| `cidr supernet <cidr> <prefix>` | The enclosing block of the given prefix |

| Flag | Meaning |
| --- | --- |
| `--json` | Machine-readable output |
| `--no-color` | Never emit ANSI colour (also honours `NO_COLOR`; colour is off when piped) |
| `--expand` | Also print every address in each block |
| `--expand-limit <n>` | Refuse to expand more than `n` addresses (default `65536`) |
| `-h`, `--help` | Usage |
| `-v`, `--version` | Version |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | A `contains` check was false |
| `2` | Usage or I/O error |
| `3` | `--expand` would exceed `--expand-limit` |

`contains` uses exit codes so it works directly in shell conditionals:

```sh
$ cidr contains 10.0.0.0/8 10.1.2.0/24
yes 10.0.0.0/8 contains 10.1.2.0/24
$ echo $?
0

$ cidr contains 10.0.0.0/8 11.0.0.0/8
no 10.0.0.0/8 does not contain 11.0.0.0/8
$ echo $?
1
```

## Examples

### info

```sh
$ cidr info 10.0.0.0/24
10.0.0.0/24
network:          10.0.0.0
first:            10.0.0.0
last:             10.0.0.255
usable range:     10.0.0.1 - 10.0.0.254
usable count:     254 addresses
total addresses:  256 (2^8)
prefix length:    /24 (8 host bits)
```

The same for an IPv6 /64 — note the exact count, no floating-point rounding:

```sh
$ cidr info 2001:db8::/64
2001:db8::/64
network:          2001:db8::
first:            2001:db8::
last:             2001:db8::ffff:ffff:ffff:ffff
usable range:     2001:db8::1 - 2001:db8::ffff:ffff:ffff:fffe
usable count:     18446744073709551614 addresses
total addresses:  18446744073709551616 (2^64)
prefix length:    /64 (64 host bits)
```

`--json` gives every field, including the count as an exact decimal string:

```sh
$ cidr info 0.0.0.0/0 --json
{
  "input": "0.0.0.0/0",
  "cidr": "0.0.0.0/0",
  "family": 4,
  "version": 4,
  "prefix": 0,
  "hostBits": 32,
  "network": "0.0.0.0",
  "first": "0.0.0.0",
  "last": "255.255.255.255",
  "broadcast": "255.255.255.255",
  "usableKind": "first-last",
  "usableFirst": "0.0.0.1",
  "usableLast": "255.255.255.254",
  "usableCount": "4294967294",
  "count": "4294967296",
  "countHex": "0x100000000",
  "hostBitsSet": false,
  "zone": null
}
```

### split

```sh
$ cidr split 10.0.0.0/24 26
10.0.0.0/24 -> 4 x /26
10.0.0.0/26
10.0.0.64/26
10.0.0.128/26
10.0.0.192/26
```

### summarise

Two adjacent /24s are one /23:

```sh
$ cidr summarise 10.0.0.0/25 10.0.0.128/25
2 entries -> 1 blocks
10.0.0.0/24
```

A lone /24 stays a /24 — collapsing it would cover addresses you did not ask
for:

```sh
$ cidr summarise 10.0.1.0/24
1 entries -> 1 blocks
10.0.1.0/24
```

`summarise` also reads a list on standard input:

```sh
$ printf '10.0.0.0/24\n10.0.1.0/24\n' | cidr summarise
2 entries -> 1 blocks
10.0.0.0/23
```

### diff

```sh
$ cidr diff 10.0.0.0/22 10.0.0.128/25
10.0.0.0/22 minus 10.0.0.128/25
10.0.0.0/25
10.0.1.0/24
10.0.2.0/23
```

### supernet

```sh
$ cidr supernet 10.1.2.3/24 16
10.1.0.0/16
  enclosing /16 of 10.1.2.0/24
```

### --expand

Listing every address is refused once the block is larger than the limit, so
`0.0.0.0/0` and `::/0` can never be materialised by accident:

```sh
$ cidr info 10.0.0.0/30 --expand
10.0.0.0/30
network:          10.0.0.0
first:            10.0.0.0
last:             10.0.0.3
usable range:     10.0.0.1 - 10.0.0.2
usable count:     2 addresses
total addresses:  4 (2^2)
prefix length:    /30 (2 host bits)
  10.0.0.0 167772160
  10.0.0.1 167772161
  10.0.0.2 167772162
  10.0.0.3 167772163

$ cidr info 10.0.0.0/8 --expand
cidr: refusing to expand 10.0.0.0/8: it holds 16777216 addresses, above the --expand-limit of 65536
$ echo $?
3
```

## Library

```js
const {
  parseCidr,
  subnets,
  summariseTexts,
  intersect,
  contains,
  differenceTexts,
  supernetOf,
  sortCidrs,
  count,
} = require('cidr-math');
```

Every function accepts either a CIDR string or an already-parsed record, so you
can parse once and reuse.

### Parsing

```js
const { parseCidr, parseAddress, formatAddress, splitCidr } = require('cidr-math/src/address.js');

parseCidr('10.0.0.5/24');
// {
//   family: 4, bits: 32, prefix: 24,
//   base: 167772160n, last: 167772415n,
//   zone: null, hostBitsSet: true,
//   text: '10.0.0.0/24'
// }
```

Host bits below the prefix are cleared, and `hostBitsSet` records that the
input had them, so `10.0.0.5/24` and `10.0.0.0/24` are recognisably the same
block without you having to compare twice.

### Input that is accepted

* IPv6 shorthand — `::1`, `::`, `fe80::/64`, `2001:db8::/32`
* Mixed notation — `::ffff:1.2.3.4`
* Leading zeros — `2001:0db8::1`, `010.0.0.1`
* Zone identifiers — `fe80::1%eth0` and the `fe80::/64%eth0` spelling some
  tools emit; both normalise to the zone sitting on the address
* A bare address with no prefix, which defaults to a host route

Equivalent spellings normalise to one canonical output (RFC 5952 for IPv6: the
longest run of zero groups becomes `::`, ties broken leftmost):

```js
formatAddress(parseAddress('2001:0db8:0000::1'));  // '2001:db8::1'
formatAddress(parseAddress('2001:DB8:0:0:0:0:0:1')); // '2001:db8::1'
formatAddress(parseAddress('010.0.0.1'));           // '10.0.0.1'
```

Malformed input is rejected with a message that says what was wrong:

```js
parseAddress('10.0.0.256');
// CidrError: invalid IPv4 address "10.0.0.256": octet 4 ("256") is out of range 0-255

parseAddress('2001:db8:::1');
// CidrError: invalid IPv6 address "2001:db8:::1": ":::" is not allowed

parseCidr('2001:db8::/129');
// CidrError: invalid CIDR "2001:db8::/129": prefix length /129 exceeds 128 for IPv6
```

### Core operations

```js
subnets('10.0.0.0/24', 26);
// four records: 10.0.0.0/26, 10.0.0.64/26, 10.0.0.128/26, 10.0.0.192/26

summariseTexts(['10.0.0.0/24', '10.0.1.0/24']);  // ['10.0.0.0/23']
summariseTexts(['10.0.1.0/24']);                  // ['10.0.1.0/24']

intersect('10.0.0.0/22', '10.0.2.0/24').text;    // '10.0.2.0/24'
intersect('10.0.0.0/24', '10.0.1.0/24');         // null
intersect('10.0.0.0/8', '2001:db8::/32');        // null, not an error

contains('10.0.0.0/8', '10.1.2.0/24');           // true
contains('::/0', '10.0.0.1');                     // false: different family

differenceTexts('10.0.0.0/22', '10.0.0.128/25');
// ['10.0.0.0/25', '10.0.1.0/24', '10.0.2.0/23']

supernetOf('10.1.2.3/24', 16).text;               // '10.1.0.0/16'
sortCidrs(['2001:db8::1', '10.0.0.10', '10.0.0.9', '::1']);
// ['10.0.0.9/32', '10.0.0.10/32', '::1/128', '2001:db8::1/128']
```

### Exact counts

```js
count(parseCidr('10.0.0.0/24')).toString();   // '256'
count(parseCidr('0.0.0.0/0')).toString();     // '4294967296'
count(parseCidr('::/0')).toString();
// '340282366920938463463374607431768211456'
count(parseCidr('2001:db8::/64')).toString(); // '18446744073709551616'
```

## Design notes

**Everything is BigInt.** Addresses are held as `bigint` values throughout, and
masks are built with `BigInt` shifts. There is no `Number` in any arithmetic
path, so there is no precision cliff to fall off.

**Contiguity is numeric, never textual.** Two blocks merge only when their
address ranges actually touch. `10.0.0.0/23` covers `10.0.0.0`–`10.0.1.255`
and those merge into it; two `/31`s that are far apart do not. Sorting is
numeric too, so `10.0.0.9` precedes `10.0.0.10` rather than following it.

**Mixed families are disjoint, never an error.** `intersect('10.0.0.0/8',
'2001:db8::/32')` is `null` and `contains('::/0', '10.0.0.1')` is `false`. This
matters because `::a00:1` is numerically the same `bigint` as `10.0.0.1`; the
family is always checked separately, so the two can never be mistaken for one
another.

**Minimal means minimal.** `summarise` returns the fewest blocks that cover
exactly the addresses given — no more, no fewer. Adding a block that lies
*inside* an existing one changes nothing; adding a neighbouring one merges.

## Testing

```sh
node --test
```

The suite covers IPv4 `/31` and `/32`, `/0` and the full default routes in both
families, IPv6 `/128`, the split of a `/24` into four `/26`s, differences that
yield 1, 2, 3 and 4 blocks, normalisation of one IPv6 address written three
ways, and property tests over random blocks — including that summarising every
address of a `/24` returns that `/24`, and that splitting a block in half and
diffing reassembles it.

The arithmetic is additionally cross-checked against Python's `ipaddress`, an
independent implementation written by different people for a different purpose:

```console
$ python3 scripts/crosscheck.py
crosscheck: 900/900 cases agree with python ipaddress (seed=20261003; ...)
```

Every expectation elsewhere in this suite comes from the code under test, so a
symmetric bug would satisfy them all. Agreement with a second implementation is
what makes this evidence rather than self-consistency. The check compares
numbers, not text, because Python writes the IPv4-mapped form as
`::ffff:102:304` where RFC 5952 canonical text is `::ffff:1.2.3.4`.

**What the cross-check does not cover.** It generates only valid inputs and
compares only arithmetic results, so it says nothing about input rejection
(leading zeros in an octet, a double slash, a prefix out of range), nothing
about RFC 5952 formatting, and nothing about the invariants Python cannot
express at all — a mixed-family `intersect` must be `null`, which is a
`TypeError` on the Python side. `node --test` owns all of that. The harness is a
development tool: it needs Python, so it is not in the published package and not
part of `npm test`.

## Licence

MIT — Copyright (c) 2026 Xwalims