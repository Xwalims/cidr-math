#!/usr/bin/env python3
"""Cross-check cidr-math's set arithmetic against Python's ``ipaddress``.

Why this exists
---------------
Every other expectation in this repository's suite comes from the code under
test, which means such a suite certifies self-consistency: if ``coverRange`` is
wrong in a symmetric way, its own property tests still pass. Python's
``ipaddress`` module is an independent implementation written by different people
for a different purpose, so agreeing with it is real evidence.

What it does NOT cover (do not mistake this for a total oracle)
--------------------------------------------------------------
This harness generates only VALID inputs and compares only arithmetic RESULTS.
It therefore says nothing about:

- input rejection -- `parseIPv4` leading zeros, a double slash in a CIDR, a
  prefix out of range, `:::` in IPv6. All of those are parser policy, and
  Python's acceptance differs from this package's on several of them, so there
  is no ground truth to compare against. `node --test` owns that territory.
- text formatting -- RFC 5952 canonical output. Python's `str(IPv6Address)`
  differs by design (`::ffff:102:304` vs `::ffff:1.2.3.4`), and comparison here
  is deliberately numeric, so a formatter regression is invisible to it. The
  suite asserts formatting directly.
- invariants Python cannot express: mixed-family `intersect` must be null (a
  TypeError there), `supernetOf` with an equal prefix is a no-op, and so on.

Those gaps are why this is an addition to the suite, not a replacement for it.
It is a *development* tool, not part of the shipped package and not part of the
CI suite: it needs Python, and the published package must stay dependency- and
build-free. Run it explicitly:

    python3 scripts/crosscheck.py            # ~900 cases, fixed seed
    python3 scripts/crosscheck.py 5000       # more cases
    python3 scripts/crosscheck.py --seed 12345

Ground truth per operation
--------------------------
summarise   ``ipaddress.summarize_address_range`` over the numerically merged
            input ranges -- Python's own minimal cover, not a reimplementation.
subnets     ``subnets()`` on the input network.
difference  the address-set difference, summarised back to minimal blocks.
intersect   "the overlap summarised returns exactly one block, and that block" --
            an intersection of two CIDRs is always a CIDR, so a disagreeing
            harness would be wrong, not the code.
supernet    ``supernet()``.
count       ``len(network)``.
parse       host bits cleared to the aligned network, plus the
            ``hostBitsSet`` flag.

Comparison is numeric (version, base, last as integers), never textual: Python
writes the IPv4-mapped form as ``::ffff:102:304`` while RFC 5952 canonical text
in this package is ``::ffff:1.2.3.4``. A formatting difference is not an
arithmetic difference, and conflating them would make the harness report noise
instead of bugs. Text consistency is checked separately, inside the worker, by
re-parsing every block it reports.

Bounds
------
Generated cases are constrained so no operation can emit an unbounded list, and
every bound is asserted rather than assumed: a case whose ground truth exceeds
MAX_BLOCKS, or whose input set exceeds MAX_ADDRESSES, is discarded instead of
silently truncated.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WORKER = os.path.join(HERE, "crosscheck-worker.js")

# Per-case output bounds. Exceeding them is a harness bug, so they are asserted.
MAX_BLOCKS = 512
MAX_ADDRESSES = 1 << 14


def addr_cls(version):
    return ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address


def net_cls(version):
    return ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network


def width(version):
    return 32 if version == 4 else 128


def triples(net):
    """(version, base, last) as plain ints -- comparable across languages."""
    return [net.version, int(net.network_address), int(net.broadcast_address)]


def ranges_of(nets):
    out = sorted(
        (int(net.network_address), int(net.broadcast_address)) for net in nets
    )
    return out


def merge_ranges(ranges):
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def minimal_cover(ranges, version):
    """Python's own minimal block cover of a list of inclusive ranges."""
    first_cls = addr_cls(version)
    blocks = []
    for start, end in merge_ranges(ranges):
        cover = ipaddress.summarize_address_range(first_cls(start), first_cls(end))
        blocks.extend(cover)
    if len(blocks) > MAX_BLOCKS:
        raise ValueError("ground truth exceeds MAX_BLOCKS")
    return blocks


def block_count(ranges, version):
    """Size of the minimal cover, without materialising it."""
    total = 0
    for start, end in merge_ranges(ranges):
        # Reuse Python's own cover; cheap for the small ranges generated here.
        total += len(minimal_cover([(start, end)], version))
    return total


class CaseBuilder:
    """Deterministic generator of bounded cases."""

    def __init__(self, rng):
        self.rng = rng
        self.cases = []
        self.expected = []
        self.skipped = 0

    # -- generators -----------------------------------------------------
    def _rand_net(self, version, max_prefix=None):
        limit = width(version) if max_prefix is None else max_prefix
        # Bias toward realistic prefixes while keeping short ones reachable.
        if self.rng.random() < 0.7:
            prefix = self.rng.randint(max(0, limit - 20), limit)
        else:
            prefix = self.rng.randint(0, limit)
        value = self.rng.getrandbits(width(version))
        # strict=False: this package accepts host bits below the prefix and
        # clears them, so the generator may write an unaligned address.
        return net_cls(version)((value, prefix), strict=False)

    def _small_net(self, version):
        """A network small enough to expand into an address set."""
        bits = width(version)
        return net_cls(version)(
            (self.rng.getrandbits(bits), self.rng.randint(max(0, bits - 12), bits)),
            strict=False,
        )

    def _neighbour(self, anchor, version):
        """A block one step away from ``anchor`` in the same family.

        Random blocks almost never touch, so a summarise case built only from
        them has nothing to collapse and tests nothing. This is the case where a
        greedy minimal cover can actually be wrong.
        """
        size = 1 << (width(version) - anchor.prefixlen)
        base = int(anchor.network_address) + self.rng.choice((-1, 1)) * size
        top = 1 << width(version)
        # Both the neighbour and the step past it must stay inside the family's
        # address space; Python raises AddressValueError rather than wrapping,
        # and a different --seed hits that (2**32 for IPv4).
        if base < 0 or base + size > top or base % size != 0:
            return None
        return net_cls(version)((base, anchor.prefixlen), strict=False)

    def _add(self, case, expected):
        self.cases.append(case)
        self.expected.append(expected)

    # -- operations -----------------------------------------------------
    def op_parse(self, n):
        for _ in range(n):
            version = self.rng.choice((4, 4, 4, 6, 6))
            net = self._rand_net(version)
            self._add(
                {"op": "parse", "cidr": str(net)},
                {"net": triples(net), "text": str(net), "hostBitsSet": False},
            )
            if net.prefixlen < width(version):
                # Host bits set: this package clears them, so the result is the
                # aligned network rather than the written address.
                aligned = ipaddress.ip_network(str(net), strict=False)
                # Write a real address with host bits set, not a bare integer:
                # this package parses dotted / colon-grouped text only.
                messy = f"{addr_cls(version)(int(aligned.network_address) + 1)}/{net.prefixlen}"
                self._add(
                    {"op": "parse", "cidr": messy},
                    {
                        "net": triples(aligned),
                        "text": str(aligned),
                        "hostBitsSet": True,
                    },
                )

    def op_summarise(self, n):
        for _ in range(n):
            version = self.rng.choice((4, 4, 6))
            nets = []
            for _ in range(self.rng.randint(1, 5)):
                if nets and self.rng.random() < 0.5:
                    neighbour = self._neighbour(self.rng.choice(nets), version)
                    if neighbour is not None:
                        nets.append(neighbour)
                        continue
                nets.append(self._rand_net(version))
            ranges = ranges_of(nets)
            spans = sum(end - start + 1 for start, end in ranges)
            if spans > MAX_ADDRESSES:
                self.skipped += 1
                continue
            expected = minimal_cover(ranges, version)
            self._add(
                {"op": "summarise", "cidrs": [str(net) for net in nets]},
                {"blocks": [triples(net) for net in expected]},
            )

    def op_subnets(self, n):
        for _ in range(n):
            version = self.rng.choice((4, 4, 6))
            net = self._rand_net(version)
            new_prefix = net.prefixlen + self.rng.randint(0, min(9, width(version) - net.prefixlen))
            expected = list(net.subnets(new_prefix=new_prefix))
            if len(expected) > MAX_BLOCKS:
                self.skipped += 1
                continue
            self._add(
                {"op": "subnets", "cidr": str(net), "newPrefix": new_prefix},
                {"blocks": [triples(sub) for sub in expected]},
            )

    def op_difference(self, n):
        for _ in range(n):
            version = self.rng.choice((4, 4, 6))
            outer = self._small_net(version)
            span = int(outer.broadcast_address) - int(outer.network_address) + 1
            if span > MAX_ADDRESSES:
                self.skipped += 1
                continue
            holes = set()
            for _ in range(self.rng.randint(1, 2)):
                if self.rng.random() < 0.6:
                    # A hole strictly INSIDE the outer block. Two independent
                    # random networks are almost never nested, so without this
                    # the generator never exercises the case where subtracting
                    # the hole has to keep the tail -- which is exactly where
                    # difference() can silently drop addresses.
                    bits = width(version)
                    if outer.prefixlen >= bits:
                        continue
                    base = int(outer.network_address)
                    size = 1 << (bits - outer.prefixlen)
                    offset = self.rng.randrange(1, size)
                    # Keep the hole small enough that both sides survive.
                    tail_bits = self.rng.randint(0, min(9, bits - outer.prefixlen - 1))
                    hole_prefix = min(bits - tail_bits, outer.prefixlen + tail_bits + 1)
                    hole_size = 1 << (bits - hole_prefix)
                    hole_base = base + (offset // hole_size) * hole_size
                    if hole_base == base or hole_base + hole_size > base + size:
                        continue
                    holes.update(
                        int(addr)
                        for addr in net_cls(version)(
                            (hole_base, hole_prefix), strict=False
                        )
                    )
                else:
                    holes.update(int(addr) for addr in self._small_net(version))
            if not holes:
                continue
            # The expected answer is the minimal cover of the kept address set.
            # Covering (first, last) as one range would be wrong: the holes split
            # the set into several runs, and each run is covered on its own.
            runs = []
            for addr in outer:
                value = int(addr)
                if value in holes:
                    continue
                if runs and runs[-1][1] == value - 1:
                    runs[-1][1] = value
                else:
                    runs.append([value, value])
            expected = minimal_cover([tuple(run) for run in runs], version)
            self._add(
                {
                    "op": "difference",
                    "a": str(outer),
                    "b": [str(addr_cls(version)(h)) for h in sorted(holes)],
                },
                {"blocks": [triples(block) for block in expected]},
            )

    def op_intersect(self, n):
        # Mixed-family pairs, chosen so a missing family guard would produce a
        # real block instead of falling through to the start > end path.
        # 10.0.0.0/8 against ::/0 has base 0 <= 10.0.0.0 and a last of 2^128,
        # so without `if (family !== family) return null` intersect() would hand
        # back an IPv6 block covering an IPv4 range. Python cannot even hold that
        # comparison (mixed families are a TypeError there), so the expectation
        # is written down rather than computed.
        mixed = [
            ("10.0.0.0/8", "::/0"),
            ("0.0.0.0/0", "2001:db8::/32"),
            ("10.0.0.0/8", "::1/128"),
            ("192.168.0.0/16", "fe80::/10"),
            ("::/0", "0.0.0.0/0"),
            ("2001:db8:1::/48", "10.1.0.0/16"),
            ("172.16.0.0/12", "ffff:ffff:ffff:ffff::/17"),
        ]
        for left, right in mixed:
            self._add({"op": "intersect", "a": left, "b": right}, {"net": None})
            self._add({"op": "intersect", "a": right, "b": left}, {"net": None})

        for _ in range(n):
            version = self.rng.choice((4, 4, 6))
            left = self._rand_net(version)
            right = self._rand_net(version)
            start = max(int(left.network_address), int(right.network_address))
            end = min(int(left.broadcast_address), int(right.broadcast_address))
            if start > end:
                expected = {"net": None}
            else:
                blocks = minimal_cover([(start, end)], version)
                if len(blocks) != 1:
                    # An intersection of two CIDRs is always a single CIDR, so
                    # reaching here means the harness is wrong, not the code.
                    raise AssertionError(
                        f"intersection of {left} and {right} is not one block: {blocks}"
                    )
                expected = {"net": triples(blocks[0])}
            self._add({"op": "intersect", "a": str(left), "b": str(right)}, expected)

    def op_supernet(self, n):
        for _ in range(n):
            version = self.rng.choice((4, 4, 6))
            net = self._rand_net(version)
            # Python refuses a LONGER prefix ("must be shorter"); an equal
            # prefix is a no-op on both sides. This package also rejects a
            # longer prefix, so the generator only asks for equal or shorter.
            prefix = max(0, net.prefixlen - self.rng.randint(0, 8))
            expected = net.supernet(new_prefix=prefix)
            self._add(
                {"op": "supernet", "cidr": str(net), "prefix": prefix},
                {"net": triples(expected)},
            )

    def op_count(self, n):
        for _ in range(n):
            version = self.rng.choice((4, 4, 6))
            net = self._rand_net(version)
            self._add({"op": "count", "cidr": str(net)}, {"count": str(1 << (width(version) - net.prefixlen))})


def build_cases(total, seed):
    builder = CaseBuilder(random.Random(seed))
    weights = {
        "parse": 0.10,
        "summarise": 0.24,
        "subnets": 0.18,
        "difference": 0.18,
        "intersect": 0.18,
        "supernet": 0.08,
        "count": 0.04,
    }
    for name, weight in weights.items():
        getattr(builder, f"op_{name}")(max(1, round(total * weight)))
    while len(builder.cases) < total:
        builder.op_parse(1)
    return builder.cases[:total], builder.expected[:total], builder.skipped


def normalise(value):
    """Turn the worker's decimal-string addresses back into ints.

    JSON has no BigInt, so the worker emits base/last as strings. Comparing
    those against Python's ints would report every case as a mismatch, which is
    exactly the "harness fails on 100% of cases" symptom of a bug in the
    harness rather than in the code under test.
    """
    if not isinstance(value, dict):
        return value
    out = dict(value)
    for key in ("blocks",):
        if isinstance(out.get(key), list):
            out[key] = [[int(x) for x in triple] for triple in out[key]]
    if isinstance(out.get("net"), list):
        out["net"] = [int(x) for x in out["net"]]
    return out


def compare(case, want, got):
    """Return None when the worker agrees with Python, else a diff string.

    Key order matters and is not cosmetic: a `parse` expectation carries net,
    text AND hostBitsSet, so the net check must come last. Testing "net" first
    returns early on the numbers and leaves text and hostBitsSet unchecked --
    a whole branch of the expectation becomes dead code, and a formatter or
    host-bit regression slips through a harness that looks exhaustive.
    """
    if not got.get("ok"):
        return f"worker error: {got.get('error')}"
    # Addresses cross the process boundary as decimal strings (JSON has no
    # BigInt), so both sides are normalised to ints before comparing.
    value = normalise(got["value"])
    if "text" in want:
        if (
            value.get("net") == want["net"]
            and value.get("text") == want["text"]
            and value.get("hostBitsSet") == want["hostBitsSet"]
        ):
            return None
        return f"expected {want}\n  actual   {value}"
    if "blocks" in want:
        if value.get("blocks") == want["blocks"]:
            return None
        return f"expected {want['blocks']}\n  actual   {value.get('blocks')}"
    if "count" in want:
        if value.get("count") == want["count"]:
            return None
        return f"expected {want['count']}\n  actual   {value.get('count')}"
    if "net" in want:
        if value.get("net") == want["net"]:
            return None
        return f"expected {want['net']}\n  actual   {value.get('net')}"
    raise AssertionError(f"no expectation shape for {case}")


def main():
    parser = argparse.ArgumentParser(description="Cross-check cidr-math against python ipaddress.")
    parser.add_argument("total", nargs="?", type=int, default=900)
    parser.add_argument("--seed", type=int, default=20261003)
    args = parser.parse_args()

    if not os.path.exists(WORKER):
        print(f"crosscheck: worker not found at {WORKER}", file=sys.stderr)
        return 2

    cases, expected, skipped = build_cases(args.total, args.seed)
    proc = subprocess.run(
        [os.environ.get("NODE", "node"), WORKER],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print("crosscheck: worker failed", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        if not proc.stderr.strip():
            print(
                "  (no stderr: the worker most likely ran out of memory, which "
                "means a case blew up in the code under test -- rerun with a "
                "smaller `total` and a --seed that isolates it)",
                file=sys.stderr,
            )
        return 2
    results = json.loads(proc.stdout)

    failures = []
    for case, want, got in zip(cases, expected, results):
        diff = compare(case, want, got)
        if diff is not None:
            failures.append(f"{json.dumps(case)}\n  {diff}")

    by_op = {}
    for case in cases:
        by_op[case["op"]] = by_op.get(case["op"], 0) + 1
    breakdown = ", ".join(f"{op}={count}" for op, count in sorted(by_op.items()))

    if failures:
        print(
            f"crosscheck: {len(failures)}/{len(cases)} cases disagree with "
            f"python ipaddress (seed={args.seed}; {breakdown})",
            file=sys.stderr,
        )
        for line in failures[:10]:
            print(f"  {line}", file=sys.stderr)
        if len(failures) > 10:
            print(f"  ... and {len(failures) - 10} more", file=sys.stderr)
        return 1

    print(
        f"crosscheck: {len(cases)}/{len(cases)} cases agree with python ipaddress "
        f"(seed={args.seed}; {breakdown}"
        + (f"; {skipped} oversized cases skipped" if skipped else "")
        + ")"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())