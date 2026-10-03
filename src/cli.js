'use strict';

/**
 * cidr — IP subnet arithmetic on the command line.
 *
 * Exit codes: 0 success, 1 a "contains" check came back false, 2 a usage or
 * I/O error, 3 an --expand request exceeded the safety limit.
 */

const fs = require('node:fs');

const {
  CidrError,
  formatAddress,
  formatCidr,
  parseAddress,
  parseCidr,
} = require('./address.js');
const {
  contains: containsNet,
  containsAddress,
  count: netCount,
  difference,
  expand,
  hostBits: netHostBits,
  intersect,
  subnetTexts,
  subnets,
  supernetOf,
  summariseTexts,
} = require('./ipset.js');
const { sortCidrs } = require('./sort.js');

/** Single source of truth for every tunable default. */
const DEFAULTS = Object.freeze({
  expandLimit: 65536n,
});

const EXIT = Object.freeze({
  OK: 0,
  FALSE: 1,
  USAGE: 2,
  LIMIT: 3,
});

const COMMANDS = ['info', 'split', 'summarise', 'contains', 'diff', 'sort', 'supernet'];

const USAGE = `cidr — IP subnet arithmetic for IPv4 and IPv6

Usage:
  cidr info <cidr>                 Show network, first/last, usable range and count
  cidr split <cidr> <new-prefix>   Split a block into equal subnets
  cidr summarise [<cidr>...]       Minimal CIDR set covering the same addresses
  cidr contains <container> <inner>  Exit 0 if the first block contains the second
  cidr diff <a> <b>                Blocks in <a> that are not in <b>
  cidr sort [<cidr>...]            Deterministic order: IPv4 then IPv6, numeric
  cidr supernet <cidr> <prefix>    The enclosing block of the given prefix

Flags:
  --json                 Machine-readable output
  --no-color, --no-colour   Never emit ANSI colour
  --color, --colour         Force ANSI colour even when output is piped
  --expand               Also print every address in each block
  --expand-limit <n>     Refuse to expand more than <n> addresses (default ${DEFAULTS.expandLimit})
  --new-prefix <n>       New prefix length for "split" (alternative to the
                         positional argument)
  --prefix <n>           Prefix length for "supernet" (alternative to the
                         positional argument)
  -h, --help             Show this help
  -v, --version          Show the version

Exit codes:
  0  success
  1  a "contains" check was false
  2  usage or I/O error
  3  --expand would exceed the limit

Examples:
  cidr info 10.0.0.0/24
  cidr split 10.0.0.0/24 26
  cidr summarise 10.0.0.0/25 10.0.0.128/25
  cidr contains 10.0.0.0/8 10.1.2.3 && echo covered
`;

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

class LimitError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LimitError';
  }
}

// ---------------------------------------------------------------- formatting

/**
 * Colour is for terminals only. Piped or redirected output must stay plain,
 * so this is driven by the TTY check as well as by --no-color / NO_COLOR.
 */
function useColor(requested) {
  if (!requested) return false;
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(process.stdout.isTTY);
}

function palette(enabled) {
  if (!enabled) {
    return { key: (s) => s, value: (s) => s, accent: (s) => s, dim: (s) => s };
  }
  return {
    key: (s) => `[36m${s}[0m`,
    value: (s) => `[32m${s}[0m`,
    accent: (s) => `[33m${s}[0m`,
    dim: (s) => `[2m${s}[0m`,
  };
}

/** A count as an exact decimal string, with a hex and power-of-two hint. */
function describeCount(value) {
  const decimal = value.toString(10);
  let power = null;
  if (value > 0n && (value & (value - 1n)) === 0n) {
    power = (() => {
      let exponent = 0n;
      for (let probe = value; probe > 1n; probe >>= 1n) exponent += 1n;
      return exponent.toString(10);
    })();
  }
  return { decimal, hex: `0x${value.toString(16)}`, power };
}

function countLabel(value) {
  const described = describeCount(value);
  return described.power === null
    ? described.decimal
    : `${described.decimal} (2^${described.power})`;
}

/** Host-address semantics: /31 and /32 keep their addresses (RFC 3021). */
function usableRange(net) {
  const hosts = netHostBits(net);
  if (hosts === 0) {
    return {
      kind: 'single',
      first: formatAddress({ family: net.family, value: net.base, zone: net.zone }),
      last: formatAddress({ family: net.family, value: net.last, zone: net.zone }),
      count: net.last - net.base + 1n,
    };
  }
  if (hosts === 1) {
    return {
      kind: 'point-to-point',
      first: formatAddress({ family: net.family, value: net.base, zone: net.zone }),
      last: formatAddress({ family: net.family, value: net.last, zone: net.zone }),
      count: net.last - net.base + 1n,
    };
  }
  return {
    kind: 'first-last',
    first: formatAddress({ family: net.family, value: net.base + 1n, zone: net.zone }),
    last: formatAddress({ family: net.family, value: net.last - 1n, zone: net.zone }),
    count: net.last - net.base - 1n,
  };
}

function netToJson(net, input) {
  const first = formatAddress({ family: net.family, value: net.base, zone: net.zone });
  const last = formatAddress({ family: net.family, value: net.last, zone: net.zone });
  const usable = usableRange(net);
  return {
    input: input === undefined ? net.text : input,
    cidr: net.text,
    family: net.family,
    version: net.family,
    prefix: net.prefix,
    hostBits: netHostBits(net),
    network: first,
    first,
    last,
    broadcast: last,
    usableKind: usable.kind,
    usableFirst: usable.first,
    usableLast: usable.last,
    usableCount: usable.count.toString(10),
    count: netCount(net).toString(10),
    countHex: `0x${netCount(net).toString(16)}`,
    hostBitsSet: net.hostBitsSet,
    zone: net.zone,
  };
}

// -------------------------------------------------------------------- output

function writeOut(text) {
  process.stdout.write(`${text}\n`);
}

function renderInfo(net, input, options) {
  if (options.json) {
    return { lines: [JSON.stringify(netToJson(net, input), null, 2)] };
  }
  const colour = palette(options.color);
  const data = netToJson(net, input);
  // A /32 has exactly one usable address, so "addresses" would be wrong.
  const usableCount = BigInt(data.usableCount);
  const rows = [
    ['network', data.network],
    ['first', data.first],
    ['last', data.last],
    ['usable range', `${data.usableFirst} - ${data.usableLast}`],
    ['usable count', `${data.usableCount} ${usableCount === 1n ? 'address' : 'addresses'}`],
    ['total addresses', countLabel(netCount(net))],
    ['prefix length', `/${data.prefix} (${data.hostBits} host bits)`],
  ];
  const lines = [colour.accent(data.cidr)];
  const width = Math.max(...rows.map(([key]) => key.length));
  for (const [key, value] of rows) {
    const label = `${colour.dim(`${key}:`.padEnd(width + 2))}`;
    lines.push(`${label} ${colour.value(value)}`);
  }
  if (data.hostBitsSet) {
    lines.push(
      colour.dim(
        `note: ${input} had host bits set; the block is ${data.cidr}`
      )
    );
  }
  if (options.expand) {
    lines.push(...renderBlocks([net], options).lines.slice(1));
  }
  return { lines };
}

/** Body lines for a list of networks, optionally expanding each one. */
function renderBlocks(nets, options, headings = null) {
  const colour = palette(options.color);
  const lines = [];
  if (headings) lines.push(...headings);
  if (nets.length === 0) {
    lines.push(colour.dim('(no blocks)'));
    return { lines };
  }
  for (const net of nets) {
    lines.push(colour.value(formatCidr(net)));
    if (!options.expand) continue;
    for (const value of expand(net)) {
      const literal = value.toString(10);
      lines.push(`${colour.dim('  ')}${formatAddress({ family: net.family, value, zone: net.zone })} ${colour.dim(literal)}`);
    }
  }
  return { lines };
}

function expandGuard(net, options) {
  const size = netCount(net);
  if (size > options.expandLimit) {
    throw new LimitError(
      `refusing to expand ${formatCidr(net)}: it holds ${size} addresses, ` +
        `above the --expand-limit of ${options.expandLimit}`
    );
  }
  return size;
}

// ------------------------------------------------------------------ commands

function readStdin() {
  try {
    return fs.readFileSync(0, 'utf8');
  } catch (error) {
    throw new UsageError(`cannot read from standard input: ${error.message}`);
  }
}

/** Collect CIDRs from argv, falling back to newline/whitespace-separated stdin. */
function collectEntries(positional, options) {
  if (positional.length > 0) return positional;
  const text = readStdin();
  const entries = text.split(/[\s,]+/).filter((token) => token !== '');
  if (entries.length === 0) {
    throw new UsageError(
      'no CIDRs given: pass them as arguments or pipe a list on standard input'
    );
  }
  return entries;
}

function parsePrefixArgument(raw, label) {
  if (typeof raw !== 'string' || raw === '') {
    throw new UsageError(`${label} is required (for example "26" or "/26")`);
  }
  const digits = raw.startsWith('/') ? raw.slice(1) : raw;
  if (!/^\d{1,3}$/.test(digits)) {
    throw new UsageError(`${label} "${raw}" is not a valid prefix length`);
  }
  return Number(digits);
}

function commandInfo(positional, options) {
  if (positional.length !== 1) {
    throw new UsageError('info takes exactly one CIDR');
  }
  const input = positional[0];
  const net = parseCidr(input);
  if (options.expand) expandGuard(net, options);
  return { lines: renderInfo(net, input, options).lines };
}

function commandSplit(positional, options, flags) {
  if (positional.length < 1 || positional.length > 2) {
    throw new UsageError('split takes a CIDR and a new prefix length');
  }
  const input = positional[0];
  const rawPrefix = positional[1] === undefined ? flags.newPrefix : positional[1];
  if (rawPrefix === undefined) {
    throw new UsageError(
      'split needs a new prefix length (for example: cidr split 10.0.0.0/24 26)'
    );
  }
  const net = parseCidr(input);
  const newPrefix = parsePrefixArgument(String(rawPrefix), 'new prefix length');
  const nets = subnets(net, newPrefix);
  if (options.expand) for (const child of nets) expandGuard(child, options);
  if (options.json) {
    return {
      lines: [
        JSON.stringify(
          {
            input,
            source: net.text,
            newPrefix,
            count: nets.length,
            subnets: nets.map((child) => formatCidr(child)),
          },
          null,
          2
        ),
      ],
    };
  }
  const colour = palette(options.color);
  return {
    lines: renderBlocks(nets, options, [
      `${colour.accent(net.text)} -> ${nets.length} x /${newPrefix}`,
    ]).lines,
  };
}

function commandSummarise(positional, options) {
  const entries = collectEntries(positional, options);
  const texts = summariseTexts(entries);
  const nets = texts.map((text) => parseCidr(text));
  if (options.expand) for (const net of nets) expandGuard(net, options);
  if (options.json) {
    return {
      lines: [
        JSON.stringify({ input: entries, count: nets.length, minimal: texts }, null, 2),
      ],
    };
  }
  const colour = palette(options.color);
  return {
    lines: renderBlocks(nets, options, [
      colour.dim(`${entries.length} entries -> ${nets.length} blocks`),
    ]).lines,
  };
}

function commandContains(positional, options) {
  if (positional.length !== 2) {
    throw new UsageError('contains takes exactly two CIDRs');
  }
  const [containerText, innerText] = positional;

  // A bare address on the right-hand side is checked as a single point.
  let innerIsAddress = false;
  try {
    parseCidr(innerText);
  } catch {
    parseAddress(innerText);
    innerIsAddress = true;
  }

  const container = parseCidr(containerText);
  const result = innerIsAddress
    ? containsAddress(container, innerText)
    : containsNet(container, parseCidr(innerText));

  if (options.json) {
    return {
      lines: [JSON.stringify({ container: container.text, inner: innerText, contains: result }, null, 2)],
      code: result ? EXIT.OK : EXIT.FALSE,
    };
  }
  const colour = palette(options.color);
  return {
    lines: [
      result
        ? `${colour.value('yes')} ${colour.dim(`${container.text} contains ${innerText}`)}`
        : `${colour.accent('no')} ${colour.dim(`${container.text} does not contain ${innerText}`)}`,
    ],
    code: result ? EXIT.OK : EXIT.FALSE,
  };
}

function commandDiff(positional, options) {
  if (positional.length !== 2) {
    throw new UsageError('diff takes exactly two CIDRs');
  }
  const [aText, bText] = positional;
  const a = parseCidr(aText);
  const nets = difference(a, parseCidr(bText));
  if (options.expand) for (const net of nets) expandGuard(net, options);
  if (options.json) {
    return {
      lines: [
        JSON.stringify(
          { a: a.text, b: parseCidr(bText).text, count: nets.length, difference: nets.map((n) => n.text) },
          null,
          2
        ),
      ],
    };
  }
  const colour = palette(options.color);
  return {
    lines: renderBlocks(nets, options, [
      colour.dim(`${a.text} minus ${parseCidr(bText).text}`),
    ]).lines,
  };
}

function commandSort(positional, options) {
  const entries = collectEntries(positional, options);
  const texts = sortCidrs(entries);
  if (options.json) {
    return { lines: [JSON.stringify({ input: entries, sorted: texts }, null, 2)] };
  }
  return { lines: renderBlocks(texts.map((text) => parseCidr(text)), options).lines };
}

function commandSupernet(positional, options, flags) {
  if (positional.length < 1 || positional.length > 2) {
    throw new UsageError('supernet takes a CIDR and a prefix length');
  }
  const input = positional[0];
  const rawPrefix = positional[1] === undefined ? flags.prefix : positional[1];
  if (rawPrefix === undefined) {
    throw new UsageError(
      'supernet needs a prefix length (for example: cidr supernet 10.1.2.3/24 16)'
    );
  }
  const net = parseCidr(input);
  const prefix = parsePrefixArgument(String(rawPrefix), 'supernet prefix length');
  const enclosing = supernetOf(net, prefix);
  if (options.expand) expandGuard(enclosing, options);
  if (options.json) {
    return { lines: [JSON.stringify({ input, prefix, supernet: enclosing.text }, null, 2)] };
  }
  const colour = palette(options.color);
  return {
    lines: [
      colour.value(enclosing.text),
      colour.dim(`  enclosing /${prefix} of ${net.text}`),
    ],
  };
}

// -------------------------------------------------------------- arg handling

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  let expandLimit = DEFAULTS.expandLimit;
  let json = false;
  let colorRequested = true;
  let expand = false;
  let terminated = false;

  const setLimit = (raw, token) => {
    if (!/^\d{1,20}$/.test(raw)) {
      throw new UsageError(`${token} expects a non-negative integer, got "${raw}"`);
    }
    expandLimit = BigInt(raw);
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (terminated || !arg.startsWith('-') || arg === '-') {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf('=');
    const name = eq === -1 ? arg : arg.slice(0, eq);
    const inlineValue = eq === -1 ? null : arg.slice(eq + 1);
    const nextValue = () => {
      if (inlineValue !== null) return inlineValue;
      i += 1;
      if (i >= argv.length) throw new UsageError(`${name} expects a value`);
      return argv[i];
    };

    switch (name) {
      case '--json':
        json = true;
        break;
      case '--no-color':
      case '--no-colour':
        colorRequested = false;
        break;
      case '--color':
      case '--colour':
        colorRequested = true;
        break;
      case '--expand':
        expand = true;
        break;
      case '--expand-limit':
        setLimit(nextValue(), name);
        break;
      case '--new-prefix':
        flags.newPrefix = nextValue();
        break;
      case '--prefix':
        flags.prefix = nextValue();
        break;
      case '-h':
      case '--help':
        flags.help = true;
        break;
      case '-v':
      case '--version':
        flags.version = true;
        break;
      case '--':
        terminated = true;
        break;
      default:
        throw new UsageError(`unknown option "${name}"`);
    }
  }

  return {
    flags,
    positional,
    options: {
      json,
      // Resolved here rather than in each command, so that piped output is
      // never coloured by accident.
      color: useColor(colorRequested),
      expand,
      expandLimit,
    },
  };
}

/** @returns {number} process exit code. */
function main(argv) {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`cidr: ${error.message}\n\nRun "cidr --help" for usage.\n`);
    return EXIT.USAGE;
  }

  const { flags, positional, options } = parsed;

  if (flags.version) {
    const version = require('../package.json').version;
    writeOut(version);
    return EXIT.OK;
  }
  if (flags.help || positional.length === 0) {
    writeOut(USAGE.trimEnd());
    return flags.help || positional.length === 0 ? EXIT.OK : EXIT.USAGE;
  }

  const command = positional[0];
  const rest = positional.slice(1);

  if (!COMMANDS.includes(command)) {
    process.stderr.write(
      `cidr: unknown command "${command}"\n` +
        `cidr: expected one of ${COMMANDS.join(', ')}\n\nRun "cidr --help" for usage.\n`
    );
    return EXIT.USAGE;
  }

  const handlers = {
    info: commandInfo,
    split: commandSplit,
    summarise: commandSummarise,
    contains: commandContains,
    diff: commandDiff,
    sort: commandSort,
    supernet: commandSupernet,
  };

  let result;
  try {
    result = handlers[command](rest, options, flags);
  } catch (error) {
    if (error instanceof LimitError) {
      process.stderr.write(`cidr: ${error.message}\n`);
      return EXIT.LIMIT;
    }
    if (error instanceof UsageError || error instanceof CidrError) {
      process.stderr.write(`cidr: ${error.message}\n`);
      return EXIT.USAGE;
    }
    process.stderr.write(`cidr: ${error && error.message ? error.message : error}\n`);
    return EXIT.USAGE;
  }

  writeOut(result.lines.join('\n'));
  return result.code === undefined ? EXIT.OK : result.code;
}

module.exports = {
  DEFAULTS,
  EXIT,
  LimitError,
  UsageError,
  USAGE,
  collectEntries,
  describeCount,
  main,
  netToJson,
  parseArgs,
  renderBlocks,
  renderInfo,
  usableRange,
};