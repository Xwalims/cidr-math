'use strict';

/**
 * Deterministic ordering for a mixed IPv4/IPv6 set.
 *
 * Ordering is by family first (all IPv4, then all IPv6) and by numeric address
 * within a family. Numeric rather than lexicographic ordering matters: as
 * strings "10.0.0.10" sorts before "10.0.0.9".
 */

const { formatCidr, parseAddress, parseCidr } = require('./address.js');
const { asNet } = require('./ipset.js');

/**
 * Comparator over parsed network records: IPv4 before IPv6, then by base
 * address, then by prefix (longer prefix first) as a tie-break.
 */
function compareNets(a, b) {
  if (a.family !== b.family) return a.family - b.family;
  if (a.base !== b.base) return a.base < b.base ? -1 : 1;
  return b.prefix - a.prefix;
}

/** Comparator over bare addresses (from parseAddress). */
function compareAddresses(a, b) {
  if (a.family !== b.family) return a.family - b.family;
  if (a.value !== b.value) return a.value < b.value ? -1 : 1;
  return 0;
}

/**
 * Sort a mixed set of CIDR strings, bare addresses or parsed records.
 * Returns new parsed network records in order.
 */
function sortNets(entries) {
  const list = Array.isArray(entries) ? entries : [entries];
  return list.map((entry) => asNet(entry, 'entry')).sort(compareNets);
}

/** Same as sortNets(), returning canonical CIDR strings. */
function sortCidrs(entries) {
  return sortNets(entries).map((net) => net.text);
}

/** Sort bare addresses; returns the input values in order. */
function sortAddresses(entries) {
  const list = Array.isArray(entries) ? entries : [entries];
  return list
    .map((entry) => (typeof entry === 'string' ? parseAddress(entry) : entry))
    .sort(compareAddresses);
}

module.exports = {
  compareAddresses,
  compareNets,
  formatCidr,
  sortAddresses,
  sortCidrs,
  sortNets,
};