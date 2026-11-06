'use strict';

const net = require('node:net');
const crypto = require('node:crypto');

function parseIPv4(value) {
  if (typeof value !== 'string' || net.isIP(value) !== 4) {
    throw new Error(`Invalid IPv4 address: ${String(value)}`);
  }
  return value.split('.').reduce((n, octet) => (n * 256) + Number(octet), 0) >>> 0;
}

function intToIPv4(value) {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255
  ].join('.');
}

function parseCIDR(value) {
  if (typeof value !== 'string') throw new Error('CIDR must be a string');
  const parts = value.trim().split('/');
  if (parts.length > 2) throw new Error('Invalid CIDR notation');
  const ip = parseIPv4(parts[0]);
  const prefix = parts.length === 1 ? 32 : Number(parts[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error('CIDR prefix must be between 0 and 32');
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return { network, broadcast, prefix };
}

function isAllowedIPv4(ip, allowlist) {
  const candidate = parseIPv4(ip);
  return allowlist.some((entry) => {
    const range = typeof entry === 'string' ? parseCIDR(entry) : entry;
    return candidate >= range.network && candidate <= range.broadcast;
  });
}

function parseAuthorizedCIDRs(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('AUTHORIZED_CIDRS must contain at least one explicitly authorized IPv4 address or CIDR');
  }
  return raw.split(',').map((part) => parseCIDR(part.trim()));
}

function parsePorts(value, maxPorts = 32) {
  if (!Array.isArray(value) || value.length < 1 || value.length > maxPorts) {
    throw new Error(`Provide between 1 and ${maxPorts} ports`);
  }
  const ports = value.map((port) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('Ports must be integers between 1 and 65535');
    }
    return port;
  });
  if (new Set(ports).size !== ports.length) throw new Error('Duplicate ports are not allowed');
  return ports;
}

function expandTargetInput(input, allowlist, maxTargets = 128) {
  if (typeof input !== 'string' || input.length > 128) throw new Error('Target must be a string of at most 128 characters');
  const value = input.trim();
  if (!value || value.includes('://') || value.includes('@') || value.includes('[')) {
    throw new Error('Use an IPv4 address or IPv4 CIDR; URLs and hostnames are not accepted');
  }

  const range = parseCIDR(value);
  const size = range.broadcast - range.network + 1;
  if (size > maxTargets) throw new Error(`Target range exceeds MAX_TARGETS (${maxTargets})`);

  const targets = [];
  if (range.prefix <= 30) {
    for (let n = range.network + 1; n < range.broadcast; n++) targets.push(intToIPv4(n));
  } else {
    for (let n = range.network; n <= range.broadcast; n++) targets.push(intToIPv4(n));
  }
  if (!targets.length) targets.push(intToIPv4(range.network));

  for (const ip of targets) {
    if (!isAllowedIPv4(ip, allowlist)) throw new Error(`Target ${ip} is outside AUTHORIZED_CIDRS`);
  }
  return targets;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = {
  parseIPv4, intToIPv4, parseCIDR, isAllowedIPv4, parseAuthorizedCIDRs,
  parsePorts, expandTargetInput, safeEqual, hashToken
};
