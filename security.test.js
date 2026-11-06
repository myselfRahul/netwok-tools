'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseIPv4, parseCIDR, isAllowedIPv4, parseAuthorizedCIDRs,
  parsePorts, expandTargetInput, safeEqual
} = require('../src/security');

test('validates IPv4 and rejects malformed addresses', () => {
  assert.equal(parseIPv4('192.168.1.1'), 3232235777);
  assert.throws(() => parseIPv4('192.168.1.999'));
  assert.throws(() => parseIPv4('example.com'));
});

test('parses CIDR ranges and authorizes only configured targets', () => {
  const ranges = parseAuthorizedCIDRs('192.168.10.0/24,10.0.0.5');
  assert.equal(isAllowedIPv4('192.168.10.42', ranges), true);
  assert.equal(isAllowedIPv4('192.168.11.42', ranges), false);
  assert.equal(isAllowedIPv4('10.0.0.5', ranges), true);
});

test('expands bounded CIDR and rejects out-of-scope targets', () => {
  const ranges = parseAuthorizedCIDRs('192.168.20.0/29');
  assert.deepEqual(expandTargetInput('192.168.20.0/29', ranges, 16),
    ['192.168.20.1','192.168.20.2','192.168.20.3','192.168.20.4','192.168.20.5','192.168.20.6']);
  assert.throws(() => expandTargetInput('192.168.21.1', ranges, 16), /outside AUTHORIZED_CIDRS/);
  assert.throws(() => expandTargetInput('192.168.0.0/16', ranges, 16), /exceeds MAX_TARGETS/);
  assert.throws(() => expandTargetInput('https://example.com', ranges, 16));
});

test('validates ports strictly', () => {
  assert.deepEqual(parsePorts([22, 443]), [22, 443]);
  assert.throws(() => parsePorts([22, 22]), /Duplicate/);
  assert.throws(() => parsePorts([0]), /integers/);
  assert.throws(() => parsePorts(['80']), /integers/);
});

test('constant-time equality helper handles equal and unequal values', () => {
  assert.equal(safeEqual('abc', 'abc'), true);
  assert.equal(safeEqual('abc', 'abd'), false);
  assert.equal(safeEqual('abc', 'abcd'), false);
});
