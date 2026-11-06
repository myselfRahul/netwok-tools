const test = require('node:test');
const assert = require('node:assert/strict');
const { assessPort, sanitizeBanner } = require('../src/scanner');

test('classifies exposed administrative and database services', () => {
  const result = assessPort(3389, '');
  assert.equal(result.service, 'RDP');
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].remediation, /Restrict access/);
});

test('does not claim a CVE from a banner string', () => {
  const result = assessPort(80, 'Apache/2.4.49');
  assert.equal(result.findings.length, 0);
});

test('sanitizes control characters and truncates banners', () => {
  assert.equal(sanitizeBanner('hello\r\nworld'), 'hello world');
  assert.ok(sanitizeBanner('x'.repeat(500)).length <= 200);
});
