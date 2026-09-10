const { test } = require('node:test');
const assert = require('node:assert/strict');
const { deriveKeys, seal, open, randomToken } = require('../lib/crypto');

const SECRET = 's3cret'.padEnd(32, '.');
const OTHER = 'other'.padEnd(32, '.');

test('deriveKeys: deterministic, 32-byte, cookie ≠ seal', () => {
  const a = deriveKeys(SECRET); const b = deriveKeys(SECRET);
  assert.equal(a.cookieKey.length, 32); assert.equal(a.sealKey.length, 32);
  assert.ok(a.cookieKey.equals(b.cookieKey)); assert.ok(!a.cookieKey.equals(a.sealKey));
  assert.ok(!deriveKeys(OTHER).sealKey.equals(a.sealKey));
  assert.throws(() => deriveKeys(''), /secret/);
});

test('deriveKeys: a secret shorter than 32 characters is refused', () => {
  assert.throws(() => deriveKeys('x'.repeat(31)), /at least 32 characters/);
  assert.equal(deriveKeys('x'.repeat(32)).sealKey.length, 32);
});

test('seal/open round-trips objects and refuses tampering', () => {
  const { sealKey } = deriveKeys(SECRET);
  const s = seal(sealKey, { refreshToken: 'rt', roles: ['admin'], n: 1 });
  assert.match(s, /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/);
  assert.ok(!s.includes('rt'));
  assert.deepEqual(open(sealKey, s), { refreshToken: 'rt', roles: ['admin'], n: 1 });
  const parts = s.split('.'); parts[2] = parts[2].slice(0, -2) + 'AA';
  assert.throws(() => open(sealKey, parts.join('.')), /unsealable/);
  assert.throws(() => open(deriveKeys(OTHER).sealKey, s), /unsealable/);
  assert.throws(() => open(sealKey, 'garbage'), /unsealable/);
});

test('open() rejects sealed blobs with extra or missing segments', () => {
  const { sealKey } = deriveKeys(SECRET);
  const s = seal(sealKey, { x: 1 });
  assert.throws(() => open(sealKey, s + '.x'), /unsealable/);
  const parts = s.split('.'); parts.pop();
  assert.throws(() => open(sealKey, parts.join('.')), /unsealable/);
});

test('randomToken: 64 hex, unique', () => {
  const t = randomToken();
  assert.match(t, /^[0-9a-f]{64}$/);
  assert.notEqual(t, randomToken());
});
