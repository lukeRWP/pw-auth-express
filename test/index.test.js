const { test } = require('node:test');
const assert = require('node:assert/strict');
const pwAuth = require('../index');

const base = { issuer: 'https://id.example.com', clientId: 'a-prod', clientSecret: 's', baseUrl: 'https://a.example.com', secret: 'x'.padEnd(32, '.'), session: pwAuth.memorySession(), resolveUser: async () => ({ id: 1 }) };

test('pwAuth: required options, defaults, surface', () => {
  for (const k of Object.keys(base)) {
    const o = { ...base }; delete o[k];
    assert.throws(() => pwAuth(o), new RegExp(`"${k}" is required`));
  }
  assert.throws(() => pwAuth({ ...base, resolveUser: 'nope' }), /resolveUser must be a function/);
  const a = pwAuth(base);
  for (const k of ['routes', 'requireAuth', 'loginUrl', 'close', 'sweepExpiredSessions']) assert.equal(typeof a[k], 'function');
  assert.equal(a.loginUrl(), '/api/auth/login');
  assert.equal(typeof pwAuth.memorySession, 'function');
});

test('sweepExpiredSessions deletes the rows the injected clock has passed, and only those', async () => {
  const clock = { t: Date.now() };
  const session = pwAuth.memorySession();
  const a = pwAuth({ ...base, session, now: () => clock.t });
  const row = (token, ms) => session.create({ token, userId: 1, sub: 'u', sid: null, expiresAt: new Date(clock.t + ms), state: 'v1.enc' });
  await row('a'.repeat(64), 1000);
  await row('b'.repeat(64), 3600000);
  assert.equal(await a.sweepExpiredSessions(), 0, 'nothing expired yet');
  clock.t += 2000;
  assert.equal(await a.sweepExpiredSessions(), 1);
  assert.equal(await session.get('a'.repeat(64)), null);
  assert.ok(await session.get('b'.repeat(64)), 'the live row survives');
});
