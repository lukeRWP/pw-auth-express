const { test } = require('node:test');
const assert = require('node:assert/strict');
const pwAuth = require('../index');

const base = { issuer: 'https://id.example.com', clientId: 'a-prod', clientSecret: 's', baseUrl: 'https://a.example.com', secret: 'x', session: pwAuth.memorySession(), resolveUser: async () => ({ id: 1 }) };

test('pwAuth: required options, defaults, surface', () => {
  for (const k of Object.keys(base)) {
    const o = { ...base }; delete o[k];
    assert.throws(() => pwAuth(o), new RegExp(`"${k}" is required`));
  }
  assert.throws(() => pwAuth({ ...base, resolveUser: 'nope' }), /resolveUser must be a function/);
  const a = pwAuth(base);
  for (const k of ['routes', 'requireAuth', 'loginUrl', 'close']) assert.equal(typeof a[k], 'function');
  assert.equal(a.loginUrl(), '/api/auth/login');
  assert.equal(typeof pwAuth.memorySession, 'function');
});
