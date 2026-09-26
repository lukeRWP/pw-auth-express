'use strict';
// test/apiKeyVerifier.test.js — the standalone verifier for non-shim services that cannot construct
// the full login config (e.g. the PW orchestrator, which reaches the issuer through a proxy).
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const pwAuth = require('../index');
const { OidcError } = require('../lib/oidc');

let F;
before(async () => { F = await startFakeIssuer(); });
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); });

// same deterministic pwk_<keyId>_<secret> generator as stepUpAndKeys.test.js
function apiKey(label) {
  const id = crypto.createHash('sha256').update(`${label}:id`).digest().subarray(0, 8).toString('hex');
  const secret = crypto.createHash('sha256').update(`${label}:secret`).digest().toString('base64url');
  return `pwk_${id}_${secret}`;
}
const introspects = () => F.calls.filter((c) => c.path === '/apikeys/introspect').length;
const sa = (kind) => ({ active: true, sub: `sa:${kind}`, service_account: { id: `01H${kind}`, name: `${kind}-1`, kind }, app: 'pw', env: 'prod', key_id: '01HK', exp: Math.floor(Date.now() / 1000) + 3600 });

test('pwAuth.apiKeyVerifier is a static factory, independent of a full pwAuth() config', () => {
  assert.equal(typeof pwAuth.apiKeyVerifier, 'function');
});

test('apiKeyVerifier.verify: introspects a shape-valid key and returns pwiam\'s body verbatim; rejects malformed keys locally', async () => {
  const v = pwAuth.apiKeyVerifier({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true });
  const key = apiKey('orchestrator-1');
  F.apiKeys.set(key, sa('orchestrator-client'));
  const r = await v.verify(key);
  assert.equal(r.active, true);
  assert.deepEqual(r.service_account, { id: '01Horchestrator-client', name: 'orchestrator-client-1', kind: 'orchestrator-client' });
  assert.deepEqual(await v.verify('not-pwk-shaped'), { active: false });
  assert.equal(introspects(), 1, 'the malformed key never reached the issuer');
});

test('apiKeyVerifier.verify: an unregistered but shape-valid key introspects to {active:false}', async () => {
  const v = pwAuth.apiKeyVerifier({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true });
  assert.deepEqual(await v.verify(apiKey('never-seen')), { active: false });
  assert.equal(introspects(), 1);
});

test('apiKeyVerifier.verify: caches for cacheTtlMs, then re-introspects', async () => {
  const clock = { t: Date.now() };
  const v = pwAuth.apiKeyVerifier({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true, now: () => clock.t, cacheTtlMs: 1000, graceMs: 5000 });
  const key = apiKey('orchestrator-cache');
  F.apiKeys.set(key, sa('orchestrator-client'));
  await v.verify(key);
  assert.equal(introspects(), 1);
  await v.verify(key);
  assert.equal(introspects(), 1, 'still within cacheTtlMs');
  clock.t += 1001;
  await v.verify(key);
  assert.equal(introspects(), 2, 'cacheTtlMs elapsed');
});

test('apiKeyVerifier.verify: a failing issuer serves the cached verdict inside graceMs, then rejects once the grace is gone', async () => {
  const clock = { t: Date.now() };
  const v = pwAuth.apiKeyVerifier({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true, now: () => clock.t, cacheTtlMs: 1000, graceMs: 5000 });
  const key = apiKey('orchestrator-outage');
  F.apiKeys.set(key, sa('orchestrator-client'));
  await v.verify(key);
  clock.t += 1500; // past cacheTtlMs, inside graceMs
  F.fail.add('introspect');
  const r = await v.verify(key);
  assert.equal(r.active, true, 'served from the grace-window cache during an outage');
  clock.t += 6000; // past graceMs too
  await assert.rejects(v.verify(key), (e) => e instanceof OidcError && e.kind === 'issuer_error');
});

test('apiKeyVerifier.verify: a 429 gets the same grace treatment as a 5xx', async () => {
  const clock = { t: Date.now() };
  const v = pwAuth.apiKeyVerifier({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true, now: () => clock.t, cacheTtlMs: 1000, graceMs: 5000 });
  const key = apiKey('orchestrator-429');
  F.apiKeys.set(key, sa('orchestrator-client'));
  await v.verify(key);
  clock.t += 1500;
  F.fail.add('introspect_429');
  const r = await v.verify(key);
  assert.equal(r.active, true, '429 served from the grace-window cache, not an immediate rejection');
});

test('apiKeyVerifier: an injectable fetch reaches the issuer, for services that go through a proxy', async () => {
  const seen = [];
  const spy = (url, init) => { seen.push(new URL(url).pathname); return fetch(url, init); };
  const v = pwAuth.apiKeyVerifier({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true, fetch: spy });
  await v.verify(apiKey('via-proxy'));
  // introspectApiKey calls the issuer directly (no discovery round-trip first — see lib/oidc.js)
  assert.deepEqual(seen, ['/apikeys/introspect']);
});

test('apiKeyVerifier: requires issuer, clientId and clientSecret like createOidc does', () => {
  assert.throws(() => pwAuth.apiKeyVerifier({ clientId: 'x', clientSecret: 'y' }), /issuer.*required/);
});
