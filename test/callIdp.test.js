'use strict';
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const { startApp, agent, loginVia } = require('./helpers/app');

let F;
before(async () => { F = await startFakeIssuer(); });
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); F.rp = { status: 201 }; });

const extend = (app, auth) => {
  app.post('/mint', auth.requireAuth, async (req, res, next) => {
    try { res.json(await auth.callIdp(req, 'POST', '/rp/device-keys', { kind: 'location-ingest', label: 'Phone' })); } catch (e) { next(e); }
  });
  app.delete('/revoke', auth.requireAuth, async (req, res, next) => {
    try { res.json(await auth.callIdp(req, 'DELETE', '/rp/device-keys/01J0000000000000000000000A')); } catch (e) { next(e); }
  });
  app.get('/list', auth.requireAuth, async (req, res, next) => {
    try { res.json(await auth.callIdp(req, 'GET', '/rp/device-keys?kind=location-ingest')); } catch (e) { next(e); }
  });
  app.get('/elsewhere', auth.requireAuth, async (req, res, next) => {
    try { res.json(await auth.callIdp(req, 'GET', '/manage/users')); } catch (e) { next(e); }
  });
};
const rpCalls = () => F.calls.filter((c) => c.path.startsWith('/rp/'));

test('callIdp: POST sends bearer + client-credential headers, JSON body, never creds in the URL or body', async () => {
  const app = await startApp({ F, extend });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const r = await (await a.req('/mint', { method: 'POST' })).json();
    assert.equal(r.status, 201);
    assert.match(r.body.apiKey, /^pwk_/);
    const [c] = rpCalls();
    assert.match(c.headers.authorization, /^Bearer /);
    assert.equal(c.headers['x-pw-client-id'], F.clientId);
    assert.equal(c.headers['x-pw-client-secret'], F.clientSecret);
    assert.deepEqual(c.body, { kind: 'location-ingest', label: 'Phone' });
    assert.ok(!c.url.includes('secret') && !JSON.stringify(c.body).includes(F.clientSecret));
  } finally { await app.close(); }
});

test('callIdp: GET keeps creds out of the query; DELETE returns 204 as { status, body: null }', async () => {
  const app = await startApp({ F, extend });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    F.rp = { status: 200, body: { keys: [] } };
    assert.deepEqual(await (await a.req('/list')).json(), { status: 200, body: { keys: [] } });
    assert.equal(rpCalls()[0].url, '/rp/device-keys?kind=location-ingest');
    assert.deepEqual(await (await a.req('/revoke', { method: 'DELETE' })).json(), { status: 204, body: null });
  } finally { await app.close(); }
});

test('callIdp: pwiam error statuses come back as values, not throws', async () => {
  const app = await startApp({ F, extend });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    F.rp = { status: 409, body: { error: 'limit_reached', message: 'limit 5' } };
    const r = await (await a.req('/mint', { method: 'POST' })).json();
    assert.deepEqual(r, { status: 409, body: { error: 'limit_reached', message: 'limit 5' } });
  } finally { await app.close(); }
});

test('callIdp: refuses non-/rp/ paths and requires a user session', async () => {
  const app = await startApp({ F, extend });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const r = await a.req('/elsewhere');
    assert.equal(r.status, 500);
    assert.match((await r.json()).message, /only \/rp\/ paths/);
    assert.equal(rpCalls().length, 0);
  } finally { await app.close(); }
  const dev = await startApp({ F, extend, options: { bypassAuth: true } });
  try {
    const r = await agent(dev.baseUrl).req('/mint', { method: 'POST' });
    assert.equal(r.status, 500);
    assert.match((await r.json()).message, /no user session/);
  } finally { await dev.close(); }
});

test('callIdp: refreshes a near-expiry session before calling', async () => {
  const clock = { t: Date.now() };
  const app = await startApp({ F, extend, options: { now: () => clock.t } });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const before = F.calls.filter((c) => c.path === '/token').length;
    clock.t += (F.accessTtl - 10) * 1000; // inside REFRESH_SKEW_MS
    const r = await (await a.req('/mint', { method: 'POST' })).json();
    assert.equal(r.status, 201);
    assert.ok(F.calls.filter((c) => c.path === '/token').length > before, 'refresh grant was used');
  } finally { await app.close(); }
});
