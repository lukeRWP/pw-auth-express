// test/stepUpAndKeys.test.js
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const { startApp, agent, loginVia } = require('./helpers/app');

let F;
before(async () => { F = await startFakeIssuer(); });
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); F.user.roles = ['user']; F.ignoreAcr = false; });

const extend = (app, auth) => {
  app.get('/admin/danger', auth.requireAcr('webauthn', { maxAge: 300 }), (req, res) => res.json({ ok: true, acr: req.auth.acr }));
  app.get('/admin/any-age', auth.requireAcr('webauthn'), (req, res) => res.json({ ok: true }));
  app.post('/print', auth.requireApiKey('print-agent'), (req, res) => res.json({ principal: req.principal, auth: req.auth }));
  app.get('/cal', auth.requireAuth, async (req, res, next) => { try { res.json(await auth.getUpstreamToken(req, 'entra')); } catch (e) { next(e); } });
};
const introspects = () => F.calls.filter((c) => c.path === '/apikeys/introspect').length;

test('requireAcr: pwd-otp session is told to step up; after a webauthn login it passes; max_age re-triggers; no-maxAge variant only checks acr', async () => {
  const clock = { t: Date.now() };
  const app = await startApp({ F, extend, options: { now: () => clock.t } });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const r = await a.req('/admin/danger?x=1');
    assert.equal(r.status, 401);
    assert.deepEqual(await r.json(), { error: 'step_up_required', loginUrl: '/api/auth/login?return_to=%2Fadmin%2Fdanger%3Fx%3D1&acr=webauthn&max_age=300' });
    const h = await a.req('/admin/danger', { headers: { accept: 'text/html' } });
    assert.equal(h.status, 302); assert.equal(h.headers.get('location'), '/api/auth/login?return_to=%2Fadmin%2Fdanger&acr=webauthn&max_age=300');
    // follow the step-up: the issuer sees acr_values=webauthn + max_age + prompt=login
    const cb = await loginVia(a, F, h.headers.get('location'));
    assert.equal(cb.headers.get('location'), '/admin/danger');
    const az = F.calls.filter((c) => c.path === '/authorize').pop().query;
    assert.equal(az.acr_values, 'webauthn'); assert.equal(az.max_age, '300'); assert.equal(az.prompt, 'login');
    const ok = await a.req('/admin/danger');
    assert.equal(ok.status, 200); assert.deepEqual(await ok.json(), { ok: true, acr: 'webauthn' });
    const { auth } = await (await a.req('/api/me')).json();
    // re-anchor on the issuer's real-clock auth_time so the +301 s is exact on a slow runner
    clock.t = auth.authTime * 1000 + 301 * 1000;
    assert.equal((await a.req('/admin/danger')).status, 401, 'auth_time older than max_age');
    assert.equal((await a.req('/admin/any-age')).status, 200, 'acr alone still satisfied');
    assert.equal((await a.req('/admin/danger', { headers: { cookie: '' } })).status, 401);
  } finally { await app.close(); }
});

test('requireAcr: an issuer that ignores acr_values gets exactly one step-up attempt, then a terminal 403 — never a redirect loop', async () => {
  const clock = { t: Date.now() };
  const app = await startApp({ F, extend, options: { now: () => clock.t } });
  const refreshes = () => F.calls.filter((c) => c.path === '/token' && c.body.grant_type === 'refresh_token').length;
  const authorizes = () => F.calls.filter((c) => c.path === '/authorize').length;
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const first = await a.req('/admin/danger', { headers: { accept: 'text/html' } });
    assert.equal(first.status, 302);
    // the issuer answers the step-up with pwd-otp anyway
    F.ignoreAcr = true;
    const cb = await loginVia(a, F, first.headers.get('location'));
    assert.equal(cb.headers.get('location'), '/admin/danger', 'the login itself succeeded');
    const denied = await a.req('/admin/danger');
    assert.equal(denied.status, 403);
    assert.deepEqual(await denied.json(), { error: 'step_up_failed', acr: 'webauthn' });
    assert.equal(denied.headers.get('cache-control'), 'no-store');
    const n = authorizes();
    const again = await a.req('/admin/danger', { headers: { accept: 'text/html' } });
    assert.equal(again.status, 403, 'a browser is not redirected back into the loop either');
    assert.deepEqual(await again.json(), { error: 'step_up_failed', acr: 'webauthn' });
    assert.equal(authorizes(), n, 'no second authorization request');
    // the marker rides through a silent refresh
    const r = refreshes();
    clock.t += 880 * 1000;
    assert.equal((await a.req('/admin/danger')).status, 403);
    assert.equal(refreshes(), r + 1, 'the session did refresh');
    // ...and is cleared by the next successful step-up login
    clock.t = Date.now();
    F.ignoreAcr = false;
    await loginVia(a, F, '/api/auth/login?acr=webauthn&max_age=300');
    const ok = await a.req('/admin/danger');
    assert.equal(ok.status, 200); assert.deepEqual(await ok.json(), { ok: true, acr: 'webauthn' });
  } finally { await app.close(); }
});

test('requireAcr under bypassAuth passes', async () => {
  const app = await startApp({ F, extend, options: { bypassAuth: true } });
  try { assert.equal((await agent(app.baseUrl).req('/admin/danger')).status, 200); } finally { await app.close(); }
});

test('requireApiKey: header/kind/active checks, 60s cache, grace on issuer outage, 503 without a usable verdict', async () => {
  const clock = { t: Date.now() };
  const logs = [];
  const app = await startApp({ F, extend, options: { now: () => clock.t, logger: { info() {}, warn() {}, error: (m) => logs.push(m) } } });
  const sa = (kind) => ({ active: true, sub: `sa:${kind}`, service_account: { id: `01H${kind}`, name: `${kind}-1`, kind }, app: 'tally', env: 'prod', key_id: '01HK', exp: Math.floor(Date.now() / 1000) + 3600 });
  F.apiKeys.set('pk-print', sa('print-agent')); F.apiKeys.set('pk-ci', sa('ci'));
  try {
    const call = (key) => fetch(`${app.baseUrl}/print`, { method: 'POST', headers: key ? { authorization: `Bearer ${key}` } : {} });
    const none = await call();
    assert.equal(none.status, 401); assert.equal(none.headers.get('www-authenticate'), 'Bearer');
    assert.equal((await call('nope')).status, 401);
    assert.equal((await call('pk-ci')).status, 401, 'wrong kind');
    const ok = await call('pk-print');
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.deepEqual(body.principal, { kind: 'service-account', id: '01Hprint-agent', name: 'print-agent-1', saKind: 'print-agent', app: 'tally', env: 'prod', keyId: '01HK', sub: 'sa:print-agent' });
    assert.deepEqual(body.auth, { sub: 'sa:print-agent', roles: [], acr: null, authTime: null, stale: false, bypass: false, apiKey: true });
    const n = introspects();
    assert.equal((await call('pk-print')).status, 200);
    assert.equal(introspects(), n, 'cached');
    clock.t += 61 * 1000;
    assert.equal((await call('pk-print')).status, 200);
    assert.equal(introspects(), n + 1, 're-introspected after 60s');
    // outage inside the grace window: cached verdict served, error logged
    clock.t += 61 * 1000; F.fail.add('introspect');
    assert.equal((await call('pk-print')).status, 200);
    assert.equal(logs.length, 1); assert.match(logs[0], /serving the cached verdict/);
    // ...and the failure is backed off: a blackholed issuer is not re-dialled on every request
    const failed = introspects();
    for (let i = 0; i < 4; i++) assert.equal((await call('pk-print')).status, 200);
    assert.equal(introspects(), failed, 'no retry inside the 60s backoff');
    clock.t += 61 * 1000;
    assert.equal((await call('pk-print')).status, 200);
    assert.equal(introspects(), failed + 1, 'exactly one retry after the backoff');
    // never-seen key during the outage: 503
    assert.equal((await call('pk-new')).status, 503);
    // beyond grace: 503
    clock.t += 6 * 60 * 1000;
    assert.equal((await call('pk-print')).status, 503);
    F.fail.clear();
    assert.equal((await call('pk-print')).status, 200);
  } finally { await app.close(); }
});

test('requireApiKey: a verdict is not reused past its own exp, even inside the 60s cache window', async () => {
  const clock = { t: Date.now() };
  const app = await startApp({ F, extend, options: { now: () => clock.t } });
  F.apiKeys.set('pk-short', { active: true, sub: 'sa:print-agent', service_account: { id: '1', name: 'p', kind: 'print-agent' }, app: 'tally', env: 'prod', key_id: 'k', exp: Math.floor(clock.t / 1000) + 5 });
  try {
    const call = () => fetch(`${app.baseUrl}/print`, { method: 'POST', headers: { authorization: 'Bearer pk-short' } });
    assert.equal((await call()).status, 200);
    const n = introspects();
    clock.t += 6 * 1000;
    assert.equal((await call()).status, 200);
    assert.equal(introspects(), n + 1, 'the verdict expired before the cache window did');
  } finally { await app.close(); }
});

test('requireApiKey: wrong client secret (invalid_client) is a 503, not a 401 for the caller', async () => {
  const app = await startApp({ F, extend, options: { clientSecret: 'wrong' } });
  F.apiKeys.set('pk-print', { active: true, sub: 'sa:x', service_account: { id: '1', name: 'p', kind: 'print-agent' }, app: 'tally', env: 'prod', key_id: 'k', exp: 0 });
  try {
    const r = await fetch(`${app.baseUrl}/print`, { method: 'POST', headers: { authorization: 'Bearer pk-print' } });
    assert.equal(r.status, 503);
  } finally { await app.close(); }
});

test('requireApiKey under bypassAuth yields a dev service-account principal', async () => {
  const app = await startApp({ F, extend, options: { bypassAuth: true } });
  try {
    const r = await fetch(`${app.baseUrl}/print`, { method: 'POST' });
    assert.equal(r.status, 200); assert.equal((await r.json()).principal.saKind, 'print-agent');
  } finally { await app.close(); }
});

test('requireApiKey: the introspection cache is bounded — past the cap the oldest entry is evicted and re-introspected', async () => {
  const app = await startApp({ F, extend });
  try {
    const CAP = 1000; // matches KEY_CACHE_MAX in lib/middleware.js (not exported — kept behavioural per Ruling 14)
    for (let i = 0; i <= CAP; i++) {
      const key = `cache-test-${i}`;
      F.apiKeys.set(key, { active: true, sub: `sa:${i}`, service_account: { id: `id${i}`, name: `n${i}`, kind: 'print-agent' }, app: 'tally', env: 'prod', key_id: `k${i}`, exp: Math.floor(Date.now() / 1000) + 3600 });
      // eslint-disable-next-line no-await-in-loop
      const r = await fetch(`${app.baseUrl}/print`, { method: 'POST', headers: { authorization: `Bearer ${key}` } });
      assert.equal(r.status, 200);
    }
    const before = introspects();
    const again = await fetch(`${app.baseUrl}/print`, { method: 'POST', headers: { authorization: 'Bearer cache-test-0' } });
    assert.equal(again.status, 200);
    assert.equal(introspects(), before + 1, 'the oldest key was evicted by the cap and had to be re-introspected');
  } finally { await app.close(); }
});

test('requireApiKey: concurrent requests for the same cold key share one introspection call', async () => {
  const app = await startApp({ F, extend });
  F.apiKeys.set('pk-concurrent', { active: true, sub: 'sa:print-agent', service_account: { id: '1', name: 'p', kind: 'print-agent' }, app: 'tally', env: 'prod', key_id: 'k', exp: Math.floor(Date.now() / 1000) + 3600 });
  try {
    const call = () => fetch(`${app.baseUrl}/print`, { method: 'POST', headers: { authorization: 'Bearer pk-concurrent' } });
    const results = await Promise.all([call(), call(), call(), call(), call()]);
    for (const r of results) assert.equal(r.status, 200);
    assert.equal(introspects(), 1, 'five concurrent requests for the same cold key shared one introspection call');
  } finally { await app.close(); }
});

test('getUpstreamToken: exchanges the session access token once per hour; errors without a user session', async () => {
  const app = await startApp({ F, extend });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const t1 = await (await a.req('/cal')).json();
    assert.equal(t1.accessToken, `entra-at-${F.user.sub}`); assert.ok(t1.expiresAt > Date.now());
    const t2 = await (await a.req('/cal')).json();
    assert.deepEqual(t2, t1);
    assert.equal(F.calls.filter((c) => c.path === '/upstream/entra/token').length, 1);
  } finally { await app.close(); }
  const dev = await startApp({ F, extend, options: { bypassAuth: true } });
  try {
    const r = await agent(dev.baseUrl).req('/cal');
    assert.equal(r.status, 500); assert.match((await r.json()).message, /no user session/);
  } finally { await dev.close(); }
});

test('getUpstreamToken: honours the injected clock (not the real clock) for upstream-token expiry', async () => {
  const clock = { t: Date.now() };
  const app = await startApp({ F, extend, options: { now: () => clock.t } });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const t0 = clock.t;
    await a.req('/cal');
    assert.equal(F.calls.filter((c) => c.path === '/upstream/entra/token').length, 1);
    clock.t = t0 + 3600 * 1000 - 120 * 1000; // t0 + 58min: still outside the 60s pre-expiry window
    await a.req('/cal');
    assert.equal(F.calls.filter((c) => c.path === '/upstream/entra/token').length, 1, 'still cached at 58 minutes');
    clock.t = t0 + 3600 * 1000 - 30 * 1000; // t0 + 59.5min: inside the 60s pre-expiry window
    await a.req('/cal');
    assert.equal(F.calls.filter((c) => c.path === '/upstream/entra/token').length, 2, 're-exchanged inside the 60s pre-expiry window');
  } finally { await app.close(); }
});
