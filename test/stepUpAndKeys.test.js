// test/stepUpAndKeys.test.js
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const { startApp, agent, loginVia } = require('./helpers/app');

let F;
before(async () => { F = await startFakeIssuer(); });
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); F.user.roles = ['user']; });

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
    clock.t += 301 * 1000;
    assert.equal((await a.req('/admin/danger')).status, 401, 'auth_time older than max_age');
    assert.equal((await a.req('/admin/any-age')).status, 200, 'acr alone still satisfied');
    assert.equal((await a.req('/admin/danger', { headers: { cookie: '' } })).status, 401);
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
    // never-seen key during the outage: 503
    assert.equal((await call('pk-new')).status, 503);
    // beyond grace: 503
    clock.t += 6 * 60 * 1000;
    assert.equal((await call('pk-print')).status, 503);
    F.fail.clear();
    assert.equal((await call('pk-print')).status, 200);
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
