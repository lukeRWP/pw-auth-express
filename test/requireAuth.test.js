const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const client = require('openid-client');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const { createOidc } = require('../lib/oidc');
const { deriveKeys, seal } = require('../lib/crypto');
const { memorySession } = require('../lib/session/memory');
const { createSessionStore } = require('../lib/sessions');
const { createMiddleware, DEV_CLAIMS } = require('../lib/middleware');
const { signValue } = require('../lib/cookies');

const DAY = 86400000;
let F, oidc;
before(async () => { F = await startFakeIssuer(); oidc = createOidc({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true }); });
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); F.user.roles = ['user']; F.refreshIdToken = true; });

function makeCtx({ resolveUser, bypassAuth = false } = {}) {
  const keys = deriveKeys('s3cret');
  const adapter = memorySession();
  const store = createSessionStore({ adapter, sealKey: keys.sealKey });
  const clock = { t: Date.now() };
  const calls = [];
  const o = {
    cookie: { name: 'session_token', secure: false }, routePrefix: '/api/auth', bypassAuth, sessionMaxAge: DAY, now: () => clock.t,
    resolveUser: resolveUser || (async (c) => { calls.push(c); return { id: 42, name: c.name, roles: c.roles }; }),
  };
  const logs = [];
  const log = { info() {}, warn: (m) => logs.push(['warn', m]), error: (m) => logs.push(['error', m]) };
  const mw = createMiddleware({ o, keys, oidc, store, log });
  return { mw, store, adapter, keys, clock, logs, resolveCalls: calls };
}

async function realTokens() {
  const codeVerifier = client.randomPKCECodeVerifier(), state = client.randomState(), nonce = client.randomNonce();
  const cb = await F.authorize(await oidc.authorizationUrl({ redirectUri: 'http://app.test/cb', state, nonce, codeVerifier }));
  return oidc.exchangeCode({ currentUrl: new URL(cb), codeVerifier, state, nonce });
}

async function seed(t, { accessExpiresAt, expiresAt, refreshToken } = {}) {
  const tokens = await realTokens();
  const c = tokens.claims;
  const now = t.clock.t;
  const token = await t.store.create({ userId: 42, sub: c.sub, sid: c.sid, expiresAt: expiresAt || new Date(now + DAY), state: {
    refreshToken: refreshToken || tokens.refreshToken, accessToken: tokens.accessToken, accessExpiresAt: accessExpiresAt ?? now + 900000,
    idToken: tokens.idToken, acr: c.acr, authTime: c.auth_time, roles: c.roles, user: { id: 42, name: c.name, roles: c.roles },
  } });
  return { token, cookie: `session_token=${signValue(t.keys.cookieKey, token)}`, tokens };
}

function run(mw, { cookie, accept = 'application/json', url = '/api/things?x=1' } = {}) {
  return new Promise((resolve) => {
    const h = {};
    const req = { headers: { cookie, accept }, originalUrl: url };
    const res = {
      statusCode: 200, getHeader: (n) => h[n.toLowerCase()], setHeader: (n, v) => { h[n.toLowerCase()] = v; },
      status(c) { this.statusCode = c; return this; },
      json(b) { resolve({ req, status: this.statusCode, body: b, headers: h }); },
      redirect(c, u) { resolve({ req, status: c, location: u, headers: h }); },
    };
    mw(req, res, (err) => resolve({ req, next: true, err, headers: h }));
  });
}
const tokenCalls = () => F.calls.filter((c) => c.path === '/token');

test('no cookie → JSON 401 with loginUrl; html → 302 to login with return_to', async () => {
  const t = makeCtx();
  const r = await run(t.mw.requireAuth, {});
  assert.equal(r.status, 401); assert.deepEqual(r.body, { error: 'unauthorized', loginUrl: '/api/auth/login?return_to=%2Fapi%2Fthings%3Fx%3D1' });
  const h = await run(t.mw.requireAuth, { accept: 'text/html,*/*', url: '/items/7' });
  assert.equal(h.status, 302); assert.equal(h.location, '/api/auth/login?return_to=%2Fitems%2F7');
});

test('bad signature / unknown token → 401 and the cookie is cleared', async () => {
  const t = makeCtx();
  const r = await run(t.mw.requireAuth, { cookie: 'session_token=deadbeef.notasig' });
  assert.equal(r.status, 401); assert.match(r.headers['set-cookie'][0], /^session_token=; Max-Age=0/);
  const s = await seed(t);
  const r2 = await run(t.mw.requireAuth, { cookie: `session_token=${signValue(deriveKeys('other').cookieKey, s.token)}` });
  assert.equal(r2.status, 401);
});

test('valid session with a live access token → next(), req.user/req.auth set, issuer not called', async () => {
  const t = makeCtx();
  const s = await seed(t);
  F.calls.length = 0;
  const r = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r.next, true); assert.equal(r.err, undefined);
  assert.deepEqual(r.req.user, { id: 42, name: 'Ada Lovelace', roles: ['user'] });
  assert.equal(r.req.auth.sub, F.user.sub); assert.equal(r.req.auth.sid, s.tokens.claims.sid); assert.deepEqual(r.req.auth.roles, ['user']);
  assert.equal(r.req.auth.acr, 'pwd-otp'); assert.equal(r.req.auth.stale, false); assert.equal(r.req.auth.bypass, false);
  assert.equal(r.req.pwSession.token, s.token);
  assert.equal(tokenCalls().length, 0);
});

test('access token within 30s of expiry → silent refresh: rotated tokens stored, roles re-read, resolveUser called again', async () => {
  const t = makeCtx();
  const s = await seed(t, { accessExpiresAt: t.clock.t + 10000 });
  F.user.roles = ['user', 'admin'];
  F.calls.length = 0; t.resolveCalls.length = 0;
  const r = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r.next, true);
  assert.equal(tokenCalls().length, 1); assert.equal(tokenCalls()[0].body.grant_type, 'refresh_token');
  assert.deepEqual(r.req.auth.roles, ['user', 'admin']); assert.deepEqual(r.req.user.roles, ['user', 'admin']);
  assert.equal(t.resolveCalls.length, 1); assert.deepEqual(t.resolveCalls[0].roles, ['user', 'admin']); assert.equal(t.resolveCalls[0].sub, F.user.sub);
  const after = await t.store.get(s.token);
  assert.notEqual(after.state.refreshToken, s.tokens.refreshToken); assert.notEqual(after.state.accessToken, s.tokens.accessToken);
  assert.ok(after.state.accessExpiresAt > t.clock.t + 800000);
  assert.equal(r.req.auth.stale, false);
});

test('refresh without id_token falls back to userinfo for roles', async () => {
  const t = makeCtx();
  const s = await seed(t, { accessExpiresAt: t.clock.t });
  F.refreshIdToken = false; F.user.roles = ['ops'];
  const r = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r.next, true); assert.deepEqual(r.req.auth.roles, ['ops']);
  assert.equal(F.calls.filter((c) => c.path === '/userinfo').length, 1);
});

test('concurrent requests on one expired session refresh exactly once (rotating refresh tokens)', async () => {
  const t = makeCtx();
  const s = await seed(t, { accessExpiresAt: t.clock.t });
  F.calls.length = 0;
  const rs = await Promise.all([1, 2, 3, 4, 5].map(() => run(t.mw.requireAuth, { cookie: s.cookie })));
  assert.deepEqual(rs.map((r) => r.next), [true, true, true, true, true]);
  assert.equal(tokenCalls().length, 1);
});

test('refresh rejected with invalid_grant → session destroyed, cookie cleared, 401, warn without the token value', async () => {
  const t = makeCtx();
  const s = await seed(t, { accessExpiresAt: t.clock.t, refreshToken: 'REVOKEDTOKENVALUE' });
  const r = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r.status, 401); assert.match(r.headers['set-cookie'][0], /^session_token=; Max-Age=0/);
  assert.equal(await t.store.get(s.token), null);
  assert.equal(t.logs.length, 1); assert.equal(t.logs[0][0], 'warn'); assert.match(t.logs[0][1], /refresh rejected/); assert.ok(!t.logs[0][1].includes('REVOKEDTOKENVALUE'));
});

test('issuer 5xx on refresh → stale-not-invalid: request passes with auth.stale, error logged, retried at most once per 60s, dies at absolute expiry', async () => {
  const t = makeCtx();
  const s = await seed(t, { accessExpiresAt: t.clock.t });
  F.calls.length = 0;
  F.fail.add('token');
  const r1 = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r1.next, true); assert.equal(r1.req.auth.stale, true); assert.deepEqual(r1.req.user, { id: 42, name: 'Ada Lovelace', roles: ['user'] });
  assert.equal(t.logs.filter((l) => l[0] === 'error').length, 1); assert.match(t.logs[0][1], /issuer_error 500/);
  assert.equal(tokenCalls().length, 1);
  const r2 = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r2.next, true); assert.equal(r2.req.auth.stale, true); assert.equal(tokenCalls().length, 1, 'no retry inside the backoff window');
  t.clock.t += 61000;
  F.fail.clear();
  const r3 = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r3.next, true); assert.equal(r3.req.auth.stale, false); assert.equal(tokenCalls().length, 2, 'retried after the backoff');
  t.clock.t += DAY;
  const r4 = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r4.status, 401, 'absolute session expiry wins over stale-not-invalid');
});

test('resolveUser returning null on refresh ends the session', async () => {
  const t = makeCtx({ resolveUser: async () => null });
  const s = await seed(t, { accessExpiresAt: t.clock.t });
  const r = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r.status, 401); assert.equal(await t.store.get(s.token), null);
});

test('unsealable session state (rotated secret) → 401 and the row is removed', async () => {
  const t = makeCtx();
  const s = await seed(t);
  await t.adapter.update(s.token, { state: seal(deriveKeys('rotated').sealKey, { anything: 1 }) });
  const r = await run(t.mw.requireAuth, { cookie: s.cookie });
  assert.equal(r.status, 401); assert.equal(await t.adapter.get(s.token), null);
});

test('bypassAuth → dev principal through resolveUser once, roles admin, store untouched', async () => {
  const t = makeCtx({ bypassAuth: true });
  const r1 = await run(t.mw.requireAuth, {});
  const r2 = await run(t.mw.requireAuth, {});
  assert.equal(r1.next, true); assert.equal(r2.next, true);
  assert.deepEqual(r1.req.user, { id: 42, name: 'Dev User', roles: ['admin'] });
  assert.equal(r1.req.auth.bypass, true); assert.deepEqual(r1.req.auth.roles, ['admin']); assert.equal(r1.req.auth.sub, 'dev');
  assert.equal(t.resolveCalls.length, 1); assert.equal(t.resolveCalls[0].sub, DEV_CLAIMS.sub); assert.equal(t.resolveCalls[0].email, 'dev@localhost');
});

test('loginUrl builds return_to and step-up params', () => {
  const t = makeCtx();
  assert.equal(t.mw.loginUrl(), '/api/auth/login');
  assert.equal(t.mw.loginUrl({ returnTo: '/a b' }), '/api/auth/login?return_to=%2Fa+b');
  assert.equal(t.mw.loginUrl({ returnTo: '/x', acr: 'webauthn', maxAge: 300 }), '/api/auth/login?return_to=%2Fx&acr=webauthn&max_age=300');
});
