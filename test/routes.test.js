const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const { startApp, agent, loginVia } = require('./helpers/app');
const { STATE_COOKIE } = require('../lib/routes');

let F;
before(async () => { F = await startFakeIssuer(); });
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); F.user.roles = ['user']; });

test('GET /login → 302 to the issuer with PKCE/state/nonce and a sealed state cookie; return_to is path-only; step-up params pass through', async () => {
  const app = await startApp({ F });
  try {
    const a = agent(app.baseUrl);
    const r = await a.req('/api/auth/login?return_to=%2Fitems%2F3');
    assert.equal(r.status, 302);
    const u = new URL(r.headers.get('location'));
    assert.equal(u.origin + u.pathname, `${F.issuer}/authorize`);
    assert.equal(u.searchParams.get('redirect_uri'), `${app.baseUrl}/api/auth/callback`);
    assert.equal(u.searchParams.get('code_challenge_method'), 'S256'); assert.ok(u.searchParams.get('state')); assert.ok(u.searchParams.get('nonce'));
    assert.equal(u.searchParams.has('acr_values'), false);
    const sc = r.headers.getSetCookie().find((c) => c.startsWith(`${STATE_COOKIE}=`));
    assert.match(sc, /; Max-Age=300; Path=\/; HttpOnly; SameSite=Lax$/);
    assert.ok(!sc.includes(u.searchParams.get('state')), 'state cookie is sealed, not plaintext');

    const su = new URL((await a.req('/api/auth/login?acr=webauthn&max_age=300')).headers.get('location'));
    assert.equal(su.searchParams.get('acr_values'), 'webauthn'); assert.equal(su.searchParams.get('max_age'), '300'); assert.equal(su.searchParams.get('prompt'), 'login');
    const bad = new URL((await a.req('/api/auth/login?acr=web%20authn&max_age=x')).headers.get('location'));
    assert.equal(bad.searchParams.has('acr_values'), false); assert.equal(bad.searchParams.has('max_age'), false);
  } finally { await app.close(); }
});

test('callback: happy path creates the session, honours return_to, clears the state cookie; /session and a protected route work', async () => {
  const seen = [];
  const app = await startApp({ F, resolveUser: async (c, extra) => { seen.push({ c, extra }); return { id: 7, name: c.name, roles: c.roles }; } });
  try {
    const a = agent(app.baseUrl);
    const cb = await loginVia(a, F, '/api/auth/login?return_to=%2Fitems%2F3');
    assert.equal(cb.status, 302); assert.equal(cb.headers.get('location'), '/items/3');
    const cookies = cb.headers.getSetCookie();
    assert.ok(cookies.some((c) => /^pw_auth_state=; Max-Age=0/.test(c)));
    const sess = cookies.find((c) => c.startsWith('session_token='));
    assert.match(sess, /^session_token=[0-9a-f]{64}\.[A-Za-z0-9_-]+; Max-Age=86400; Path=\/; HttpOnly; SameSite=Lax$/);
    assert.equal(seen.length, 1); assert.equal(seen[0].c.entra_oid, 'oid-ada'); assert.equal(seen[0].c.sub, F.user.sub); assert.ok(seen[0].extra.tokens.accessToken);

    const me = await a.req('/api/me');
    assert.equal(me.status, 200);
    const body = await me.json();
    assert.deepEqual(body.user, { id: 7, name: 'Ada Lovelace', roles: ['user'] });
    assert.equal(body.auth.sub, F.user.sub); assert.equal(body.auth.acr, 'pwd-otp'); assert.equal(body.auth.stale, false);
    assert.equal(body.auth.accessToken, undefined, 'tokens never leave the server');

    const s = await a.req('/api/auth/session');
    assert.equal(s.status, 200); assert.equal(s.headers.get('cache-control'), 'no-store');
    assert.deepEqual((await s.json()).user, { id: 7, name: 'Ada Lovelace', roles: ['user'] });
    assert.equal((await a.req('/page', { headers: { accept: 'text/html' } })).status, 200);
  } finally { await app.close(); }
});

test('callback: missing state cookie, replayed callback, cross-bound state, expired state → /login?error=auth_failed, no session', async () => {
  const clock = { t: Date.now() };
  const app = await startApp({ F, options: { now: () => clock.t } });
  try {
    const a = agent(app.baseUrl);
    const r1 = await a.req('/api/auth/login');
    const cbUrl = await F.authorize(r1.headers.get('location'));
    // no cookie at all
    const bare = await fetch(cbUrl, { redirect: 'manual' });
    assert.equal(bare.status, 302); assert.equal(bare.headers.get('location'), '/login?error=auth_failed');
    // cross-bound: a second login's cookie with the first login's callback
    const b = agent(app.baseUrl);
    await b.req('/api/auth/login');
    const cross = await b.req(cbUrl);
    assert.equal(cross.headers.get('location'), '/login?error=auth_failed');
    assert.equal((await b.req('/api/me')).status, 401);
    // correct browser, but the state cookie has expired
    clock.t += 6 * 60 * 1000;
    const late = await a.req(cbUrl);
    assert.equal(late.headers.get('location'), '/login?error=auth_failed');
    assert.equal((await a.req('/api/me')).status, 401);
    // good login, then replay the same callback URL
    clock.t = Date.now();
    const c = agent(app.baseUrl);
    const r2 = await c.req('/api/auth/login');
    const cb2 = await F.authorize(r2.headers.get('location'));
    assert.equal((await c.req(cb2)).headers.get('location'), '/');
    const replay = await c.req(cb2);
    assert.equal(replay.headers.get('location'), '/login?error=auth_failed');
    assert.equal((await c.req('/api/me')).status, 200, 'the earlier valid session survives a failed replay');
  } finally { await app.close(); }
});

test('callback: issuer access_denied, resolveUser throwing, resolveUser returning null → error redirect + warn', async () => {
  const logs = [];
  let mode = 'deny';
  const app = await startApp({ F, resolveUser: async (c) => { if (mode === 'throw') throw new Error('db down'); if (mode === 'null') return null; return { id: 1, name: c.name }; }, options: { logger: { info() {}, warn: (m) => logs.push(m), error: (m) => logs.push(m) } } });
  try {
    F.fail.add('authorize');
    const a = agent(app.baseUrl);
    assert.equal((await loginVia(a, F)).headers.get('location'), '/login?error=auth_failed');
    F.fail.clear();
    mode = 'throw';
    assert.equal((await loginVia(a, F)).headers.get('location'), '/login?error=auth_failed');
    mode = 'null';
    assert.equal((await loginVia(a, F)).headers.get('location'), '/login?error=auth_failed');
    assert.equal(logs.length, 3);
    assert.match(logs[0], /code exchange/); assert.match(logs[1], /resolveUser threw: db down/); assert.match(logs[2], /no user/);
    assert.equal((await a.req('/api/me')).status, 401);
  } finally { await app.close(); }
});

test('logout: destroys the session, clears the cookie, sends the browser to the issuer end-session with id_token_hint; json callers get { redirect }', async () => {
  const app = await startApp({ F });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const r = await a.req('/api/auth/logout', { method: 'POST', headers: { accept: 'text/html' } });
    assert.equal(r.status, 302);
    const u = new URL(r.headers.get('location'));
    assert.equal(u.origin + u.pathname, `${F.issuer}/session/end`);
    assert.ok(u.searchParams.get('id_token_hint')); assert.equal(u.searchParams.get('post_logout_redirect_uri'), `${app.baseUrl}/`); assert.equal(u.searchParams.get('client_id'), F.clientId);
    assert.ok(r.headers.getSetCookie().some((c) => /^session_token=; Max-Age=0/.test(c)));
    assert.equal((await a.req('/api/me')).status, 401);
    // second logout, no session: still a clean answer
    const again = await a.req('/api/auth/logout', { method: 'POST' });
    assert.equal(again.status, 200); assert.deepEqual(await again.json(), { redirect: `${app.baseUrl}/` });
    // json caller with a session
    await loginVia(a, F);
    const j = await a.req('/api/auth/logout', { method: 'POST', headers: { accept: 'application/json' } });
    assert.equal(j.status, 200); assert.match((await j.json()).redirect, /\/session\/end\?/);
  } finally { await app.close(); }
});

test('bypassAuth: /login is 503, /session and protected routes serve the dev principal', async () => {
  const app = await startApp({ F, options: { bypassAuth: true } });
  try {
    const a = agent(app.baseUrl);
    const l = await a.req('/api/auth/login');
    assert.equal(l.status, 503); assert.equal((await l.json()).error, 'bypass');
    const s = await a.req('/api/auth/session');
    assert.equal(s.status, 200);
    const b = await s.json();
    assert.deepEqual(b.user, { id: 42, name: 'Dev User', roles: ['admin'] }); assert.equal(b.auth.bypass, true);
  } finally { await app.close(); }
});

test('a second login from a browser that already has a session replaces it (old row destroyed)', async () => {
  const app = await startApp({ F });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const first = a.jar.get('session_token');
    await loginVia(a, F, '/api/auth/login?acr=webauthn');
    assert.notEqual(a.jar.get('session_token'), first);
    const me = await (await a.req('/api/me')).json();
    assert.equal(me.auth.acr, 'webauthn');
    const stale = await fetch(`${app.baseUrl}/api/me`, { headers: { cookie: `session_token=${first}` } });
    assert.equal(stale.status, 401);
  } finally { await app.close(); }
});
