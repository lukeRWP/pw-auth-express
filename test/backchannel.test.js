// test/backchannel.test.js
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const { startApp, agent, loginVia } = require('./helpers/app');

let F;
before(async () => { F = await startFakeIssuer(); });
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); });

const post = (app, token) => fetch(`${app.baseUrl}/api/auth/backchannel-logout`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: token === undefined ? '' : new URLSearchParams({ logout_token: token }).toString() });
const sidOf = async (a) => (await (await a.req('/api/me')).json()).auth.sid;

test('logout_token with sid ends exactly that session; others survive', async () => {
  const app = await startApp({ F });
  try {
    const a = agent(app.baseUrl), b = agent(app.baseUrl);
    await loginVia(a, F); await loginVia(b, F);
    const sidA = await sidOf(a), sidB = await sidOf(b);
    assert.notEqual(sidA, sidB);
    const r = await post(app, await F.logoutToken({ sid: sidA }));
    assert.equal(r.status, 200); assert.equal(r.headers.get('cache-control'), 'no-store');
    assert.equal((await a.req('/api/me')).status, 401);
    assert.equal((await b.req('/api/me')).status, 200);
    // unknown sid: still 200 (no oracle)
    assert.equal((await post(app, await F.logoutToken({ sid: 'sid-does-not-exist' }))).status, 200);
  } finally { await app.close(); }
});

test('logout_token with sub (no sid) ends every session of that user', async () => {
  const app = await startApp({ F });
  try {
    const a = agent(app.baseUrl), b = agent(app.baseUrl);
    await loginVia(a, F); await loginVia(b, F);
    assert.equal((await post(app, await F.logoutToken({ sub: F.user.sub }))).status, 200);
    assert.equal((await a.req('/api/me')).status, 401); assert.equal((await b.req('/api/me')).status, 401);
  } finally { await app.close(); }
});

test('a body the parser refuses is still answered in the back-channel shape, uncacheable', async () => {
  const app = await startApp({ F });
  try {
    const r = await fetch(`${app.baseUrl}/api/auth/backchannel-logout`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `logout_token=${'x'.repeat(20 * 1024)}`,
    });
    assert.equal(r.status, 400);
    assert.deepEqual(await r.json(), { error: 'invalid_request', message: 'malformed body' });
    assert.equal(r.headers.get('cache-control'), 'no-store');
  } finally { await app.close(); }
});

test('rejects: empty body, garbage, wrong audience, stale iat, nonce present, missing events; replayed jti', async () => {
  const logs = [];
  const app = await startApp({ F, options: { logger: { info() {}, warn: (m) => logs.push(m), error: (m) => logs.push(m) } } });
  try {
    const a = agent(app.baseUrl);
    await loginVia(a, F);
    const sid = await sidOf(a);
    const bad = [
      undefined,
      'not.a.jwt',
      await F.logoutToken({ sid, aud: 'someone-else' }),
      await F.logoutToken({ sid, iat: Math.floor(Date.now() / 1000) - 900 }),
      await F.logoutToken({ sid, nonce: 'n' }),
      await F.logoutToken({ sid, events: {} }),
    ];
    for (const t of bad) {
      const r = await post(app, t);
      assert.equal(r.status, 400, `expected 400 for ${String(t).slice(0, 20)}`);
      assert.equal((await r.json()).error, 'invalid_request');
      assert.equal(r.headers.get('cache-control'), 'no-store', 'every answer is uncacheable');
    }
    assert.equal((await a.req('/api/me')).status, 200, 'no rejected token touched the session');
    const good = await F.logoutToken({ sid, jti: 'once' });
    assert.equal((await post(app, good)).status, 200);
    const replay = await post(app, good);
    assert.equal(replay.status, 400); assert.match((await replay.json()).message, /replay/);
    assert.ok(logs.some((m) => /replay/.test(m)));
    assert.ok(logs.every((m) => !m.includes(good)), 'the token itself is never logged');
  } finally { await app.close(); }
});
