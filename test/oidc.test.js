const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { createOidc, OidcError } = require('../lib/oidc');
const { startFakeIssuer } = require('./helpers/fakeIssuer');
const client = require('openid-client');

let F, oidc;
const REDIRECT = 'http://app.test/api/auth/callback';
before(async () => {
  F = await startFakeIssuer();
  oidc = createOidc({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true });
});
after(() => F.close());
beforeEach(() => { F.calls.length = 0; F.fail.clear(); F.user.roles = ['user']; F.refreshIdToken = true; });

async function login({ acrValues, maxAge, prompt } = {}) {
  const codeVerifier = client.randomPKCECodeVerifier(); const state = client.randomState(); const nonce = client.randomNonce();
  const url = await oidc.authorizationUrl({ redirectUri: REDIRECT, state, nonce, codeVerifier, acrValues, maxAge, prompt });
  const cb = await F.authorize(url);
  const tokens = await oidc.exchangeCode({ currentUrl: new URL(cb), codeVerifier, state, nonce });
  return { tokens, url: new URL(url) };
}

test('authorizationUrl carries code+PKCE S256, state, nonce, scope=openid and the step-up params', async () => {
  const codeVerifier = client.randomPKCECodeVerifier();
  const u = new URL(await oidc.authorizationUrl({ redirectUri: REDIRECT, state: 's1', nonce: 'n1', codeVerifier, acrValues: 'webauthn', maxAge: 300, prompt: 'login' }));
  assert.equal(u.origin + u.pathname, `${F.issuer}/authorize`);
  const q = u.searchParams;
  assert.equal(q.get('client_id'), F.clientId); assert.equal(q.get('response_type'), 'code'); assert.equal(q.get('scope'), 'openid');
  assert.equal(q.get('redirect_uri'), REDIRECT); assert.equal(q.get('state'), 's1'); assert.equal(q.get('nonce'), 'n1');
  assert.equal(q.get('code_challenge_method'), 'S256'); assert.equal(q.get('code_challenge'), await client.calculatePKCECodeChallenge(codeVerifier));
  assert.equal(q.get('acr_values'), 'webauthn'); assert.equal(q.get('max_age'), '300'); assert.equal(q.get('prompt'), 'login');
  const plain = new URL(await oidc.authorizationUrl({ redirectUri: REDIRECT, state: 's', nonce: 'n', codeVerifier }));
  assert.equal(plain.searchParams.has('acr_values'), false); assert.equal(plain.searchParams.has('max_age'), false); assert.equal(plain.searchParams.has('prompt'), false);
});

test('exchangeCode: full code flow returns tokens + verified ID token claims', async () => {
  const { tokens } = await login();
  assert.match(tokens.accessToken, /^[A-Za-z0-9_-]+$/); assert.ok(tokens.refreshToken); assert.ok(tokens.idToken);
  assert.equal(tokens.expiresIn, 900);
  assert.equal(tokens.claims.sub, F.user.sub); assert.deepEqual(tokens.claims.roles, ['user']);
  assert.equal(tokens.claims.acr, 'pwd-otp'); assert.equal(tokens.claims.sid, 'sid-1'); assert.equal(typeof tokens.claims.auth_time, 'number');
  assert.equal(tokens.claims.entra_oid, 'oid-ada');
  const tok = F.calls.find((c) => c.path === '/token');
  assert.equal(tok.body.grant_type, 'authorization_code'); assert.ok(tok.body.code_verifier); assert.equal(tok.body.redirect_uri, REDIRECT);
});

test('exchangeCode: state mismatch, nonce mismatch and access_denied all throw', async () => {
  const codeVerifier = client.randomPKCECodeVerifier();
  const url = await oidc.authorizationUrl({ redirectUri: REDIRECT, state: 'st', nonce: 'no', codeVerifier });
  const cb = await F.authorize(url);
  await assert.rejects(oidc.exchangeCode({ currentUrl: new URL(cb), codeVerifier, state: 'WRONG', nonce: 'no' }), OidcError);
  const cb2 = await F.authorize(url);
  await assert.rejects(oidc.exchangeCode({ currentUrl: new URL(cb2), codeVerifier, state: 'st', nonce: 'WRONG' }), OidcError);
  F.fail.add('authorize');
  const cb3 = await F.authorize(url);
  await assert.rejects(oidc.exchangeCode({ currentUrl: new URL(cb3), codeVerifier, state: 'st', nonce: 'no' }), (e) => e instanceof OidcError && e.kind === 'protocol');
});

test('refresh: rotates the token, re-reads roles from the new ID token; reuse of the old token is invalid_grant', async () => {
  const { tokens } = await login();
  F.user.roles = ['user', 'admin'];
  const r1 = await oidc.refresh(tokens.refreshToken);
  assert.notEqual(r1.refreshToken, tokens.refreshToken); assert.notEqual(r1.accessToken, tokens.accessToken);
  assert.deepEqual(r1.claims.roles, ['user', 'admin']); assert.equal(r1.claims.sid, tokens.claims.sid); assert.equal(r1.claims.nonce, undefined);
  await assert.rejects(oidc.refresh(tokens.refreshToken), (e) => e instanceof OidcError && e.kind === 'invalid_grant' && e.status === 400);
  // the family was revoked by the reuse
  await assert.rejects(oidc.refresh(r1.refreshToken), (e) => e instanceof OidcError && e.kind === 'invalid_grant');
});

test('refresh: no id_token in the response → claims null (caller falls back to userinfo)', async () => {
  const { tokens } = await login();
  F.refreshIdToken = false;
  const r = await oidc.refresh(tokens.refreshToken);
  assert.equal(r.claims, null); assert.equal(r.idToken, null);
  F.user.roles = ['ops'];
  const ui = await oidc.userinfo(r.accessToken, F.user.sub);
  assert.deepEqual(ui.roles, ['ops']); assert.equal(ui.sub, F.user.sub);
  await assert.rejects(oidc.userinfo('not-a-token', F.user.sub), OidcError);
});

test('refresh: issuer 5xx and connection refused are issuer_error, not invalid_grant', async () => {
  const { tokens } = await login();
  F.fail.add('token');
  await assert.rejects(oidc.refresh(tokens.refreshToken), (e) => e instanceof OidcError && e.kind === 'issuer_error' && e.status === 500);
  const dead = createOidc({ issuer: 'http://127.0.0.1:1', clientId: 'x', clientSecret: 'y', allowInsecure: true });
  await assert.rejects(dead.refresh('rt'), (e) => e instanceof OidcError && e.kind === 'issuer_error');
});

test('endSessionUrl: id_token_hint + post_logout_redirect_uri + client_id', async () => {
  const { tokens } = await login();
  const u = new URL(await oidc.endSessionUrl({ idToken: tokens.idToken, postLogoutRedirectUri: 'http://app.test/' }));
  assert.equal(u.origin + u.pathname, `${F.issuer}/session/end`);
  assert.equal(u.searchParams.get('id_token_hint'), tokens.idToken);
  assert.equal(u.searchParams.get('post_logout_redirect_uri'), 'http://app.test/');
  assert.equal(u.searchParams.get('client_id'), F.clientId);
  const noHint = new URL(await oidc.endSessionUrl({ postLogoutRedirectUri: 'http://app.test/' }));
  assert.equal(noHint.searchParams.has('id_token_hint'), false);
});

test('verifyLogoutToken: accepts a good token; rejects bad aud/iss, nonce, missing events, stale iat, no sid/sub, wrong key', async () => {
  const ok = await oidc.verifyLogoutToken(await F.logoutToken({ sid: 'sid-9', jti: 'j1' }));
  assert.equal(ok.sid, 'sid-9'); assert.equal(ok.sub, null); assert.equal(ok.jti, 'j1'); assert.equal(typeof ok.iat, 'number');
  const bySub = await oidc.verifyLogoutToken(await F.logoutToken({ sub: 'u1' }));
  assert.equal(bySub.sub, 'u1'); assert.equal(bySub.sid, null);
  await assert.rejects(oidc.verifyLogoutToken(await F.logoutToken({ sid: 's', aud: 'other-client' })), /audience/);
  await assert.rejects(oidc.verifyLogoutToken(await F.logoutToken({ sid: 's', iss: 'http://evil.test' })), /issuer/);
  await assert.rejects(oidc.verifyLogoutToken(await F.logoutToken({ sid: 's', nonce: 'n' })), /nonce/);
  await assert.rejects(oidc.verifyLogoutToken(await F.logoutToken({ sid: 's', events: {} })), /event/);
  await assert.rejects(oidc.verifyLogoutToken(await F.logoutToken({ sid: 's', events: { 'http://schemas.openid.net/event/backchannel-logout': 'yes' } })), /event/);
  await assert.rejects(oidc.verifyLogoutToken(await F.logoutToken({ sid: 's', iat: Math.floor(Date.now() / 1000) - 600 })), /iat|age|old/i);
  await assert.rejects(oidc.verifyLogoutToken(await F.logoutToken({})), /sid|sub/);
  const { privateKey } = await require('jose').generateKeyPair('ES256');
  const forged = await new (require('jose').SignJWT)({ iss: F.issuer, aud: F.clientId, iat: Math.floor(Date.now() / 1000), jti: 'x', sid: 's', events: { 'http://schemas.openid.net/event/backchannel-logout': {} } }).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(privateKey);
  await assert.rejects(oidc.verifyLogoutToken(forged), /signature/);
});

test('introspectApiKey: pwiam body passthrough, inactive, client auth failure, issuer 5xx', async () => {
  F.apiKeys.set('pk_live_1', { active: true, sub: 'sa:01HSA', service_account: { id: '01HSA', name: 'print-agent-pi', kind: 'print-agent' }, app: 'tally', env: 'prod', key_id: '01HKEY', exp: Math.floor(Date.now() / 1000) + 3600 });
  const a = await oidc.introspectApiKey('pk_live_1');
  assert.equal(a.active, true); assert.equal(a.service_account.kind, 'print-agent');
  assert.deepEqual(await oidc.introspectApiKey('nope'), { active: false });
  assert.deepEqual(F.calls.filter((c) => c.path === '/apikeys/introspect').map((c) => c.body), [{ key: '<redacted>' }, { key: '<redacted>' }]);
  const bad = createOidc({ issuer: F.issuer, clientId: F.clientId, clientSecret: 'wrong', allowInsecure: true });
  await assert.rejects(bad.introspectApiKey('pk_live_1'), (e) => e instanceof OidcError && e.kind === 'invalid_client' && e.status === 401);
  F.fail.add('introspect');
  await assert.rejects(oidc.introspectApiKey('pk_live_1'), (e) => e instanceof OidcError && e.kind === 'issuer_error');
});

test('upstreamToken: exchanges the user access token; rejected token is invalid_grant; unknown provider is protocol', async () => {
  const { tokens } = await login();
  const t = await oidc.upstreamToken('entra', tokens.accessToken);
  assert.equal(t.accessToken, `entra-at-${F.user.sub}`);
  assert.ok(t.expiresAt > Date.now() + 3500 * 1000 && t.expiresAt <= Date.now() + 3600 * 1000);
  await assert.rejects(oidc.upstreamToken('entra', 'garbage'), (e) => e instanceof OidcError && e.kind === 'invalid_grant');
  await assert.rejects(oidc.upstreamToken('google', tokens.accessToken), (e) => e instanceof OidcError && e.kind === 'protocol' && e.status === 404);
});

test('custom fetch is used for every request', async () => {
  const seen = [];
  const spy = (url, init) => { seen.push(new URL(url).pathname); return fetch(url, init); };
  const o = createOidc({ issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true, fetch: spy });
  await o.serverMetadata();
  await o.introspectApiKey('x');
  await o.verifyLogoutToken(await F.logoutToken({ sid: 's' }));
  assert.deepEqual(seen, ['/.well-known/openid-configuration', '/apikeys/introspect', '/jwks']);
});
