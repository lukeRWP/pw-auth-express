const { test } = require('node:test');
const assert = require('node:assert/strict');
const { deriveKeys } = require('../lib/crypto');
const { readCookies, signValue, unsignValue, setCookie, clearCookie, getCookie, cookieName } = require('../lib/cookies');

const { cookieKey } = deriveKeys('s3cret'.padEnd(32, '.'));
function fakeRes() { const h = {}; return { getHeader: (n) => h[n.toLowerCase()], setHeader: (n, v) => { h[n.toLowerCase()] = v; }, _h: h }; }

test('sign/unsign: valid round-trip, tamper → null, wrong key → null', () => {
  const s = signValue(cookieKey, 'abc');
  assert.match(s, /^abc\.[A-Za-z0-9_-]+$/);
  assert.equal(unsignValue(cookieKey, s), 'abc');
  assert.equal(unsignValue(cookieKey, 'abd' + s.slice(3)), null);
  assert.equal(unsignValue(deriveKeys('x'.padEnd(32, '.')).cookieKey, s), null);
  assert.equal(unsignValue(cookieKey, 'nodot'), null);
  assert.equal(unsignValue(cookieKey, undefined), null);
});

test('readCookies parses the header', () => {
  assert.deepEqual(readCookies({ headers: { cookie: 'a=1; b=two' } }), { a: '1', b: 'two' });
  assert.deepEqual(readCookies({ headers: {} }), {});
});

test('cookieName: __Host- prefix only when secure', () => {
  assert.equal(cookieName('session_token', true), '__Host-session_token');
  assert.equal(cookieName('pw_auth_state', true), '__Host-pw_auth_state');
  assert.equal(cookieName('session_token', false), 'session_token');
});

test('setCookie: secure → __Host- prefix, Secure, HttpOnly, Path=/, SameSite=Lax, no Domain', () => {
  const res = fakeRes();
  setCookie(res, 'session_token', 'v1', { maxAge: 1000, secure: true });
  setCookie(res, 'pw_auth_state', 'v2', { maxAge: 300000, secure: true });
  const set = res.getHeader('Set-Cookie');
  assert.equal(set.length, 2);
  assert.match(set[0], /^__Host-session_token=v1; Max-Age=1; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
  assert.match(set[1], /^__Host-pw_auth_state=v2; Max-Age=300; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
  for (const sc of set) assert.ok(!/domain/i.test(sc), `no Domain attribute: ${sc}`);
});

test('setCookie: dev fallback — insecure config keeps the plain name and drops Secure', () => {
  const res = fakeRes();
  setCookie(res, 'session_token', 'v1', { maxAge: 1000, secure: false });
  const set = res.getHeader('Set-Cookie');
  assert.equal(set.length, 1);
  assert.match(set[0], /^session_token=v1; Max-Age=1; Path=\/; HttpOnly; SameSite=Lax$/);
  assert.ok(!set[0].includes('__Host-'));
});

test('clearCookie: secure clears both the __Host- name and the pre-0.4.0 bare name', () => {
  const res = fakeRes();
  clearCookie(res, 'session_token', { secure: true });
  const set = res.getHeader('Set-Cookie');
  assert.equal(set.length, 2);
  assert.match(set[0], /^__Host-session_token=; Max-Age=0; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
  assert.match(set[1], /^session_token=; Max-Age=0; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
});

test('clearCookie: insecure (dev fallback) clears only the plain name', () => {
  const res = fakeRes();
  clearCookie(res, 'session_token', { secure: false });
  const set = res.getHeader('Set-Cookie');
  assert.equal(set.length, 1);
  assert.match(set[0], /^session_token=; Max-Age=0; Path=\/; HttpOnly; SameSite=Lax$/);
});

test('getCookie: secure reads the __Host- name; a legacy bare-name cookie is reported but not trusted unless acceptLegacy', () => {
  const both = { '__Host-session_token': 'new-value', session_token: 'old-value' };
  assert.deepEqual(getCookie(both, 'session_token', true), { value: 'new-value', legacyPresent: true });

  const onlyLegacy = { session_token: 'old-value' };
  assert.deepEqual(getCookie(onlyLegacy, 'session_token', true), { value: undefined, legacyPresent: true });
  assert.deepEqual(getCookie(onlyLegacy, 'session_token', true, { acceptLegacy: true }), { value: 'old-value', legacyPresent: true });

  assert.deepEqual(getCookie({}, 'session_token', true), { value: undefined, legacyPresent: false });
});

test('getCookie: insecure — no prefix, no legacy concept', () => {
  assert.deepEqual(getCookie({ session_token: 'v1' }, 'session_token', false), { value: 'v1', legacyPresent: false });
  assert.deepEqual(getCookie({}, 'session_token', false), { value: undefined, legacyPresent: false });
});
