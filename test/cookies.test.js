const { test } = require('node:test');
const assert = require('node:assert/strict');
const { deriveKeys } = require('../lib/crypto');
const { readCookies, signValue, unsignValue, setCookie, clearCookie } = require('../lib/cookies');

const { cookieKey } = deriveKeys('s3cret');
function fakeRes() { const h = {}; return { getHeader: (n) => h[n.toLowerCase()], setHeader: (n, v) => { h[n.toLowerCase()] = v; }, _h: h }; }

test('sign/unsign: valid round-trip, tamper → null, wrong key → null', () => {
  const s = signValue(cookieKey, 'abc');
  assert.match(s, /^abc\.[A-Za-z0-9_-]+$/);
  assert.equal(unsignValue(cookieKey, s), 'abc');
  assert.equal(unsignValue(cookieKey, 'abd' + s.slice(3)), null);
  assert.equal(unsignValue(deriveKeys('x').cookieKey, s), null);
  assert.equal(unsignValue(cookieKey, 'nodot'), null);
  assert.equal(unsignValue(cookieKey, undefined), null);
});

test('readCookies parses the header; setCookie accumulates Set-Cookie with the right attributes', () => {
  assert.deepEqual(readCookies({ headers: { cookie: 'a=1; b=two' } }), { a: '1', b: 'two' });
  assert.deepEqual(readCookies({ headers: {} }), {});
  const res = fakeRes();
  setCookie(res, 'session_token', 'v1', { maxAge: 1000, secure: true });
  setCookie(res, 'pw_auth_state', 'v2', { maxAge: 300000, secure: false });
  const set = res.getHeader('Set-Cookie');
  assert.equal(set.length, 2);
  assert.match(set[0], /^session_token=v1; Max-Age=1; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
  assert.match(set[1], /^pw_auth_state=v2; Max-Age=300; Path=\/; HttpOnly; SameSite=Lax$/);
  clearCookie(res, 'session_token', { secure: true });
  assert.match(res.getHeader('Set-Cookie')[2], /^session_token=; Max-Age=0; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
});
