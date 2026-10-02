'use strict';
const crypto = require('node:crypto');
const cookie = require('cookie');

function readCookies(req) {
  const h = req.headers && req.headers.cookie;
  return h ? Object.assign({}, cookie.parse(h)) : {};
}

function hmac(key, value) { return crypto.createHmac('sha256', key).update(value).digest('base64url'); }

function signValue(key, value) { return `${value}.${hmac(key, value)}`; }

function unsignValue(key, signed) {
  if (typeof signed !== 'string') return null;
  const i = signed.lastIndexOf('.');
  if (i <= 0) return null;
  const value = signed.slice(0, i);
  const sig = Buffer.from(signed.slice(i + 1));
  const want = Buffer.from(hmac(key, value));
  return sig.length === want.length && crypto.timingSafeEqual(sig, want) ? value : null;
}

function append(res, str) {
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, str) : [str]);
}

// __Host- is the browser's strongest cookie-isolation prefix: it refuses the cookie unless the
// response also carries Secure, Path=/ and no Domain attribute — which in exchange guarantees no
// sibling (sub)domain can set or clear it. It only works over https, so a shim configured insecure
// (local dev over plain http) falls back to the bare name verbatim; browsers would reject the
// prefixed name outright over http.
function cookieName(name, secure) { return secure ? `__Host-${name}` : name; }

function setCookie(res, name, value, { maxAge, secure = true, sameSite = 'lax', httpOnly = true } = {}) {
  // Path is always '/' and Domain is never set — both are hard requirements of __Host-, so they
  // are not exposed as options here; every cookie this shim issues already wants them.
  append(res, cookie.serialize(cookieName(name, secure), value, { maxAge: Math.floor(maxAge / 1000), path: '/', httpOnly, secure, sameSite }));
}

// Clears the current (possibly __Host--prefixed) name. When secure, also clears the pre-0.4.0 bare
// name, so a cookie set by an older deploy of this shim never lingers in the browser once the app
// upgrades — this runs on every clear (login failure, logout, a rejected session), not just once,
// so it needs no migration flag or cleanup-later step of its own.
function clearCookie(res, name, { secure = true, sameSite = 'lax' } = {}) {
  append(res, cookie.serialize(cookieName(name, secure), '', { maxAge: 0, path: '/', httpOnly: true, secure, sameSite }));
  if (secure) append(res, cookie.serialize(name, '', { maxAge: 0, path: '/', httpOnly: true, secure, sameSite }));
}

// Reads a shim cookie out of an already-parsed cookie object, resolving the __Host- prefix the same
// way setCookie does. `legacyPresent` tells the caller a pre-0.4.0 bare-name cookie is still sitting
// in the browser (so it knows to clear it) independent of whether that cookie's value was used.
//
// `acceptLegacy` opts a caller into actually trusting the legacy name's value when the current name
// is absent — a one-time fallback for a cookie issued by the shim just before an upgrade and read
// just after. It is NOT the default: see routes.js (state/CSRF cookie, uses it) and middleware.js
// (session cookie, deliberately does not — a dropped session is just a silent re-login via pwiam SSO).
function getCookie(cookies, name, secure, { acceptLegacy = false } = {}) {
  const current = cookies[cookieName(name, secure)];
  const legacyPresent = secure && cookies[name] !== undefined;
  if (current !== undefined) return { value: current, legacyPresent };
  if (acceptLegacy && legacyPresent) return { value: cookies[name], legacyPresent };
  return { value: undefined, legacyPresent };
}

module.exports = { readCookies, signValue, unsignValue, setCookie, clearCookie, getCookie, cookieName };
