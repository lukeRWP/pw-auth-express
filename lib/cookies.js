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

function setCookie(res, name, value, { maxAge, secure = true, path = '/', sameSite = 'lax', httpOnly = true } = {}) {
  append(res, cookie.serialize(name, value, { maxAge: Math.floor(maxAge / 1000), path, httpOnly, secure, sameSite }));
}

function clearCookie(res, name, { secure = true, path = '/' } = {}) {
  append(res, cookie.serialize(name, '', { maxAge: 0, path, httpOnly: true, secure, sameSite: 'lax' }));
}

module.exports = { readCookies, signValue, unsignValue, setCookie, clearCookie };
