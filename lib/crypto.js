'use strict';
const crypto = require('node:crypto');

function deriveKeys(secret) {
  if (typeof secret !== 'string' || secret.length < 1) throw new Error('pw-auth: secret is required');
  const ikm = Buffer.from(secret, 'utf8');
  const hkdf = (info) => Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.from(info), 32));
  return { cookieKey: hkdf('pw-auth-express/cookie/v1'), sealKey: hkdf('pw-auth-express/seal/v1') };
}

const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => Buffer.from(s, 'base64url');

function seal(key, obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return `v1.${b64u(iv)}.${b64u(ct)}.${b64u(c.getAuthTag())}`;
}

function open(key, str) {
  try {
    const parts = String(str).split('.');
    if (parts.length !== 4 || parts[0] !== 'v1') throw new Error();
    const [v, iv, ct, tag] = parts;
    if (!iv || ct === undefined || !tag) throw new Error();
    const d = crypto.createDecipheriv('aes-256-gcm', key, unb64u(iv));
    d.setAuthTag(unb64u(tag));
    return JSON.parse(Buffer.concat([d.update(unb64u(ct)), d.final()]).toString('utf8'));
  } catch {
    throw new Error('unsealable');
  }
}

const randomToken = () => crypto.randomBytes(32).toString('hex');

module.exports = { deriveKeys, seal, open, randomToken };
