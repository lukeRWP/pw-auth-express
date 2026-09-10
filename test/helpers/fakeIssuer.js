'use strict';
// A real HTTP OpenID issuer shaped like pwiam (oidc-provider): ES256 ID tokens, opaque access tokens,
// rotating refresh tokens with family-reuse revocation, back-channel logout tokens, pwiam's
// /apikeys/introspect and /upstream/<p>/token. Tests drive the real openid-client against it.
const http = require('node:http');
const crypto = require('node:crypto');
const jose = require('jose');

const nowSec = () => Math.floor(Date.now() / 1000);
const b64u = (b) => Buffer.from(b).toString('base64url');

async function startFakeIssuer({ clientId = 'tally-prod', clientSecret = 'cs-secret', accessTtl = 900 } = {}) {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
  const jwk = { ...(await jose.exportJWK(publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
  const server = http.createServer((req, res) => handle(req, res).catch((e) => json(res, 500, { error: 'server_error', error_description: e.message })));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const issuer = `http://127.0.0.1:${server.address().port}`;

  const F = {
    issuer, jwk, clientId, clientSecret, accessTtl,
    calls: [], fail: new Set(), refreshIdToken: true,
    user: { sub: '01HUSERAAAAAAAAAAAAAAAAAAA', name: 'Ada Lovelace', email: 'ada@example.com', roles: ['user'], entra_oid: 'oid-ada' },
    apiKeys: new Map(),
    codes: new Map(),     // code -> { challenge, redirectUri, nonce, acr, amr, authTime, sid }
    refresh: new Map(),   // refreshToken -> { family, used, sid, acr, amr, authTime }
    access: new Map(),    // accessToken -> { sub, sid, exp }
    sidCounter: 0,
    close: () => new Promise((r) => server.close(r)),
  };

  async function sign(claims, { typ } = {}) {
    const header = { alg: 'ES256', kid: 'k1' };
    if (typ) header.typ = typ;
    return new jose.SignJWT(claims).setProtectedHeader(header).sign(privateKey);
  }
  F.sign = sign;

  F.logoutToken = async ({ sid, sub, jti = crypto.randomUUID(), iat = nowSec(), events = { 'http://schemas.openid.net/event/backchannel-logout': {} }, nonce, aud = clientId, iss = issuer } = {}) => {
    const c = { iss, aud, iat, jti, events };
    if (sid) c.sid = sid;
    if (sub) c.sub = sub;
    if (nonce) c.nonce = nonce;
    return sign(c, { typ: 'logout+jwt' });
  };

  F.authorize = async (url) => {
    const r = await fetch(url, { redirect: 'manual' });
    if (r.status !== 302) throw new Error(`authorize answered ${r.status}`);
    return r.headers.get('location');
  };

  function json(res, status, body, headers = {}) {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    res.end(JSON.stringify(body));
  }
  async function readForm(req) {
    let s = ''; for await (const c of req) s += c;
    const ct = req.headers['content-type'] || '';
    if (ct.includes('application/json')) return JSON.parse(s || '{}');
    return Object.fromEntries(new URLSearchParams(s));
  }
  function basicOk(req) {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Basic ')) return false;
    const [id, sec] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':').map(decodeURIComponent);
    return id === clientId && sec === clientSecret;
  }
  function bearer(req) {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) return null;
    const at = F.access.get(h.slice(7));
    return at && at.exp > nowSec() ? at : null;
  }

  async function issueTokens({ sid, acr, amr, authTime, nonce, family }) {
    const now = nowSec();
    const accessToken = crypto.randomBytes(24).toString('base64url');
    F.access.set(accessToken, { sub: F.user.sub, sid, exp: now + F.accessTtl });
    const refreshToken = crypto.randomBytes(24).toString('base64url');
    F.refresh.set(refreshToken, { family, used: false, sid, acr, amr, authTime });
    const body = { access_token: accessToken, token_type: 'Bearer', expires_in: F.accessTtl, refresh_token: refreshToken, scope: 'openid' };
    if (nonce !== undefined || F.refreshIdToken) {
      const claims = { iss: issuer, aud: clientId, sub: F.user.sub, iat: now, exp: now + 900, sid, acr, amr, auth_time: authTime,
        name: F.user.name, email: F.user.email, roles: F.user.roles, entra_oid: F.user.entra_oid };
      if (nonce !== undefined) claims.nonce = nonce;
      body.id_token = await sign(claims);
    }
    return body;
  }

  async function handle(req, res) {
    const url = new URL(req.url, issuer);
    const path = url.pathname;
    const query = Object.fromEntries(url.searchParams);

    if (req.method === 'GET' && path === '/.well-known/openid-configuration') {
      return json(res, 200, {
        issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`,
        userinfo_endpoint: `${issuer}/userinfo`, end_session_endpoint: `${issuer}/session/end`,
        response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['ES256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'], code_challenge_methods_supported: ['S256'],
        grant_types_supported: ['authorization_code', 'refresh_token'], scopes_supported: ['openid'],
        backchannel_logout_supported: true, backchannel_logout_session_supported: true,
      });
    }
    if (req.method === 'GET' && path === '/jwks') return json(res, 200, { keys: [jwk] });

    if (req.method === 'GET' && path === '/authorize') {
      F.calls.push({ method: 'GET', path, query });
      const back = new URL(query.redirect_uri);
      if (query.client_id !== clientId || query.response_type !== 'code' || query.code_challenge_method !== 'S256' || !query.code_challenge || !query.state) {
        back.searchParams.set('error', 'invalid_request'); if (query.state) back.searchParams.set('state', query.state);
        res.writeHead(302, { location: back.href }); return res.end();
      }
      if (F.fail.has('authorize')) {
        back.searchParams.set('error', 'access_denied'); back.searchParams.set('state', query.state);
        res.writeHead(302, { location: back.href }); return res.end();
      }
      const code = crypto.randomBytes(16).toString('base64url');
      const acr = query.acr_values || 'pwd-otp';
      F.codes.set(code, { challenge: query.code_challenge, redirectUri: query.redirect_uri, nonce: query.nonce, acr,
        amr: acr === 'webauthn' ? ['webauthn'] : ['pwd', 'otp'], authTime: nowSec(), sid: `sid-${++F.sidCounter}` });
      back.searchParams.set('code', code); back.searchParams.set('state', query.state);
      res.writeHead(302, { location: back.href }); return res.end();
    }

    if (req.method === 'POST' && path === '/token') {
      const body = await readForm(req);
      F.calls.push({ method: 'POST', path, body: { ...body } });
      if (!basicOk(req)) return json(res, 401, { error: 'invalid_client' }, { 'www-authenticate': 'Basic realm="token"' });
      if (F.fail.has('token')) return json(res, 500, { error: 'server_error' });
      if (body.grant_type === 'authorization_code') {
        const c = F.codes.get(body.code); F.codes.delete(body.code);
        if (!c || c.redirectUri !== body.redirect_uri || b64u(crypto.createHash('sha256').update(body.code_verifier || '').digest()) !== c.challenge) {
          return json(res, 400, { error: 'invalid_grant', error_description: 'bad code, verifier or redirect_uri' });
        }
        return json(res, 200, await issueTokens({ ...c, family: crypto.randomUUID() }));
      }
      if (body.grant_type === 'refresh_token') {
        const r = F.refresh.get(body.refresh_token);
        if (!r) return json(res, 400, { error: 'invalid_grant', error_description: 'unknown refresh token' });
        if (r.used) {
          for (const [k, v] of F.refresh) if (v.family === r.family) F.refresh.delete(k);
          return json(res, 400, { error: 'invalid_grant', error_description: 'refresh token reuse — family revoked' });
        }
        r.used = true;
        return json(res, 200, await issueTokens({ sid: r.sid, acr: r.acr, amr: r.amr, authTime: r.authTime, family: r.family }));
      }
      return json(res, 400, { error: 'unsupported_grant_type' });
    }

    if (req.method === 'GET' && path === '/userinfo') {
      F.calls.push({ method: 'GET', path });
      if (F.fail.has('userinfo')) return json(res, 500, { error: 'server_error' });
      const at = bearer(req);
      if (!at) return json(res, 401, { error: 'invalid_token' }, { 'www-authenticate': 'Bearer error="invalid_token"' });
      return json(res, 200, { sub: F.user.sub, name: F.user.name, email: F.user.email, roles: F.user.roles });
    }

    if (req.method === 'GET' && path === '/session/end') {
      F.calls.push({ method: 'GET', path, query });
      const to = query.post_logout_redirect_uri;
      if (to) { res.writeHead(302, { location: to }); return res.end(); }
      res.writeHead(200); return res.end('signed out');
    }

    if (req.method === 'POST' && path === '/apikeys/introspect') {
      const body = await readForm(req);
      F.calls.push({ method: 'POST', path, body: { key: body.key ? '<redacted>' : undefined } });
      if (!basicOk(req)) return json(res, 401, { error: 'invalid_client', message: 'client authentication failed' });
      if (F.fail.has('introspect')) return json(res, 500, { error: 'server_error' });
      return json(res, 200, F.apiKeys.get(body.key) || { active: false });
    }

    const up = path.match(/^\/upstream\/([a-z]+)\/token$/);
    if (req.method === 'GET' && up) {
      F.calls.push({ method: 'GET', path });
      if (F.fail.has('upstream')) return json(res, 500, { error: 'server_error' });
      const at = bearer(req);
      if (!at) return json(res, 401, { error: 'invalid_token' });
      if (up[1] !== 'entra') return json(res, 404, { error: 'not_found', message: `no upstream ${up[1]}` });
      return json(res, 200, { access_token: `${up[1]}-at-${at.sub}`, expires_in: 3600 });
    }

    json(res, 404, { error: 'not_found' });
  }

  return F;
}

module.exports = { startFakeIssuer };
