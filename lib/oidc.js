'use strict';
// Thin wrapper over openid-client v6 + jose v6. Everything that talks to pwiam goes through here so
// the routes/middleware never see library error types — only OidcError with a `kind`.
const client = require('openid-client');
const jose = require('jose');

class OidcError extends Error {
  constructor(kind, message, { status, cause } = {}) {
    super(message);
    this.name = 'OidcError';
    this.kind = kind;       // 'invalid_grant' | 'issuer_error' | 'protocol' | 'invalid_client'
    this.status = status;
    this.cause = cause;
  }
}

const isTransport = (e) => e && (e.name === 'TypeError' || e.name === 'AbortError' || e.name === 'TimeoutError' || e.code === 'ECONNREFUSED' || e.code === 'UND_ERR_CONNECT_TIMEOUT');

function classify(e) {
  if (e instanceof OidcError) return e;
  if (e instanceof client.ResponseBodyError) {
    if (e.error === 'invalid_grant') return new OidcError('invalid_grant', e.error_description || 'invalid_grant', { status: e.status, cause: e });
    if (e.error === 'invalid_client') return new OidcError('invalid_client', e.error_description || 'invalid_client', { status: e.status, cause: e });
    return new OidcError('protocol', `${e.error}${e.error_description ? `: ${e.error_description}` : ''}`, { status: e.status, cause: e });
  }
  // oauth4webapi reports "unexpected status" with the Response as `cause`, and WWWAuthenticateChallengeError has status directly
  const status = typeof e.status === 'number' ? e.status : (e && e.cause && typeof e.cause === 'object' && typeof e.cause.status === 'number' ? e.cause.status : undefined);
  if (status >= 500 || isTransport(e) || isTransport(e && e.cause)) return new OidcError('issuer_error', (e && e.message) || 'issuer unreachable', { status, cause: e });
  return new OidcError('protocol', (e && e.message) || 'oidc protocol error', { status, cause: e });
}

function normalize(t) {
  const claims = t.claims();
  // The issuer's declared TTL, not openid-client's real-clock remainder (which
  // rounds down across a second boundary); consumers add it to the injected clock.
  const expiresIn = typeof t.expires_in === 'number' ? t.expires_in : t.expiresIn();
  // Without it the session's access token would look expired on the very next request,
  // so every request would refresh — churning the rotating refresh family, silently.
  if (!Number.isFinite(expiresIn) || expiresIn <= 0) throw new OidcError('protocol', 'token response has no expires_in');
  return {
    accessToken: t.access_token,
    refreshToken: t.refresh_token || null,
    idToken: t.id_token || null,
    expiresIn,
    claims: claims ? { ...claims } : null,
  };
}

function createOidc({ issuer, clientId, clientSecret, fetch: fetchImpl, allowInsecure = false, timeoutSec = 10, now = Date.now }) {
  if (!issuer || !clientId || !clientSecret) throw new Error('pw-auth: issuer, clientId and clientSecret are required');
  const base = String(issuer).replace(/\/+$/, '');
  const doFetch = fetchImpl || globalThis.fetch;
  let configPromise = null;
  let jwks = null;

  function config() {
    if (!configPromise) {
      const opts = { timeout: timeoutSec, execute: allowInsecure ? [client.allowInsecureRequests] : [] };
      if (fetchImpl) opts[client.customFetch] = fetchImpl;
      configPromise = client.discovery(new URL(base), clientId, undefined, client.ClientSecretBasic(clientSecret), opts)
        .catch((e) => { configPromise = null; throw classify(e); });
    }
    return configPromise;
  }

  async function serverMetadata() { return (await config()).serverMetadata(); }

  function remoteJwks(jwksUri) {
    if (!jwks) {
      const o = {};
      if (fetchImpl) o[jose.customFetch] = fetchImpl;
      jwks = jose.createRemoteJWKSet(new URL(jwksUri), o);
    }
    return jwks;
  }

  async function authorizationUrl({ redirectUri, state, nonce, codeVerifier, acrValues, maxAge, prompt }) {
    const c = await config();
    const params = {
      redirect_uri: redirectUri, scope: 'openid', state, nonce,
      code_challenge: await client.calculatePKCECodeChallenge(codeVerifier), code_challenge_method: 'S256',
    };
    if (acrValues) params.acr_values = acrValues;
    if (maxAge !== undefined && maxAge !== null) params.max_age = String(maxAge);
    if (prompt) params.prompt = prompt;
    return client.buildAuthorizationUrl(c, params).href;
  }

  async function exchangeCode({ currentUrl, codeVerifier, state, nonce }) {
    const c = await config();
    try {
      const t = await client.authorizationCodeGrant(c, currentUrl, { pkceCodeVerifier: codeVerifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
      return normalize(t);
    } catch (e) { throw classify(e); }
  }

  async function refresh(refreshToken) {
    const c = await config();
    try { return normalize(await client.refreshTokenGrant(c, refreshToken)); } catch (e) { throw classify(e); }
  }

  async function userinfo(accessToken, expectedSub) {
    const c = await config();
    try { return await client.fetchUserInfo(c, accessToken, expectedSub); } catch (e) { throw classify(e); }
  }

  async function endSessionUrl({ idToken, postLogoutRedirectUri }) {
    const c = await config();
    const params = { post_logout_redirect_uri: postLogoutRedirectUri };
    if (idToken) params.id_token_hint = idToken;
    return client.buildEndSessionUrl(c, params).href;
  }

  async function verifyLogoutToken(token, { now } = {}) {
    const meta = await serverMetadata();
    const opts = { issuer: meta.issuer, audience: clientId, maxTokenAge: '120s', clockTolerance: 5, requiredClaims: ['events', 'iat', 'jti'] };
    if (now) opts.currentDate = new Date(now);
    let payload;
    try {
      const result = await jose.jwtVerify(token, remoteJwks(meta.jwks_uri), opts);
      payload = result.payload;
    } catch (e) {
      const msg = e.message || '';
      if (msg.includes('"aud"')) throw new Error(`audience claim mismatch: ${msg}`);
      if (msg.includes('"iss"')) throw new Error(`issuer claim mismatch: ${msg}`);
      if (msg.includes('exp') || msg.includes('iat') || msg.includes('age')) throw new Error(`token is too old: ${msg}`);
      if (msg.includes('signature')) throw new Error(`signature verification failed: ${msg}`);
      throw e;
    }
    if (payload.nonce !== undefined) throw new Error('logout token must not carry a nonce');
    const ev = payload.events && payload.events['http://schemas.openid.net/event/backchannel-logout'];
    if (!ev || typeof ev !== 'object') throw new Error('logout token is missing the backchannel-logout event');
    if (!payload.sid && !payload.sub) throw new Error('logout token needs sid or sub');
    return { sid: payload.sid || null, sub: payload.sub || null, jti: payload.jti, iat: payload.iat };
  }

  async function callUrl(href, init) {
    try {
      return await doFetch(href, { ...init, signal: AbortSignal.timeout(timeoutSec * 1000) });
    } catch (e) { throw classify(e); }
  }

  async function call(path, init) {
    return callUrl(`${base}${path}`, init);
  }

  async function introspectApiKey(key) {
    const auth = 'Basic ' + Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64');
    const res = await call('/apikeys/introspect', { method: 'POST', headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: new URLSearchParams({ key }).toString() });
    if (res.status === 401) throw new OidcError('invalid_client', 'introspection rejected the client credentials', { status: 401 });
    // 429 is an outage, not a protocol error: callers cache/grace/back off on issuer_error, and a
    // rate-limited pwiam wants exactly that, not an immediate hard failure.
    if (res.status >= 500 || res.status === 429) throw new OidcError('issuer_error', `introspection answered ${res.status}`, { status: res.status });
    if (!res.ok) throw new OidcError('protocol', `introspection answered ${res.status}`, { status: res.status });
    try {
      return await res.json();
    } catch (e) {
      throw new OidcError('protocol', 'malformed response from introspection', { status: res.status });
    }
  }

  async function upstreamToken(provider, accessToken) {
    if (!/^[a-z]+$/.test(provider)) throw new OidcError('protocol', `bad upstream provider ${provider}`);
    const res = await call(`/upstream/${provider}/token`, { headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' } });
    if (res.status === 401) throw new OidcError('invalid_grant', 'access token rejected by the issuer', { status: 401 });
    if (res.status >= 500) throw new OidcError('issuer_error', `upstream token answered ${res.status}`, { status: res.status });
    if (!res.ok) throw new OidcError('protocol', `upstream token answered ${res.status}`, { status: res.status });
    let body;
    try {
      body = await res.json();
    } catch (e) {
      throw new OidcError('protocol', 'malformed response from upstream token', { status: res.status });
    }
    const expiresIn = Number(body.expires_in);
    if (!Number.isFinite(expiresIn) || expiresIn <= 0) throw new OidcError('protocol', 'token response has no expires_in');
    return { accessToken: body.access_token, expiresAt: now() + expiresIn * 1000 };
  }

  // Relying-party calls to pwiam's /rp/* surface (self-service device keys). The user is proven
  // by their access token, the app by its client credentials — sent as headers, never in a URL
  // or body (a query string lands in access and proxy logs; Authorization is the bearer's).
  //
  // This is the ONE choke point that decides what "an /rp/ path" means — callIdp in middleware.js
  // delegates here rather than re-checking, so there is exactly one place that can get it wrong.
  // A caller-supplied path is treated as hostile: it reaches pwiam with the app's client secret
  // attached, so `/rp/../manage/users`-style traversal (raw, percent-encoded, or backslash) must
  // never resolve outside `/rp/`. Refusal messages never echo the caller's path back (the path
  // itself may be attacker-controlled input reflected into logs/responses).
  const RP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
  const BAD_PATH = /[\\\t\n\r]|%2e|%2f|%5c/i;
  const INVALID_PATH = () => new Error('pw-auth: callIdp: invalid path');
  const baseUrl = new URL(base);
  const rpPrefix = `${baseUrl.pathname.replace(/\/$/, '')}/rp/`;

  function resolveRpUrl(path) {
    if (typeof path !== 'string' || !path) throw INVALID_PATH();
    if (BAD_PATH.test(path)) throw INVALID_PATH();
    const segments = path.split('?')[0].split('/');
    if (segments.some((s) => s === '.' || s === '..')) throw INVALID_PATH();
    if (!path.startsWith('/rp/')) throw INVALID_PATH();
    let u;
    try { u = new URL(base + path); } catch { throw INVALID_PATH(); }
    if (u.origin !== baseUrl.origin || !u.pathname.startsWith(rpPrefix)) throw INVALID_PATH();
    return u;
  }

  async function rpCall({ method: rawMethod, path, accessToken, body }) {
    const method = typeof rawMethod === 'string' ? rawMethod.toUpperCase() : rawMethod;
    if (!RP_METHODS.has(method)) throw new Error('pw-auth: callIdp: unsupported method');
    if (body !== undefined && method === 'GET') throw new Error('pw-auth: callIdp: GET requests cannot carry a body');
    const u = resolveRpUrl(path);
    const headers = {
      authorization: `Bearer ${accessToken}`,
      'x-pw-client-id': clientId,
      'x-pw-client-secret': clientSecret,
      accept: 'application/json',
    };
    // Never follow a redirect: a 3xx off pwiam could point cross-origin, and fetch's default
    // 'follow' strips only Authorization on such a hop — not X-PW-Client-Secret.
    const init = { method, headers, redirect: 'manual' };
    if (body !== undefined && method !== 'GET') {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const res = await callUrl(u.href, init);
    if (res.status >= 300 && res.status < 400) {
      await res.body?.cancel().catch(() => {}); // unread, the body would hold the socket until GC
      return { status: res.status, body: null };
    }
    if (res.status === 204) return { status: 204, body: null };
    let parsed = null;
    try { parsed = await res.json(); } catch { parsed = null; }
    return { status: res.status, body: parsed };
  }

  return { authorizationUrl, exchangeCode, refresh, userinfo, endSessionUrl, verifyLogoutToken, introspectApiKey, upstreamToken, rpCall, serverMetadata };
}

module.exports = { createOidc, OidcError };
