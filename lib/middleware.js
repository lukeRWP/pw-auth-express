'use strict';
const { readCookies, unsignValue, clearCookie, getCookie } = require('./cookies');
const { isValidApiKeyShape } = require('./apiKeyShape');
const { createKeyCache, CACHE_TTL_MS: KEY_CACHE_MS, GRACE_MS: KEY_GRACE_MS } = require('./apiKeyVerifier');
const { OidcError } = require('./oidc');

const REFRESH_SKEW_MS = 30 * 1000;   // refresh when the access token has < 30s left
const RETRY_BACKOFF_MS = 60 * 1000;  // after a transient refresh failure, don't hammer the issuer

const DEV_CLAIMS = Object.freeze({ sub: 'dev', name: 'Dev User', email: 'dev@localhost', preferred_username: 'dev', roles: ['admin'], acr: 'dev', amr: ['dev'], sid: null, entra_oid: null });

function createMiddleware(ctx) {
  const { o, keys, oidc, store, log } = ctx;
  const cookieOpts = { secure: o.cookie.secure };
  const inflight = new Map(); // session token -> Promise<Session|null>; serialises refreshes per session
  let devUser = null;

  function loginUrl({ returnTo, acr, maxAge } = {}) {
    const q = new URLSearchParams();
    if (returnTo) q.set('return_to', returnTo);
    if (acr) { q.set('acr', acr); if (maxAge !== undefined && maxAge !== null) q.set('max_age', String(maxAge)); }
    const s = q.toString();
    return `${o.routePrefix}/login${s ? `?${s}` : ''}`;
  }

  const wantsHtml = (req) => String(req.headers.accept || '').includes('text/html');

  function deny(req, res, { stepUp } = {}) {
    const url = loginUrl({ returnTo: req.originalUrl, ...(stepUp || {}) });
    if (wantsHtml(req)) return res.redirect(302, url);
    return res.status(401).json({ error: stepUp ? 'step_up_required' : 'unauthorized', loginUrl: url });
  }

  function refreshSession(sess) {
    const t = sess.token;
    if (inflight.has(t)) return inflight.get(t);
    const p = (async () => {
      const fresh = await store.get(t); // re-read after acquiring the mutex: a sibling may have refreshed already
      if (!fresh) return null;
      const st = fresh.state;
      if (st.accessExpiresAt - REFRESH_SKEW_MS > o.now()) return fresh;
      if (st.refreshFailedAt && o.now() - st.refreshFailedAt < RETRY_BACKOFF_MS) { fresh.stale = true; return fresh; }
      let tokens;
      try {
        tokens = await oidc.refresh(st.refreshToken);
      } catch (e) {
        if (e.kind === 'invalid_grant') {
          await store.destroy(t);
          log.warn(`pw-auth: session ended — refresh rejected by the issuer (sub ${fresh.sub})`);
          return null;
        }
        log.error(`pw-auth: refresh failed (${e.kind}${e.status ? ` ${e.status}` : ''}): ${e.message} — serving the stale session for sub ${fresh.sub}`);
        fresh.state = { ...st, refreshFailedAt: o.now() };
        await store.setState(t, fresh.state);
        fresh.stale = true;
        return fresh;
      }
      let claims = tokens.claims;
      if (!claims) {
        try { claims = await oidc.userinfo(tokens.accessToken, fresh.sub); }
        catch (e) { log.error(`pw-auth: userinfo failed after refresh (${e.kind}): ${e.message} — keeping the previous roles`); claims = null; }
      }
      let user = st.user;
      if (claims) {
        claims = { ...claims, sub: fresh.sub };
        try { user = await o.resolveUser(claims, { tokens }); }
        catch (e) { log.error(`pw-auth: resolveUser threw on refresh: ${e.message} — keeping the previous user snapshot`); user = st.user; }
        if (!user || user.id === undefined || user.id === null) {
          await store.destroy(t);
          log.warn(`pw-auth: session ended — resolveUser returned no user on refresh (sub ${fresh.sub})`);
          return null;
        }
      }
      const now = o.now();
      fresh.state = {
        ...st,
        refreshToken: tokens.refreshToken || st.refreshToken,
        accessToken: tokens.accessToken,
        accessExpiresAt: now + tokens.expiresIn * 1000,
        idToken: tokens.idToken || st.idToken,
        roles: claims && Array.isArray(claims.roles) ? claims.roles : st.roles,
        acr: (claims && claims.acr) || st.acr,
        authTime: (claims && claims.auth_time) || st.authTime,
        user,
        refreshFailedAt: undefined,
      };
      await store.setState(t, fresh.state);
      fresh.stale = false;
      return fresh;
    })().finally(() => inflight.delete(t));
    inflight.set(t, p);
    return p;
  }

  async function requireAuth(req, res, next) {
    try {
      if (o.bypassAuth) {
        if (!devUser) devUser = await o.resolveUser({ ...DEV_CLAIMS, auth_time: Math.floor(o.now() / 1000) }, { tokens: null });
        req.user = devUser;
        req.auth = { sub: DEV_CLAIMS.sub, sid: null, roles: DEV_CLAIMS.roles, acr: DEV_CLAIMS.acr, authTime: Math.floor(o.now() / 1000), stale: false, bypass: true };
        req.pwSession = null;
        return next();
      }
      // The session cookie never accepts a pre-0.4.0 bare-name cookie as a live session (unlike the
      // state cookie in routes.js): dropping it just means a silent re-login through pwiam SSO,
      // simpler and safer than trusting an unprefixed cookie's value. Either way the stale cookie
      // must not linger, so its mere presence (legacyPresent) is still enough to clear it below.
      const { value: raw, legacyPresent } = getCookie(readCookies(req), o.cookie.name, cookieOpts.secure);
      const token = unsignValue(keys.cookieKey, raw);
      let sess = token ? await store.get(token) : null;
      if (sess && sess.expiresAt.getTime() <= o.now()) { await store.destroy(sess.token); sess = null; }
      if (sess && sess.state.accessExpiresAt - REFRESH_SKEW_MS <= o.now()) sess = await refreshSession(sess);
      if (!sess) {
        if (raw !== undefined || legacyPresent) clearCookie(res, o.cookie.name, cookieOpts);
        return deny(req, res);
      }
      req.user = sess.state.user;
      req.auth = { sub: sess.sub, sid: sess.sid, roles: sess.state.roles, acr: sess.state.acr, authTime: sess.state.authTime, stale: !!sess.stale, bypass: false };
      req.pwSession = sess;
      return next();
    } catch (e) { return next(e); }
  }

  function requireAcr(acr, { maxAge } = {}) {
    if (typeof acr !== 'string' || !acr) throw new Error('pw-auth: requireAcr needs an acr value');
    return (req, res, next) => {
      const check = () => {
        if (req.auth.bypass) return next();
        const fresh = maxAge === undefined || maxAge === null || Math.floor(o.now() / 1000) - (req.auth.authTime || 0) <= maxAge;
        if (req.auth.acr === acr && fresh) return next();
        // the issuer already refused this step-up once for this session: asking again is a redirect loop
        if (req.pwSession && req.pwSession.state.stepUpFailed === acr) {
          res.set('Cache-Control', 'no-store');
          return res.status(403).json({ error: 'step_up_failed', acr });
        }
        return deny(req, res, { stepUp: { acr, maxAge } });
      };
      if (req.auth) return check();
      return requireAuth(req, res, (err) => (err ? next(err) : check()));
    };
  }

  // Shared with the standalone apiKeyVerifier (lib/apiKeyVerifier.js) so the cache/grace/backoff/
  // shape-check logic exists exactly once; this instance is bound to the app's own oidc client
  // (already carrying its clientId/clientSecret) rather than building a second one.
  const apiKeyCache = createKeyCache({ introspect: oidc.introspectApiKey, now: o.now, cacheTtlMs: KEY_CACHE_MS, graceMs: KEY_GRACE_MS });
  function requireApiKey(kind) {
    if (typeof kind !== 'string' || !kind) throw new Error('pw-auth: requireApiKey needs a service-account kind');
    const reject = (res, message) => res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'unauthorized', message });
    return async (req, res, next) => {
      try {
        if (o.bypassAuth) {
          req.principal = { kind: 'service-account', id: 'dev', name: 'dev', saKind: kind, app: null, env: null, keyId: null, sub: 'sa:dev' };
          req.auth = { sub: 'sa:dev', roles: [], acr: null, authTime: null, stale: false, bypass: true, apiKey: true };
          return next();
        }
        const h = String(req.headers.authorization || '');
        if (!h.startsWith('Bearer ') || !h.slice(7).trim()) return reject(res, 'API key required');
        const key = h.slice(7).trim();
        let result;
        try {
          result = await apiKeyCache.verify(key);
        } catch (e) {
          log.error(`pw-auth: api-key introspection failed (${e.kind}${e.status ? ` ${e.status}` : ''}): ${e.message}`);
          return res.status(503).json({ error: 'auth_unavailable', message: 'API key verification is unavailable' });
        }
        // a failed introspection is backed off like a failed refresh: without this, every request
        // for the whole grace window re-dials a blackholed issuer and waits out the timeout
        if (result.error) {
          const e = result.error;
          log.error(`pw-auth: api-key introspection failed (${e.kind}${e.status ? ` ${e.status}` : ''}): ${e.message} — serving the cached verdict`);
        }
        const b = result.body || {};
        if (!b.active || !b.service_account || b.service_account.kind !== kind) return reject(res, 'API key rejected');
        req.principal = { kind: 'service-account', id: b.service_account.id, name: b.service_account.name, saKind: b.service_account.kind, app: b.app, env: b.env, keyId: b.key_id, sub: b.sub };
        req.auth = { sub: b.sub, roles: [], acr: null, authTime: null, stale: false, bypass: false, apiKey: true };
        return next();
      } catch (e) { return next(e); }
    };
  }

  // For apps that need to bind a pasted/out-of-band API key to something of their own (proof of
  // possession) rather than gate a route: same shape check as requireApiKey, but every call is a
  // fresh introspection — no cache, no grace. A binding is a rare, security-sensitive, user-driven
  // action, so it should reflect pwiam's verdict *right now*, not one that's up to 5 minutes stale.
  async function introspectApiKey(key) {
    if (!isValidApiKeyShape(key)) return { active: false };
    const body = await oidc.introspectApiKey(key);
    if (!body.active || !body.service_account) return { active: false };
    return {
      active: true,
      serviceAccount: { id: body.service_account.id, name: body.service_account.name, kind: body.service_account.kind },
      app: body.app,
      env: body.env,
      keyId: body.key_id,
      exp: body.exp,
    };
  }

  const UPSTREAM_CACHE_MAX = 1000;
  function capped(map, isExpired, now) {
    if (map.size < UPSTREAM_CACHE_MAX) return;
    for (const [k, v] of map) if (isExpired(v, now)) map.delete(k);
    while (map.size >= UPSTREAM_CACHE_MAX) map.delete(map.keys().next().value); // Map iterates in insertion order — oldest first
  }

  const upstreamCache = new Map(); // `${sessionToken}:${provider}` -> { accessToken, expiresAt }
  async function getUpstreamToken(req, provider) {
    if (!req.pwSession) throw new Error('pw-auth: getUpstreamToken: no user session on the request (not available under bypass or for API-key principals)');
    const k = `${req.pwSession.token}:${provider}`;
    const hit = upstreamCache.get(k);
    if (hit && hit.expiresAt - 60 * 1000 > o.now()) return hit;
    const t = await oidc.upstreamToken(provider, req.pwSession.state.accessToken);
    capped(upstreamCache, (v, now) => v.expiresAt <= now, o.now());
    upstreamCache.set(k, t);
    return t;
  }

  // Calls pwiam's /rp/* surface as the signed-in user (self-service device keys). The bearer proves
  // the user; the app's own client credentials (already held by this instance) prove the app —
  // both go in headers, never in the URL or body. Refreshes a near-expiry session first so the
  // bearer sent is never the one about to expire out from under the call.
  async function callIdp(req, method, path, body) {
    if (!req.pwSession) throw new Error('pw-auth: callIdp: no user session on the request (not available under bypass or for API-key principals)');
    let sess = req.pwSession;
    if (sess.state.accessExpiresAt - REFRESH_SKEW_MS <= o.now()) {
      sess = await refreshSession(sess);
      if (!sess) throw new OidcError('invalid_grant', 'session expired');
      // refreshSession serves a stale (pre-refresh) session when the issuer itself is unreachable.
      // That's the right call for requireAuth (keep the app usable), but callIdp must never send an
      // access token that's actually past its expiry — pwiam would 401 it anyway, and a caller that
      // can't tell "session expired" apart from "pwiam is down" would treat a transient outage as a
      // login failure.
      if (sess.stale && sess.state.accessExpiresAt <= o.now()) throw new OidcError('issuer_error', 'session could not be refreshed');
      req.pwSession = sess;
    }
    // rpCall is the single choke point for path validation (method allowlist, traversal/encoding
    // checks, origin+prefix confinement) — callIdp does not duplicate any of it here.
    return oidc.rpCall({ method, path, accessToken: sess.state.accessToken, body });
  }

  return { requireAuth, requireAcr, requireApiKey, introspectApiKey, getUpstreamToken, callIdp, loginUrl, deny, refreshSession, DEV_CLAIMS };
}

module.exports = { createMiddleware, DEV_CLAIMS, REFRESH_SKEW_MS, RETRY_BACKOFF_MS, KEY_CACHE_MS, KEY_GRACE_MS };
