'use strict';
const crypto = require('node:crypto');
const { readCookies, unsignValue, clearCookie } = require('./cookies');

const REFRESH_SKEW_MS = 30 * 1000;   // refresh when the access token has < 30s left
const RETRY_BACKOFF_MS = 60 * 1000;  // after a transient refresh failure, don't hammer the issuer
const KEY_CACHE_MS = 60 * 1000;      // introspection verdicts are reused for a minute
const KEY_GRACE_MS = 5 * 60 * 1000;  // ...and up to five more minutes when pwiam is unreachable
const KEY_CACHE_MAX = 1000;

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
      const raw = readCookies(req)[o.cookie.name];
      const token = unsignValue(keys.cookieKey, raw);
      let sess = token ? await store.get(token) : null;
      if (sess && sess.expiresAt.getTime() <= o.now()) { await store.destroy(sess.token); sess = null; }
      if (sess && sess.state.accessExpiresAt - REFRESH_SKEW_MS <= o.now()) sess = await refreshSession(sess);
      if (!sess) {
        if (raw) clearCookie(res, o.cookie.name, cookieOpts);
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

  function capped(map, isExpired, now) {
    if (map.size < KEY_CACHE_MAX) return;
    for (const [k, v] of map) if (isExpired(v, now)) map.delete(k);
    while (map.size >= KEY_CACHE_MAX) map.delete(map.keys().next().value); // Map iterates in insertion order — oldest first
  }

  const keyCache = new Map(); // sha256(key) -> { body, fetchedAt }
  const keyInflight = new Map(); // sha256(key) -> Promise<body>; de-dupes concurrent cold introspections
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
        const ck = crypto.createHash('sha256').update(key).digest('hex');
        const now = o.now();
        let entry = keyCache.get(ck);
        const usable = entry && now - entry.fetchedAt < KEY_CACHE_MS + KEY_GRACE_MS;
        // a failed introspection is backed off like a failed refresh: without this, every request
        // for the whole grace window re-dials a blackholed issuer and waits out the timeout
        const backedOff = usable && entry.failedAt !== undefined && now - entry.failedAt < RETRY_BACKOFF_MS;
        if ((!entry || now - entry.fetchedAt >= KEY_CACHE_MS) && !backedOff) {
          try {
            let p = keyInflight.get(ck);
            if (!p) {
              p = oidc.introspectApiKey(key)
                .then((body) => {
                  const fresh = { body, fetchedAt: now };
                  capped(keyCache, (v, n) => n - v.fetchedAt > KEY_CACHE_MS + KEY_GRACE_MS, now);
                  keyCache.set(ck, fresh);
                  return fresh;
                })
                .finally(() => keyInflight.delete(ck));
              keyInflight.set(ck, p);
            }
            entry = await p;
          } catch (e) {
            if (e.kind === 'issuer_error' && usable) {
              entry.failedAt = now;
              log.error(`pw-auth: api-key introspection failed (${e.kind}${e.status ? ` ${e.status}` : ''}): ${e.message} — serving the cached verdict`);
            } else {
              log.error(`pw-auth: api-key introspection failed (${e.kind}${e.status ? ` ${e.status}` : ''}): ${e.message}`);
              return res.status(503).json({ error: 'auth_unavailable', message: 'API key verification is unavailable' });
            }
          }
        }
        const b = entry.body || {};
        if (!b.active || !b.service_account || b.service_account.kind !== kind) return reject(res, 'API key rejected');
        req.principal = { kind: 'service-account', id: b.service_account.id, name: b.service_account.name, saKind: b.service_account.kind, app: b.app, env: b.env, keyId: b.key_id, sub: b.sub };
        req.auth = { sub: b.sub, roles: [], acr: null, authTime: null, stale: false, bypass: false, apiKey: true };
        return next();
      } catch (e) { return next(e); }
    };
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

  return { requireAuth, requireAcr, requireApiKey, getUpstreamToken, loginUrl, deny, refreshSession, DEV_CLAIMS };
}

module.exports = { createMiddleware, DEV_CLAIMS, REFRESH_SKEW_MS, RETRY_BACKOFF_MS, KEY_CACHE_MS, KEY_GRACE_MS };
