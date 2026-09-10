'use strict';
const { readCookies, unsignValue, clearCookie } = require('./cookies');

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
        accessExpiresAt: now + (tokens.expiresIn || 0) * 1000,
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

  return { requireAuth, loginUrl, deny, refreshSession, DEV_CLAIMS };
}

module.exports = { createMiddleware, DEV_CLAIMS, REFRESH_SKEW_MS, RETRY_BACKOFF_MS };
