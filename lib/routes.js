'use strict';
const express = require('express');
const client = require('openid-client');
const { readCookies, signValue, unsignValue, setCookie, clearCookie } = require('./cookies');
const { seal, open } = require('./crypto');

const STATE_COOKIE = 'pw_auth_state';
const STATE_TTL_MS = 5 * 60 * 1000;

// return_to must be a same-origin path: starts with one '/', not '//' or '/\' (protocol-relative escapes)
const safePath = (v) => (typeof v === 'string' && /^\/(?![/\\])/.test(v) ? v : null);
const wantsHtml = (req) => String(req.headers.accept || '').includes('text/html');

function createRoutes(ctx, mw) {
  const { o, keys, oidc, store, redirectUri, log } = ctx;
  const cookieOpts = { secure: o.cookie.secure };
  const router = express.Router();

  router.get(`${o.routePrefix}/login`, async (req, res, next) => {
    try {
      if (o.bypassAuth) return res.status(503).json({ error: 'bypass', message: 'BYPASS_AUTH is on — there is no login; unset it to authenticate against pwiam' });
      const codeVerifier = client.randomPKCECodeVerifier();
      const state = client.randomState();
      const nonce = client.randomNonce();
      const returnTo = safePath(req.query.return_to) || o.postLoginRedirect;
      const acr = typeof req.query.acr === 'string' && /^[a-z][a-z-]{0,31}$/.test(req.query.acr) ? req.query.acr : undefined;
      const maxAge = acr && typeof req.query.max_age === 'string' && /^\d{1,7}$/.test(req.query.max_age) ? Number(req.query.max_age) : undefined;
      const url = await oidc.authorizationUrl({ redirectUri, state, nonce, codeVerifier, acrValues: acr, maxAge, prompt: acr ? 'login' : undefined });
      // stepUp rides in the state cookie so the callback can tell whether the issuer actually
      // honoured acr_values — if it didn't, a second denial must be terminal, not another redirect.
      const sealed = seal(keys.sealKey, { codeVerifier, state, nonce, returnTo, exp: o.now() + STATE_TTL_MS, stepUp: acr ? { acr, maxAge } : undefined });
      setCookie(res, STATE_COOKIE, sealed, { ...cookieOpts, maxAge: STATE_TTL_MS });
      return res.redirect(302, url);
    } catch (e) { return next(e); }
  });

  router.get(new URL(redirectUri).pathname, async (req, res, next) => {
    const fail = (why, err) => {
      log.warn(`pw-auth: login failed — ${why}${err ? `: ${err.message}` : ''}`);
      clearCookie(res, STATE_COOKIE, cookieOpts);
      return res.redirect(302, o.loginErrorRedirect);
    };
    try {
      const cookies = readCookies(req);
      let st;
      try { st = open(keys.sealKey, cookies[STATE_COOKIE]); } catch { return fail('no valid state cookie'); }
      if (st.exp < o.now()) return fail('state cookie expired');
      let tokens;
      try {
        tokens = await oidc.exchangeCode({ currentUrl: new URL(req.originalUrl, o.baseUrl), codeVerifier: st.codeVerifier, state: st.state, nonce: st.nonce });
      } catch (e) { return fail(`code exchange (${e.kind})`, e); }
      const claims = tokens.claims;
      let user;
      try { user = await o.resolveUser(claims, { tokens }); } catch (e) { return fail('resolveUser threw', e); }
      if (!user || user.id === undefined || user.id === null) return fail('resolveUser returned no user');
      const prev = unsignValue(keys.cookieKey, cookies[o.cookie.name]);
      if (prev) await store.destroy(prev); // a re-login (e.g. step-up) replaces the browser's existing session
      const now = o.now();
      const authTime = claims.auth_time || Math.floor(now / 1000);
      const state = {
        refreshToken: tokens.refreshToken, accessToken: tokens.accessToken, accessExpiresAt: now + tokens.expiresIn * 1000, idToken: tokens.idToken,
        acr: claims.acr || null, authTime, roles: Array.isArray(claims.roles) ? claims.roles : [], user,
      };
      if (st.stepUp) {
        const acrOk = claims.acr === st.stepUp.acr;
        const age = Math.floor(now / 1000) - authTime;
        const ageOk = st.stepUp.maxAge === undefined || age <= st.stepUp.maxAge;
        if (!acrOk || !ageOk) {
          state.stepUpFailed = st.stepUp.acr;   // requireAcr answers 403 instead of asking again
          const why = !acrOk ? `issuer returned acr ${claims.acr || 'none'}` : `auth_time is ${age}s old against max_age ${st.stepUp.maxAge} (prompt=login not honoured, or clock skew)`;
          log.warn(`pw-auth: step-up to ${st.stepUp.acr} failed — ${why} — the login stands, the guarded route will refuse`);
        }
      }
      const token = await store.create({
        userId: user.id, sub: claims.sub, sid: claims.sid || null, expiresAt: new Date(now + o.sessionMaxAge), state,
      });
      clearCookie(res, STATE_COOKIE, cookieOpts);
      setCookie(res, o.cookie.name, signValue(keys.cookieKey, token), { ...cookieOpts, maxAge: o.sessionMaxAge });
      return res.redirect(302, st.returnTo || o.postLoginRedirect);
    } catch (e) { return next(e); }
  });

  router.get(`${o.routePrefix}/session`, mw.requireAuth, (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ user: req.user, auth: req.auth });
  });

  router.post(`${o.routePrefix}/logout`, async (req, res, next) => {
    try {
      const cookies = readCookies(req);
      const token = unsignValue(keys.cookieKey, cookies[o.cookie.name]);
      const sess = token ? await store.get(token) : null;
      if (token) await store.destroy(token);
      if (cookies[o.cookie.name] !== undefined) clearCookie(res, o.cookie.name, cookieOpts);
      const postLogout = new URL(o.postLogoutRedirect, o.baseUrl).href;
      let url = postLogout;
      if (sess && !o.bypassAuth) {
        try { url = await oidc.endSessionUrl({ idToken: sess.state.idToken, postLogoutRedirectUri: postLogout }); }
        catch (e) { log.error(`pw-auth: end-session URL unavailable (${e.kind || e.name}): ${e.message} — local logout only`); }
      }
      res.set('Cache-Control', 'no-store');
      if (wantsHtml(req)) return res.redirect(302, url);
      return res.json({ redirect: url });
    } catch (e) { return next(e); }
  });

  // OIDC Back-Channel Logout 1.0: the issuer POSTs a logout_token when the user's pwiam session ends.
  const seenJti = new Map(); // jti -> forget-after (ms)
  const JTI_TTL_MS = 5 * 60 * 1000;
  const noStore = (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }; // set before the parser: it applies to the parser's own errors too
  router.post(`${o.routePrefix}/backchannel-logout`, noStore, express.urlencoded({ extended: false, limit: '16kb' }), async (req, res, next) => {
    try {
      const token = req.body && req.body.logout_token;
      if (typeof token !== 'string' || !token) return res.status(400).json({ error: 'invalid_request', message: 'logout_token required' });
      let lt;
      try { lt = await oidc.verifyLogoutToken(token, { now: o.now() }); }
      catch (e) {
        log.warn(`pw-auth: back-channel logout rejected: ${e.message}`);
        return res.status(400).json({ error: 'invalid_request', message: 'logout_token rejected' });
      }
      const now = o.now();
      for (const [j, until] of seenJti) if (until < now) seenJti.delete(j);
      if (seenJti.has(lt.jti)) {
        log.warn(`pw-auth: back-channel logout rejected: replayed jti`);
        return res.status(400).json({ error: 'invalid_request', message: 'logout_token replayed' });
      }
      seenJti.set(lt.jti, now + JTI_TTL_MS);
      const n = lt.sid ? await store.destroyBySid(lt.sid) : await store.destroyBySub(lt.sub);
      log.info(`pw-auth: back-channel logout — ${n} session(s) ended (${lt.sid ? `sid ${lt.sid}` : `sub ${lt.sub}`})`);
      return res.status(200).end();
    } catch (e) { return next(e); }
  // eslint-disable-next-line no-unused-vars
  }, (err, req, res, next) => {
    if (typeof err.type !== 'string') return next(err); // body-parser errors carry a type; anything else is our fault, not the issuer's
    log.warn(`pw-auth: back-channel logout rejected: malformed body (${err.type})`);
    return res.status(400).json({ error: 'invalid_request', message: 'malformed body' });
  });

  return router;
}

module.exports = { createRoutes, STATE_COOKIE, STATE_TTL_MS };
