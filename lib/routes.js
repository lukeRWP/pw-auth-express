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
      const sealed = seal(keys.sealKey, { codeVerifier, state, nonce, returnTo, exp: o.now() + STATE_TTL_MS });
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
      const token = await store.create({
        userId: user.id, sub: claims.sub, sid: claims.sid || null, expiresAt: new Date(now + o.sessionMaxAge),
        state: {
          refreshToken: tokens.refreshToken, accessToken: tokens.accessToken, accessExpiresAt: now + (tokens.expiresIn || 0) * 1000, idToken: tokens.idToken,
          acr: claims.acr || null, authTime: claims.auth_time || Math.floor(now / 1000), roles: Array.isArray(claims.roles) ? claims.roles : [], user,
        },
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

  return router;
}

module.exports = { createRoutes, STATE_COOKIE, STATE_TTL_MS };
