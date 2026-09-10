'use strict';
const { deriveKeys } = require('./lib/crypto');
const { createOidc } = require('./lib/oidc');
const { createSessionStore } = require('./lib/sessions');
const { createMiddleware } = require('./lib/middleware');
const { createRoutes } = require('./lib/routes');
const { memorySession } = require('./lib/session/memory');
const { mysqlSession } = require('./lib/session/mysql');

const REQUIRED = ['issuer', 'clientId', 'clientSecret', 'baseUrl', 'secret', 'session', 'resolveUser'];

function pwAuth(options = {}) {
  for (const k of REQUIRED) if (!options[k]) throw new Error(`pw-auth: option "${k}" is required`);
  if (typeof options.resolveUser !== 'function') throw new Error('pw-auth: resolveUser must be a function');
  const o = {
    redirectPath: '/api/auth/callback', routePrefix: '/api/auth',
    postLoginRedirect: '/', loginErrorRedirect: '/login?error=auth_failed', postLogoutRedirect: '/',
    sessionMaxAge: 24 * 60 * 60 * 1000,
    bypassAuth: process.env.BYPASS_AUTH === 'true',
    logger: console, fetch: undefined, now: Date.now, allowInsecure: false,
    ...options,
    cookie: { name: 'session_token', secure: true, ...(options.cookie || {}) },
  };
  const keys = deriveKeys(o.secret);
  const oidc = createOidc({ issuer: o.issuer, clientId: o.clientId, clientSecret: o.clientSecret, fetch: o.fetch, allowInsecure: o.allowInsecure, now: o.now });
  const store = createSessionStore({ adapter: o.session, sealKey: keys.sealKey, now: o.now });
  const ctx = { o, keys, oidc, store, redirectUri: new URL(o.redirectPath, o.baseUrl).href, log: o.logger };
  const mw = createMiddleware(ctx);
  return {
    routes: () => createRoutes(ctx, mw),
    requireAuth: mw.requireAuth,
    requireAcr: mw.requireAcr,
    requireApiKey: mw.requireApiKey,
    getUpstreamToken: mw.getUpstreamToken,
    loginUrl: mw.loginUrl,
    sweepExpiredSessions: () => store.sweepExpired(),
    close: async () => { if (typeof o.session.close === 'function') await o.session.close(); },
  };
}

pwAuth.memorySession = memorySession;
pwAuth.mysqlSession = mysqlSession;

module.exports = pwAuth;
