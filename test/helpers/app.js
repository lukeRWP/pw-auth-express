'use strict';
const http = require('node:http');
const express = require('express');
const pwAuth = require('../../index');

async function startApp({ F, resolveUser, options = {}, extend } = {}) {
  const server = http.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const auth = pwAuth({
    issuer: F.issuer, clientId: F.clientId, clientSecret: F.clientSecret, allowInsecure: true, baseUrl,
    secret: 'app-cookie-secret', session: pwAuth.memorySession(), cookie: { secure: false },
    resolveUser: resolveUser || (async (c) => ({ id: 42, name: c.name, roles: c.roles })),
    logger: { info() {}, warn() {}, error() {} },
    ...options,
  });
  const app = express();
  app.use(auth.routes());
  app.get('/api/me', auth.requireAuth, (req, res) => res.json({ user: req.user, auth: req.auth }));
  app.get('/page', auth.requireAuth, (req, res) => res.type('html').send('<h1>hi</h1>'));
  if (extend) extend(app, auth);
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => res.status(500).json({ error: 'internal', message: err.message }));
  server.on('request', app);
  return { auth, baseUrl, close: () => new Promise((r) => server.close(r)) };
}

function agent(baseUrl) {
  const jar = new Map();
  async function req(path, { method = 'GET', headers = {}, body, redirect = 'manual' } = {}) {
    const url = path.startsWith('http') ? path : baseUrl + path;
    const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(url, { method, headers: { ...(cookie ? { cookie } : {}), ...headers }, body, redirect });
    for (const sc of res.headers.getSetCookie()) {
      const [kv, ...attrs] = sc.split(';');
      const i = kv.indexOf('='); const k = kv.slice(0, i).trim(); const v = kv.slice(i + 1);
      if (attrs.some((a) => /^\s*max-age=0$/i.test(a))) jar.delete(k); else jar.set(k, v);
    }
    return res;
  }
  return { req, jar };
}

async function loginVia(a, F, path = '/api/auth/login') {
  const r1 = await a.req(path, { headers: { accept: 'text/html' } });
  if (r1.status !== 302) throw new Error(`login answered ${r1.status}`);
  const cb = await F.authorize(r1.headers.get('location'));
  return a.req(cb, { headers: { accept: 'text/html' } });
}

module.exports = { startApp, agent, loginVia };
