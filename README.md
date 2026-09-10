# @pw/auth-express

Express auth shim for Prevailing Winds apps. Puts `pwiam` (OIDC) in front of an app: login, callback, sealed server-side sessions with refresh, back-channel logout, step-up (`acr`), API-key principals for service accounts, and upstream (Entra) token exchange.

Spec: `prevailing-winds/docs/superpowers/specs/2026-09-08-pw-iam-design.md` §7.

## Install

Consumed as a git tag (no registry):

```json
"dependencies": { "@pw/auth-express": "github:lukeRWP/pw-auth-express#v0.1.0" }
```

Node ≥ 22.12, Express 4 or 5.

## Use

```js
const pwAuth = require('@pw/auth-express');
const auth = pwAuth({
  issuer: 'https://id.razorwire-productions.com',
  clientId: process.env.PW_IAM_CLIENT_ID,
  clientSecret: process.env.PW_IAM_CLIENT_SECRET,
  baseUrl: 'https://tally.razorwire-productions.com',
  secret: process.env.COOKIE_SECRET,            // one secret → HKDF cookie-signing + state/session sealing keys
  session: pwAuth.mysqlSession(db),             // or pwAuth.memorySession() for tests
  resolveUser: async (claims) => users.upsertFromIam(claims),   // claims.sub / name / email / roles / entra_oid
});
app.use(auth.routes());                          // /api/auth/login, /callback, /session, /logout, /backchannel-logout
app.get('/api/items', auth.requireAuth, handler);                          // req.user, req.auth
app.post('/api/admin/wipe', auth.requireAcr('webauthn', { maxAge: 300 }), handler);
app.post('/api/print', auth.requireApiKey('print-agent'), handler);       // req.principal
const { accessToken } = await auth.getUpstreamToken(req, 'entra');
const url = auth.loginUrl({ returnTo: '/reports', acr: 'webauthn', maxAge: 300 });   // build a (step-up) login URL for your own redirects
await auth.close();                              // on shutdown: closes the session adapter if it has close()
```

`resolveUser(claims, { tokens })` must return the app's user row (becomes `req.user`) or `null` to refuse the login. It runs at login and on every token refresh (~15 min). Pattern for apps migrating from Entra-direct login:

```js
async function resolveUser(c) {
  let u = await users.bySub(c.sub);
  if (!u && c.entra_oid) { u = await users.byEntraId(c.entra_oid); if (u) await users.setSub(u.ID, c.sub); }
  if (!u) u = await users.insert({ SUB: c.sub, NAME: c.name, EMAIL: c.email });
  return { ...u, roles: c.roles };
}
```

## Options

| option | default | notes |
|---|---|---|
| `issuer`, `clientId`, `clientSecret`, `baseUrl`, `secret`, `session`, `resolveUser` | — | required; `secret` must be ≥32 chars |
| `redirectPath` | `/api/auth/callback` | must match the client's registered redirect URI (pw.json `iam.redirectUris`) |
| `routePrefix` | `/api/auth` | |
| `postLoginRedirect` / `loginErrorRedirect` / `postLogoutRedirect` | `/`, `/login?error=auth_failed`, `/` | |
| `sessionMaxAge` | 86400000 (24 h) | cookie + row lifetime; pwiam's refresh token (30 d) outlives it |
| `cookie` | `{ name: 'session_token', secure: true }` | |
| `bypassAuth` | `process.env.BYPASS_AUTH === 'true'` | dev only: `req.user = resolveUser(DEV_CLAIMS)`, `/login` → 503 |
| `logger` | `console` | needs `info/warn/error` |
| `now`, `fetch`, `allowInsecure` | `Date.now`, global, `false` | test hooks |

## Behaviour that matters in production

- Access tokens are opaque and never checked locally; roles come from the ID token at login and every refresh. A role change lands within 15 minutes.
- Only `invalid_grant` from the issuer ends a session. A pwiam outage (5xx/timeout) serves the last-known session and retries once a minute — apps keep working; `logger.error` lines say `serving the stale session`.
- API-key verdicts cache 60 s and survive a pwiam outage for 5 more minutes.
- Back-channel logout ends sessions by `sid`, or all of a user's sessions by `sub`.

## Session table (MySQL)

```sql
ALTER TABLE sessions
  ADD COLUMN SUB VARCHAR(64) NULL, ADD COLUMN SID VARCHAR(64) NULL, ADD COLUMN IAM_STATE TEXT NULL,
  ADD INDEX IDX_SESSIONS_SID (SID), ADD INDEX IDX_SESSIONS_SUB (SUB);
ALTER TABLE users ADD COLUMN SUB VARCHAR(26) NULL, ADD UNIQUE INDEX UQ_USERS_SUB (SUB);
```

`pwAuth.mysqlSession(db, { table, columns })` — `db.query(sql, params)` may return rows or mysql2's `[rows, fields]`.

## Develop

`npm ci --no-audit && npm test` (node:test against an in-process fake issuer; no network).
