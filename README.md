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

`resolveUser(claims, { tokens })` must return the app's user row (becomes `req.user`) or `null` to refuse the login. It runs at login and on every token refresh (~15 min). Whatever it returns is sealed into the session row **and** served verbatim by `GET /api/auth/session` — return a projection, not a raw DB row with a password hash in it. Pattern for apps migrating from Entra-direct login:

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
| `timeoutSec` | `10` | per-request timeout on every call to pwiam (discovery, token, introspection, upstream) |
| `logger` | `console` | needs `info/warn/error` |
| `now`, `fetch`, `allowInsecure` | `Date.now`, global, `false` | test hooks |

## Behaviour that matters in production

- Access tokens are opaque and never checked locally; roles come from the ID token at login and every refresh. A role change lands within 15 minutes.
- Only `invalid_grant` from the issuer ends a session. A pwiam outage (5xx/timeout) serves the last-known session and retries once a minute — apps keep working; `logger.error` lines say `serving the stale session`.
- `requireAcr` asks for a step-up login once (401 `step_up_required`, or a 302 for a browser). If the issuer answers without the requested `acr`, the login still succeeds but the guarded route then answers `403 { error: 'step_up_failed', acr }` — terminal, so a pwiam that cannot do `webauthn` produces an error page, not a redirect loop. The next successful step-up login clears it.
- API-key verdicts cache 60 s and survive a pwiam outage for 5 more minutes.
- Back-channel logout ends sessions by `sid`; a token carrying both uses `sid` and leaves the user's other sessions alone. `sub` alone ends all of them.
- The refresh mutex and the back-channel `jti` guard are per-process. Scale out and both weaken: a replayed `jti` becomes an idempotent no-op on another instance (still safe), but two instances refreshing one session can race and get the whole refresh family revoked.
- Discovery metadata is fetched once and cached for the life of the process — moving a pwiam endpoint needs an app restart, not just a pwiam deploy.
- Two logins started at once in one browser share the one state cookie: the second overwrites it, so the first callback loses — `login failed — code exchange`, and the user simply logs in again.

## Session table (MySQL)

The adapter reads and writes exactly these six columns (rename any of them with `columns`):

| column | type | holds |
|---|---|---|
| `TOKEN` | `CHAR(64)` primary key | the opaque session token from the cookie |
| `USER_ID` | the app's own user id type | whatever `resolveUser` returned as `id` |
| `SUB` | `VARCHAR(64) NULL` | pwiam subject — back-channel logout by user |
| `SID` | `VARCHAR(64) NULL` | pwiam session id — back-channel logout by session |
| `EXPIRES_AT` | `DATETIME NOT NULL` | absolute session expiry (`sessionMaxAge`) |
| `IAM_STATE` | `TEXT NULL` | the sealed blob: refresh/access/ID tokens, roles, user snapshot |

`create()` inserts those six and nothing else, so any **other** `NOT NULL` column without a default on the app's table will break it.

Greenfield:

```sql
CREATE TABLE sessions (
  TOKEN CHAR(64) NOT NULL PRIMARY KEY,
  USER_ID BIGINT NOT NULL,
  SUB VARCHAR(64) NULL,
  SID VARCHAR(64) NULL,
  EXPIRES_AT DATETIME NOT NULL,
  IAM_STATE TEXT NULL,
  INDEX IDX_SESSIONS_SID (SID),
  INDEX IDX_SESSIONS_SUB (SUB),
  INDEX IDX_SESSIONS_EXPIRES_AT (EXPIRES_AT)
);
```

An app that already has a `sessions` table:

```sql
ALTER TABLE sessions
  ADD COLUMN SUB VARCHAR(64) NULL, ADD COLUMN SID VARCHAR(64) NULL, ADD COLUMN IAM_STATE TEXT NULL,
  ADD INDEX IDX_SESSIONS_SID (SID), ADD INDEX IDX_SESSIONS_SUB (SUB);
ALTER TABLE users ADD COLUMN SUB VARCHAR(26) NULL, ADD UNIQUE INDEX UQ_USERS_SUB (SUB);
```

`pwAuth.mysqlSession(db, { table, columns })` — `db.query(sql, params)` may return rows or mysql2's `[rows, fields]`. `table` accepts `schema.table` (e.g. `'TALLY.sessions'`).

Every expiry comparison binds a JS `Date`, so the pool wants `timezone: '+00:00'` and `dateStrings: false` — otherwise the driver and the column disagree about what the timestamp means.

Call `auth.sweepExpiredSessions()` on an interval (e.g. hourly); the shim never deletes expired rows on its own.

A custom adapter implements `create(row)`, `get(token)`, `update(token, patch)`, `destroy(token)`, `destroyBySid(sid)`, `destroyBySub(sub)`, `deleteExpired(now)` (returns the count; `sweepExpiredSessions()` throws without it) and optionally `close()`. `lib/session/memory.js` is the reference implementation.

## Develop

`npm ci --no-audit && npm test` (node:test against an in-process fake issuer; no network).
