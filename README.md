# @pw/auth-express

Express auth shim for Prevailing Winds apps. Puts `pwiam` (OIDC) in front of an app: login, callback, sealed server-side sessions with refresh, back-channel logout, step-up (`acr`), API-key principals for service accounts, and upstream (Entra) token exchange.

Spec: `prevailing-winds/docs/superpowers/specs/2026-09-08-pw-iam-design.md` §7.

## Install

Consumed as a git tag (no registry):

```json
"dependencies": { "@pw/auth-express": "github:lukeRWP/pw-auth-express#v0.4.1" }
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
| `cookie` | `{ name: 'session_token', secure: true }` | `secure: false` only for local http — see Cookies below |
| `bypassAuth` | `process.env.BYPASS_AUTH === 'true'` | dev only: `req.user = resolveUser(DEV_CLAIMS)`, `/login` → 503 |
| `timeoutSec` | `10` | per-request timeout on every call to pwiam (discovery, token, introspection, upstream) |
| `logger` | `console` | needs `info/warn/error` |
| `now`, `fetch`, `allowInsecure` | `Date.now`, global, `false` | test hooks |

## Cookies

Two cookies, both named/set/cleared through one helper (`lib/cookies.js`): the session cookie
(`cookie.name`, default `session_token`) and the OIDC state/PKCE/CSRF-double-submit cookie
(`pw_auth_state`, fixed). When `cookie.secure` is true (the default — production), both carry the
`__Host-` prefix: `__Host-session_token`, `__Host-pw_auth_state`. Browsers enforce `__Host-` by
refusing the cookie unless the response also sets `Secure`, `Path=/` and omits `Domain` — which in
exchange guarantees that no sibling (sub)domain, and nothing else able to set a cookie for the
shared parent domain, can toss or fixate either one. With `cookie.secure: false` (local http,
`__Host-` cookies are rejected by browsers outright), both keep their plain, unprefixed names.

Upgrading a deployment past 0.4.0 crosses a cookie rename, handled per cookie:

- The **session cookie** treats a pre-0.4.0 bare-name cookie as absent rather than trusting its
  value — the user is silently re-authenticated through pwiam SSO (the login redirect round-trips
  without them re-entering credentials).
- The **state/CSRF cookie** accepts one read of the pre-0.4.0 bare name when the current name is
  absent, so a login started just before an upgrade still completes when its callback lands just
  after — there's no SSO fallback for a lost mid-flight login, only a dead-end error page.
- Either way, both names get cleared (logout, a rejected session, or once the state cookie is
  consumed) so a stale pre-0.4.0 cookie never lingers in the browser.

**If your app's own CSRF middleware decides "is there a session" by checking the literal
`session_token` cookie name** (as tally's, docket's, daybook's and blueprint's all do today), update
that check to the `__Host-` name alongside — not before, not after — bumping that app's pin past
0.4.0 in production. Otherwise the check always reads "no session" once this shim starts naming the
cookie `__Host-session_token`, and CSRF validation silently stops running for every state-changing
request. This failure mode is entirely in the consuming app; this package's tests cannot see it.

## API keys

Three ways to work with pwiam's service-account API keys, all sharing one local shape check —
`pwk_<16-hex keyId>_<43-char secret>` — so anything else is refused before it ever costs a network
call or a cache entry:

- **`auth.requireApiKey(kind)`** — Express middleware that gates a route to service accounts of the
  given `kind` (shown under Use, above): 401 without a matching bearer, sets `req.principal`/`req.auth`
  on success. 60 s cache, 5-minute grace on a pwiam outage (429 included).
- **`auth.introspectApiKey(key)`** — for proof-of-possession binding, not route-gating: hand it a key
  an app received out of band (pasted by a user, sent by a device) and get back
  `{ active, serviceAccount: { id, name, kind }, app, env, keyId, exp }` or `{ active: false }`, using
  the app's own client credentials and the same shape check as `requireApiKey`.

  ```js
  const introspection = await auth.introspectApiKey(req.body.deviceKey);
  if (!introspection.active) return res.status(400).json({ error: 'invalid_key' });
  ```

  Deliberately **uncached** — unlike `requireApiKey`, every call is a fresh introspection. A binding is
  a rare, security-sensitive, user-driven action, so it should reflect pwiam's verdict *right now*
  rather than one that's already up to 5 minutes stale from `requireApiKey`'s cache; the two caches
  (or lack thereof) are independent, and that's intentional.
- **`pwAuth.apiKeyVerifier({ issuer, clientId, clientSecret, fetch?, timeoutSec?, allowInsecure?, now?, cacheTtlMs?, graceMs? })`**
  — a standalone factory for a service that can't construct the full login config (no
  `baseUrl`/`secret`/`session`/`resolveUser`) but still needs to verify pwiam API keys — e.g. the PW
  orchestrator, which reaches the issuer through a proxy, hence the injectable `fetch`. Returns
  `{ verify(key) }` with the same shape-check/cache/grace/backoff semantics as `requireApiKey`:
  `verify()` resolves pwiam's introspection body verbatim (`{ active: false }` for an inactive or
  malformed key) and rejects once there's no usable verdict left to serve.

  ```js
  const verifier = pwAuth.apiKeyVerifier({ issuer, clientId, clientSecret, fetch: viaProxy });
  const body = await verifier.verify(key);
  if (!body.active) return res.status(401).end();
  ```

**Binding pattern.** pwiam API keys carry no user or resource binding of their own — they identify a
service account, not a person or a thing. If your app needs one (e.g. daybook binding a pasted device
key to the signed-in user, so the device can post on their behalf later), record it yourself, keyed by
the service account's **id**, never its **name** — a name isn't guaranteed stable or unique, an id is:

```js
await db.deviceBindings.upsert({ userId: req.user.id, serviceAccountId: introspection.serviceAccount.id });
```

## Calling pwiam as the signed-in user

`auth.callIdp(req, method, path, body?)` calls pwiam's `/rp/*` routes (self-service, user-driven
actions — e.g. minting or revoking the user's own device keys) as the signed-in user: the session's
access token goes as the `Authorization: Bearer` header (proves the user), and the app's own
`clientId`/`clientSecret` go as `X-PW-Client-Id`/`X-PW-Client-Secret` headers (proves the app) —
never in the URL or body, where a query string would land in access and proxy logs.

```js
app.post('/api/device-keys', auth.requireAuth, async (req, res, next) => {
  try {
    const { status, body } = await auth.callIdp(req, 'POST', '/rp/device-keys', { kind: 'location-ingest', label: req.body.label });
    res.status(status).json(body);
  } catch (e) { next(e); }
});
```

It resolves to `{ status, body }` for **every** HTTP status pwiam answers with, including 4xx/5xx —
callers decide what a `409 limit_reached` means, `callIdp` doesn't swallow it. A `204` resolves as
`{ status: 204, body: null }`. **Redirects are never followed** — `fetch` is called with
`redirect: 'manual'`, so a `3xx` from pwiam also resolves as `{ status, body: null }` rather than
being chased; a 3xx pointed cross-origin would otherwise leak the bearer and (fetch's default
redirect handling only strips `Authorization`, not custom headers) the app's own client secret to
whatever it points at.

`path` is treated as hostile input — it reaches pwiam carrying `X-PW-Client-Secret`, so `rpCall` (the
one choke point behind `callIdp`; there is no second check anywhere else) resolves it against the
issuer's base URL and rejects it, with a fixed message that never echoes the path back, unless
**all** of the following hold: it starts with `/rp/`; it contains none of `\`, tab, `\r`, `\n`,
`%2e`, `%2f` or `%5c` (case-insensitive — blocks percent-encoded and backslash traversal); none of
its `/`-separated segments (before any `?`) is `.` or `..`; and the resolved URL's origin and path
prefix still land inside `<issuer>/rp/`. Anything that fails any of those throws
`Error('pw-auth: callIdp: invalid path')`. `method` must be one of `GET`/`POST`/`PUT`/`PATCH`/`DELETE` (case-insensitive)
(anything else throws `Error('pw-auth: callIdp: unsupported method')`), and a `GET` may not carry a
`body` (throws `Error('pw-auth: callIdp: GET requests cannot carry a body')`).

Requires a real user session (`req.pwSession`): throws `Error('pw-auth: callIdp: no user session on
the request (not available under bypass or for API-key principals)')` under `bypassAuth` or for
`requireApiKey` principals. If the session is near expiry it's refreshed first (same
`REFRESH_SKEW_MS` as `requireAuth`, and this refresh is `callIdp`'s own — it doesn't rely on
`requireAuth` having already done it for the same request). If that refresh is rejected outright,
throws `OidcError('invalid_grant', 'session expired')`. If the issuer can't be reached to refresh and
the access token is already past its actual expiry (not just inside the skew window), `callIdp` never
sends the stale bearer — it throws `OidcError('issuer_error', 'session could not be refreshed')`
instead. A transport failure or timeout talking to pwiam throws `OidcError('issuer_error')`.

## Behaviour that matters in production

- Access tokens are opaque and never checked locally; roles come from the ID token at login and every refresh. A role change lands within 15 minutes.
- Only `invalid_grant` from the issuer ends a session. A pwiam outage (5xx/timeout) serves the last-known session and retries once a minute — apps keep working; `logger.error` lines say `serving the stale session`.
- `requireAcr` asks for a step-up login once (401 `step_up_required`, or a 302 for a browser). If the issuer answers without the requested `acr`, the login still succeeds but the guarded route then answers `403 { error: 'step_up_failed', acr }` — terminal, so a pwiam that cannot do `webauthn` produces an error page, not a redirect loop. The next successful step-up login clears it.
- API-key verdicts cache 60 s and survive a pwiam outage for 5 more minutes; a 429 (rate limited) from introspection gets the same treatment as a 5xx — cached verdict, then backs off — not an immediate failure.
- `requireApiKey`, `introspectApiKey` and `apiKeyVerifier` all reject a bearer that isn't shaped like a pwiam API key (`pwk_<16-hex keyId>_<43-char secret>`) before it costs a network call or a cache entry.
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
