# Changelog

## 0.4.0

Security hardening (M8): every cookie this shim sets now uses the `__Host-` prefix when configured
secure — the session cookie (`cookie.name`, default `session_token`) and the OIDC state/PKCE/CSRF
double-submit cookie (`pw_auth_state`), becoming `__Host-session_token` and `__Host-pw_auth_state`.
`__Host-` is enforced browser-side (Secure, `Path=/`, no `Domain`), which is exactly what stops a
sibling subdomain under the shared parent domain — or anything able to set a cookie for it — from
tossing or fixating either cookie. All naming, setting, and clearing now goes through one helper
(`lib/cookies.js`); see its `cookieName`/`setCookie`/`clearCookie`/`getCookie`.

- **Dev fallback**: with `cookie.secure: false` (local http), cookies keep their plain, unprefixed
  names exactly as before — browsers reject `__Host-` cookies outright over a non-TLS origin.
- **Upgrade migration, one-time**: a browser still holding a pre-0.4.0 cookie is handled differently
  per cookie, because they have different failure modes:
  - The **session cookie** treats a pre-0.4.0 bare-name cookie as absent rather than trusting its
    value. The user is silently re-authenticated through pwiam SSO (the redirect round-trip
    completes without them re-entering credentials) — simpler and safer than special-casing an
    unprefixed cookie into the trust path.
  - The **state/CSRF cookie** accepts one read of the pre-0.4.0 bare name when the new name is
    absent, so a login started just before an upgrade still completes when its callback lands just
    after. Unlike the session cookie there is no SSO fallback here — only a dead-end error page — so
    this one-shot cookie's double-submit check must survive the deploy boundary outright.
  - Either way, both names are cleared going forward (on logout, a rejected session, or once the
    state cookie is consumed) so a stale pre-0.4.0 cookie never lingers in the browser.
- **Consuming apps, read before upgrading in production**: if your app's own CSRF double-submit
  middleware decides "is there a session" by checking the literal `session_token` cookie name
  (several of ours do, e.g. `req.cookies?.session_token`), that check must be updated to the
  `__Host-` name (when `cookie.secure` is true) in the **same** deploy that upgrades past 0.4.0 in
  production. Otherwise the check always reads "no session", CSRF validation silently stops running
  for every state-changing request, and the app serves on with no CSRF protection at all. This is
  not caught by this package's own test suite — it lives entirely in the consuming app.

## 0.3.0

`callIdp`: call pwiam `/rp/*` as the signed-in user (self-service actions like minting device keys),
proving the user with the session's access token and the app with its own client credentials.

## 0.2.0

Local API-key shape check before any network call, 429-from-introspection given the same
cache/grace treatment as a 5xx, `introspectApiKey` for proof-of-possession binding, and the
standalone `apiKeyVerifier` factory for services that can't construct the full login config.

## 0.1.0

Initial release: OIDC code+PKCE login, sealed server-side sessions with silent refresh,
back-channel logout, step-up (`acr`), API-key principals for service accounts, and upstream
(Entra) token exchange.
