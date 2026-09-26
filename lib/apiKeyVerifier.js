'use strict';
// The api-key cache/grace/backoff/shape-check machinery, factored out so requireApiKey (which
// already has an oidc client bound to the app's own credentials) and the standalone apiKeyVerifier
// (which builds its own) share one implementation instead of two copies that could drift apart.
const crypto = require('node:crypto');
const { createOidc } = require('./oidc');
const { isValidApiKeyShape } = require('./apiKeyShape');

const CACHE_TTL_MS = 60 * 1000;      // introspection verdicts are reused for a minute
const GRACE_MS = 5 * 60 * 1000;      // ...and up to five more minutes when pwiam is unreachable
const RETRY_BACKOFF_MS = 60 * 1000;  // a failing issuer isn't re-dialled on every request
const CACHE_MAX = 1000;

function capped(map, isExpired, now) {
  if (map.size < CACHE_MAX) return;
  for (const [k, v] of map) if (isExpired(v, now)) map.delete(k);
  while (map.size >= CACHE_MAX) map.delete(map.keys().next().value); // Map iterates in insertion order — oldest first
}

// verify(key) resolves { body, error } — body is pwiam's introspection response verbatim
// ({ active:false } for a malformed key, with no network call and no cache entry), and error is
// set (non-fatal) when a fresh introspection attempt failed but a cached verdict inside the grace
// window covered it. It only rejects when there's no usable verdict left to serve.
function createKeyCache({ introspect, now = Date.now, cacheTtlMs = CACHE_TTL_MS, graceMs = GRACE_MS }) {
  const cache = new Map();    // sha256(key) -> { body, fetchedAt, failedAt? }
  const inflight = new Map(); // sha256(key) -> Promise<entry>; de-dupes concurrent cold introspections
  // a verdict is good until cacheTtlMs, or until pwiam says the key itself expires — whichever is first
  const staleAt = (v) => Math.min(v.fetchedAt + cacheTtlMs, typeof v.body.exp === 'number' && v.body.exp > 0 ? v.body.exp * 1000 : Infinity);

  async function verify(key) {
    if (!isValidApiKeyShape(key)) return { body: { active: false } };
    const ck = crypto.createHash('sha256').update(key).digest('hex');
    const t = now();
    let entry = cache.get(ck);
    const usable = entry && t - entry.fetchedAt < cacheTtlMs + graceMs;
    const backedOff = usable && entry.failedAt !== undefined && t - entry.failedAt < RETRY_BACKOFF_MS;
    if ((!entry || t >= staleAt(entry)) && !backedOff) {
      let p = inflight.get(ck);
      if (!p) {
        p = introspect(key)
          .then((body) => {
            const fresh = { body, fetchedAt: t };
            capped(cache, (v, n) => n - v.fetchedAt > cacheTtlMs + graceMs, t);
            cache.set(ck, fresh);
            return fresh;
          })
          .finally(() => inflight.delete(ck));
        inflight.set(ck, p);
      }
      try {
        entry = await p;
      } catch (e) {
        if (e.kind === 'issuer_error' && usable) {
          entry.failedAt = t;
          return { body: entry.body, error: e };
        }
        throw e;
      }
    }
    return { body: entry.body };
  }

  return { verify };
}

// The public, verifier-only factory: for a service that can't (or shouldn't) construct the full
// pwAuth login config — no baseUrl/secret/session/resolveUser, just enough to introspect API keys
// with requireApiKey's own cache/grace/shape-check semantics. `fetch` is injectable because some
// callers (e.g. the PW orchestrator) reach the issuer through a proxy rather than directly.
function apiKeyVerifier({ issuer, clientId, clientSecret, fetch, timeoutSec, allowInsecure, now, cacheTtlMs, graceMs } = {}) {
  const oidc = createOidc({ issuer, clientId, clientSecret, fetch, allowInsecure, timeoutSec, now });
  const cache = createKeyCache({ introspect: oidc.introspectApiKey, now, cacheTtlMs, graceMs });
  return { verify: async (key) => (await cache.verify(key)).body };
}

module.exports = { apiKeyVerifier, createKeyCache, CACHE_TTL_MS, GRACE_MS };
