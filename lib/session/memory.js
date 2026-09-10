'use strict';
// In-process adapter: tests, and any app that is fine losing sessions on restart.
function memorySession() {
  const rows = new Map();
  const live = (r) => r && r.expiresAt.getTime() > Date.now() ? r : null;
  return {
    async create(row) { rows.set(row.token, { ...row }); },
    async get(token) { const r = live(rows.get(token)); return r ? { ...r } : null; },
    async update(token, patch) { const r = rows.get(token); if (r) Object.assign(r, patch); },
    async destroy(token) { rows.delete(token); },
    async destroyBySid(sid) { let n = 0; for (const [k, r] of rows) if (r.sid === sid) { rows.delete(k); n++; } return n; },
    async destroyBySub(sub) { let n = 0; for (const [k, r] of rows) if (r.sub === sub) { rows.delete(k); n++; } return n; },
    async deleteExpired(now) { let n = 0; for (const [k, r] of rows) if (r.expiresAt.getTime() <= now.getTime()) { rows.delete(k); n++; } return n; },
  };
}
module.exports = { memorySession };
