'use strict';
const { seal, open, randomToken } = require('./crypto');

// Wraps a storage adapter: generates the opaque session token and seals/opens the IAM state blob so
// the refresh token never sits in the app's database in the clear.
function createSessionStore({ adapter, sealKey, now = Date.now }) {
  return {
    async create({ userId, sub, sid, expiresAt, state }) {
      const token = randomToken();
      await adapter.create({ token, userId, sub, sid: sid || null, expiresAt, state: seal(sealKey, state) });
      return token;
    },
    async get(token) {
      if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) return null;
      const row = await adapter.get(token);
      if (!row) return null;
      let state;
      try { state = open(sealKey, row.state); } catch { await adapter.destroy(token); return null; }
      if (new Date(row.expiresAt).getTime() <= now()) { await adapter.destroy(token); return null; }
      return { token, userId: row.userId, sub: row.sub, sid: row.sid, expiresAt: new Date(row.expiresAt), state };
    },
    setState: (token, state) => adapter.update(token, { state: seal(sealKey, state) }),
    destroy: (token) => adapter.destroy(token),
    destroyBySid: (sid) => adapter.destroyBySid(sid),
    destroyBySub: (sub) => adapter.destroyBySub(sub),
    sweepExpired: () => adapter.deleteExpired(new Date(now())),
  };
}

module.exports = { createSessionStore };
