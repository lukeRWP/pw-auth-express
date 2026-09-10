const { test } = require('node:test');
const assert = require('node:assert/strict');
const { memorySession } = require('../lib/session/memory');

test('memory adapter: create/get/update/destroy, expiry, by-sid and by-sub deletes', async () => {
  const a = memorySession();
  const future = new Date(Date.now() + 60000);
  await a.create({ token: 't1', userId: 7, sub: 'u1', sid: 's1', expiresAt: future, state: 'enc1' });
  await a.create({ token: 't2', userId: 7, sub: 'u1', sid: 's2', expiresAt: future, state: 'enc2' });
  await a.create({ token: 't3', userId: 8, sub: 'u2', sid: 's3', expiresAt: new Date(Date.now() - 1), state: 'old' });
  assert.deepEqual(await a.get('t1'), { token: 't1', userId: 7, sub: 'u1', sid: 's1', expiresAt: future, state: 'enc1' });
  assert.equal(await a.get('t3'), null, 'expired rows read as missing');
  assert.equal(await a.get('nope'), null);
  await a.update('t1', { state: 'enc1b' });
  assert.equal((await a.get('t1')).state, 'enc1b');
  assert.equal(await a.destroyBySid('s2'), 1);
  assert.equal(await a.get('t2'), null);
  assert.equal(await a.destroyBySub('u1'), 1);
  assert.equal(await a.get('t1'), null);
  await a.destroy('t1'); // idempotent
});
