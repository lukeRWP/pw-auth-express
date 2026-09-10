// test/sessionMysql.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mysqlSession } = require('../lib/session/mysql');

// A recording fake: every call is captured; the next result is scripted per call.
function fakeDb(results = []) {
  const calls = [];
  return { calls, query: async (sql, params) => { calls.push({ sql: sql.replace(/\s+/g, ' ').trim(), params }); return results.shift(); } };
}
const row = { token: 'a'.repeat(64), userId: 7, sub: '01HUSER', sid: 'sid-1', expiresAt: new Date('2026-09-10T00:00:00Z'), state: 'v1.enc' };

test('create inserts all six columns with backticked identifiers', async () => {
  const db = fakeDb([{ affectedRows: 1 }]);
  await mysqlSession(db).create(row);
  assert.equal(db.calls[0].sql, 'INSERT INTO `sessions` (`TOKEN`, `USER_ID`, `SUB`, `SID`, `EXPIRES_AT`, `IAM_STATE`) VALUES (?, ?, ?, ?, ?, ?)');
  assert.deepEqual(db.calls[0].params, [row.token, 7, '01HUSER', 'sid-1', row.expiresAt, 'v1.enc']);
});

test('get selects only unexpired rows and maps columns back; accepts rows or [rows, fields]', async () => {
  const dbRow = { TOKEN: row.token, USER_ID: 7, SUB: '01HUSER', SID: 'sid-1', EXPIRES_AT: row.expiresAt, IAM_STATE: 'v1.enc' };
  const direct = fakeDb([[dbRow]]);
  const got = await mysqlSession(direct).get(row.token);
  assert.deepEqual(got, row);
  assert.equal(direct.calls[0].sql, 'SELECT `TOKEN`, `USER_ID`, `SUB`, `SID`, `EXPIRES_AT`, `IAM_STATE` FROM `sessions` WHERE `TOKEN` = ? AND `EXPIRES_AT` > ? LIMIT 1');
  assert.equal(direct.calls[0].params[0], row.token); assert.ok(direct.calls[0].params[1] instanceof Date);
  const tuple = fakeDb([[[dbRow], [{ name: 'TOKEN' }]]]);
  assert.deepEqual(await mysqlSession(tuple).get(row.token), row);
  assert.equal(await mysqlSession(fakeDb([[]])).get(row.token), null);
  assert.equal(await mysqlSession(fakeDb([[[], []]])).get(row.token), null);
});

test('update writes only the given fields; ignores unknown keys; no-op on empty patch', async () => {
  const db = fakeDb([{ affectedRows: 1 }]);
  const s = mysqlSession(db);
  await s.update(row.token, { state: 'v1.new', sid: 'sid-2', bogus: 1 });
  assert.equal(db.calls[0].sql, 'UPDATE `sessions` SET `IAM_STATE` = ?, `SID` = ? WHERE `TOKEN` = ?');
  assert.deepEqual(db.calls[0].params, ['v1.new', 'sid-2', row.token]);
  await s.update(row.token, { bogus: 1 });
  assert.equal(db.calls.length, 1);
});

test('destroy / destroyBySid / destroyBySub return affected counts from either result shape', async () => {
  const db = fakeDb([{ affectedRows: 1 }, [{ affectedRows: 2 }, undefined], { affectedRows: 3 }]);
  const s = mysqlSession(db);
  assert.equal(await s.destroy(row.token), 1);
  assert.equal(await s.destroyBySid('sid-1'), 2);
  assert.equal(await s.destroyBySub('01HUSER'), 3);
  assert.deepEqual(db.calls.map((c) => c.sql), [
    'DELETE FROM `sessions` WHERE `TOKEN` = ?',
    'DELETE FROM `sessions` WHERE `SID` = ?',
    'DELETE FROM `sessions` WHERE `SUB` = ?',
  ]);
});

test('deleteExpired removes every row at or past the given instant and returns the count', async () => {
  const db = fakeDb([{ affectedRows: 4 }]);
  const when = new Date('2026-09-10T00:00:00Z');
  assert.equal(await mysqlSession(db).deleteExpired(when), 4);
  assert.equal(db.calls[0].sql, 'DELETE FROM `sessions` WHERE `EXPIRES_AT` <= ?');
  assert.deepEqual(db.calls[0].params, [when]);
});

test('a schema-qualified table is backticked part by part; empty or unsafe parts are rejected', async () => {
  const db = fakeDb([{ affectedRows: 1 }]);
  await mysqlSession(db, { table: 'TALLY.sessions' }).destroy('x');
  assert.equal(db.calls[0].sql, 'DELETE FROM `TALLY`.`sessions` WHERE `TOKEN` = ?');
  for (const bad of ['a..b', '.x', 'x.', 'TALLY.sess;ions']) assert.throws(() => mysqlSession(db, { table: bad }), /identifier/, bad);
});

test('custom table/columns are honoured; bad identifiers are rejected at construction', async () => {
  const db = fakeDb([{ affectedRows: 1 }]);
  await mysqlSession(db, { table: 'app_sessions', columns: { token: 'tok', expiresAt: 'expires' } }).destroy('x');
  assert.equal(db.calls[0].sql, 'DELETE FROM `app_sessions` WHERE `tok` = ?');
  assert.throws(() => mysqlSession(db, { table: 'sessions; DROP' }), /identifier/);
  assert.throws(() => mysqlSession(db, { columns: { sid: 'a`b' } }), /identifier/);
  assert.throws(() => mysqlSession({}), /query/);
});
