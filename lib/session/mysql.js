'use strict';
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const DEFAULT_COLUMNS = { token: 'TOKEN', userId: 'USER_ID', sub: 'SUB', sid: 'SID', expiresAt: 'EXPIRES_AT', state: 'IAM_STATE' };
const FIELDS = Object.keys(DEFAULT_COLUMNS);

// `schema.table` is quoted part by part — one backticked string would name a table with a dot in it
function q(name) {
  const parts = String(name).split('.');
  if (!parts.every((p) => IDENT.test(p))) throw new Error(`pw-auth: invalid SQL identifier "${name}"`);
  return parts.map((p) => `\`${p}\``).join('.');
}

// mysql2/promise returns [rows, fields] for SELECT and [ResultSetHeader, undefined] for writes;
// app wrappers (tally's db.query) return the rows / header directly. Accept both.
function unwrap(r) {
  if (Array.isArray(r) && Array.isArray(r[0])) return { rows: r[0], affectedRows: 0 };
  if (Array.isArray(r) && r[0] && typeof r[0].affectedRows === 'number') return { rows: [], affectedRows: r[0].affectedRows };
  if (r && !Array.isArray(r) && typeof r.affectedRows === 'number') return { rows: [], affectedRows: r.affectedRows };
  return { rows: Array.isArray(r) ? r : [], affectedRows: 0 };
}

function mysqlSession(db, { table = 'sessions', columns = {} } = {}) {
  if (!db || typeof db.query !== 'function') throw new Error('pw-auth: mysqlSession needs a db with query(sql, params)');
  const col = { ...DEFAULT_COLUMNS, ...columns };
  const T = q(table);
  const C = Object.fromEntries(FIELDS.map((f) => [f, q(col[f])]));
  const columnList = FIELDS.map((f) => C[f]).join(', ');
  const toRow = (r) => ({ token: r[col.token], userId: r[col.userId], sub: r[col.sub], sid: r[col.sid], expiresAt: r[col.expiresAt], state: r[col.state] });

  return {
    async create(row) {
      await db.query(`INSERT INTO ${T} (${columnList}) VALUES (?, ?, ?, ?, ?, ?)`, FIELDS.map((f) => row[f] === undefined ? null : row[f]));
    },
    async get(token) {
      const { rows } = unwrap(await db.query(`SELECT ${columnList} FROM ${T} WHERE ${C.token} = ? AND ${C.expiresAt} > ? LIMIT 1`, [token, new Date()]));
      return rows.length ? toRow(rows[0]) : null;
    },
    async update(token, patch) {
      const keys = Object.keys(patch).filter((f) => f !== 'token' && FIELDS.includes(f) && patch[f] !== undefined); // caller's order
      if (!keys.length) return;
      await db.query(`UPDATE ${T} SET ${keys.map((f) => `${C[f]} = ?`).join(', ')} WHERE ${C.token} = ?`, [...keys.map((f) => patch[f]), token]);
    },
    async destroy(token) { return unwrap(await db.query(`DELETE FROM ${T} WHERE ${C.token} = ?`, [token])).affectedRows; },
    async destroyBySid(sid) { return unwrap(await db.query(`DELETE FROM ${T} WHERE ${C.sid} = ?`, [sid])).affectedRows; },
    async destroyBySub(sub) { return unwrap(await db.query(`DELETE FROM ${T} WHERE ${C.sub} = ?`, [sub])).affectedRows; },
  };
}

module.exports = { mysqlSession, DEFAULT_COLUMNS };
