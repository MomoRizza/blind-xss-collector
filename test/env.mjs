// Test harness: a D1-compatible adapter backed by node:sqlite, so the REAL
// src/worker.js runs unmodified against real SQLite.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

export function makeEnv(authKey = 'testkey') {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(join(here, '..', 'schema.sql'), 'utf8'));
  const DB = {
    prepare(sql) {
      return {
        _sql: sql, _args: [],
        bind(...a) { this._args = a; return this; },
        async run() { db.prepare(this._sql).run(...this._args); return { success: true }; },
        async all() { return { results: db.prepare(this._sql).all(...this._args) }; },
        async first() { return db.prepare(this._sql).get(...this._args); }
      };
    }
  };
  return { DB, AUTH_KEY: authKey, _raw: db };
}
