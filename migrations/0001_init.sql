-- rules metadata
CREATE TABLE IF NOT EXISTS rules (
  id SERIAL PRIMARY KEY,
  rule_uid TEXT UNIQUE,
  title TEXT,
  level TEXT,
  description TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- endpoints (kept from previous inline schema)
CREATE TABLE IF NOT EXISTS endpoints (
  endpoint_id   TEXT PRIMARY KEY,
  host_name     TEXT,
  ip            TEXT,
  agent_version TEXT,
  last_seen     TIMESTAMP NOT NULL
);

-- events
CREATE TABLE IF NOT EXISTS events (
  id          BIGSERIAL PRIMARY KEY,
  received_at TIMESTAMP NOT NULL,
  endpoint_id TEXT,
  event       JSONB
);

-- event_rules many-to-many
CREATE TABLE IF NOT EXISTS event_rules (
  id BIGSERIAL PRIMARY KEY,
  event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  rule_id  INTEGER NOT NULL REFERENCES rules(id)  ON DELETE CASCADE,
  UNIQUE(event_id, rule_id)
);

-- detections kept for backward-compat and tests
CREATE TABLE IF NOT EXISTS detections (
  id          BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMP NOT NULL,
  endpoint_id TEXT,
  rule_id     INTEGER,
  rule_name   TEXT,
  severity    TEXT,
  confidence  DOUBLE PRECISION,
  context     JSONB
);

