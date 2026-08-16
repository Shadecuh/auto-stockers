-- Adds key/value settings storage for Google Calendar OAuth tokens.
-- Single-tenant app (one admin), so this is a simple KV table rather than
-- per-user rows.

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);
