-- Auto Stockers D1 schema — MULTI-TENANT
-- Run with: wrangler d1 execute auto-stockers-db --remote --file=./schema.sql
--
-- Every business that signs up gets a row in `companies`. Every other table
-- carries a `company_id` foreign key, and every query in the Worker filters
-- on it. That column is the entire isolation boundary — there is no
-- separate database or schema per tenant, just a WHERE clause that is never
-- allowed to be missing. See index.ts: getSession() resolves company_id
-- from the auth token, and every handler binds it into its queries.

DROP TABLE IF EXISTS restock_recommendations;
DROP TABLE IF EXISTS sales_log;
DROP TABLE IF EXISTS receipt_items;
DROP TABLE IF EXISTS receipts;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS companies;

-- One row per business/tenant. business_type is display-only metadata
-- (lets the UI say "menu items" for a restaurant vs "products" for a
-- store) — it doesn't change how any table is structured or queried.
CREATE TABLE companies (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  business_type TEXT DEFAULT 'General',
  created_at    TEXT DEFAULT (datetime('now'))
);

-- Login identities. One company can have multiple users later; for now
-- every signup creates exactly one (the owner).
CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id    INTEGER NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,   -- PBKDF2 derived key, hex
  password_salt TEXT NOT NULL,   -- random per-user salt, hex
  created_at    TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE products (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id        INTEGER NOT NULL,
  name              TEXT NOT NULL,
  normalized_name   TEXT NOT NULL,
  category          TEXT DEFAULT 'General',
  unit_price        REAL DEFAULT 0,
  current_stock     INTEGER DEFAULT 0,
  lead_time_days    INTEGER DEFAULT 3,
  safety_z          REAL DEFAULT 1.65,        -- ~95% service level (z-score)
  demand_level      REAL DEFAULT 0,           -- Holt level: smoothed units/day
  demand_trend      REAL DEFAULT 0,           -- Holt trend: change in units/day per day
  demand_variance   REAL DEFAULT 0,           -- EW variance of forecast error, for safety stock
  last_sale_date    TEXT,
  archived          INTEGER DEFAULT 0,
  created_at        TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE receipts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id    INTEGER NOT NULL,
  vendor        TEXT,
  receipt_date  TEXT,
  uploaded_at   TEXT DEFAULT (datetime('now')),
  status        TEXT DEFAULT 'pending', -- pending | confirmed
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE receipt_items (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id            INTEGER NOT NULL,   -- denormalized from receipts, so item
                                             -- queries can filter directly without a
                                             -- join — one less place isolation can slip
  receipt_id            INTEGER NOT NULL,
  raw_text              TEXT NOT NULL,
  qty                   INTEGER NOT NULL DEFAULT 1,
  unit_price            REAL DEFAULT 0,
  suggested_product_id  INTEGER,
  match_confidence      REAL DEFAULT 0,
  resolved_product_id   INTEGER,       -- set once the human confirms/creates a match
  status                TEXT DEFAULT 'unconfirmed', -- unconfirmed | matched | new_product | ignored
  FOREIGN KEY (company_id) REFERENCES companies(id),
  FOREIGN KEY (receipt_id) REFERENCES receipts(id)
);

CREATE TABLE sales_log (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id        INTEGER NOT NULL,
  product_id        INTEGER NOT NULL,
  qty               INTEGER NOT NULL,
  sale_date         TEXT NOT NULL,
  receipt_item_id   INTEGER,
  created_at        TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE restock_recommendations (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id            INTEGER NOT NULL,
  product_id            INTEGER NOT NULL,
  reorder_point         REAL,
  target_stock          REAL,
  recommended_qty       INTEGER,
  days_of_stock_left    REAL,
  reasoning             TEXT,
  ai_summary            TEXT,
  computed_at           TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Key/value settings store — currently holds each company's Google Calendar
-- OAuth tokens (google_refresh_token, google_access_token,
-- google_token_expires_at). Composite key means every company connects and
-- disconnects their own calendar independently; company A can never read
-- company B's tokens because the row simply doesn't match their company_id.
CREATE TABLE settings (
  company_id  INTEGER NOT NULL,
  key         TEXT NOT NULL,
  value       TEXT,
  PRIMARY KEY (company_id, key),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE INDEX idx_users_company ON users(company_id);
CREATE INDEX idx_products_company ON products(company_id);
CREATE INDEX idx_products_normalized ON products(company_id, normalized_name);
CREATE INDEX idx_receipts_company ON receipts(company_id);
CREATE INDEX idx_receipt_items_receipt ON receipt_items(receipt_id);
CREATE INDEX idx_receipt_items_company ON receipt_items(company_id);
CREATE INDEX idx_sales_log_product ON sales_log(product_id);
CREATE INDEX idx_sales_log_company ON sales_log(company_id);

CREATE TABLE assistant_messages (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id    INTEGER NOT NULL,
  role          TEXT NOT NULL,
  message       TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE INDEX idx_assistant_messages_company ON assistant_messages(company_id, created_at);
