-- Auto Stockers D1 schema
-- Run with: wrangler d1 execute auto-stockers-db --remote --file=./schema.sql

DROP TABLE IF EXISTS restock_recommendations;
DROP TABLE IF EXISTS sales_log;
DROP TABLE IF EXISTS receipt_items;
DROP TABLE IF EXISTS receipts;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS settings;

CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  category TEXT DEFAULT 'General',
  unit_price REAL DEFAULT 0,
  current_stock INTEGER DEFAULT 0,
  lead_time_days INTEGER DEFAULT 3,
  safety_z REAL DEFAULT 1.65,        -- ~95% service level (z-score)
  demand_level REAL DEFAULT 0,       -- Holt level: smoothed units/day
  demand_trend REAL DEFAULT 0,       -- Holt trend: change in units/day per day
  demand_variance REAL DEFAULT 0,    -- EW variance of forecast error, for safety stock
  last_sale_date TEXT,
  archived INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE receipts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor TEXT,
  receipt_date TEXT,
  uploaded_at TEXT DEFAULT (datetime('now')),
  status TEXT DEFAULT 'pending' -- pending | confirmed
);

CREATE TABLE receipt_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id INTEGER NOT NULL,
  raw_text TEXT NOT NULL,
  qty INTEGER NOT NULL DEFAULT 1,
  unit_price REAL DEFAULT 0,
  suggested_product_id INTEGER,
  match_confidence REAL DEFAULT 0,
  resolved_product_id INTEGER,       -- set once the human confirms/creates a match
  status TEXT DEFAULT 'unconfirmed', -- unconfirmed | matched | new_product | ignored
  FOREIGN KEY (receipt_id) REFERENCES receipts(id)
);

CREATE TABLE sales_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  qty INTEGER NOT NULL,
  sale_date TEXT NOT NULL,
  receipt_item_id INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE restock_recommendations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  reorder_point REAL,
  target_stock REAL,
  recommended_qty INTEGER,
  days_of_stock_left REAL,
  reasoning TEXT,
  ai_summary TEXT,
  computed_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE INDEX idx_sales_log_product ON sales_log(product_id);
CREATE INDEX idx_receipt_items_receipt ON receipt_items(receipt_id);
CREATE INDEX idx_products_normalized ON products(normalized_name);

-- Key/value settings store — currently holds Google Calendar OAuth tokens
-- (google_refresh_token, google_access_token, google_token_expires_at).
-- Single-tenant app, so no per-user rows needed.
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);
