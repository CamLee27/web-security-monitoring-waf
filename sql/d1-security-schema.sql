-- CamCareer Web Security Monitoring & WAF
-- Public D1 schema excerpt
--
-- This file documents the security-focused tables used by the integrated
-- production Cloudflare Worker. Visitor analytics tables are intentionally
-- omitted because they are documented in the separate visitor-reporting project.
--
-- No production data is included.

CREATE TABLE request_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visitor_hash TEXT NOT NULL,
  ip TEXT NOT NULL,
  visit_date TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  path TEXT NOT NULL,
  method TEXT NOT NULL,
  status INTEGER NOT NULL,
  is_404 INTEGER NOT NULL DEFAULT 0,
  suspicious_path INTEGER NOT NULL DEFAULT 0,
  suspicious_categories TEXT NOT NULL DEFAULT '[]',
  referrer TEXT,
  city TEXT,
  region TEXT,
  region_code TEXT,
  postal_code TEXT,
  country TEXT,
  internet_provider TEXT,
  user_agent TEXT,
  browser_brands TEXT,
  platform_hint TEXT,
  mobile_hint TEXT,
  bot_score INTEGER,
  bot_js_passed INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE report_state (
  id INTEGER PRIMARY KEY,
  last_reported_request_id INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_reported_page_view_id INTEGER NOT NULL DEFAULT 0,
  last_reported_navigation_id INTEGER NOT NULL DEFAULT 0
);
