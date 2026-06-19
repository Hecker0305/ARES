-- Run this SQL in your Supabase project SQL Editor to create the login_keys table.
-- After running, insert one or more keys to allow access.

CREATE TABLE IF NOT EXISTS login_keys (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT 'Operator',
  role TEXT NOT NULL DEFAULT 'admin',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (optional — safe defaults for anon access)
ALTER TABLE login_keys ENABLE ROW LEVEL SECURITY;

-- Allow anonymous users to SELECT from login_keys (needed for key validation)
CREATE POLICY "anon can select login_keys"
  ON login_keys
  FOR SELECT
  TO anon
  USING (true);

-- Insert a default key (CHANGE THIS to your own secret key)
INSERT INTO login_keys (key, name, role)
VALUES ('change-me-to-your-secret-key', 'Admin', 'admin')
ON CONFLICT (key) DO NOTHING;

-- ============================================================
-- Scan Keys — validity system
-- Each key has a limited number of scans (default 1).
-- After all scans are used, the key is expired.
-- ============================================================

CREATE TABLE IF NOT EXISTS scan_keys (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT 'Operator',
  role TEXT NOT NULL DEFAULT 'admin',
  scans_remaining INT NOT NULL DEFAULT 1,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  used_at TIMESTAMPTZ
);

ALTER TABLE scan_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "anon can select scan_keys"
  ON scan_keys
  FOR SELECT
  TO anon
  USING (true);

CREATE POLICY "anon can update scan_keys"
  ON scan_keys
  FOR UPDATE
  TO anon
  USING (true)
  WITH CHECK (true);

-- Insert a default scan key (CHANGE THIS to match your login key)
INSERT INTO scan_keys (key, name, role, scans_remaining)
VALUES ('change-me-to-your-secret-key', 'Admin', 'admin', 1)
ON CONFLICT (key) DO NOTHING;
