PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  login TEXT NOT NULL,
  avatar_url TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS installations (
  installation_id INTEGER PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL CHECK (target_type = 'User'),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS repos (
  id INTEGER PRIMARY KEY,
  installation_id INTEGER NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE,
  full_name TEXT NOT NULL UNIQUE,
  private INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  default_repo_id INTEGER NOT NULL REFERENCES repos(id),
  ai_readme INTEGER NOT NULL DEFAULT 0,
  path_template TEXT NOT NULL DEFAULT 'problems/{primary}/{slug}',
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ext_instance_id TEXT NOT NULL,
  hashed_token TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_used INTEGER
);

CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  slug TEXT NOT NULL,
  language TEXT,
  url TEXT,
  ts TEXT,
  code_sha TEXT NOT NULL,
  size INTEGER,
  difficulty TEXT,
  tags_json TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_flows (
  nonce TEXT PRIMARY KEY,
  client TEXT,
  redirect TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_submissions_user ON submissions(user_id, created_at DESC);
