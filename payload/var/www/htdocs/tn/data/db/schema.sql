-- SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
--
-- SPDX-License-Identifier: BSD-3-Clause

-- ============================================================
-- schema.sql - TNAuth Suite Database Schema
-- ============================================================
-- SQLite database schema for user management, sessions,
-- security questions, recovery codes, and audit logging.
--
-- AUTHOR: David Peter, Tangent Networks
-- VERSION: 2.1.0
-- LAST UPDATED: 2026-03-07
-- ============================================================

-- ============================================================
-- USERS TABLE
-- ============================================================
-- Stores user accounts with credentials and metadata
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER NOT NULL,
    last_login INTEGER,
    login_count INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    locked INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    CONSTRAINT chk_role CHECK (role IN ('user', 'admin'))
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- ============================================================
-- SECURITY QUESTIONS TABLE
-- ============================================================
-- Stores hashed security questions and answers for password reset
-- ============================================================

CREATE TABLE IF NOT EXISTS security_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    question TEXT NOT NULL,
    answer_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    answer_salt TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_questions_user_id ON security_questions(user_id);

-- ============================================================
-- RECOVERY CODES TABLE
-- ============================================================
-- Stores hashed one-time recovery codes for account recovery
-- ============================================================

CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    used_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_used CHECK (used IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id ON recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_used ON recovery_codes(used);

-- ============================================================
-- REGISTRATION TOKENS TABLE
-- ============================================================
-- Stores invitation tokens for user registration
-- ============================================================

CREATE TABLE IF NOT EXISTS registration_tokens (
    token TEXT PRIMARY KEY,
    created_by TEXT,
    created_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    used_by TEXT,
    used_at INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_used CHECK (used IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_registration_tokens_used ON registration_tokens(used);
CREATE INDEX IF NOT EXISTS idx_registration_tokens_created_by ON registration_tokens(created_by);

-- ============================================================
-- SESSIONS TABLE
-- ============================================================
-- Stores active user sessions
-- ============================================================

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- ============================================================
-- SECURITY LOG TABLE
-- ============================================================
-- Audit log for security events
-- ============================================================

CREATE TABLE IF NOT EXISTS security_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    level TEXT NOT NULL,
    event TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    user_id TEXT,
    username TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_level CHECK (level IN ('debug', 'info', 'warning', 'error', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_security_log_timestamp ON security_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_log_level ON security_log(level);
CREATE INDEX IF NOT EXISTS idx_security_log_user_id ON security_log(user_id);
CREATE INDEX IF NOT EXISTS idx_security_log_event ON security_log(event);

-- ============================================================
-- RATE LIMITS TABLE
-- ============================================================
-- Tracks rate limiting per IP/user
-- ============================================================

CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,
    limit_type TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    window_start INTEGER NOT NULL,
    violations INTEGER NOT NULL DEFAULT 0,
    last_request INTEGER NOT NULL,
    blocked_until INTEGER DEFAULT 0,
    CONSTRAINT uq_identifier_type UNIQUE (identifier, limit_type)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier);
CREATE INDEX IF NOT EXISTS idx_rate_limits_type ON rate_limits(limit_type);
CREATE INDEX IF NOT EXISTS idx_rate_limits_blocked_until ON rate_limits(blocked_until);

-- ============================================================
-- VIEWS
-- ============================================================

-- Active sessions view
CREATE VIEW IF NOT EXISTS v_active_sessions AS
SELECT
    s.session_id,
    s.user_id,
    u.username,
    u.role,
    s.created_at,
    s.last_activity,
    s.expires_at,
    s.ip_address,
    s.user_agent,
    (s.expires_at - s.last_activity) as time_remaining
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.expires_at > strftime('%s', 'now');

-- User statistics view
CREATE VIEW IF NOT EXISTS v_user_stats AS
SELECT
    u.id,
    u.username,
    u.email,
    u.role,
    u.created_at,
    u.last_login,
    u.login_count,
    u.failed_attempts,
    COUNT(DISTINCT s.session_id) as active_sessions,
    COUNT(DISTINCT rc.id) as unused_recovery_codes
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id AND s.expires_at > strftime('%s', 'now')
LEFT JOIN recovery_codes rc ON u.id = rc.user_id AND rc.used = 0
GROUP BY u.id;

-- Security events summary view
CREATE VIEW IF NOT EXISTS v_security_summary AS
SELECT
    date(timestamp, 'unixepoch') as date,
    level,
    COUNT(*) as event_count
FROM security_log
GROUP BY date(timestamp, 'unixepoch'), level
ORDER BY date DESC, level;

-- ============================================================
-- DATABASE VERSION
-- ============================================================

CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

INSERT OR REPLACE INTO schema_version (version, applied_at)
VALUES ('2.1.0', strftime('%s', 'now'));

-- ============================================================
-- VACUUM AND ANALYZE
-- ============================================================

-- Optimize database
VACUUM;
ANALYZE;

-- ============================================================
-- SCHEMA CHANGELOG
-- ============================================================
-- v2.1.0 (2026-03-07):
--   - Removed csrf_tokens table (DB-003: dead code, CSRF is stateless HMAC)
--   - Removed failed_login_count column from users (DB-004: deprecated, use failed_attempts)
--
-- v2.0.1 (2026-01-13):
--   - Added 'locked' field to users table
--   - Added 'failed_attempts' field to users table
--   - Added 'answer_salt' field to security_questions table
--
-- v2.0.0 (Initial):
--   - Base schema with all core tables
-- ============================================================
