CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id TEXT PRIMARY KEY,
    security_log_channel TEXT,
    language TEXT DEFAULT 'fr',
    mode TEXT,
    rule_preset TEXT,
    retention_days INTEGER,
    spam_messages INTEGER,
    spam_window_seconds INTEGER,
    raid_joins INTEGER,
    raid_window_seconds INTEGER,
    phishing_risk INTEGER,
    lockdown_enabled INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id TEXT NOT NULL,
    user_id TEXT,
    level TEXT,
    event TEXT,
    details TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_allowlist (
    guild_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    PRIMARY KEY (guild_id, domain)
);

CREATE TABLE IF NOT EXISTS domain_blocklist (
    guild_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    PRIMARY KEY (guild_id, domain)
);

CREATE TABLE IF NOT EXISTS risk_scores (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    score REAL NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE IF NOT EXISTS trust_scores (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    score REAL NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);
