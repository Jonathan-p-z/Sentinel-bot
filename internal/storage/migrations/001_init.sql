CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id TEXT PRIMARY KEY,
    security_log_channel TEXT DEFAULT '',
    language TEXT DEFAULT 'fr',
    mode TEXT DEFAULT 'normal',
    rule_preset TEXT DEFAULT 'medium',
    retention_days INTEGER DEFAULT 14,
    spam_messages INTEGER DEFAULT 6,
    spam_window_seconds INTEGER DEFAULT 8,
    raid_joins INTEGER DEFAULT 6,
    raid_window_seconds INTEGER DEFAULT 10,
    phishing_risk INTEGER DEFAULT 30,
    lockdown_enabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT,
    level TEXT,
    event TEXT,
    details TEXT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_guild_time ON audit_logs(guild_id, created_at DESC);

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
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE IF NOT EXISTS trust_scores (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    score REAL NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);
