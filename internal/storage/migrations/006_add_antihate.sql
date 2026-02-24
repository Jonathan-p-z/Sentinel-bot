CREATE TABLE IF NOT EXISTS user_infractions (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    category TEXT NOT NULL,
    count_total INTEGER NOT NULL DEFAULT 0,
    last_at INTEGER NOT NULL,
    last_action TEXT DEFAULT '',
    reset_at INTEGER DEFAULT NULL,
    PRIMARY KEY (guild_id, user_id, category)
);

CREATE INDEX IF NOT EXISTS idx_user_infractions_reset_at ON user_infractions(reset_at);
ALTER TABLE guild_settings ADD COLUMN anti_hate_enabled INTEGER DEFAULT 1;
