CREATE TABLE IF NOT EXISTS user_strikes (
    guild_id    TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    strike_type TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (guild_id, user_id, strike_type)
);
