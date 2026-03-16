CREATE TABLE IF NOT EXISTS join_log (
    id        BIGSERIAL PRIMARY KEY,
    guild_id  TEXT   NOT NULL,
    user_id   TEXT   NOT NULL,
    username  TEXT   NOT NULL,
    joined_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_join_log_guild_joined
    ON join_log (guild_id, joined_at DESC);

CREATE TABLE IF NOT EXISTS banned_users (
    guild_id  TEXT   NOT NULL,
    user_id   TEXT   NOT NULL,
    username  TEXT   NOT NULL,
    banned_at BIGINT NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_banned_users_guild_banned
    ON banned_users (guild_id, banned_at DESC);
