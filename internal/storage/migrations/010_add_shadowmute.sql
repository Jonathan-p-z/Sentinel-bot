CREATE TABLE IF NOT EXISTS shadow_mutes (
    id         BIGSERIAL PRIMARY KEY,
    guild_id   TEXT   NOT NULL,
    user_id    TEXT   NOT NULL,
    muted_by   TEXT   NOT NULL,
    reason     TEXT   NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    expires_at BIGINT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_shadow_mutes_guild_user
    ON shadow_mutes (guild_id, user_id);

CREATE INDEX IF NOT EXISTS idx_shadow_mutes_guild_expires
    ON shadow_mutes (guild_id, expires_at);
