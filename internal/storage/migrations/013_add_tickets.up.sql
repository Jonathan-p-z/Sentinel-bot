CREATE TABLE IF NOT EXISTS tickets (
    id         BIGSERIAL PRIMARY KEY,
    guild_id   TEXT      NOT NULL,
    user_id    TEXT      NOT NULL,
    channel_id TEXT      NOT NULL,
    status     TEXT      NOT NULL DEFAULT 'open',
    created_at BIGINT    NOT NULL,
    closed_at  BIGINT    NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS tickets_open_per_user
    ON tickets (guild_id, user_id)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS tickets_guild_status
    ON tickets (guild_id, status);
