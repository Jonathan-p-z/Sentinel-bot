CREATE TABLE IF NOT EXISTS escalation_log (
    id         BIGSERIAL PRIMARY KEY,
    guild_id   TEXT    NOT NULL,
    user_id    TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    score      REAL    NOT NULL,
    created_at BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_escalation_log_guild_user
    ON escalation_log (guild_id, user_id, created_at DESC);
