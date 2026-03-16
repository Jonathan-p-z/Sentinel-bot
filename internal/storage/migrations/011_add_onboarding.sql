CREATE TABLE IF NOT EXISTS onboarding_sessions (
    id           BIGSERIAL PRIMARY KEY,
    guild_id     TEXT   NOT NULL,
    user_id      TEXT   NOT NULL,
    captcha_code TEXT   NOT NULL DEFAULT '',
    attempts     INT    NOT NULL DEFAULT 0,
    created_at   BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL,
    status       TEXT   NOT NULL DEFAULT 'pending_captcha'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_onboarding_sessions_guild_user
    ON onboarding_sessions (guild_id, user_id);

CREATE INDEX IF NOT EXISTS idx_onboarding_sessions_expires
    ON onboarding_sessions (expires_at);
