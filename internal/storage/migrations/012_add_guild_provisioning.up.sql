ALTER TABLE guild_settings
    ADD COLUMN IF NOT EXISTS onboarding_role_id        TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS shadowmute_log_channel_id TEXT NOT NULL DEFAULT '';
