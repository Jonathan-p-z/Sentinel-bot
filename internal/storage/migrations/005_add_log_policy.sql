ALTER TABLE guild_settings ADD COLUMN audit_log_channel TEXT DEFAULT '';
ALTER TABLE guild_settings ADD COLUMN discord_min_level TEXT DEFAULT 'HIGH';
ALTER TABLE guild_settings ADD COLUMN discord_categories TEXT DEFAULT 'anti_hate,anti_phishing,anti_spam,anti_raid,anti_nuke,raid_lockdown,risk_action,action_failed,nuke_timeout';
ALTER TABLE guild_settings ADD COLUMN discord_rate_limit_seconds INTEGER DEFAULT 10;
ALTER TABLE guild_settings ADD COLUMN digest_interval_minutes INTEGER DEFAULT 15;
ALTER TABLE guild_settings ADD COLUMN warn_rare_minutes INTEGER DEFAULT 60;
ALTER TABLE guild_settings ADD COLUMN dedup_window_seconds INTEGER DEFAULT 60;

ALTER TABLE audit_logs ADD COLUMN event_id TEXT DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN trace_id TEXT DEFAULT '';
ALTER TABLE audit_logs ADD COLUMN details_json TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_id ON audit_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_trace_id ON audit_logs(trace_id);
