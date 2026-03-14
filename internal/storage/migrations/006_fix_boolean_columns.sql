ALTER TABLE guild_settings ALTER COLUMN lockdown_enabled TYPE BOOLEAN USING lockdown_enabled::boolean;
ALTER TABLE guild_settings ALTER COLUMN nuke_enabled TYPE BOOLEAN USING nuke_enabled::boolean;
