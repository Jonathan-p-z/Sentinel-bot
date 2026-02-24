# Sentinel Adaptive

Sentinel Adaptive is a privacy-first, defensive Discord security bot for multi-guild deployments. It focuses on risk scoring, trust, behavior signals, and modular playbooks while keeping storage minimal and homelab-friendly.

## Highlights
- Defensive-only controls with audit-only mode
- Risk engine with decay, TTL, and trust offsets
- Anti-spam, anti-raid, anti-phishing modules
- Structured JSON logs and optional health endpoint
- SQLite by default, Postgres optional later

## Quick Start (Docker)
1) Copy .env.example to .env and set DISCORD_TOKEN
2) Copy config.yaml.example to config.yaml (optional)
3) Run: docker compose up -d

## Configuration
Environment variables override config.yaml. Minimal required:
- DISCORD_TOKEN

Common environment options:
- DATABASE_PATH (default /data/sentinel.db)
- LOG_LEVEL (debug, info, warn, error)
- DEFAULT_SECURITY_LOG_CHANNEL
- DEFAULT_LANGUAGE (fr, en, es)
- RETENTION_DAYS
- RULE_PRESET (low, medium, high)
- MODE (normal, audit)
- ACTIONS_ENABLED (enable enforcement)
- ACTIONS_TIMEOUT_MINUTES (timeout duration)
- QUARANTINE_ROLE_ID (optional quarantine role)
- CHANNEL_WARN_ENABLED (send warnings to security channel)
- DM_WARN_ENABLED (send warnings by DM)
- AUDIT_TO_CHANNEL (mirror audit logs to security channel)
- DAILY_SUMMARY (daily summary of top risk and voice)
- EMBED_COLOR_ACTION (decimal color for action embed)
- EMBED_COLOR_WARNING (decimal color for warning embed)
- EMBED_COLOR_ERROR (decimal color for error embed)

## Sensitive Files
Keep secrets and local data out of git. Create these in the project root unless noted.
- .env (real tokens and secrets; based on .env.example)
- config.yaml (local settings; based on config.yaml.example)
- data/sentinel.db (SQLite database file)
- logs/ (local log files, if you enable file logging)

If you need per-machine overrides, use .env.local or config.yaml.local and keep them ignored.

Example .env (project root):
```
DISCORD_TOKEN=YOUR_DISCORD_BOT_TOKEN
CONFIG_PATH=config.yaml
DATABASE_PATH=./data/sentinel.db
LOG_LEVEL=info
DEFAULT_SECURITY_LOG_CHANNEL=
DEFAULT_LANGUAGE=fr
MODE=normal
ACTIONS_ENABLED=false
AUDIT_TO_CHANNEL=true
DAILY_SUMMARY=true
```

Example config.yaml (project root):
```yaml
discord_token: ""
database_path: "./data/sentinel.db"
log_level: "info"
default_security_log_channel: ""
default_language: "fr"
retention_days: 14
rule_preset: "medium"
mode: "normal"

actions:
	enabled: false
	timeout_minutes: 10
	quarantine_role_id: ""

notifications:
	channel_warn_enabled: true
	dm_warn_enabled: true
	audit_to_channel: true
	daily_summary: true
```

## Audit-Only Mode
When MODE is audit, actions are simulated and only logged. This lets you validate rules before enabling enforcement.

## Data Retention
Audit logs are kept for RETENTION_DAYS and then removed during cleanup cycles. Only minimal identifiers and event summaries are stored.

## Health Endpoint
Set HEALTH_ENABLED=true and HEALTH_ADDR=":8080" to expose /health.

## Slash Commands
- /status
- /mode audit|normal
- /preset low|medium|high
- /lockdown on|off
- /logs (set admin-only channel)
- /rules view|set
- /domain allow add|remove|list
- /domain block add|remove|list
- /report day|week
- /language (fr|en|es)
- /risk reset [user]
- /whitelist add|remove|list [user] [role]
- /nuke status|enable|disable|set
- /verify

## Anti-Nuke and Whitelist
Anti-nuke detects rapid destructive actions from a single actor and responds automatically.
- It uses audit logs to identify who performed the action.
- It counts actions per actor inside `window_seconds` and triggers when the threshold is reached.
- When triggered, it logs `anti_nuke`, enters lockdown, and timeouts the actor (if enforcement is enabled).
- Whitelisted/exempt actors can still trigger lockdown if they exceed the extreme threshold, but no sanction is applied.
- Configure the exempt extreme rule with `nuke.exempt_threshold` and `nuke.exempt_window_seconds`.

Whitelist exclusions:
- Server owner and admins are always excluded.
- You can add trusted users or roles with `/whitelist`.

Keys for `/nuke set`:
- window_seconds
- channel_delete, channel_create, channel_update
- role_delete, role_create, role_update
- webhook_update
- ban_add
- guild_update

## Recommended Stable Defaults
These defaults aim for a stable and autonomous configuration on small/medium servers.

```yaml
nuke:
	enabled: true
	window_seconds: 20
	channel_delete: 3
	channel_create: 5
	channel_update: 8
	role_delete: 2
	role_create: 4
	role_update: 6
	webhook_update: 3
	ban_add: 3
	guild_update: 2
	exempt_threshold: 20
	exempt_window_seconds: 10

playbook:
	lockdown_slowmode_seconds: 10
	lockdown_deny_send: true

thresholds:
	spam_messages: 6
	spam_window_seconds: 8
	raid_joins: 6
	raid_window_seconds: 10
	phishing_risk: 30
	burst_links: 3
	burst_window_seconds: 60

actions:
	enabled: true
	timeout_minutes: 10
```

## Notes on Actions
Delete, quarantine, timeout, and ban thresholds are configurable. Enforcement is gated by `ACTIONS_ENABLED`. When enabled, Sentinel can apply timeouts and bans, and add a quarantine role if `QUARANTINE_ROLE_ID` is set. Delete still requires message context and remains logged by default.

## Notifications
Warnings are sent as embeds to the security channel and by DM. Audit logs can be mirrored to the security channel. Use `CHANNEL_WARN_ENABLED`, `DM_WARN_ENABLED`, and `AUDIT_TO_CHANNEL` to toggle, and adjust colors using `EMBED_COLOR_ACTION`, `EMBED_COLOR_WARNING`, and `EMBED_COLOR_ERROR`.

## top.gg Ready
Recommended scopes:
- bot
- applications.commands

Recommended permissions:
- Read Messages/View Channels
- Manage Messages
- Moderate Members (for timeouts)
- Ban Members (optional)

Privacy statement: Sentinel Adaptive stores minimal security metadata (guild ID, user ID, event, and timestamp) and respects configurable retention.

## Development
- Go 1.21+
- Build: go build ./cmd/sentinel
- Test: go test ./...

## Migrations
- SQLite migrations live in internal/storage/migrations
- Optional helper: scripts/migrate.sh (requires sqlite3)

## Homelab Tips
- Mount /data as a persistent volume
- Keep LOG_LEVEL=info for JSON logs
- Run audit mode first to tune thresholds
