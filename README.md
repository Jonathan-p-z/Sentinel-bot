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
- /verify

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
