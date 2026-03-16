# Sentinel Adaptive

> Defensive Discord security bot — risk scoring, trust engine, modular threat detection, and an optional web dashboard.

Sentinel Adaptive is a self-hosted, privacy-first Discord bot designed for multi-guild deployments. It combines an in-memory risk/trust engine with specialized detection modules (anti-spam, anti-raid, anti-phishing, anti-nuke, escalation ladder) and a playbook-based lockdown system — all driven by structured configuration and a PostgreSQL backend.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start — Docker](#quick-start--docker)
- [Quick Start — Manual](#quick-start--manual)
- [Configuration Reference](#configuration-reference)
- [Slash Commands](#slash-commands)
- [Detection Modules](#detection-modules)
  - [Risk Engine](#risk-engine)
  - [Trust Engine](#trust-engine)
  - [Anti-Spam](#anti-spam)
  - [Anti-Raid](#anti-raid)
  - [Anti-Phishing](#anti-phishing)
  - [Anti-Nuke](#anti-nuke)
  - [Escalation Ladder](#escalation-ladder)
  - [Lockdown Playbook](#lockdown-playbook)
- [Audit System](#audit-system)
- [Whitelist](#whitelist)
- [Notifications](#notifications)
- [Web Dashboard](#web-dashboard)
- [Audit-Only Mode](#audit-only-mode)
- [Discord Permissions](#discord-permissions)
- [Development](#development)

---

## Features

| Module | What it does |
|---|---|
| **Risk Engine** | In-memory score per user with configurable decay, TTL, and trust offset |
| **Trust Engine** | Positive score that reduces effective risk for well-behaved users |
| **Anti-Spam** | Sliding-window burst detection; adds risk and deletes messages |
| **Anti-Raid** | Join rate monitor; triggers lockdown when threshold is exceeded |
| **Anti-Phishing** | Blocklist + link reputation pipeline (redirect resolution, WHOIS age, Google Safe Browsing) |
| **Anti-Nuke** | Per-actor action counter against channel/role/webhook/ban/guild mass-events |
| **Escalation Ladder** | Centralized risk-score-driven palier system: warn → mute → kick → ban |
| **Lockdown Playbook** | Multi-phase channel freeze (Lockdown → Strict → Exiting → Normal) with auto-restore |
| **Audit Logger** | Structured DB log with optional mirror to security channel |
| **Web Dashboard** | OAuth2 Discord login, guild overview, audit log, risk leaderboard, module config |
| **Audit-Only Mode** | Simulate all enforcement silently — ideal for threshold tuning |

---

## Architecture

```
Discord Gateway
      │
      ▼
  bot.go  ──────────────────────────────────────────────────────────────
  │  onMessageCreate        → antispam, antiphishing, behavior, trust
  │  onGuildMemberAdd       → antiraid → lockdown
  │  onChannel/Role/WebhookUpdate, onGuildBanAdd, onGuildUpdate
  │                         → antinuke → lockdown + sanction
  │  applyRiskActions       → escalation ladder → legacy action thresholds
  └─────────────────────────────────────────────────────────────────────

  internal/
  ├── risk/          In-memory risk engine (decay, TTL, composite score)
  ├── trust/         In-memory trust engine (capped positive score)
  ├── playbook/      Lockdown state machine (multi-phase, timed exit)
  ├── analytics/     Aggregated report queries
  ├── modules/
  │   ├── antispam/        Sliding-window burst detection
  │   ├── antiraid/        Join-rate sliding window
  │   ├── antiphishing/    Blocklist + 3-step reputation pipeline
  │   ├── antinuke/        Per-actor action counter
  │   ├── audit/           Structured audit logger
  │   ├── behavior/        Passive signal collector
  │   ├── escalation/      Centralized risk-palier action engine
  │   └── verification/    /verify handler
  ├── storage/       PostgreSQL store + embedded SQL migrations
  ├── config/        YAML + env config loader
  └── dashboard/     HTTP server (OAuth2, guild pages, billing)
```

---

## Requirements

- **Go 1.24+**
- **PostgreSQL 14+** — the only supported database (connection via `DATABASE_URL`)
- A Discord bot application with the following gateway intents:
  - `GUILDS`, `GUILD_MESSAGES`, `GUILD_MEMBERS`, `GUILD_BANS`, `MESSAGE_CONTENT`, `GUILD_VOICE_STATES`

---

## Quick Start — Docker

```bash
# 1. Copy and fill in the required secrets
cp .env.example .env
# Set at minimum: DISCORD_TOKEN and DATABASE_URL

# 2. Copy the example config (optional — environment variables take precedence)
cp config.yaml.example config.yaml

# 3. Start
docker compose up -d
```

The compose stack runs a single `sentinel` container. Mount `/data` as a persistent volume if you need the legacy database path (unused by default — `DATABASE_URL` is required).

---

## Quick Start — Manual

```bash
# Build
go build -o sentinel ./cmd/sentinel

# Run (minimal)
DISCORD_TOKEN=your_token DATABASE_URL=postgres://user:pass@host/db ./sentinel

# Run with config file
CONFIG_PATH=./config.yaml ./sentinel
```

Migrations run automatically at startup. No manual `migrate` step is needed.

---

## Configuration Reference

All keys in `config.yaml` can be overridden by environment variables. Required fields are marked.

### Core

| ENV | YAML key | Default | Notes |
|---|---|---|---|
| `DISCORD_TOKEN` ★ | `discord_token` | — | Bot token (required) |
| `DATABASE_URL` ★ | `database_url` | — | PostgreSQL DSN (required) |
| `LOG_LEVEL` | `log_level` | `info` | `debug`, `info`, `warn`, `error` |
| `DEFAULT_SECURITY_LOG_CHANNEL` | `default_security_log_channel` | — | Fallback channel ID for security events |
| `DEFAULT_LANGUAGE` | `default_language` | `fr` | `fr`, `en`, `es` |
| `RETENTION_DAYS` | `retention_days` | `14` | Audit log retention in days |
| `RULE_PRESET` | `rule_preset` | `medium` | `low`, `medium`, `high` — adjusts action thresholds |
| `MODE` | `mode` | `normal` | `normal` or `audit` — audit disables enforcement |
| `ADMIN_DISCORD_USER_ID` | `admin_discord_user_id` | — | Discord user ID with access to `/admin` dashboard |

### Health Endpoint

| ENV | YAML key | Default |
|---|---|---|
| `HEALTH_ENABLED` | `health.enabled` | `false` |
| `HEALTH_ADDR` | `health.addr` | `:8080` |

Exposes `GET /health → 200 ok` when enabled.

### Risk Engine

| YAML key | Default | Notes |
|---|---|---|
| `risk.decay_per_minute` | `0.5` | Score points removed per minute of inactivity |
| `risk.ttl_minutes` | `60` | Entry deleted after this period of inactivity |
| `risk.trust_weight` | `0.5` | Multiplier applied to trust score when computing effective risk |

**Effective score** = `max(0, risk_score − trust_score × trust_weight)`

### Trust Engine

| YAML key | Default | Notes |
|---|---|---|
| `trust.max_score` | `100` | Upper cap |
| `trust.ttl_minutes` | `1440` | 24 h default |

Trust increases by +0.5 for every clean message. It never decays passively — only via TTL expiry.

### Thresholds

| YAML key | Default | Notes |
|---|---|---|
| `thresholds.spam_messages` | `6` | Messages within the spam window to trigger |
| `thresholds.spam_window_seconds` | `8` | Rolling window for spam detection |
| `thresholds.raid_joins` | `6` | Joins within the raid window to trigger lockdown |
| `thresholds.raid_window_seconds` | `10` | Rolling window for raid detection |
| `thresholds.phishing_risk` | `30` | Risk delta added on static phishing detection |
| `thresholds.burst_links` | `3` | Links within the burst window |
| `thresholds.burst_window_seconds` | `20` | Rolling window for link burst |

### Actions (Legacy Thresholds)

Applied in `applyRiskActions` after the escalation ladder.

| YAML key | Default | Notes |
|---|---|---|
| `actions.enabled` | `false` | Master switch — enforcement disabled by default |
| `actions.delete` | `20` | Effective score threshold for delete signal |
| `actions.quarantine` | `40` | Effective score threshold for quarantine role |
| `actions.timeout` | `60` | Effective score threshold for timeout |
| `actions.ban` | `80` | Effective score threshold for ban |
| `actions.timeout_minutes` | `10` | Duration of applied timeout |
| `actions.quarantine_role_id` | — | Role ID to assign on quarantine |

Presets (`rule_preset`) override these thresholds at load time:

| Preset | delete | quarantine | timeout | ban |
|---|---|---|---|---|
| `low` | 30 | 55 | 75 | 95 |
| `medium` | 20 | 40 | 60 | 80 |
| `high` | 15 | 30 | 50 | 70 |

### Anti-Nuke

| YAML key | Default |
|---|---|
| `nuke.enabled` | `true` |
| `nuke.window_seconds` | `20` |
| `nuke.channel_delete` | `3` |
| `nuke.channel_create` | `6` |
| `nuke.channel_update` | `6` |
| `nuke.role_delete` | `3` |
| `nuke.role_create` | `6` |
| `nuke.role_update` | `6` |
| `nuke.webhook_update` | `4` |
| `nuke.ban_add` | `3` |
| `nuke.guild_update` | `2` |
| `nuke.exempt_threshold` | `20` |
| `nuke.exempt_window_seconds` | `10` |

Whitelisted actors use `exempt_threshold` / `exempt_window_seconds` instead of the regular limits. Exceeding the exempt threshold triggers lockdown only (no personal sanction).

### Escalation Ladder

| YAML key | Default | Notes |
|---|---|---|
| `escalation.enabled` | `false` | Master switch |
| `escalation.cooldown_minutes` | `60` | Minimum time between two escalations for the same user |
| `escalation.paliers` | see below | Ordered list of score thresholds |

Default paliers:

```yaml
escalation:
  enabled: true
  cooldown_minutes: 60
  paliers:
    - score: 30
      action: warn
    - score: 50
      action: mute
      duration_minutes: 5
    - score: 70
      action: mute
      duration_minutes: 30
    - score: 85
      action: kick
    - score: 100
      action: ban
```

Actions: `warn` (audit only), `mute` (Discord timeout), `kick`, `ban`. The highest matching palier is selected. The cooldown is stored in `escalation_log` and persists across restarts.

### Lockdown Playbook

| YAML key | Default | Notes |
|---|---|---|
| `playbook.lockdown_minutes` | `15` | Total lockdown duration |
| `playbook.strict_mode_minutes` | `10` | Duration of the initial strict phase |
| `playbook.exit_step_seconds` | `20` | Delay between exit phases |
| `playbook.lockdown_slowmode_seconds` | `10` | Slowmode applied during lockdown |
| `playbook.lockdown_deny_send` | `true` | Deny `SEND_MESSAGES` during lockdown |

Phase sequence: **Lockdown + Strict** → (strict_mode_minutes) → **Lockdown + Exiting** → (lockdown_minutes) → **Normal**. Channel permissions are snapshotted and restored automatically.

### Notifications

| ENV | YAML key | Default |
|---|---|---|
| `CHANNEL_WARN_ENABLED` | `notifications.channel_warn_enabled` | `true` |
| `DM_WARN_ENABLED` | `notifications.dm_warn_enabled` | `true` |
| `AUDIT_TO_CHANNEL` | `notifications.audit_to_channel` | `true` |
| `DAILY_SUMMARY` | `notifications.daily_summary` | `true` |
| `EMBED_COLOR_ACTION` | `notifications.embed_colors.action` | `16001675` |
| `EMBED_COLOR_WARNING` | `notifications.embed_colors.warning` | `15684410` |
| `EMBED_COLOR_ERROR` | `notifications.embed_colors.error` | `16309654` |

### Dashboard

| ENV | YAML key | Notes |
|---|---|---|
| `DASHBOARD_ADDR` | `dashboard.addr` | Default `0.0.0.0:8081` |
| `DISCORD_CLIENT_ID` | `dashboard.client_id` | OAuth2 client ID |
| `DISCORD_CLIENT_SECRET` | `dashboard.client_secret` | OAuth2 secret |
| `DASHBOARD_REDIRECT_URL` | `dashboard.redirect_url` | Must match Discord app settings |
| `DASHBOARD_SESSION_SECRET` | `dashboard.session_secret` | Cookie signing secret |

---

## Slash Commands

| Command | Description |
|---|---|
| `/status` | Current mode, preset, and lockdown state |
| `/mode audit\|normal` | Switch enforcement mode |
| `/preset low\|medium\|high` | Switch rule preset |
| `/lockdown on\|off` | Manually enter or exit lockdown |
| `/logs [channel]` | View or set the security log channel |
| `/rules view` | Show current thresholds |
| `/rules set [options]` | Update spam/raid/phishing thresholds |
| `/domain allow add\|remove\|list [domain]` | Manage phishing allowlist |
| `/domain block add\|remove\|list [domain]` | Manage phishing blocklist |
| `/risk reset [user]` | Reset a user's risk score |
| `/whitelist add\|remove\|list [user] [role]` | Manage whitelist |
| `/nuke status` | Show anti-nuke configuration |
| `/nuke enable\|disable` | Toggle anti-nuke |
| `/nuke set key value` | Update a specific nuke threshold |
| `/report day\|week` | Audit summary for the period |
| `/language fr\|en\|es` | Set server language |
| `/test raid\|spam\|phishing\|risk` | Simulate a detection event |
| `/verify` | Request manual verification |

---

## Detection Modules

### Risk Engine

The risk engine maintains an in-memory `float64` score per `(guildID, userID)` pair. Each detection module adds a risk delta. The score decays passively at `decay_per_minute` and is erased after `ttl_minutes` of inactivity.

**Effective score** offsets risk by the user's trust score: a user with trust 80 and risk weight 0.5 has their effective risk reduced by 40 points. This lets long-standing members tolerate occasional flags without being sanctioned.

### Trust Engine

Trust is a capped positive score that accumulates passively (`+0.5` per clean message). It is never automatically decreased — only the TTL removes it. It is used exclusively to compute the effective risk score.

### Anti-Spam

Tracks per-user message counts in a sliding window (`spam_window_seconds`). When the count exceeds `spam_messages`:
- Adds +12 risk points
- Deletes the triggering message (if not in audit mode)
- Logs `anti_spam` WARN

### Anti-Raid

Tracks guild join events in a sliding window (`raid_window_seconds`). When the count exceeds `raid_joins`:
- Triggers lockdown immediately
- Logs `raid_lockdown` WARN

### Anti-Phishing

Two-phase detection:

**Phase 1 — Static blocklist (fast path)**
- Checks each URL against the per-guild blocklist
- Checks message content for phishing keywords (`nitro`, `free`, `claim`, `gift`, `steam`, `giveaway`)
- On match: adds `phishing_risk` points, deletes the message, logs WARN

**Phase 2 — Reputation pipeline** (runs in parallel for URLs not in the blocklist)

The pipeline has a 5-second global timeout and two concurrent goroutines:

| | Step | Timeout | On failure |
|---|---|---|---|
| Goroutine A | **1. Redirect resolution** — follows HTTP redirects (max 5 hops) with a neutral User-Agent to obtain the real final domain | 3 s | Uses original domain |
| Goroutine A | **2. WHOIS domain age** — queries WHOIS for the registrable domain; < 7 days → +70, < 30 days → +40. Results cached 1 h in memory. | 3 s | Score 0 (fail open) |
| Goroutine B | **3. Google Safe Browsing v4** — checks MALWARE, SOCIAL\_ENGINEERING, UNWANTED\_SOFTWARE. On match → +80, log CRIT. | 3 s | Score 0 (fail open) |

The pipeline only runs when `SAFE_BROWSING_API_KEY` is set in the environment (step 3 is silently skipped otherwise). All steps fail open — a network error never flags a message.

### Anti-Nuke

Monitors destructive guild events in a per-actor sliding window. When the count for a single actor exceeds the configured threshold within `window_seconds`:
1. Triggers lockdown
2. Applies a timeout to the actor (if `actions.enabled`)
3. Logs `anti_nuke` CRIT

Whitelisted actors are subject to `exempt_threshold` / `exempt_window_seconds`. When exceeded, lockdown is triggered but no personal sanction is applied.

Tracked event types: `channel_delete`, `channel_create`, `channel_update`, `role_delete`, `role_create`, `role_update`, `webhook_update`, `ban_add`, `guild_update`.

### Escalation Ladder

A centralized palier system driven by the **effective risk score**. It runs in `applyRiskActions`, alongside — not replacing — the legacy action thresholds.

1. Checks if the module is enabled
2. Finds the highest palier whose `score` threshold is met
3. Checks the per-user cooldown from the `escalation_log` table
4. Skips whitelisted users
5. Applies the action, logs the event, and persists the record

Actions available: `warn` (audit-only log), `mute` (Discord timeout with configurable duration), `kick`, `ban`.

### Lockdown Playbook

The playbook is a state machine per guild. Once triggered:

```
[Normal] → [Lockdown + Strict]
               │ (strict_mode_minutes)
               ▼
           [Lockdown + Exiting]
               │ (lockdown_minutes)
               ▼
           [Normal]  ← permissions restored from snapshot
```

On entry, all text/news channels have their `@everyone` permission overwrites snapshotted. Slowmode is applied and `SEND_MESSAGES` is denied (when `lockdown_deny_send: true`). On exit, all overwrites are restored to their original state.

---

## Audit System

Every detection and enforcement action is written to the `audit_logs` table:

| Field | Description |
|---|---|
| `guild_id` | Affected guild |
| `user_id` | Target user (empty for guild-level events) |
| `level` | `INFO`, `WARN`, or `CRIT` |
| `event` | Machine-readable event type (e.g. `anti_spam`, `anti_nuke`, `escalation`) |
| `details` | Human-readable summary |
| `created_at` | Unix timestamp |

When `audit_to_channel: true`, logs are mirrored as embeds to the security log channel in real time. Logs older than `retention_days` are purged automatically.

---

## Whitelist

The whitelist exempts users and roles from module enforcement. Server owners and administrators are always implicitly whitelisted.

Manage via `/whitelist add|remove|list [user] [role]`.

- Whitelisted users bypass: anti-spam, anti-phishing, and escalation.
- Whitelisted users are subject to anti-nuke's `exempt_threshold` instead of the regular thresholds.
- The whitelist is stored per-guild in the `whitelist_users` and `whitelist_roles` tables.

---

## Notifications

Three notification channels are available:

| Channel | Config key | Description |
|---|---|---|
| Security embed | `channel_warn_enabled` | Action summary sent as a rich embed to the security log channel |
| DM warning | `dm_warn_enabled` | Warning DM sent to the target user |
| Audit mirror | `audit_to_channel` | All `audit.Log` entries mirrored to the security channel |

Embed colors are fully configurable as decimal integers.

---

## Web Dashboard

The dashboard is a server-side rendered web UI accessible at `dashboard.addr` (default `:8081`). Authentication is via Discord OAuth2.

| Route | Description |
|---|---|
| `/` | Public landing page |
| `/login` | Login page |
| `/auth/login` | OAuth2 redirect |
| `/auth/callback` | OAuth2 callback |
| `/app` | Guild selector (requires auth) |
| `/app/guild` | Guild overview — mode, preset, lockdown state |
| `/app/guild/audit` | Audit log browser |
| `/app/guild/risk` | Risk score leaderboard |
| `/app/guild/modules` | Module configuration |
| `/app/billing` | Subscription management (Stripe) |
| `/admin` | Admin panel (requires `admin_discord_user_id`) |

**Required OAuth2 scopes:** `identify`, `guilds`, `email`
**Redirect URL** must be set in both `dashboard.redirect_url` and the Discord application's OAuth2 settings.

---

## Audit-Only Mode

Set `MODE=audit` (or `mode: audit` in config.yaml, or `/mode audit`) to run without enforcement:

- All detections are logged normally
- No messages are deleted
- No timeouts, kicks, or bans are applied
- Escalation logs `audit=true` but does not act
- Embeds display `[SIMULATION]` labels

Use audit mode to tune thresholds before going live. Switching back to `normal` mode activates enforcement immediately.

---

## Discord Permissions

Minimum required permissions:

| Permission | Why |
|---|---|
| `Read Messages / View Channels` | Event handling |
| `Manage Messages` | Delete flagged messages |
| `Manage Channels` | Apply slowmode during lockdown |
| `Moderate Members` | Issue timeouts |
| `Kick Members` | Escalation kick action |
| `Ban Members` | Escalation / anti-nuke ban action |
| `View Audit Log` | Resolve actor in anti-nuke events |

Recommended invite scope: `bot applications.commands`

---

## Development

```bash
# Build
go build ./cmd/sentinel

# Run all tests
go test ./...

# Run tests for a specific module
go test ./internal/modules/antiphishing/... -v

# Lint (if golangci-lint is installed)
golangci-lint run
```

### Project Layout

```
cmd/sentinel/          Entry point
internal/
  analytics/           Report queries
  bot/                 Core bot wiring, Discord event handlers
  config/              Config loader (YAML + env)
  dashboard/           HTTP dashboard server
  modules/
    antinuke/          Action counter per actor
    antiphishing/      Phishing detection + reputation pipeline
    antiraid/          Join rate limiter
    antispam/          Message burst detector
    audit/             Structured audit logger
    behavior/          Passive signal collector
    escalation/        Risk-palier enforcement ladder
    verification/      /verify handler
  playbook/            Lockdown state machine
  risk/                In-memory risk engine
  storage/             PostgreSQL store + SQL migrations
  trust/               In-memory trust engine
  utils/               Sliding window, URL normalizer, join counter
web/                   Embedded static assets
```

### Environment Variables for Development

```bash
DISCORD_TOKEN=your_token
DATABASE_URL=postgres://sentinel:secret@localhost/sentinel
LOG_LEVEL=debug
MODE=audit
ACTIONS_ENABLED=false
CONFIG_PATH=./config.yaml
SAFE_BROWSING_API_KEY=          # optional
```

### Adding a Module

1. Create `internal/modules/yourmodule/module.go`
2. Define a `Module` struct with `*risk.Engine` and `*audit.Logger`
3. Implement a `Handle*` method that returns `(score float64, flagged bool)`
4. Add the module field and `New(...)` call in `internal/bot/bot.go`
5. Call the handler from the appropriate Discord event handler in `bot.go`
6. Add any new config keys to `internal/config/config.go` and `config.yaml.example`

---

## Sensitive Files

Keep the following out of version control:

```
.env                   # real tokens and secrets
config.yaml            # local overrides
```

Both are in `.gitignore` by default. Use `.env.example` and `config.yaml.example` as templates.

---

*Copyright (c) 2026 yaiito. All rights reserved. See [LICENSE](LICENSE) for terms.*
