CREATE TABLE subscriptions (
    id                     SERIAL PRIMARY KEY,
    guild_id               TEXT NOT NULL UNIQUE,
    stripe_customer_id     TEXT,
    stripe_subscription_id TEXT,
    price_id               TEXT,
    tier                   TEXT NOT NULL DEFAULT 'free',
    status                 TEXT NOT NULL DEFAULT 'active',
    current_period_end     TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
