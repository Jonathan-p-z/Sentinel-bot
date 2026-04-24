package billing

import "time"

type Subscription struct {
	ID                   int64
	GuildID              string
	StripeCustomerID     string
	StripeSubscriptionID string
	PriceID              string
	Tier                 string     // "free", "pro", "business", "enterprise"
	Status               string     // "active", "canceled", "past_due"
	CurrentPeriodEnd     *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}
