package billing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/storage"
)

func (s *BillingService) WebhookHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		payload, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		event, err := webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), s.cfg.Stripe.WebhookSecret)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		ctx := context.Background()
		switch event.Type {
		case "checkout.session.completed":
			s.handleCheckoutCompleted(ctx, event)
		case "customer.subscription.updated":
			s.handleSubscriptionUpdated(ctx, event)
		case "customer.subscription.deleted":
			s.handleSubscriptionDeleted(ctx, event)
		}

		w.WriteHeader(http.StatusOK)
	}
}

func (s *BillingService) handleCheckoutCompleted(ctx context.Context, event stripe.Event) {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		return
	}
	if session.Mode != stripe.CheckoutSessionModeSubscription {
		return
	}

	guildID := session.Metadata["guild_id"]
	priceID := session.Metadata["price_id"]
	if guildID == "" || session.Customer == nil || session.Subscription == nil {
		return
	}

	sub := storage.Subscription{
		GuildID:              guildID,
		StripeCustomerID:     session.Customer.ID,
		StripeSubscriptionID: session.Subscription.ID,
		PriceID:              priceID,
		Tier:                 tierFromPriceID(priceID, s.cfg),
		Status:               "active",
		CurrentPeriodEnd:     time.Now().AddDate(0, 1, 0),
	}
	_ = s.store.UpsertSubscription(ctx, sub)
}

func (s *BillingService) handleSubscriptionUpdated(ctx context.Context, event stripe.Event) {
	var stripeSub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &stripeSub); err != nil {
		return
	}

	row, err := s.store.GetSubscriptionByStripeSubID(ctx, stripeSub.ID)
	if err != nil || row == nil {
		return
	}

	row.Status = string(stripeSub.Status)
	if stripeSub.Items != nil && len(stripeSub.Items.Data) > 0 {
		item := stripeSub.Items.Data[0]
		if item.CurrentPeriodEnd > 0 {
			row.CurrentPeriodEnd = time.Unix(item.CurrentPeriodEnd, 0)
		}
		if item.Price != nil {
			row.PriceID = item.Price.ID
			row.Tier = tierFromPriceID(row.PriceID, s.cfg)
		}
	}
	_ = s.store.UpsertSubscription(ctx, *row)
}

func (s *BillingService) handleSubscriptionDeleted(ctx context.Context, event stripe.Event) {
	var stripeSub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &stripeSub); err != nil {
		return
	}

	row, err := s.store.GetSubscriptionByStripeSubID(ctx, stripeSub.ID)
	if err != nil || row == nil {
		return
	}

	row.Tier = "free"
	row.Status = "canceled"
	_ = s.store.UpsertSubscription(ctx, *row)
}

func tierFromPriceID(priceID string, cfg *config.Config) string {
	switch priceID {
	case cfg.Stripe.PriceIDPro:
		return "pro"
	case cfg.Stripe.PriceIDBusiness:
		return "business"
	case cfg.Stripe.PriceIDEnterprise:
		return "enterprise"
	default:
		return "free"
	}
}
