package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/client"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/storage"
)

type BillingService struct {
	sc    *client.API
	store *storage.Store
	cfg   *config.Config
}

func New(cfg *config.Config, store *storage.Store) *BillingService {
	sc := &client.API{}
	sc.Init(cfg.Stripe.SecretKey, nil)
	return &BillingService{sc: sc, store: store, cfg: cfg}
}

func (s *BillingService) CreateCheckoutSession(guildID, discordUserID, priceID, successURL, cancelURL string) (*stripe.CheckoutSession, error) {
	ctx := context.Background()

	row, err := s.store.GetSubscription(ctx, guildID)
	if err != nil {
		return nil, fmt.Errorf("get subscription: %w", err)
	}

	customerID := ""
	if row != nil && row.StripeCustomerID != "" {
		customerID = row.StripeCustomerID
	} else {
		c, err := s.sc.Customers.New(&stripe.CustomerParams{
			Metadata: map[string]string{
				"guild_id":        guildID,
				"discord_user_id": discordUserID,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("create stripe customer: %w", err)
		}
		customerID = c.ID
	}

	params := &stripe.CheckoutSessionParams{
		Customer:   stripe.String(customerID),
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL: stripe.String(successURL),
		CancelURL:  stripe.String(cancelURL),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		Metadata: map[string]string{
			"guild_id":        guildID,
			"discord_user_id": discordUserID,
			"price_id":        priceID,
		},
	}
	return s.sc.CheckoutSessions.New(params)
}

func (s *BillingService) GetSubscription(guildID string) (*Subscription, error) {
	row, err := s.store.GetSubscription(context.Background(), guildID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return &Subscription{GuildID: guildID, Tier: "free", Status: "active"}, nil
	}
	return fromStorage(row), nil
}

func (s *BillingService) CancelSubscription(guildID string) error {
	ctx := context.Background()
	row, err := s.store.GetSubscription(ctx, guildID)
	if err != nil {
		return fmt.Errorf("get subscription: %w", err)
	}
	if row == nil || row.StripeSubscriptionID == "" {
		return errors.New("no active subscription for this guild")
	}

	if _, err := s.sc.Subscriptions.Cancel(row.StripeSubscriptionID, nil); err != nil {
		return fmt.Errorf("cancel stripe subscription: %w", err)
	}

	now := time.Now()
	row.Tier = "free"
	row.Status = "canceled"
	row.CurrentPeriodEnd = now
	return s.store.UpsertSubscription(ctx, *row)
}

func fromStorage(s *storage.Subscription) *Subscription {
	sub := &Subscription{
		ID:                   s.ID,
		GuildID:              s.GuildID,
		StripeCustomerID:     s.StripeCustomerID,
		StripeSubscriptionID: s.StripeSubscriptionID,
		PriceID:              s.PriceID,
		Tier:                 s.Tier,
		Status:               s.Status,
		CreatedAt:            s.CreatedAt,
		UpdatedAt:            s.UpdatedAt,
	}
	if !s.CurrentPeriodEnd.IsZero() {
		t := s.CurrentPeriodEnd
		sub.CurrentPeriodEnd = &t
	}
	return sub
}
