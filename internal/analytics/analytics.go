package analytics

import (
	"context"
	"time"

	"sentinel-adaptive/internal/storage"
)

type Service struct {
	store *storage.Store
}

func New(store *storage.Store) *Service {
	return &Service{store: store}
}

type Report struct {
	Total int
	ByLevel map[string]int
}

func (s *Service) Report(ctx context.Context, guildID string, since time.Time) (Report, error) {
	logs, err := s.store.ListAuditLogs(ctx, guildID, since)
	if err != nil {
		return Report{}, err
	}

	report := Report{ByLevel: make(map[string]int)}
	for _, log := range logs {
		report.Total++
		report.ByLevel[log.Level]++
	}
	return report, nil
}
