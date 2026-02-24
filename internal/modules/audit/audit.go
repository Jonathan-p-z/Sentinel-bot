package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"sentinel-adaptive/internal/storage"

	"go.uber.org/zap"
)

const (
	LevelInfo = "INFO"
	LevelWarn = "WARN"
	LevelHigh = "HIGH"
	LevelCrit = "CRIT"
)

type Logger struct {
	store  *storage.Store
	logger *zap.Logger
	notify func(context.Context, storage.AuditLog)
}

func NewLogger(store *storage.Store, logger *zap.Logger) *Logger {
	return &Logger{store: store, logger: logger}
}

func (l *Logger) SetNotifier(notify func(context.Context, storage.AuditLog)) {
	l.notify = notify
}

func (l *Logger) Log(ctx context.Context, level, guildID, userID, event, details string) {
	traceID := newEventID()
	entry := storage.AuditLog{
		EventID:     newEventID(),
		TraceID:     traceID,
		GuildID:     guildID,
		UserID:      userID,
		Level:       level,
		Event:       event,
		Details:     details,
		DetailsJSON: fmt.Sprintf(`{"event":"%s","user_id":"%s","details":%q}`, event, userID, details),
		CreatedAt:   time.Now(),
	}
	if l.store != nil {
		_ = l.store.AddAuditLog(ctx, entry)
	}
	if l.notify != nil {
		l.notify(ctx, entry)
	}
	l.logger.Info("audit", zap.String("level", level), zap.String("guild_id", guildID), zap.String("user_id", userID), zap.String("event", event), zap.String("details", details))
}

func newEventID() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("E%X", time.Now().UnixNano())
	}
	return strings.ToUpper(hex.EncodeToString(buf))
}
