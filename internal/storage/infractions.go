package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type UserInfraction struct {
	GuildID    string
	UserID     string
	Category   string
	CountTotal int
	LastAt     time.Time
	LastAction string
	ResetAt    *time.Time
}

func (s *Store) GetInfraction(ctx context.Context, guildID, userID, category string) (UserInfraction, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT guild_id, user_id, category, count_total, last_at, COALESCE(last_action, ''), reset_at
		FROM user_infractions
		WHERE guild_id = ? AND user_id = ? AND category = ?
	`, guildID, userID, category)

	var inf UserInfraction
	var lastAt int64
	var resetAt sql.NullInt64
	err := row.Scan(&inf.GuildID, &inf.UserID, &inf.Category, &inf.CountTotal, &lastAt, &inf.LastAction, &resetAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserInfraction{}, nil
		}
		return UserInfraction{}, err
	}
	inf.LastAt = time.Unix(lastAt, 0)
	if resetAt.Valid {
		value := time.Unix(resetAt.Int64, 0)
		inf.ResetAt = &value
	}
	return inf, nil
}

func (s *Store) IncrementInfraction(ctx context.Context, guildID, userID, category, lastAction string, forgiveAfter time.Duration) (int, error) {
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var count int
	var resetAt sql.NullInt64
	row := tx.QueryRowContext(ctx, `
		SELECT count_total, reset_at
		FROM user_infractions
		WHERE guild_id = ? AND user_id = ? AND category = ?
	`, guildID, userID, category)
	scanErr := row.Scan(&count, &resetAt)
	if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
		err = scanErr
		return 0, err
	}
	if scanErr == nil && resetAt.Valid && now.Unix() >= resetAt.Int64 {
		count = 0
	}

	count++
	var nextReset any
	if forgiveAfter > 0 {
		nextReset = now.Add(forgiveAfter).Unix()
	} else {
		nextReset = nil
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO user_infractions (guild_id, user_id, category, count_total, last_at, last_action, reset_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(guild_id, user_id, category) DO UPDATE SET
			count_total = excluded.count_total,
			last_at = excluded.last_at,
			last_action = excluded.last_action,
			reset_at = excluded.reset_at
	`, guildID, userID, category, count, now.Unix(), lastAction, nextReset)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}
