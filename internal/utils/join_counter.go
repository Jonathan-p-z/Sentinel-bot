package utils

import (
	"sync"
	"time"
)

type JoinCounter struct {
	mu      sync.Mutex
	window  time.Duration
	entries []time.Time
}

func NewJoinCounter(window time.Duration) *JoinCounter {
	return &JoinCounter{window: window}
}

func (c *JoinCounter) Add(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Add(-c.window)
	idx := 0
	for _, entry := range c.entries {
		if entry.After(cutoff) {
			break
		}
		idx++
	}
	c.entries = c.entries[idx:]
	c.entries = append(c.entries, now)
	return len(c.entries)
}
