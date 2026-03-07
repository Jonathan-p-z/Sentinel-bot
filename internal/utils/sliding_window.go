package utils

import (
	"sync"
	"time"
)

type SlidingWindow struct {
	mu     sync.Mutex
	window time.Duration
	hits   []time.Time
}

func NewSlidingWindow(window time.Duration) *SlidingWindow {
	return &SlidingWindow{window: window}
}

func (w *SlidingWindow) Add(now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := now.Add(-w.window)
	idx := 0
	for _, hit := range w.hits {
		if hit.After(cutoff) {
			break
		}
		idx++
	}
	w.hits = w.hits[idx:]
	w.hits = append(w.hits, now)
	return len(w.hits)
}

func (w *SlidingWindow) Count(now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := now.Add(-w.window)
	idx := 0
	for _, hit := range w.hits {
		if hit.After(cutoff) {
			break
		}
		idx++
	}
	w.hits = w.hits[idx:]
	return len(w.hits)
}

// LastAt returns the time of the last recorded hit, or zero if no hits exist.
func (w *SlidingWindow) LastAt() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.hits) == 0 {
		return time.Time{}
	}
	return w.hits[len(w.hits)-1]
}
