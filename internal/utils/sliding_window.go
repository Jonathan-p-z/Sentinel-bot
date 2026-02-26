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
