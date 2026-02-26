package utils

import (
	"testing"
	"time"
)

func TestSlidingWindowAdd(t *testing.T) {
	window := NewSlidingWindow(2 * time.Second)
	now := time.Now()
	if count := window.Add(now); count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}
	window.Add(now.Add(500 * time.Millisecond))
	if count := window.Count(now.Add(1 * time.Second)); count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}
	if count := window.Count(now.Add(3 * time.Second)); count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}
}
