package utils

import (
	"testing"
	"time"
)

func TestJoinCounter(t *testing.T) {
	counter := NewJoinCounter(5 * time.Second)
	now := time.Now()
	if count := counter.Add(now); count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}
	counter.Add(now.Add(1 * time.Second))
	counter.Add(now.Add(2 * time.Second))
	if count := counter.Add(now.Add(3 * time.Second)); count != 4 {
		t.Fatalf("expected 4, got %d", count)
	}
	if count := counter.Add(now.Add(7 * time.Second)); count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}
}
