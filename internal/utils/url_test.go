package utils

import "testing"

func TestNormalizeURL(t *testing.T) {
	normalized, domain, err := NormalizeURL("https://Example.com/path?utm_source=test&x=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domain != "example.com" {
		t.Fatalf("unexpected domain: %s", domain)
	}
	if normalized != "https://example.com/path?x=1" {
		t.Fatalf("unexpected normalized url: %s", normalized)
	}
}

func TestDomainMatch(t *testing.T) {
	allow := map[string]struct{}{"good.com": {}}
	block := map[string]struct{}{"bad.com": {}}
	allowed, blocked := DomainMatch("good.com", allow, block)
	if !allowed || blocked {
		t.Fatalf("expected allow only")
	}
	allowed, blocked = DomainMatch("bad.com", allow, block)
	if allowed || !blocked {
		t.Fatalf("expected block only")
	}
}
