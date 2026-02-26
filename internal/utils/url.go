package utils

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

var urlRegex = regexp.MustCompile(`https?://[^\s]+`)

var trackingParams = []string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"}

func ExtractURLs(content string) []string {
	return urlRegex.FindAllString(content, -1)
}

func NormalizeURL(raw string) (string, string, error) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}

	host := strings.ToLower(parsed.Hostname())
	asciiHost, err := idna.ToASCII(host)
	if err == nil {
		host = asciiHost
	}

	parsed.Host = host
	parsed.Fragment = ""
	parsed.User = nil

	query := parsed.Query()
	for _, key := range trackingParams {
		query.Del(key)
	}
	parsed.RawQuery = normalizeQuery(query)

	return parsed.String(), host, nil
}

func normalizeQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	clean := url.Values{}
	for _, key := range keys {
		clean[key] = values[key]
	}
	return clean.Encode()
}

func DomainMatch(domain string, allowlist, blocklist map[string]struct{}) (allowed bool, blocked bool) {
	domain = strings.ToLower(domain)
	if _, ok := allowlist[domain]; ok {
		return true, false
	}
	if _, ok := blocklist[domain]; ok {
		return false, true
	}
	return false, false
}
