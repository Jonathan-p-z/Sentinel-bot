package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed locales/*.json
var localesFS embed.FS

type I18n struct {
	data map[string]map[string]string
}

func New() (*I18n, error) {
	langs := []string{"fr", "en", "es"}
	data := make(map[string]map[string]string, len(langs))
	for _, lang := range langs {
		path := "locales/" + lang + ".json"
		b, err := localesFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		data[lang] = m
	}
	return &I18n{data: data}, nil
}

func (i *I18n) T(lang, key string) string {
	if lang == "" {
		lang = "fr"
	}
	if strings, ok := i.data[lang]; ok {
		if value, ok := strings[key]; ok {
			return value
		}
	}
	if strings, ok := i.data["en"]; ok {
		if value, ok := strings[key]; ok {
			return value
		}
	}
	return key
}
