package bot

func (b *Bot) t(lang, key string) string {
	return b.i18n.T(lang, key)
}
