package web

import "embed"

//go:embed static
var StaticFS embed.FS

//go:embed site
var SiteFS embed.FS
