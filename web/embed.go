package web

import "embed"

// Files contains the dependency-free management console and API documentation shell.
//
//go:embed *.html *.css *.js *.json
var Files embed.FS
