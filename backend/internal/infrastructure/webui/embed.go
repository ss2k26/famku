// Package webui holds the built frontend (vite build output, see frontend/vite.config.ts) compiled into the binary.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the frontend files with "dist/" stripped.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
