// Package web serves the embedded control-plane UI.
//
// The SPA is built from web/ (npm run build), which writes into dist/. dist is
// committed so `go build` works without Node. Rebuild it after UI changes.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler serves the SPA. Real files are served as-is; any other GET without
// a file extension gets index.html so client-side routes work. Unknown
// /api/ paths and missing assets get 404, never the HTML shell.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // embed path is fixed at compile time
	}
	files := http.FileServerFS(sub)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") {
			http.NotFound(w, r)
			return
		}
		clean := strings.TrimPrefix(path.Clean("/"+p), "/")
		if clean == "" {
			clean = "index.html"
		}
		// Hashed build assets never change; everything else (index.html,
		// theme-init.js) must be revalidated so a new release shows up at once.
		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if _, err := fs.Stat(sub, clean); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		if path.Ext(clean) != "" {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	})
}
