package httpapi

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// spa serves the single-page app (history-API fallback) or, in API-only modes, a JSON 404.
func (s *Server) spa() http.Handler {
	mode := s.Cfg.SPAMode
	if (mode != "embedded" && mode != "dir") || s.SPA == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mode == "external" && s.Cfg.SPAURL != "" && r.URL.Path == "/" {
				http.Redirect(w, r, s.Cfg.SPAURL, http.StatusFound)
				return
			}
			writeAPIError(w, http.StatusNotFound, "not_found", "Not found.")
		})
	}
	root := s.SPA
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if st, err := fs.Stat(root, p); err != nil || st.IsDir() {
			if path.Ext(p) != "" { // a missing asset is a 404, never index.html
				http.NotFound(w, r)
				return
			}
			p = "index.html" // client-side route
		}
		switch {
		case p == "index.html":
			w.Header().Set("Cache-Control", "no-cache")
		case strings.HasPrefix(p, "assets/"): // Vite content-hashed files
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		http.ServeFileFS(w, r, root, p)
	})
}
