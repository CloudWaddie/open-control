package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestServesShellAndClientRoutes(t *testing.T) {
	// /index.html is redirected to / by http.FileServer; that is expected.
	for _, p := range []string{"/", "/audit", "/profiles/3"} {
		code, body := get(t, p)
		if code != http.StatusOK || !strings.Contains(body, `id="root"`) {
			t.Errorf("GET %s: got %d, want the SPA shell", p, code)
		}
	}
}

func TestMissingAssetsAndAPIAre404(t *testing.T) {
	for _, p := range []string{"/assets/nope.js", "/favicon.ico", "/api/v1/unknown"} {
		if code, body := get(t, p); code != http.StatusNotFound || strings.Contains(body, `id="root"`) {
			t.Errorf("GET %s: got %d, want a plain 404 (not the shell)", p, code)
		}
	}
}
