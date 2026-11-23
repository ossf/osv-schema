package pkgchecker

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
)

func Test_successfulRequestsAreCached(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/Example/versions.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"1.0.0": {}}`))
	}))
	defer srv.Close()

	url := srv.URL + "/Example/versions.json"
	for range 3 {
		if !checkPackageExists(url) {
			t.Fatalf("checkPackageExists(%q) = false, want true", url)
		}
		if got, err := fetchJSONVersions(url, "@keys"); err != nil || !slices.Equal(got, []string{"1.0.0"}) {
			t.Fatalf("fetchJSONVersions(%q, %q) = %v, %v; want [1.0.0], nil", url, "@keys", got, err)
		}
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("requests for an existing package = %d, want 2 (one HEAD, one GET)", got)
	}

	requests.Store(0)
	missing := srv.URL + "/Missing/versions.json"
	for range 3 {
		if checkPackageExists(missing) {
			t.Fatalf("checkPackageExists(%q) = true, want false", missing)
		}
		if _, err := fetchJSONVersions(missing, "@keys"); err == nil {
			t.Fatalf("fetchJSONVersions(%q, %q) succeeded, want error", missing, "@keys")
		}
	}
	if got := requests.Load(); got != 6 {
		t.Errorf("requests for a missing package = %d, want 6 (failures are not cached)", got)
	}
}

func Test_versionsByURLAndJSONPath(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`[{"version":"go1.24.0","other":"1.0.0"}]`))
	}))
	defer srv.Close()

	for range 2 {
		for path, want := range map[string][]string{
			"#.version": {"go1.24.0"},
			"#.other":   {"1.0.0"},
		} {
			if got, err := fetchJSONVersions(srv.URL, path); err != nil || !slices.Equal(got, want) {
				t.Fatalf("fetchJSONVersions(%q, %q) = %v, %v; want %v, nil", srv.URL, path, got, err, want)
			}
		}
		if _, err := fetchJSONVersions(srv.URL, "missing"); err != errPathNotFound {
			t.Fatalf("fetchJSONVersions(%q, %q) error = %v, want %v", srv.URL, "missing", err, errPathNotFound)
		}
	}
	if got := requests.Load(); got != 4 {
		t.Errorf("requests = %d, want 4 (one per valid path and two for the missing path)", got)
	}
}

func Test_goModuleVersionsAreCached(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/released/@v/list" {
			_, _ = w.Write([]byte("v1.0.0\nv1.2.0\n"))
		}
	}))
	defer srv.Close()

	for range 2 {
		for path, want := range map[string][]string{
			"/released/@v/list":   {"v1.0.0", "v1.2.0"},
			"/unreleased/@v/list": {},
		} {
			url := srv.URL + path
			if got, err := fetchGoModuleVersions(url); err != nil || !slices.Equal(got, want) {
				t.Fatalf("fetchGoModuleVersions(%q) = %v, %v; want %v, nil", url, got, err, want)
			}
		}
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("requests = %d, want 2 (one per module)", got)
	}
}
