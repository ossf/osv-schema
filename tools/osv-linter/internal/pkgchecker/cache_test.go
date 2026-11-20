package pkgchecker

import (
	"net/http"
	"net/http/httptest"
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
		if _, err := fetchPackageData(url); err != nil {
			t.Fatalf("fetchPackageData(%q) error: %v", url, err)
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
		if _, err := fetchPackageData(missing); err == nil {
			t.Fatalf("fetchPackageData(%q) succeeded, want error", missing)
		}
	}
	if got := requests.Load(); got != 6 {
		t.Errorf("requests for a missing package = %d, want 6 (failures are not cached)", got)
	}
}
