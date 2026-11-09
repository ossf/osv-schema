package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConvertRecord(t *testing.T) {
	input := map[string]any{
		"id":               "EUVD-2026-15465",
		"enisaUuid":        "uuid-1",
		"description":      "Example vulnerability",
		"datePublished":    "Mar 25, 2026, 3:21:43 PM",
		"dateUpdated":      "Mar 26, 2026, 2:34:55 PM",
		"baseScore":        5.3,
		"baseScoreVersion": "3.1",
		"baseScoreVector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
		"aliases":          "CVE-2026-3210\nGHSA-example\n",
		"assigner":         "example",
		"epss":             0.22,
		"exploitedSince":   "2026-03-20",
		"references":       "https://nvd.nist.gov/vuln/detail/CVE-2026-3210\nhttps://example.com/commit/abc\n",
		"enisaIdProduct": []any{map[string]any{
			"product":         map[string]any{"name": "Material Icons", "vendor": map[string]any{"name": "Drupal"}},
			"product_version": ">=0.0.0, <2.0.4",
		}},
		"enisaIdVendor": []any{map[string]any{"vendor": map[string]any{"name": "Drupal"}}},
	}
	output := convertRecord(input)
	if output["published"] != "2026-03-25T15:21:43Z" {
		t.Fatalf("unexpected published date: %v", output["published"])
	}
	if got := output["aliases"].([]any); len(got) != 2 || got[0] != "CVE-2026-3210" {
		t.Fatalf("unexpected aliases: %v", got)
	}
	if got := output["severity"].([]any)[0].(map[string]any)["type"]; got != "CVSS_V3" {
		t.Fatalf("unexpected severity type: %v", got)
	}
	databaseSpecific := output["database_specific"].(map[string]any)
	if databaseSpecific["base_score"] != 5.3 ||
		databaseSpecific["base_score_version"] != "3.1" ||
		databaseSpecific["exploited_since"] != "2026-03-20" ||
		databaseSpecific["enisa_vendors"].([]any)[0] != "Drupal" {
		t.Fatalf("metadata was not preserved: %v", databaseSpecific)
	}
	if got := output["references"].([]any)[0].(map[string]any)["type"]; got != "ADVISORY" {
		t.Fatalf("unexpected reference type: %v", got)
	}
	affected := output["affected"].([]any)[0].(map[string]any)
	ranges := affected["ranges"].([]map[string]any)
	events := ranges[0]["events"].([]any)
	if events[1].(map[string]string)["fixed"] != "2.0.4" {
		t.Fatalf("unexpected affected range: %v", events)
	}
}

func TestDumpPaginationAndFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		if query.Get("fromDate") != "2025-10-01" {
			t.Errorf("fromDate query missing: %v", query)
		}
		var items []map[string]any
		switch query.Get("page") {
		case "0":
			items = []map[string]any{
				{"id": "EUVD-TEST-1", "aliases": "CVE-1", "baseScore": 5.3},
				{"id": "EUVD-TEST-2", "aliases": "CVE-1", "baseScore": 7.0},
			}
		case "1":
			items = []map[string]any{{"id": "EUVD-TEST-3", "aliases": "GHSA-1", "baseScore": 5.3}}
		default:
			t.Errorf("unexpected page: %s", query.Get("page"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"total": 3, "items": items})
	}))
	defer server.Close()

	outputDirectory := t.TempDir()
	stdout := new(strings.Builder)
	err := runDump([]string{
		"--fromDate", "2025-10-01", "--aliases", "CVE-1", "--baseScore", "5.3", outputDirectory,
	}, stdout, io.Discard, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDirectory, "EUVD-TEST-1.json")); err != nil {
		t.Fatalf("expected matching advisory file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDirectory, "EUVD-TEST-2.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected non-matching advisory file, stat error: %v", err)
	}
	if stdout.String() != "Dumped 1 advisories.\n" {
		t.Fatalf("unexpected summary: %q", stdout.String())
	}
}

func TestFetchDumpPageRetriesForbidden(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(writer, "temporary rate limit", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"total": 1,
			"items": []map[string]any{{"id": "EUVD-TEST-200"}},
		})
	}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fetchDumpPage(server.Client(), request, 200, func(time.Duration) {})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || len(response.Items) != 1 || response.Items[0]["id"] != "EUVD-TEST-200" {
		t.Fatalf("unexpected retry result: attempts=%d response=%v", attempts, response)
	}
}

func TestParseVersionRanges(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"Before 2.0", `[{"events":[{"introduced":"0"},{"fixed":"2.0"}],"type":"ECOSYSTEM"}]`},
		{"Before and including 3.0", `[{"events":[{"introduced":"0"},{"last_affected":"3.0"}],"type":"ECOSYSTEM"}]`},
		{">=1.0, <2.0", `[{"events":[{"introduced":"1.0"},{"fixed":"2.0"}],"type":"ECOSYSTEM"}]`},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			got, err := json.Marshal(parseVersionRanges(test.version))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestQueryEncoding(t *testing.T) {
	values := url.Values{"text": {"a & b"}}
	if values.Encode() != "text=a+%26+b" {
		t.Fatalf("unexpected URL encoding: %s", values.Encode())
	}
}
