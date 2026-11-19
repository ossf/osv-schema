package checks

import (
	"testing"

	"github.com/tidwall/gjson"
)

// gjson tolerates the trailing comma and keeps it in Raw, so the schema
// validator's parser is the first thing that rejects this record.
const unparseableRecord = `{"id":"CVE-2018-5407","modified":"2024-05-29T23:34:56Z",}`

func TestSchemaCheck(t *testing.T) {
	t.Parallel()

	unparseable := gjson.Parse(unparseableRecord)

	tests := []struct {
		name         string
		json         *gjson.Result
		config       *Config
		wantFindings int
	}{
		{
			name:         "A compliant file",
			json:         LoadTestData("../../testdata/CVE-2018-5407.json"),
			config:       &Config{},
			wantFindings: 0,
		},
		{
			name:         "A record the schema validator cannot parse",
			json:         &unparseable,
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "Compliant record with x_ prefix and null aliases",
			json:         parseJSON(`{"id": "x_CUSTOM-0001", "modified": "2024-05-29T23:34:56Z", "aliases": null}`),
			config:       &Config{},
			wantFindings: 0,
		},
		{
			name:         "Compliant record with valid aliases, upstream, and related",
			json:         parseJSON(`{"id": "CVE-2023-0001", "modified": "2024-05-29T23:34:56Z", "aliases": ["SNYK-JS-YARN-537806", "CVE-2023-0002"], "upstream": ["CVE-2023-0003"], "related": ["GHSA-xxxx-yyyy-zzzz"]}`),
			config:       &Config{},
			wantFindings: 0,
		},
		{
			name:         "ID with trailing comma",
			json:         parseJSON(`{"id": "GHSA-jf66-3q76-h5p5,", "modified": "2024-05-29T23:34:56Z"}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "ID with trailing space",
			json:         parseJSON(`{"id": "CVE-2023-0001 ", "modified": "2024-05-29T23:34:56Z"}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "ID with invalid prefix",
			json:         parseJSON(`{"id": "SNYK-JS-YARN-537806", "modified": "2024-05-29T23:34:56Z"}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "Alias with trailing comma (GHSA)",
			json:         parseJSON(`{"id": "GHSA-jf66-3q76-h5p5", "modified": "2024-05-29T23:34:56Z", "aliases": ["GHSA-jf66-3q76-h5p5,"]}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "Alias with trailing comma (SNYK)",
			json:         parseJSON(`{"id": "GHSA-5xf4-f2fq-f69j", "modified": "2024-05-29T23:34:56Z", "aliases": ["SNYK-JS-YARN-537806,"]}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "Alias with outer spaces",
			json:         parseJSON(`{"id": "DRUPAL-CONTRIB-2026-040", "modified": "2024-05-29T23:34:56Z", "aliases": [" CVE-2026-49977 "]}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "Empty string alias",
			json:         parseJSON(`{"id": "CVE-2023-0001", "modified": "2024-05-29T23:34:56Z", "aliases": [""]}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "Malformed upstream entry",
			json:         parseJSON(`{"id": "CVE-2023-0001", "modified": "2024-05-29T23:34:56Z", "upstream": ["CVE-2026-0001,"]}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "Malformed related entry",
			json:         parseJSON(`{"id": "CVE-2024-3566", "modified": "2024-05-29T23:34:56Z", "related": ["VU#123335"]}`),
			config:       &Config{},
			wantFindings: 1,
		},
		{
			name:         "NewEcosystem suppresses new id prefix and package.ecosystem pattern errors",
			json:         parseJSON(`{"id": "NEWDB-2026-001", "modified": "2024-05-29T23:34:56Z", "affected": [{"package": {"ecosystem": "NewEco:1.0", "name": "pkg"}, "versions": ["1.0.0"]}]}`),
			config:       &Config{NewEcosystem: true},
			wantFindings: 0,
		},
		{
			name:         "NewEcosystem still enforces idFormat on id with new prefix",
			json:         parseJSON(`{"id": "NEWDB-2026-001,", "modified": "2024-05-29T23:34:56Z"}`),
			config:       &Config{NewEcosystem: true},
			wantFindings: 1,
		},
		{
			name:         "NewEcosystem still enforces idFormat on aliases",
			json:         parseJSON(`{"id": "NEWDB-2026-001", "modified": "2024-05-29T23:34:56Z", "aliases": [" CVE-2026-49977 "]}`),
			config:       &Config{NewEcosystem: true},
			wantFindings: 1,
		},
		{
			name:         "NewEcosystem still enforces non-ecosystem pattern checks",
			json:         parseJSON(`{"id": "NEWDB-2026-001", "modified": "not-a-timestamp"}`),
			config:       &Config{NewEcosystem: true},
			wantFindings: 1,
		},
		{
			name:         "NewEcosystem still enforces severity pattern checks",
			json:         parseJSON(`{"id": "NEWDB-2026-001", "modified": "2024-05-29T23:34:56Z", "severity": [{"type": "CVSS_V3", "score": "invalid"}]}`),
			config:       &Config{NewEcosystem: true},
			wantFindings: 1,
		},
		{
			name:         "NewEcosystem does not suppress invalid id type",
			json:         parseJSON(`{"id": 123, "modified": "2024-05-29T23:34:56Z"}`),
			config:       &Config{NewEcosystem: true},
			wantFindings: 1,
		},
		{
			name:         "NewEcosystem does not suppress missing required fields",
			json:         parseJSON(`{"id": "CVE-2023-0001"}`),
			config:       &Config{NewEcosystem: true},
			wantFindings: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFindings := SchemaCheck(tt.json, tt.config)
			if len(gotFindings) != tt.wantFindings {
				t.Errorf("SchemaCheck() returned %d findings, wanted %d: %v",
					len(gotFindings), tt.wantFindings, gotFindings)
			}
		})
	}
}
