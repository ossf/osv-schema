package checks

import (
	"testing"

	"github.com/tidwall/gjson"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestAffectedField(t *testing.T) {
	t.Parallel()

	type args struct {
		json *gjson.Result
	}
	tests := []struct {
		name         string
		args         args
		wantFindings []CheckError
	}{
		{
			name: "A compliant file",
			args: args{
				json: LoadTestData("../../testdata/CVE-2023-41045.json"),
			},
			wantFindings: nil,
		},
		{
			name: "A file with an empty affected field",
			args: args{
				json: LoadTestData("../../testdata/SUSE-FU-2022_0444-1.json"),
			},
			wantFindings: []CheckError{{Message: "Invalid Affected: affected field cannot be null or empty"}},
		},
		{
			name: "A file without affected field",
			args: args{
				json: LoadTestData("../../testdata/RHSA-2022_0216.json"),
			},
			wantFindings: []CheckError{{Message: "Invalid Affected: affected field cannot be null or empty"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFindings := RecordHasAffected(tt.args.json, &Config{Verbose: true})
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("RecordHasAffected() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAliasesCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "Valid aliases",
			jsonData:     `{"id": "CVE-2023-0001", "aliases": ["GHSA-xxxx-yyyy-zzzz", "CVE-2023-0002"]}`,
			wantFindings: nil,
		},
		{
			name:         "Aliases field missing",
			jsonData:     `{"id": "CVE-2023-0001"}`,
			wantFindings: nil,
		},
		{
			name:         "Empty aliases array",
			jsonData:     `{"id": "CVE-2023-0001", "aliases": []}`,
			wantFindings: nil,
		},
		{
			name:     "Duplicate aliases",
			jsonData: `{"id": "CVE-2023-0001", "aliases": ["GHSA-xxxx-yyyy-zzzz", "GHSA-xxxx-yyyy-zzzz"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Aliases: aliases should not contain duplicate entries"},
			},
		},
		{
			name:     "Alias contains record ID",
			jsonData: `{"id": "CVE-2023-0001", "aliases": ["CVE-2023-0001", "GHSA-xxxx-yyyy-zzzz"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Aliases: aliases should not contain itself"},
			},
		},
		{
			name:     "Duplicate aliases and contains record ID",
			jsonData: `{"id": "CVE-2023-0001", "aliases": ["CVE-2023-0001", "CVE-2023-0001"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Aliases: aliases should not contain duplicate entries"},
				{Message: "Invalid Aliases: aliases should not contain itself"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonResult := gjson.Parse(tt.jsonData)
			gotFindings := AliasesCheck(&jsonResult, &Config{Verbose: true})
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("AliasesCheck() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRelatedCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "Valid related IDs",
			jsonData:     `{"id": "CVE-2023-0001", "related": ["CVE-2023-0002", "CVE-2023-0003"]}`,
			wantFindings: nil,
		},
		{
			name:         "Related field missing",
			jsonData:     `{"id": "CVE-2023-0001"}`,
			wantFindings: nil,
		},
		{
			name:         "Empty related array",
			jsonData:     `{"id": "CVE-2023-0001", "related": []}`,
			wantFindings: nil,
		},
		{
			name:     "Duplicate related IDs",
			jsonData: `{"id": "CVE-2023-0001", "related": ["CVE-2023-0002", "CVE-2023-0002"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Related: Related should not contain duplicate entries"},
			},
		},
		{
			name:     "Related ID contains record ID",
			jsonData: `{"id": "CVE-2023-0001", "related": ["CVE-2023-0001", "CVE-2023-0002"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Related: Related should not contain itself"},
			},
		},
		{
			name:     "Duplicate related IDs and contains record ID",
			jsonData: `{"id": "CVE-2023-0001", "related": ["CVE-2023-0001", "CVE-2023-0001"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Related: Related should not contain duplicate entries"},
				{Message: "Invalid Related: Related should not contain itself"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonResult := gjson.Parse(tt.jsonData)
			gotFindings := RelatedCheck(&jsonResult, &Config{Verbose: true})
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("RelatedCheck() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIDCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "Valid CVE ID",
			jsonData:     `{"id": "CVE-2023-0001"}`,
			wantFindings: nil,
		},
		{
			name:         "Valid ID with permitted punctuation",
			jsonData:     `{"id": "GO:stdlib-1.2.3_beta"}`,
			wantFindings: nil,
		},
		{
			name:         "ID field missing",
			jsonData:     `{"aliases": ["CVE-2023-0001"]}`,
			wantFindings: nil,
		},
		{
			name:     "ID contains a space",
			jsonData: `{"id": "CVE 2023 0001"}`,
			wantFindings: []CheckError{
				{Message: `Invalid ID: id "CVE 2023 0001" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
		{
			name:     "ID contains a slash",
			jsonData: `{"id": "OSV/2023/0001"}`,
			wantFindings: []CheckError{
				{Message: `Invalid ID: id "OSV/2023/0001" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonResult := gjson.Parse(tt.jsonData)
			gotFindings := IDCheck(&jsonResult, &Config{Verbose: true})
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("IDCheck() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReferencedIDsCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "Valid aliases, upstream, and related IDs",
			jsonData:     `{"id": "CVE-2023-0001", "aliases": ["SNYK-JS-YARN-537806", "GHSA-xxxx-yyyy-zzzz"], "upstream": ["GO:stdlib-1.2.3_beta"], "related": ["DSA-3029-1"]}`,
			wantFindings: nil,
		},
		{
			name:         "Fields missing",
			jsonData:     `{"id": "CVE-2023-0001"}`,
			wantFindings: nil,
		},
		{
			name:         "Null aliases and empty arrays",
			jsonData:     `{"id": "CVE-2023-0001", "aliases": null, "upstream": [], "related": []}`,
			wantFindings: nil,
		},
		{
			name:         "Non-string array entries are ignored",
			jsonData:     `{"id": "CVE-2023-0001", "aliases": [123, null, "CVE-2023-0002"], "upstream": [true], "related": [{}]}`,
			wantFindings: nil,
		},
		{
			name:     "Alias with trailing comma (GHSA)",
			jsonData: `{"id": "GHSA-jf66-3q76-h5p5", "aliases": ["GHSA-jf66-3q76-h5p5,"]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Aliases: alias "GHSA-jf66-3q76-h5p5," contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
		{
			name:     "Alias with trailing comma (SNYK)",
			jsonData: `{"id": "GHSA-5xf4-f2fq-f69j", "aliases": ["SNYK-JS-YARN-537806,"]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Aliases: alias "SNYK-JS-YARN-537806," contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
		{
			name:     "Alias with leading and trailing spaces",
			jsonData: `{"id": "DRUPAL-CONTRIB-2026-040", "aliases": [" CVE-2026-49977 "]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Aliases: alias " CVE-2026-49977 " contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
		{
			name:     "Empty string alias",
			jsonData: `{"id": "CVE-2023-0001", "aliases": [""]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Aliases: alias "" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
		{
			name:     "Invalid upstream entries",
			jsonData: `{"id": "CVE-2026-0002", "upstream": ["CVE-2026-0001,", "UP 001"]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Upstream: upstream "CVE-2026-0001," contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
				{Message: `Invalid Upstream: upstream "UP 001" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
		{
			name:     "Invalid related entries",
			jsonData: `{"id": "CVE-2024-3566", "related": ["VU#123335", "REL/001"]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Related: related "VU#123335" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
				{Message: `Invalid Related: related "REL/001" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
		{
			name:     "Multiple findings across aliases, upstream, and related",
			jsonData: `{"id": "CVE-2026-0001", "aliases": ["CVE-2026-0002,"], "upstream": ["UP 001"], "related": ["VU#123335"]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Aliases: alias "CVE-2026-0002," contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
				{Message: `Invalid Upstream: upstream "UP 001" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
				{Message: `Invalid Related: related "VU#123335" contains characters outside the permitted set [a-zA-Z0-9:_.-]`},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonResult := gjson.Parse(tt.jsonData)
			gotFindings := ReferencedIDsCheck(&jsonResult, &Config{Verbose: true})
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("ReferencedIDsCheck() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUpstreamCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "Valid upstream",
			jsonData:     `{"id": "MY-ID-001", "aliases": ["CVE-001"], "related": ["ADV-001"], "upstream": ["UP-001", "UP-002"]}`,
			wantFindings: nil,
		},
		{
			name:         "Upstream field missing",
			jsonData:     `{"id": "MY-ID-001"}`,
			wantFindings: nil,
		},
		{
			name:         "Empty upstream array",
			jsonData:     `{"id": "MY-ID-001", "upstream": []}`,
			wantFindings: nil,
		},
		{
			name:     "Duplicate upstream IDs",
			jsonData: `{"id": "MY-ID-001", "upstream": ["UP-001", "UP-001"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Upstream: upstream should not contain duplicate entries"},
			},
		},
		{
			name:     "Upstream contains record ID",
			jsonData: `{"id": "MY-ID-001", "upstream": ["MY-ID-001"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Upstream: upstream should not contain itself"},
			},
		},
		{
			name:     "Upstream contains an alias",
			jsonData: `{"id": "MY-ID-001", "aliases": ["CVE-001"], "upstream": ["CVE-001"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Upstream: upstream should not contain aliases"},
			},
		},
		{
			name:     "Upstream contains a related ID",
			jsonData: `{"id": "MY-ID-001", "related": ["ADV-001"], "upstream": ["ADV-001"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Upstream: upstream should not contain related IDs"},
			},
		},
		{
			name:     "Upstream contains duplicate, self, alias, and related",
			jsonData: `{"id": "MY-ID-001", "aliases": ["CVE-001"], "related": ["ADV-001"], "upstream": ["UP-DUP", "UP-DUP", "MY-ID-001", "CVE-001", "ADV-001"]}`,
			wantFindings: []CheckError{
				{Message: "Invalid Upstream: upstream should not contain duplicate entries"},
				{Message: "Invalid Upstream: upstream should not contain itself"},
				{Message: "Invalid Upstream: upstream should not contain aliases"},
				{Message: "Invalid Upstream: upstream should not contain related IDs"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonResult := gjson.Parse(tt.jsonData)
			gotFindings := UpstreamCheck(&jsonResult, &Config{Verbose: true})
			// Sort findings for consistent comparison as order can vary
			opts := []cmp.Option{
				cmpopts.EquateErrors(),
				cmpopts.SortSlices(func(a, b CheckError) bool { return a.Message < b.Message }),
			}
			if diff := cmp.Diff(tt.wantFindings, gotFindings, opts...); diff != "" {
				t.Errorf("UpstreamCheck() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
