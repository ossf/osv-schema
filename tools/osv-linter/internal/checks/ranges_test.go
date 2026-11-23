package checks

import (
	"os"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func LoadTestData(filename string) *gjson.Result {
	content, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	record := gjson.ParseBytes(content)
	return &record
}

func TestRangeHasIntroducedEvent(t *testing.T) {
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
			name: "A file without an introduced event",
			args: args{
				json: LoadTestData("../../testdata/nointroduced-CVE-2023-41045.json"),
			},
			wantFindings: []CheckError{{Message: "missing 'introduced' object in event"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFindings := RangeHasIntroducedEvent(tt.args.json, &Config{Verbose: true})
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("RangeHasIntroducedEvent() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRangeFixedAfterIntroduced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "fixed after introduced",
			jsonData:     `{"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.0.post1"}, {"introduced": "2.0rc1"}, {"last_affected": "2.0"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "introduced 0 is before everything",
			jsonData:     `{"affected": [{"package": {"ecosystem": "npm", "name": "foo"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.0.1"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "events don't have to be sorted",
			jsonData:     `{"affected": [{"package": {"ecosystem": "Go", "name": "example.com/foo"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.5.0"}, {"fixed": "1.2.0"}, {"introduced": "1.0.0"}, {"fixed": "1.6.0"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "equal versions are left to RNG:002",
			jsonData:     `{"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.0.0"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "GIT ranges and unknown ecosystems are not checked",
			jsonData:     `{"affected": [{"package": {"ecosystem": "NotAnEcosystem", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2"}, {"fixed": "1"}]}]}, {"ranges": [{"type": "GIT", "repo": "https://example.com/repo", "events": [{"introduced": "b"}, {"fixed": "a"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:     "swapped versions",
			jsonData: `{"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.1.0"}, {"fixed": "2.0.9"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Range: affected[0].ranges[0] (PyPI/foo) has fixed "2.0.9", which is before every introduced version`},
			},
		},
		{
			name:     "version order of the ecosystem is used",
			jsonData: `{"affected": [{"package": {"ecosystem": "Maven", "name": "org.example:foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.10"}, {"fixed": "1.9"}]}]}, {"package": {"ecosystem": "Debian:12", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1:1.0-1"}, {"last_affected": "2.0-1"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Range: affected[0].ranges[0] (Maven/org.example:foo) has fixed "1.9", which is before every introduced version`},
				{Message: `Invalid Range: affected[1].ranges[0] (Debian:12/foo) has last_affected "2.0-1", which is before every introduced version`},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			json := gjson.Parse(tt.jsonData)
			gotFindings := RangeFixedAfterIntroduced(&json, &Config{})
			if diff := cmp.Diff(tt.wantFindings, gotFindings); diff != "" {
				t.Errorf("RangeFixedAfterIntroduced() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
