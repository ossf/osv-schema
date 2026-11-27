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

func TestRangeVersionsValid(t *testing.T) {
	t.Parallel()

	const commit = "e818b74be2170fbe957a07b0da4401c2b694b3b8"
	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "valid SEMVER range",
			jsonData:     `{"affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3-rc.1+build.5"}, {"introduced": "2.0.0"}, {"last_affected": "2.0.4"}, {"limit": "*"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "valid GIT range",
			jsonData:     `{"affected": [{"ranges": [{"type": "GIT", "repo": "https://example.com/repo", "events": [{"introduced": "0"}, {"fixed": "` + commit + `"}, {"limit": "` + commit + `"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "SHA-256 commit hash",
			jsonData:     `{"affected": [{"ranges": [{"type": "GIT", "repo": "https://example.com/repo", "events": [{"introduced": "` + commit + `aaaaaaaaaaaaaaaaaaaaaaaa"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "ECOSYSTEM ranges are not checked",
			jsonData:     `{"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "v1"}, {"fixed": "1.0.post1"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:     "SEMVER versions with a v prefix or missing parts",
			jsonData: `{"affected": [{"package": {"ecosystem": "Go", "name": "example.com/foo"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "v1.0.0"}, {"fixed": "1.2"}, {"introduced": "1.3.0"}, {"limit": "01.4.0"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Range: affected[0].ranges[0] (SEMVER) has introduced "v1.0.0", which is not a SemVer 2.0.0 version without a leading "v"`},
				{Message: `Invalid Range: affected[0].ranges[0] (SEMVER) has fixed "1.2", which is not a SemVer 2.0.0 version without a leading "v"`},
				{Message: `Invalid Range: affected[0].ranges[0] (SEMVER) has limit "01.4.0", which is not a SemVer 2.0.0 version without a leading "v"`},
			},
		},
		{
			name:     "0 is only special for introduced",
			jsonData: `{"affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "0"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Range: affected[0].ranges[0] (SEMVER) has fixed "0", which is not a SemVer 2.0.0 version without a leading "v"`},
			},
		},
		{
			name:     "GIT versions that are tags or short hashes",
			jsonData: `{"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}, {"ranges": [{"type": "GIT", "repo": "https://example.com/repo", "events": [{"introduced": "v1.2.3"}, {"fixed": "e818b74"}, {"last_affected": "` + commit + `"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `Invalid Range: affected[1].ranges[0] (GIT) has introduced "v1.2.3", which is not a full-length commit hash`},
				{Message: `Invalid Range: affected[1].ranges[0] (GIT) has fixed "e818b74", which is not a full-length commit hash`},
			},
		},
		{
			name:         "no affected",
			jsonData:     `{"id": "TEST-1"}`,
			wantFindings: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			json := gjson.Parse(tt.jsonData)
			gotFindings := RangeVersionsValid(&json, &Config{})
			if diff := cmp.Diff(tt.wantFindings, gotFindings); diff != "" {
				t.Errorf("RangeVersionsValid() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
