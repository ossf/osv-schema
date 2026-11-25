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

func TestRangeEventsOrdered(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		jsonData     string
		wantFindings []CheckError
	}{
		{
			name:         "introduced below fixed",
			jsonData:     `{"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "events listed out of order still sort correctly",
			jsonData:     `{"affected": [{"package": {"ecosystem": "npm", "name": "foo"}, "ranges": [{"type": "SEMVER", "events": [{"fixed": "2.0.1"}, {"introduced": "2.0.0"}, {"fixed": "1.4.3"}, {"introduced": "1.0.0"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "last_affected equal to introduced",
			jsonData:     `{"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.0"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "several fixed events after one introduced",
			jsonData:     `{"affected": [{"package": {"ecosystem": "Alpine:v3.20", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-r0"}, {"fixed": "1.1-r0"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:     "fixed lower than introduced",
			jsonData: `{"affected": [{"package": {"ecosystem": "PyPI", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.1.5.post1"}, {"fixed": "1.1.5"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `fixed "1.1.5" in a ECOSYSTEM range for PyPI/foo is lower than every introduced event, so it has no effect`},
			},
		},
		{
			name:     "SEMVER pre-release ordering",
			jsonData: `{"affected": [{"package": {"ecosystem": "npm", "name": "foo"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0-beta1"}, {"fixed": "4.0.0-beta.11"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `fixed "4.0.0-beta.11" in a SEMVER range for npm/foo is lower than every introduced event, so it has no effect`},
			},
		},
		{
			name:     "fixed and last_affected of 0",
			jsonData: `{"affected": [{"package": {"ecosystem": "Go", "name": "example.com/foo"}, "ranges": [{"type": "SEMVER", "events": [{"fixed": "0"}, {"introduced": "1.0.0"}, {"last_affected": "0.9.0"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `fixed "0" in a SEMVER range for Go/example.com/foo is lower than every introduced event, so it has no effect`},
				{Message: `last_affected "0.9.0" in a SEMVER range for Go/example.com/foo is lower than every introduced event, so it has no effect`},
			},
		},
		{
			name:     "only the offending range of several is reported",
			jsonData: `{"affected": [{"package": {"ecosystem": "npm", "name": "foo"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.3.2"}]}, {"type": "SEMVER", "events": [{"introduced": "3.0.1"}, {"fixed": "3.0.0"}]}]}]}`,
			wantFindings: []CheckError{
				{Message: `fixed "3.0.0" in a SEMVER range for npm/foo is lower than every introduced event, so it has no effect`},
			},
		},
		{
			name:         "GIT ranges are skipped",
			jsonData:     `{"affected": [{"ranges": [{"type": "GIT", "repo": "https://example.com/repo", "events": [{"introduced": "b"}, {"fixed": "a"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "unsupported ecosystem is skipped",
			jsonData:     `{"affected": [{"package": {"ecosystem": "Example", "name": "foo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2"}, {"fixed": "1"}]}]}]}`,
			wantFindings: nil,
		},
		{
			name:         "no affected field",
			jsonData:     `{"id": "TEST-1"}`,
			wantFindings: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			json := gjson.Parse(tt.jsonData)
			gotFindings := RangeEventsOrdered(&json, &Config{})
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("RangeEventsOrdered() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
