package checks

import (
	"os"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func loadTestData(filename string) *gjson.Result {
	content, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	record := gjson.ParseBytes(content)
	return &record
}

func TestRangeHasIntroducedEvent(t *testing.T) {
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
				json: loadTestData("../../test_data/CVE-2023-41045.json"),
			},
			wantFindings: nil,
		},
		{
			name: "A file without an introduced event",
			args: args{
				json: loadTestData("../../test_data/nointroduced-CVE-2023-41045.json"),
			},
			wantFindings: []CheckError{{Message: "missing 'introduced' object in event"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFindings := RangeHasIntroducedEvent(tt.args.json)
			if diff := cmp.Diff(tt.wantFindings, gotFindings, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("RangeHasIntroducedEvent() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
