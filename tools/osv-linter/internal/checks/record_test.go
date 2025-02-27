package checks

import (
	"testing"

	"github.com/tidwall/gjson"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestAffectedField(t *testing.T) {
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
				json: LoadTestData("../../test_data/CVE-2023-41045.json"),
			},
			wantFindings: nil,
		},
		{
			name: "A file with an empty affected field",
			args: args{
				json: LoadTestData("../../test_data/SUSE-FU-2022:0444-1.json"),
			},
			wantFindings: []CheckError{{Message: "Invalid Affected: affected field cannot be null or empty"}},
		},
		{
			name: "A file without affected field",
			args: args{
				json: LoadTestData("../../test_data/RHSA-2022:0216.json"),
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
