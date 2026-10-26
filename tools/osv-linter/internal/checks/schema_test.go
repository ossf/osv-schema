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
		wantFindings int
	}{
		{
			name:         "A compliant file",
			json:         LoadTestData("../../testdata/CVE-2018-5407.json"),
			wantFindings: 0,
		},
		{
			name:         "A record the schema validator cannot parse",
			json:         &unparseable,
			wantFindings: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFindings := SchemaCheck(tt.json, &Config{})
			if len(gotFindings) != tt.wantFindings {
				t.Errorf("SchemaCheck() returned %d findings, wanted %d: %v",
					len(gotFindings), tt.wantFindings, gotFindings)
			}
		})
	}
}
