package internal

import (
	"bytes"
	"os"
	"testing"

	"github.com/ossf/osv-schema/linter/internal/checks"
)

func TestLint_WithdrawnRecords(t *testing.T) {
	// We'll use the REC:004 check (CheckRecordHasValidRelated) to verify whether
	// linting is executed or skipped since it is not bypassed by withdrawn records.
	testChecks := []*checks.CheckDef{
		checks.CheckRecordHasValidRelated,
	}

	tests := []struct {
		name             string
		filename         string
		makeInvalid      bool
		includeWithdrawn bool
		wantFindingsLen  int
	}{
		{
			name:             "Withdrawn record skipped when includeWithdrawn is false",
			filename:         "../testdata/RHSA-2022_0216-withdrawn.json",
			includeWithdrawn: false,
			wantFindingsLen:  0, // Correctly skipped, so 0 findings
		},
		{
			name:             "Withdrawn record linted and fails when includeWithdrawn is true",
			filename:         "../testdata/RHSA-2022_0216-withdrawn.json",
			includeWithdrawn: true,
			wantFindingsLen:  1, // Validation runs and catches the duplicate related ID finding
		},
		{
			name:             "Regular record without withdrawn field should not be skipped",
			filename:         "../testdata/RHSA-2022_0216.json",
			includeWithdrawn: false,
			wantFindingsLen:  1, // Should not be skipped and identify the finding
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contentBytes, err := os.ReadFile(tt.filename)
			if err != nil {
				t.Fatalf("failed to read test file %q: %v", tt.filename, err)
			}

			// Inject a duplicate entry into "related" to ensure a finding is triggered when run
			badRelated := []byte(`"related": ["CVE-2021-44832", "CVE-2021-44832"],`)
			contentBytes = bytes.Replace(contentBytes, []byte(`"related": [`), badRelated, 1)

			content := &Content{
				filename: tt.filename,
				bytes:    contentBytes,
			}
			config := &Config{
				checks:           testChecks,
				includeWithdrawn: tt.includeWithdrawn,
			}

			gotFindings := lint(content, config)
			if len(gotFindings) != tt.wantFindingsLen {
				t.Errorf("lint(%q, {includeWithdrawn: %t}) = %d findings, want %d; findings: %v",
					tt.filename, config.includeWithdrawn, len(gotFindings), tt.wantFindingsLen, gotFindings)
			}
		})
	}
}
