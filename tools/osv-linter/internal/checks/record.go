package checks

import (
	"github.com/tidwall/gjson"
)

var CheckRecordHasAffected = &CheckDef{
	Code:        "A0001",
	Name:        "affected-data-exists",
	Description: "every record has affected data",
	Check:       RecordHasAffected,
}

// RecordHasAffected checks if the 'affected' field exists in the JSON and is not an empty array.
func RecordHasAffected(json *gjson.Result, config *Config) (findings []CheckError) {
	affectedEntries := json.Get("affected")
	if !affectedEntries.Exists() || affectedEntries.String() == "[]" {
		findings = append(findings, CheckError{Message: "Invalid Affected: affected field cannot be null or empty"})
	}
	return findings
}
