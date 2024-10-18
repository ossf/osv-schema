package checks

import (
	"github.com/tidwall/gjson"
)

var CheckAffectedFieldValid = &CheckDef{
	Code:        "A0001",
	Name:        "affected-field-valid",
	Description: "affected field validates",
	Check:       AffectedFieldValid,
}

// AffectedFieldValid checks if the 'affected' field exists in the JSON and is not an empty array.
func AffectedFieldValid(json *gjson.Result, config *Config) (findings []CheckError) {
	affectedEntries := json.Get("affected")
	if !affectedEntries.Exists() || affectedEntries.String() == "[]" {
		findings = append(findings, CheckError{Message: "Invalid Affected: affected filed cannot be null or empty"})
	}
	return findings
}
