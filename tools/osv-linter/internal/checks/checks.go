// Package checks defines and implements all checks and collections of checks.
//
// To add additional checks:
// 1. define a new instance of `Check`
// 2. add it to the `checks` array
// 3. add it to the relevent collections defined in `checkCollections`
//
// To add additional collections of checks:
// 1. add to the `checkCollections` array.
package checks

import (
	"fmt"

	"github.com/tidwall/gjson"
)

// CheckError describes when a check fails.
type CheckError struct {
	Code    string
	Message string
}

// Error returns the error message, including the code.
func (ce *CheckError) Error() string {
	return fmt.Sprintf("%s: %s", ce.Code, ce.Message)
}

// CheckDef defines a single check.
type CheckDef struct {
	Code        string
	Name        string
	Description string
	Check       Check
}

// Check defines how to run the check.
type Check func(*gjson.Result) []CheckError

// Run runs the check, returning any findings.
// The check has no awareness of the check's Code,
// this merges that with the check's findings.
func (c *CheckDef) Run(json *gjson.Result) (findings []CheckError) {
	for _, finding := range c.Check(json) {
		findings = append(findings, CheckError{
			Code:    c.Code,
			Message: finding.Error(),
		})
	}
	return findings
}

// CheckCollectionDef defines a named collection of checks.
type CheckCollectionDef struct {
	Name        string
	Description string
	Checks      []*CheckDef
}

// FromCode returns the check with a specific code.
func FromCode(code string) *CheckDef {
	for _, check := range CollectionFromName("ALL").Checks {
		if check.Code == code {
			return check
		}
	}
	return nil
}

// FromName returns the check with a specific name.
func FromName(name string) *CheckDef {
	for _, check := range CollectionFromName("ALL").Checks {
		if check.Name == name {
			return check
		}
	}
	return nil
}

var Collections = []CheckCollectionDef{
	{
		Name:        "ALL",
		Description: "all checks currently defined",
		Checks: []*CheckDef{
			CheckRangeHasIntroducedEvent,
			CheckRangeIsDistinct,
		},
	},
	{
		Name:        "osv.dev",
		Description: "the checks OSV.dev considers necessary for a high quality record",
		Checks: []*CheckDef{
			CheckRangeHasIntroducedEvent,
			CheckRangeIsDistinct,
		},
	},
}

// CollectionFromName returns the CheckCollectionDef with the given name.
func CollectionFromName(name string) *CheckCollectionDef {
	for _, checkcollection := range Collections {
		if checkcollection.Name == name {
			return &checkcollection
		}
	}
	return nil
}
