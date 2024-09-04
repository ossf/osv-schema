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
	if ce.Code == "" {
		return fmt.Sprintf("%s", ce.Message)
	}
	return fmt.Sprintf("[%s]: %s", ce.Code, ce.Message)
}

// CheckDef defines a single check.
type CheckDef struct {
	Code        string
	Name        string
	Description string
	Check       Check
}

// CheckConfig defines the configuration for a check.
type CheckConfig struct {
	Verbose bool
}

// Check defines how to run the check.
type Check func(*gjson.Result, *CheckConfig) []CheckError

// Run runs the check, returning any findings.
// The check has no awareness of the check's Code,
// this merges that with the check's findings.
func (c *CheckDef) Run(json *gjson.Result, config *CheckConfig) (findings []CheckError) {
	for _, finding := range c.Check(json, config) {
		findings = append(findings, CheckError{
			Code:    c.Code,
			Message: finding.Error(),
		})
	}
	return findings
}

// CheckCollection defines a named collection of checks.
type CheckCollection struct {
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

var Collections = []CheckCollection{
	{
		Name:        "ALL",
		Description: "all checks currently defined",
		Checks: []*CheckDef{
			CheckRangeHasIntroducedEvent,
			CheckRangeIsDistinct,
			CheckPackageExists,
			CheckPackageVersionsExist,
			CheckPackagePurlValid,
		},
	},
	{
		Name:        "offline",
		Description: "checks that do not have remote data dependencies",
		Checks: []*CheckDef{
			CheckRangeHasIntroducedEvent,
			CheckRangeIsDistinct,
			CheckPackagePurlValid,
		},
	},
}

// CollectionFromName returns the CheckCollection with the given name.
func CollectionFromName(name string) *CheckCollection {
	for _, checkcollection := range Collections {
		if checkcollection.Name == name {
			return &checkcollection
		}
	}
	return nil
}
