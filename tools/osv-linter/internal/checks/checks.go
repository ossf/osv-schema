// Package checks defines and implements all checks and collections of checks.
//
// To add additional checks:
// 1. define a new instance of `Check`
// 2. add it to the `checks` array
// 3. add it to the relevent collections defined in `checkCollections`
//
// To add additional collections of checks:
// 1. add to the `checkCollections` array.
//
package checks

import (
	"fmt"

	"github.com/tidwall/gjson"
)

// A CheckCode is a unique code for a check.
type CheckCode string

type CheckError struct {
	Code    CheckCode
	Message string
}

// Error returns the error message, including the code.
func (ce *CheckError) Error() string {
	return fmt.Sprintf("%s: %s", ce.Code, ce.Message)
}

// CodeString returns just the error code, as a string.
func (ce *CheckError) CodeString() string {
	return string(ce.Code)
}

// Checkers are for running a discrete checking function.
type Checker interface {
	CodeString() string
	Name() string
	Description() string
	Run(*gjson.Result) []CheckError
}

// Check defines a single check.
type Check struct {
	code        CheckCode
	name        string
	description string
	check       func(*gjson.Result) []error
}

// Run runs the check, returning any findings.
func (c *Check) Run(json *gjson.Result) (findings []CheckError) {
	for _, finding := range c.check(json) {
		findings = append(findings, CheckError{
			Code:    c.code,
			Message: finding.Error(),
		})
	}
	return findings
}

// Name returns the name of the check.
func (c *Check) Name() string {
	return c.name
}

// Description returns the description of the check.
func (c *Check) Description() string {
	return c.description
}

// CodeString returns the short code for the check, as a string.
func (c *Check) CodeString() string {
	return string(c.code)
}

// Collection is a named collection of checks.
type Collection struct {
	name        string
	description string
	checks      []*Check
}

// Name returns the name of the collection.
func (cc *Collection) Name() string {
	return cc.name
}

// Description returns the description of the collection.
func (cc *Collection) Description() string {
	return cc.description
}

// Checks returns the checks in the collection.
func (cc *Collection) Checks() []*Check {
	return cc.checks
}

var CheckIntroducedEventExists = &Check{
	code:        "R0001",
	name:        "introduced-event-exists",
	description: "every range has an introduced event",
	check:       RangeHasIntroducedEvent,
}

var checks = []*Check{
	CheckIntroducedEventExists,
}

// All returns all defined checks as a map, keyed by the check's code.
func All() (allchecks map[string]*Check) {
	allchecks = make(map[string]*Check)
	for _, check := range checks {
		allchecks[check.CodeString()] = check
	}
	return allchecks
}

var checkCollections = []Collection{
	{
		name:        "osv.dev",
		description: "the checks OSV.dev considers necessary for a high quality record",
		checks: []*Check{
			CheckIntroducedEventExists,
		},
	},
}

// Collections returns a map of defined check collections, keyed by the collection's name.
func Collections() (checkcollections map[string]Collection) {
	checkcollections = make(map[string]Collection)
	for _, checkcollection := range checkCollections {
		checkcollections[checkcollection.Name()] = checkcollection
	}
	return checkcollections
}
