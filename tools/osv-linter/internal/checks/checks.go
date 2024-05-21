package checks

import "github.com/tidwall/gjson"

type CheckCode string

type CheckError struct {
	Text     string
}

type Check struct {
	Code        CheckCode
	Name        string
	Description string
	Check       func(*gjson.Result) []CheckError
}

type CheckCollection struct {
	Name        string
	Description string
	Checks      []*Check
}

var CheckIntroducedEventExists = &Check{
	Code:        "R0001",
	Name:        "introduced-event-exists",
	Description: "every range has an introduced event",
	Check:       RangeHasIntroducedEvent,
}

var AllChecks = map[string]*Check{
	"introduced-event-exists": CheckIntroducedEventExists,
}

var CheckCollections = map[string]CheckCollection{
	"osv.dev": {
		Name:        "osv.dev",
		Description: "the checks OSV.dev considers necessary for a high quality record",
		Checks: []*Check{
			CheckIntroducedEventExists,
		},
	},
}
