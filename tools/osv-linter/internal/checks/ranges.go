package checks

import (
	"github.com/tidwall/gjson"
)

var CheckRangeHasIntroducedEvent = &CheckDef{
	Code:        "R0001",
	Name:        "introduced-event-exists",
	Description: "every range has an introduced event",
	Check:       RangeHasIntroducedEvent,
}

// RangeHasIntroducedEvent checks for missing 'introduced' objects in events.
func RangeHasIntroducedEvent(json *gjson.Result) (findings []CheckError) {
	result := json.Get(`affected.#(ranges.#(events.#(introduced)))`)

	if !result.Exists() {
		findings = append(findings, CheckError{Message: "missing 'introduced' object in event"})
		return findings
	}

	return nil
}
