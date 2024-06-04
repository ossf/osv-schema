package checks

import (
	"github.com/tidwall/gjson"
)

// RangeHasIntroducedEvent checks for missing 'introduced' objects in events.
func RangeHasIntroducedEvent(json *gjson.Result) (findings []CheckError) {
	result := json.Get(`affected.#(ranges.#(events.#(introduced)))`)

	if !result.Exists() {
		findings = append(findings, CheckError{Message: "missing 'introduced' object in event"})
		return findings
	}

	return nil
}
