package checks

import (
	"fmt"

	"github.com/tidwall/gjson"
)

// RangeHasIntroducedEvent checks for missing 'introduced' objects in events.
func RangeHasIntroducedEvent(json *gjson.Result) (findings []error) {
	result := json.Get(`affected.#.ranges.#.events`)

	result.ForEach(func(key, value gjson.Result) bool {
		if !value.Get("introduced").Exists() {
			findings = append(findings, fmt.Errorf("missing 'introduced' object in event at index %s", key))
		}
		return true // Continue iteration.
	})

	return findings
}
