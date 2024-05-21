package checks

import (
	"fmt"

	"github.com/tidwall/gjson"
)

func RangeHasIntroducedEvent(json *gjson.Result) []CheckError {
	result := json.Get(`affected.#.ranges.#.events`)

	findings := []CheckError{}

	result.ForEach(func(key, value gjson.Result) bool {
		if !value.Get("introduced").Exists() {
			findings = append(findings, CheckError{Text: fmt.Sprintf("Error: Missing 'introduced' object in event at index %s", key)})
		}
		return true // Continue iteration.
	})

	if len(findings) != 0 {
		return findings
	}
	return nil
}
