package checks

import (
	"fmt"
	"slices"

	"github.com/tidwall/gjson"
)

var CheckRangeHasIntroducedEvent = &CheckDef{
	Code:        "RNG:001",
	Name:        "introduced-event-exists",
	Description: "every range has an introduced event",
	Check:       RangeHasIntroducedEvent,
}

// RangeHasIntroducedEvent checks for missing 'introduced' objects in events.
func RangeHasIntroducedEvent(json *gjson.Result, config *Config) (findings []CheckError) {
	// It is valid to not have any ranges.
	ranges := json.Get("affected.#(ranges)")
	if !ranges.Exists() {
		return nil
	}

	result := json.Get("affected.#(ranges.#(events.#(introduced)))")

	if !result.Exists() {
		findings = append(findings, CheckError{Message: "missing 'introduced' object in event"})
		return findings
	}

	return nil
}

var CheckRangeIsDistinct = &CheckDef{
	Code:        "RNG:002",
	Name:        "range-is-distinct",
	Description: "range spans multiple versions/commits",
	Check:       RangeIsDistinct,
}

// RangeIsDistinct checks that the introduced and fixed (or last_affected) values differ.
// (on a per-repo basis for GIT ranges, and on a per-package basis otherwise)
func RangeIsDistinct(json *gjson.Result, config *Config) (findings []CheckError) {
	affectedEntries := json.Get("affected")

	// Examine each entry:
	// for ones for packages, on a per-package basis
	// for GIT ranges, on a per-repo basis
	affectedEntries.ForEach(func(key, value gjson.Result) bool {
		// If it has a package field, it's for a package, otherwise confirm the range is of type GIT.
		maybePackage := value.Get("package")
		ranges := value.Get("ranges")
		var pkg bool
		if maybePackage.Exists() {
			pkg = true
		}
		ranges.ForEach(func(key, value gjson.Result) bool {
			rangeType := value.Get("type").String()
			if !pkg && rangeType != "GIT" {
				findings = append(findings, CheckError{Message: fmt.Sprintf("unexpected range type %q for %s", rangeType, value.String())})
			}
			// Examine the events, collect all of the range starting values and range ending values (fixed and last_affected).
			// There must be no overlap between these two sets of values.
			events := value.Get("events")
			var startEvents []string
			var endEvents []string
			events.ForEach(func(key, value gjson.Result) bool {
				// Collect all the introduced values.
				result := value.Get("introduced")
				if result.Exists() {
					startEvents = append(startEvents, result.String())
				}
				// Collect all the fixed
				// last_affected can be the same version as introduced
				result = value.Get("fixed")
				if result.Exists() {
					endEvents = append(endEvents, result.String())
				}
				return true // keep iterating (over events)
			})
			// Check for overlap between collected start events and end events.
			for _, endEvent := range endEvents {
				if slices.Contains(startEvents, endEvent) {
					findings = append(findings, CheckError{Message: fmt.Sprintf("overlapping event: %q", endEvent)})
				}
			}
			return true // keep iterating (over ranges)
		})
		return true // keep iterating (over affected entries)
	})
	return findings
}
