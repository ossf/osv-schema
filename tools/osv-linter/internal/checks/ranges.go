package checks

import (
	"fmt"
	"slices"

	"github.com/google/osv-scalibr/semantic"
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

var CheckRangeFixedAfterIntroduced = &CheckDef{
	Code:        "RNG:004",
	Name:        "fixed-after-introduced",
	Description: "fixed and last_affected events are not before every introduced event",
	Check:       RangeFixedAfterIntroduced,
}

// RangeFixedAfterIntroduced checks that every fixed or last_affected event of a
// SEMVER or ECOSYSTEM range comes at or after the lowest introduced event of
// that range, in the version order of the package's ecosystem. An event below
// every introduced version doesn't end any part of the range, which usually
// means the versions are swapped or belong to another range. A fixed version
// equal to an introduced one is left to RNG:002. Ranges whose ecosystem or
// versions can't be parsed are skipped.
func RangeFixedAfterIntroduced(json *gjson.Result, config *Config) (findings []CheckError) {
	affected := json.Get("affected")
	if !affected.IsArray() {
		return nil
	}

	for i, entry := range affected.Array() {
		pkg := entry.Get("package")
		ecosystem := pkg.Get("ecosystem").String()
		for j, rng := range entry.Get("ranges").Array() {
			rangeType := rng.Get("type").String()
			if rangeType != "SEMVER" && rangeType != "ECOSYSTEM" {
				continue
			}
			parse := func(v string) (semantic.Version, error) {
				if rangeType == "SEMVER" {
					return semantic.ParseSemverVersion(v), nil
				}
				return semantic.Parse(v, ecosystem)
			}

			// Find the lowest introduced version. "0" sorts before every version.
			var lowest semantic.Version
			fromZero, ok := false, true
			for _, event := range rng.Get("events").Array() {
				introduced := event.Get("introduced")
				if !introduced.Exists() {
					continue
				}
				if introduced.String() == "0" {
					fromZero = true
					break
				}
				v, err := parse(introduced.String())
				if err != nil {
					ok = false
					break
				}
				if lowest == nil {
					lowest = v
					continue
				}
				if c, err := lowest.CompareStr(introduced.String()); err != nil {
					ok = false
					break
				} else if c > 0 {
					lowest = v
				}
			}
			if fromZero || !ok || lowest == nil {
				continue
			}

			for _, event := range rng.Get("events").Array() {
				for _, eventType := range []string{"fixed", "last_affected"} {
					value := event.Get(eventType)
					if !value.Exists() {
						continue
					}
					c, err := lowest.CompareStr(value.String())
					if err != nil || c <= 0 {
						continue
					}
					findings = append(findings, CheckError{
						Message: fmt.Sprintf("Invalid Range: affected[%d].ranges[%d] (%s/%s) has %s %q, which is before every introduced version", i, j, ecosystem, pkg.Get("name").String(), eventType, value.String()),
					})
				}
			}
		}
	}

	return findings
}
