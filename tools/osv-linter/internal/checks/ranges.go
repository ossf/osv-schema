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

var CheckRangeEventsOrdered = &CheckDef{
	Code:        "RNG:004",
	Name:        "range-events-ordered",
	Description: "fixed and last_affected events are not lower than every introduced event",
	Check:       RangeEventsOrdered,
}

type rangeEvent struct {
	kind    string
	value   string
	version semantic.Version // nil for "0"
}

// compareRangeEvents orders events by version, with "0" first and, for equal
// versions, introduced before fixed and last_affected.
func compareRangeEvents(a, b rangeEvent) int {
	var c int
	switch {
	case a.version == nil && b.version == nil:
		c = 0
	case a.version == nil:
		c = -1
	case b.version == nil:
		c = 1
	default:
		c, _ = a.version.Compare(b.version)
	}
	if c != 0 {
		return c
	}
	switch {
	case a.kind == b.kind:
		return 0
	case a.kind == "introduced":
		return -1
	case b.kind == "introduced":
		return 1
	}
	return 0
}

// RangeEventsOrdered sorts the events of each SEMVER and ECOSYSTEM range by
// version, as the evaluation algorithm in the schema does, and reports fixed
// and last_affected events that are lower than every introduced event. Such
// an event can't end an affected interval, which usually means the versions
// are swapped or fixed is "0".
//
// A run of several fixed events after one introduced event is left alone:
// only the first one has an effect, but some databases list fixes that way.
//
// GIT ranges are skipped, since commits can't be ordered without the
// repository, and so are ranges with versions the ecosystem can't parse.
func RangeEventsOrdered(json *gjson.Result, config *Config) (findings []CheckError) {
	json.Get("affected").ForEach(func(_, affected gjson.Result) bool {
		pkg := affected.Get("package")
		ecosystem := pkg.Get("ecosystem").String()
		affected.Get("ranges").ForEach(func(_, rng gjson.Result) bool {
			var parse func(string) (semantic.Version, error)
			switch rng.Get("type").String() {
			case "SEMVER":
				parse = func(v string) (semantic.Version, error) {
					return semantic.ParseSemverVersion(v), nil
				}
			case "ECOSYSTEM":
				if ecosystem == "" {
					return true
				}
				parse = func(v string) (semantic.Version, error) {
					return semantic.Parse(v, ecosystem)
				}
			default:
				return true
			}

			var events []rangeEvent
			parsed := true
			rng.Get("events").ForEach(func(_, event gjson.Result) bool {
				for _, kind := range []string{"introduced", "fixed", "last_affected"} {
					value := event.Get(kind)
					if !value.Exists() {
						continue
					}
					e := rangeEvent{kind: kind, value: value.String()}
					if e.value != "0" {
						v, err := parse(e.value)
						if err != nil {
							parsed = false
							return false
						}
						e.version = v
					}
					events = append(events, e)
				}
				return true
			})
			if !parsed {
				return true
			}

			slices.SortStableFunc(events, compareRangeEvents)
			for _, e := range events {
				if e.kind == "introduced" {
					break
				}
				findings = append(findings, CheckError{
					Message: fmt.Sprintf("%s %q in a %s range for %s/%s is lower than every introduced event, so it has no effect", e.kind, e.value, rng.Get("type").String(), ecosystem, pkg.Get("name").String()),
				})
			}
			return true
		})
		return true
	})
	return findings
}
