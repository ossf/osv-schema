package checks

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

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

var CheckRangeVersionsValid = &CheckDef{
	Code:        "RNG:003",
	Name:        "range-versions-valid",
	Description: "SEMVER and GIT range events use valid versions",
	Check:       RangeVersionsValid,
}

// semverPattern is the regular expression suggested by SemVer 2.0.0 for
// matching a semantic version, with no leading "v".
var semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
	`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// gitCommitPattern matches a full-length SHA-1 or SHA-256 Git commit hash.
var gitCommitPattern = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

var rangeEventTypes = []string{"introduced", "fixed", "last_affected", "limit"}

// RangeVersionsValid checks that the event versions of SEMVER ranges are
// SemVer 2.0.0 versions without a leading "v", and that the event versions of
// GIT ranges are full-length commit hashes. The special values "0" for
// introduced and "*" for limit are allowed in both. ECOSYSTEM ranges are not
// checked, since their versions are specific to the ecosystem.
func RangeVersionsValid(json *gjson.Result, config *Config) (findings []CheckError) {
	affected := json.Get("affected")
	if !affected.IsArray() {
		return nil
	}

	for i, entry := range affected.Array() {
		for j, rng := range entry.Get("ranges").Array() {
			rangeType := rng.Get("type").String()
			var pattern *regexp.Regexp
			var want string
			switch rangeType {
			case "SEMVER":
				pattern, want = semverPattern, "a SemVer 2.0.0 version without a leading \"v\""
			case "GIT":
				pattern, want = gitCommitPattern, "a full-length commit hash"
			default:
				continue
			}
			for _, event := range rng.Get("events").Array() {
				for _, eventType := range rangeEventTypes {
					value := event.Get(eventType)
					if !value.Exists() {
						continue
					}
					version := value.String()
					if eventType == "introduced" && version == "0" {
						continue
					}
					if eventType == "limit" && strings.Contains(version, "*") {
						continue
					}
					if pattern.MatchString(version) {
						continue
					}
					findings = append(findings, CheckError{
						Message: fmt.Sprintf("Invalid Range: affected[%d].ranges[%d] (%s) has %s %q, which is not %s", i, j, rangeType, eventType, version, want),
					})
				}
			}
		}
	}

	return findings
}
