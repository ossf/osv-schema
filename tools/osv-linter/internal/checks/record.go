package checks

import (
	"fmt"
	"regexp"

	"github.com/tidwall/gjson"
)

// validIDPattern is the set of characters permitted in an OSV record id.
// Restricting ids to this ASCII subset avoids the need for URL encoding and
// prevents shell-scripting errors caused by spaces or other punctuation.
var validIDPattern = regexp.MustCompile(`^[a-zA-Z0-9:_.-]+$`)

var CheckRecordHasAffected = &CheckDef{
	Code:        "REC:001",
	Name:        "affected-data-exists",
	Description: "every record has affected data",
	Check:       RecordHasAffected,
}

var CheckRecordHasValidAliases = &CheckDef{
	Code:        "REC:002",
	Name:        "valid-aliases",
	Description: "aliases field validates",
	Check:       AliasesCheck,
}

var CheckRecordHasValidUpstream = &CheckDef{
	Code:        "REC:003",
	Name:        "valid-upstream",
	Description: "upstream field validates",
	Check:       UpstreamCheck,
}

var CheckRecordHasValidRelated = &CheckDef{
	Code:        "REC:004",
	Name:        "valid-related",
	Description: "related field validates",
	Check:       RelatedCheck,
}

var CheckRecordHasValidID = &CheckDef{
	Code:        "REC:005",
	Name:        "record-id-valid",
	Description: "id field uses only permitted characters",
	Check:       IDCheck,
}

// RecordHasAffected checks if the 'affected' field exists in the JSON and is not an empty array.
func RecordHasAffected(json *gjson.Result, config *Config) (findings []CheckError) {
	// Withdrawn records are fine to not contain affected field
	isWithdrawn := json.Get("withdrawn")
	if isWithdrawn.Exists() {
		return
	}

	affectedEntries := json.Get("affected")
	if !affectedEntries.Exists() || affectedEntries.String() == "[]" {
		findings = append(findings, CheckError{Message: "Invalid Affected: affected field cannot be null or empty"})
	}
	return findings
}

func UpstreamCheck(json *gjson.Result, config *Config) (findings []CheckError) {
	upstream := json.Get("upstream")
	bug := json.Get("id")
	if !upstream.Exists() {
		return
	}

	hasDup, unique := hasDuplicate(upstream)
	if hasDup {
		findings = append(findings, CheckError{Message: "Invalid Upstream: upstream should not contain duplicate entries"})
	}

	if _, exists := unique[bug.String()]; exists {
		findings = append(findings, CheckError{Message: "Invalid Upstream: upstream should not contain itself"})
	}

	aliases := json.Get("aliases")
	if aliases.Exists() && aliases.IsArray() {
		for _, bug := range aliases.Array() {
			if _, exists := unique[bug.String()]; exists {
				findings = append(findings, CheckError{Message: "Invalid Upstream: upstream should not contain aliases"})
				break
			}
		}
	}

	related := json.Get("related")
	if related.Exists() && related.IsArray() {
		for _, bug := range related.Array() {
			if _, exists := unique[bug.String()]; exists {
				findings = append(findings, CheckError{Message: "Invalid Upstream: upstream should not contain related IDs"})
				break
			}
		}
	}

	return findings
}

func AliasesCheck(json *gjson.Result, config *Config) (findings []CheckError) {
	aliases := json.Get("aliases")
	bug := json.Get("id")
	if !aliases.Exists() {
		return
	}

	hasDup, unique := hasDuplicate(aliases)
	if hasDup {
		findings = append(findings, CheckError{Message: "Invalid Aliases: aliases should not contain duplicate entries"})
	}

	if _, exists := unique[bug.String()]; exists {
		findings = append(findings, CheckError{Message: "Invalid Aliases: aliases should not contain itself"})
	}

	return findings
}

func RelatedCheck(json *gjson.Result, config *Config) (findings []CheckError) {
	related := json.Get("related")
	bug := json.Get("id")
	if !related.Exists() {
		return
	}

	hasDup, unique := hasDuplicate(related)
	if hasDup {
		findings = append(findings, CheckError{Message: "Invalid Related: Related should not contain duplicate entries"})
	}

	if _, exists := unique[bug.String()]; exists {
		findings = append(findings, CheckError{Message: "Invalid Related: Related should not contain itself"})
	}

	return findings
}

// IDCheck verifies that the 'id' field only contains characters from the
// permitted set (^[a-zA-Z0-9:_.-]+$).
func IDCheck(json *gjson.Result, config *Config) (findings []CheckError) {
	id := json.Get("id")
	if !id.Exists() {
		return
	}

	if !validIDPattern.MatchString(id.String()) {
		findings = append(findings, CheckError{Message: fmt.Sprintf("Invalid ID: id %q contains characters outside the permitted set [a-zA-Z0-9:_.-]", id.String())})
	}

	return findings
}

func hasDuplicate(json gjson.Result) (bool, map[string]struct{}) {
	var bugIDs []string
	if json.IsArray() { // Check if it's actually a JSON array
		for _, bugResult := range json.Array() {
			bugIDs = append(bugIDs, bugResult.String())
		}
	} else {
		return false, nil
	}

	seen := make(map[string]struct{})
	for _, bugID := range bugIDs {
		seen[bugID] = struct{}{}
	}

	return len(seen) != len(bugIDs), seen
}
