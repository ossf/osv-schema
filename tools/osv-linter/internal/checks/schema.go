package checks

import (
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/tools/osv-linter/internal/schema"
	"github.com/tidwall/gjson"
	"github.com/xeipuuv/gojsonschema"
)

var CheckInvalidSchema = &CheckDef{
	Code:        "SCH:001",
	Name:        "conforms-to-schema",
	Description: "the record must conform to the OSV JSON schema",
	Check:       SchemaCheck,
}

func SchemaCheck(json *gjson.Result, config *Config) []CheckError {
	schemaLoader := gojsonschema.NewBytesLoader(schema.LoadedSchema)
	documentLoader := gojsonschema.NewStringLoader(json.Raw)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		// The document is the record being linted, so this is a problem with
		// the record rather than with the embedded schema. Report it instead of
		// panicking, which would abandon every other file in the run.
		return []CheckError{
			{
				Message: fmt.Sprintf("Record could not be validated against the schema: %v", err),
			},
		}
	}

	if result.Valid() {
		return nil
	}

	errors := filterSchemaErrors(result.Errors(), config.NewEcosystem)

	if len(errors) == 0 {
		return nil
	}

	return []CheckError{
		{
			Message: fmt.Sprintf("Record does not conform to schema:\n %s", strings.Join(errors, "\n")),
		},
	}
}

func filterSchemaErrors(resultErrors []gojsonschema.ResultError, newEcosystem bool) []string {
	var patternFields map[string]bool
	var nonPatternFields map[string]bool
	if newEcosystem {
		patternFields = make(map[string]bool)
		nonPatternFields = make(map[string]bool)
		for _, desc := range resultErrors {
			if strings.Contains(desc.Description(), "Does not match pattern") {
				patternFields[desc.Field()] = true
			} else if !strings.Contains(desc.Description(), "Must validate all the schemas (allOf)") {
				nonPatternFields[desc.Field()] = true
			}
		}
	}

	var errors []string
	for _, desc := range resultErrors {
		if newEcosystem {
			if strings.Contains(desc.Description(), "Does not match pattern") {
				continue
			}
			// Suppress an allOf wrapper error when every failing subschema on that
			// field was a suppressed pattern check (e.g. id's prefix/idFormat allOf).
			if strings.Contains(desc.Description(), "Must validate all the schemas (allOf)") &&
				patternFields[desc.Field()] && !nonPatternFields[desc.Field()] {
				continue
			}
		}
		errors = append(errors, fmt.Sprintf("- %s", desc))
	}

	return errors
}
