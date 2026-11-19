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

func isSuppressedNewEcosystemPatternError(desc gojsonschema.ResultError) bool {
	if !strings.Contains(desc.Description(), "Does not match pattern") {
		return false
	}
	field := desc.Field()
	if field == "id" {
		return !strings.Contains(desc.Description(), validIDPattern.String())
	}
	return strings.HasPrefix(field, "affected.") && strings.HasSuffix(field, ".package.ecosystem")
}

func filterSchemaErrors(resultErrors []gojsonschema.ResultError, newEcosystem bool) []string {
	if !newEcosystem {
		errors := make([]string, 0, len(resultErrors))
		for _, desc := range resultErrors {
			errors = append(errors, fmt.Sprintf("- %s", desc))
		}
		return errors
	}

	var idPrefixSuppressed bool
	var idHasOtherError bool
	for _, desc := range resultErrors {
		if desc.Field() != "id" {
			continue
		}
		if isSuppressedNewEcosystemPatternError(desc) {
			idPrefixSuppressed = true
		} else if !strings.Contains(desc.Description(), "Must validate all the schemas (allOf)") {
			idHasOtherError = true
		}
	}

	var errors []string
	for _, desc := range resultErrors {
		if isSuppressedNewEcosystemPatternError(desc) {
			continue
		}
		// Suppress id's allOf wrapper error only when prefix failed and id had no
		// other unsuppressed error (such as idFormat or invalid type).
		if desc.Field() == "id" &&
			strings.Contains(desc.Description(), "Must validate all the schemas (allOf)") &&
			idPrefixSuppressed && !idHasOtherError {
			continue
		}
		errors = append(errors, fmt.Sprintf("- %s", desc))
	}

	return errors
}
