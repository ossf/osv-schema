package checks

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/xeipuuv/gojsonschema"
)

//go:generate cp ../../../../validation/schema.json schema_generated.json

//go:embed schema_generated.json
var embeddedSchema []byte // Please run 'go generate ./...' to sync schema.json.

var CheckInvalidSchema = &CheckDef{
	Code:        "SCH:001",
	Name:        "conforms-to-schema",
	Description: "the record must conform to the OSV JSON schema",
	Check:       SchemaCheck,
}

func SchemaCheck(json *gjson.Result, _ *Config) []CheckError {
	schemaLoader := gojsonschema.NewBytesLoader(embeddedSchema)
	documentLoader := gojsonschema.NewStringLoader(json.Raw)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		// This should not happen with a valid embedded schema.
		// It indicates a problem with the linter itself.
		panic(fmt.Sprintf("schema validation failed: %v", err))
	}

	if result.Valid() {
		return nil
	}

	var errors []string
	for _, desc := range result.Errors() {
		errors = append(errors, fmt.Sprintf("- %s", desc))
	}

	return []CheckError{
		{
			Message: fmt.Sprintf("Record does not conform to schema:\n %s", strings.Join(errors, "\n")),
		},
	}
}
