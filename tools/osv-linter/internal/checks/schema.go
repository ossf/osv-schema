package checks

import (
	_ "embed"
	"log"

	"github.com/xeipuuv/gojsonschema"
)

// The path is relative to this Go source file.
//
//go:embed schema.json
var embeddedSchema []byte

var CheckInvalidSchema = &CheckDef{
	Code:        "SCH:001",
	Name:        "conforms-to-schema",
	Description: "the record must conform to the OSV JSON schema",
}

func ValidateJSON(jsonData string, fileName string, verbose bool) bool {
	schemaLoader := gojsonschema.NewBytesLoader(embeddedSchema)

	// Load the JSON data to be validated
	documentLoader := gojsonschema.NewStringLoader(jsonData)

	// Perform the validation
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		log.Fatalf("Error during validation: %s", err)
	}

	// Check the result
	if !result.Valid() {
		if verbose {
			log.Printf("Schema validation failed for %q:", fileName)
			for _, desc := range result.Errors() {
				// desc.Description() provides a user-friendly error message
				log.Printf("\n\t- %s", desc)
			}
		}
		return false
	}

	return true
}
