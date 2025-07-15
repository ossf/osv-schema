package checks

import (
	_ "embed"
	"log"
	"os"

	"github.com/xeipuuv/gojsonschema"
)

const schemaFilePath = "./internal/checks/schema.json"

var CheckInvalidSchema = &CheckDef{
	Code:        "SCH:001",
	Name:        "conforms-to-schema",
	Description: "the record must conform to the OSV JSON schema",
}

func ValidateJSON(jsonData string, fileName string, verbose bool) bool {
	if _, err := os.Stat(schemaFilePath); os.IsNotExist(err) {
		log.Fatalf("schema file not found at %s %e\n", schemaFilePath, err)
		return true
	}

	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaFilePath)

	// Load the JSON data to be validated
	documentLoader := gojsonschema.NewStringLoader(jsonData)

	// Perform the validation
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		log.Fatalf("error during validation: %s", err)
	}

	// Check the result
	if !result.Valid() {
		if verbose {
			log.Printf("schema validation failed for %q:", fileName)
			for _, desc := range result.Errors() {
				log.Printf("\n\t- %s", desc)
			}
		}
		return false
	}

	return true
}
