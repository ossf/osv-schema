package schema

import (
	_ "embed"
	"slices"

	"github.com/tidwall/gjson"
)

// Please run 'go generate ./...' to sync schema.json.
//go:generate cp ../../../../validation/schema.json schema_generated.json

//go:embed schema_generated.json
var LoadedSchema []byte

// Ecosystems returns the list of all ecosystems defined in the loaded JSON schema.
// It panics if the schema is not loaded, has an invalid structure, or defines no ecosystems.
func Ecosystems() []string {
	if len(LoadedSchema) == 0 {
		panic("schema is not loaded")
	}

	res := gjson.GetBytes(LoadedSchema, "$defs.ecosystemName.enum")
	if !res.Exists() || !res.IsArray() {
		panic("schema is missing $defs.ecosystemName.enum array")
	}

	var ecosystems []string
	for _, item := range res.Array() {
		ecosystems = append(ecosystems, item.String())
	}

	if len(ecosystems) == 0 {
		panic("schema contains no ecosystems in $defs.ecosystemName.enum")
	}

	return ecosystems
}

// IsEcosystem reports whether ecosystem is defined in the loaded schema or is "GIT".
func IsEcosystem(ecosystem string) bool {
	if ecosystem == "GIT" {
		return true
	}
	return slices.Contains(Ecosystems(), ecosystem)
}
