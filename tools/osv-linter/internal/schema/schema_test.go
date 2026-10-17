package schema_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/tools/osv-linter/internal/schema"
)

func TestSchemaHasBeenGenerated(t *testing.T) {
	want, err := os.ReadFile("../../../../validation/schema.json")
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile("schema_generated.json")
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Schema needs to be regenerated (-want +got):\n%s", diff)
	}
}

func TestSchemaEcosystems_MatchesEcosystemsJSON(t *testing.T) {
	data, err := os.ReadFile("../../../../ecosystems.json")
	if err != nil {
		t.Fatalf("failed to read ecosystems.json: %v", err)
	}

	var ecosystemsMap map[string]string
	if err := json.Unmarshal(data, &ecosystemsMap); err != nil {
		t.Fatalf("failed to unmarshal ecosystems.json: %v", err)
	}

	ecosystems := schema.Ecosystems()
	for eco := range ecosystemsMap {
		if !slices.Contains(ecosystems, eco) {
			t.Errorf("ecosystem %q from ecosystems.json is missing from schema.Ecosystems()", eco)
		}
	}
	if len(ecosystems) != len(ecosystemsMap) {
		t.Errorf("schema.Ecosystems() length (%d) != ecosystems.json length (%d)", len(ecosystems), len(ecosystemsMap))
	}
}

func TestEcosystems_PanicsOnMissingOrInvalidSchema(t *testing.T) {
	orig := schema.LoadedSchema
	defer func() {
		schema.LoadedSchema = orig
	}()

	tests := []struct {
		name        string
		schemaBytes []byte
	}{
		{
			name:        "empty schema",
			schemaBytes: nil,
		},
		{
			name:        "missing enum",
			schemaBytes: []byte(`{}`),
		},
		{
			name:        "enum not array",
			schemaBytes: []byte(`{"$defs": {"ecosystemName": {"enum": "not-an-array"}}}`),
		},
		{
			name:        "empty enum array",
			schemaBytes: []byte(`{"$defs": {"ecosystemName": {"enum": []}}}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema.LoadedSchema = tt.schemaBytes
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic, got none")
				}
			}()
			_ = schema.Ecosystems()
		})
	}
}
