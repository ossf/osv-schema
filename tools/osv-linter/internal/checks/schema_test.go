package checks_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/linter/internal/checks"
)

func TestSchemaHasBeenGenerated(t *testing.T) {
	t.Parallel()

	var err error

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
	t.Parallel()

	data, err := os.ReadFile("../../../../ecosystems.json")
	if err != nil {
		t.Fatalf("failed to read ecosystems.json: %v", err)
	}

	var ecosystemsMap map[string]string
	if err := json.Unmarshal(data, &ecosystemsMap); err != nil {
		t.Fatalf("failed to unmarshal ecosystems.json: %v", err)
	}

	ecosystems := checks.SchemaEcosystems()
	for eco := range ecosystemsMap {
		if !slices.Contains(ecosystems, eco) {
			t.Errorf("ecosystem %q from ecosystems.json is missing from SchemaEcosystems()", eco)
		}
	}
	if len(ecosystems) != len(ecosystemsMap) {
		t.Errorf("SchemaEcosystems() length (%d) != ecosystems.json length (%d)", len(ecosystems), len(ecosystemsMap))
	}
}
