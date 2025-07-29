package checks_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
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
