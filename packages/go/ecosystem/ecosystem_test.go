package ecosystem_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ossf/osv-schema/packages/go/constants"
	"github.com/ossf/osv-schema/packages/go/ecosystem"
)

type testCase struct {
	string string
	parsed ecosystem.Parsed
}

func buildCases(t *testing.T) []testCase {
	t.Helper()

	return []testCase{
		{
			string: "crates.io",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemCratesIO,
				Suffix:    "",
			},
		},
		{
			string: "crates.io: ",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemCratesIO,
				Suffix:    " ",
			},
		},
		{
			string: "crates.io::",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemCratesIO,
				Suffix:    ":",
			},
		},
		{
			string: "npm",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemNPM,
				Suffix:    "",
			},
		},
		{
			string: "npm:abc",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemNPM,
				Suffix:    "abc",
			},
		},
		{
			string: "Alpine",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemAlpine,
				Suffix:    "",
			},
		},
		{
			string: "Alpine:v",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemAlpine,
				Suffix:    "v",
			},
		},
		{
			string: "Alpine:v3.16",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemAlpine,
				Suffix:    "v3.16",
			},
		},
		{
			string: "Alpine:3.16",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemAlpine,
				Suffix:    "3.16",
			},
		},
		{
			string: "Maven",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemMaven,
				Suffix:    "",
			},
		},
		{
			string: "Maven:https://maven.google.com",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemMaven,
				Suffix:    "https://maven.google.com",
			},
		},
		{
			string: "Photon OS",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemPhotonOS,
				Suffix:    "",
			},
		},
		{
			string: "Photon OS:abc",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemPhotonOS,
				Suffix:    "abc",
			},
		},
		{
			string: "Photon OS:3.0",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemPhotonOS,
				Suffix:    "3.0",
			},
		},
		{
			string: "Red Hat",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemRedHat,
				Suffix:    "",
			},
		},
		{
			string: "Red Hat:abc",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemRedHat,
				Suffix:    "abc",
			},
		},
		{
			string: "Red Hat:rhel_aus:8.4::appstream",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemRedHat,
				Suffix:    "rhel_aus:8.4::appstream",
			},
		},
		{
			string: "Ubuntu",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemUbuntu,
				Suffix:    "",
			},
		},
		{
			string: "Ubuntu:Pro",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemUbuntu,
				Suffix:    "Pro",
			},
		},
		{
			string: "Ubuntu:Pro:18.04:LTS",
			parsed: ecosystem.Parsed{
				Ecosystem: constants.EcosystemUbuntu,
				Suffix:    "Pro:18.04:LTS",
			},
		},
	}
}

func TestParsed_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			t.Parallel()

			var got ecosystem.Parsed

			if err := json.Unmarshal([]byte(`"`+tt.string+`"`), &got); err != nil {
				t.Fatalf("Unmarshal() = %v; want no error", err)
			}

			// ensure that the string is unmarshalled into a struct
			if !reflect.DeepEqual(got, tt.parsed) {
				t.Errorf("Unmarshal() = %v; want %v", got, tt.parsed)
			}
		})
	}
}

func TestParsed_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tt.parsed)

			if err != nil {
				t.Fatalf("Marshal() = %v; want no error", err)
			}

			// ensure that the struct is marshaled as a string
			want := `"` + tt.string + `"`
			if string(got) != want {
				t.Errorf("Marshal() = %v; want %v", string(got), want)
			}
		})
	}
}

func TestParsed_String(t *testing.T) {
	t.Parallel()

	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			t.Parallel()

			if got := tt.parsed.String(); got != tt.string {
				t.Errorf("String() = %v, want %v", got, tt.string)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	tests := buildCases(t)
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			t.Parallel()

			if got := ecosystem.Parse(tt.string); !reflect.DeepEqual(got, tt.parsed) {
				t.Errorf("Parse() = %v, want %v", got, tt.parsed)
			}
		})
	}
}
