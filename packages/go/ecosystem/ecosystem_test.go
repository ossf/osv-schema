package ecosystem_test

import (
	"reflect"
	"testing"

	"github.com/ossf/osv-schema/constants"
	"github.com/ossf/osv-schema/ecosystem"
)

type testCase struct {
	string string
	parsed ecosystem.Parsed
}

func buildCases() []testCase {
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

func TestParsed_String(t *testing.T) {
	t.Parallel()

	tests := buildCases()
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			if got := tt.parsed.String(); got != tt.string {
				t.Errorf("String() = %v, want %v", got, tt.string)
			}
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	tests := buildCases()
	for _, tt := range tests {
		t.Run(tt.string, func(t *testing.T) {
			if got := ecosystem.Parse(tt.string); !reflect.DeepEqual(got, tt.parsed) {
				t.Errorf("Parse() = %v, want %v", got, tt.parsed)
			}
		})
	}
}
