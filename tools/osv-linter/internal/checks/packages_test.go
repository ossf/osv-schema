package checks

import (
	"reflect"
	"testing"

	"github.com/tidwall/gjson"
)

func TestPackageExists(t *testing.T) {
	type args struct {
		json   *gjson.Result
		config *Config
	}
	tests := []struct {
		name         string
		args         args
		wantFindings []CheckError
	}{
		{
			name: "A malicious PyPI package no longer existing",
			args: args{
				json:   LoadTestData("../../test_data/MAL-2024-10238.json"),
				config: &Config{},
			},
			wantFindings: []CheckError{{Code: "", Message: "package \"123bla\" not found in \"PyPI\""}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotFindings := PackageExists(tt.args.json, tt.args.config); !reflect.DeepEqual(gotFindings, tt.wantFindings) {
				t.Errorf("PackageExists() = %v, want %v", gotFindings, tt.wantFindings)
			}
		})
	}
}
