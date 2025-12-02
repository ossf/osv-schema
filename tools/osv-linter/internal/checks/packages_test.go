package checks

import (
	"reflect"
	"testing"

	"github.com/tidwall/gjson"
)

func TestPackageExists(t *testing.T) {
	t.Parallel()

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
				json:   LoadTestData("../../testdata/MAL-2024-10238.json"),
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

func TestPackageVersionsExists(t *testing.T) {
	t.Parallel()

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
			name: "GIT_vuln_without_ecosystem_filter",
			args: args{
				json:   LoadTestData("../../testdata/CVE-2018-5407.json"),
				config: &Config{},
			},
		},
		{
			name: "PyPI_vuln_with_different_ecosystem_filter",
			args: args{
				json:   LoadTestData("../../testdata/GHSA-9v2f-6vcg-3hgv.json"),
				config: &Config{Ecosystems: []string{"npm"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if gotFindings := PackageVersionsExist(tt.args.json, tt.args.config); !reflect.DeepEqual(gotFindings, tt.wantFindings) {
				t.Errorf("PackageVersionsExist() = %v, want %v", gotFindings, tt.wantFindings)
			}
		})
	}
}
