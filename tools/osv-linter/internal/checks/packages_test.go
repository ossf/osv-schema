package checks

import (
	"reflect"
	"testing"

	"github.com/tidwall/gjson"
)

func parseJSON(s string) *gjson.Result {
	res := gjson.Parse(s)
	return &res
}

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
		{
			name: "Wildcard package name in PyPI",
			args: args{
				json:   LoadTestData("../../testdata/wildcard-package.json"),
				config: &Config{},
			},
			wantFindings: nil,
		},
		{
			name: "Schema ecosystem without registry check (WordPress)",
			args: args{
				json: parseJSON(`{
					"affected": [
						{
							"package": {
								"name": "my-plugin",
								"ecosystem": "WordPress:Plugin"
							}
						}
					]
				}`),
				config: &Config{},
			},
			wantFindings: nil,
		},
		{
			name: "Schema ecosystem without registry check (Homebrew)",
			args: args{
				json: parseJSON(`{
					"affected": [
						{
							"package": {
								"name": "openssl@3",
								"ecosystem": "Homebrew"
							}
						}
					]
				}`),
				config: &Config{},
			},
			wantFindings: nil,
		},
		{
			name: "Unknown ecosystem produces finding",
			args: args{
				json: parseJSON(`{
					"affected": [
						{
							"package": {
								"name": "my-pkg",
								"ecosystem": "UnknownEco"
							}
						}
					]
				}`),
				config: &Config{},
			},
			wantFindings: []CheckError{{Code: "", Message: "package \"my-pkg\" not found in \"UnknownEco\""}},
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
		{
			name: "Wildcard package versions check",
			args: args{
				json:   LoadTestData("../../testdata/wildcard-package.json"),
				config: &Config{},
			},
			wantFindings: nil,
		},
		{
			name: "Schema ecosystem without registry check (WordPress)",
			args: args{
				json: parseJSON(`{
					"affected": [
						{
							"package": {
								"name": "my-plugin",
								"ecosystem": "WordPress:Plugin"
							},
							"versions": ["1.0.0", "1.1.0"]
						}
					]
				}`),
				config: &Config{},
			},
			wantFindings: nil,
		},
		{
			name: "Schema ecosystem without registry check (Homebrew)",
			args: args{
				json: parseJSON(`{
					"affected": [
						{
							"package": {
								"name": "openssl@3",
								"ecosystem": "Homebrew"
							},
							"versions": ["3.0.0"]
						}
					]
				}`),
				config: &Config{},
			},
			wantFindings: nil,
		},
		{
			name: "Unknown ecosystem produces finding",
			args: args{
				json: parseJSON(`{
					"affected": [
						{
							"package": {
								"name": "my-pkg",
								"ecosystem": "UnknownEco"
							},
							"versions": ["1.0.0"]
						}
					]
				}`),
				config: &Config{},
			},
			wantFindings: []CheckError{{Code: "", Message: "unsupported ecosystem: UnknownEco"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotFindings := PackageVersionsExist(tt.args.json, tt.args.config); !reflect.DeepEqual(gotFindings, tt.wantFindings) {
				t.Errorf("PackageVersionsExist() = %v, want %v", gotFindings, tt.wantFindings)
			}
		})
	}
}
