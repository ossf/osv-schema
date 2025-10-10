package pkgchecker

import (
	"testing"
)

func Test_existsInCran(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "igraph",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInCran(tt.pkg); got != tt.want {
				t.Errorf("existsInCran() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInCrates(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "surrealdb-core",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
		{
			name: "rust standard library",
			pkg:  "std",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInCrates(tt.pkg); got != tt.want {
				t.Errorf("existsInCrates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInNpm(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "ip",
			want: true,
		},
		{
			name: "existing package with a special name",
			pkg:  "@posthog/plugin-server",
			want: true,
		},
		{
			name: "non-existent package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInNpm(tt.pkg); got != tt.want {
				t.Errorf("existsInNpm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInNuget(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "System.Formats.Nrbf",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInNuget(tt.pkg); got != tt.want {
				t.Errorf("existsInNuget() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInRubyGems(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "rails-html-sanitizer",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInRubyGems(tt.pkg); got != tt.want {
				t.Errorf("existsInRubyGems() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInPackagist(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "drupal/core",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInPackagist(tt.pkg); got != tt.want {
				t.Errorf("existsInPackagist() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInPub(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "serverpod_client",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInPub(tt.pkg); got != tt.want {
				t.Errorf("existsInPub() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInHackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "git-annex",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInHackage(tt.pkg); got != tt.want {
				t.Errorf("existsInHackage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInHex(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "jason",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInHex(tt.pkg); got != tt.want {
				t.Errorf("existsInHex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInJulia(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "Example",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "NonExistingPackage",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInJulia(tt.pkg); got != tt.want {
				t.Errorf("existsInJulia() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInMaven(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "de.gematik.refv.commons:commons",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInMaven(tt.pkg); got != tt.want {
				t.Errorf("existsInMaven() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInPyPI(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "python-libarchive",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInPyPI(tt.pkg); got != tt.want {
				t.Errorf("existsInPyPI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_existsInGo(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{
			name: "existing package",
			pkg:  "cosmossdk.io/math",
			want: true,
		},
		{
			name: "stdlib",
			pkg:  "stdlib",
			want: true,
		},
		{
			name: "github package",
			pkg:  "github.com/mattermost/mattermost/server/v8",
			want: true,
		},
		{
			name: "non-existing package",
			pkg:  "non-existing-package",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := existsInGo(tt.pkg); got != tt.want {
				t.Errorf("existsInGo() = %v, want %v", got, tt.want)
			}

		})
	}
}
