package pkgchecker

import (
	"fmt"
)

// Ecosystem support is a work in progress.
var SupportedEcosystems = []string{
	"CRAN",
	"crates.io",
	"Go",
	"Hackage",
	"Hex",
	"Julia",
	"Maven",
	"npm",
	"NuGet",
	"Packagist",
	"Pub",
	"PyPI",
	"RubyGems",
}

// IsSchemaEcosystem reports whether the ecosystem is valid according to the schema.
// Set by checks package at initialization.
var IsSchemaEcosystem func(ecosystem string) bool

// EcosystemBaseURLs maps ecosystems to their base API URLs.
var EcosystemBaseURLs = map[string]string{
	"CRAN":      "https://crandb.r-pkg.org/",
	"crates.io": "https://crates.io/api/v1/crates",
	"Go":        "https://proxy.golang.org",
	"Hackage":   "https://hackage.haskell.org/package",
	"Hex":       "https://hex.pm/api/packages",
	"Julia":     "http://juliaregistries.github.io/GeneralMetadata.jl/api",
	"Maven":     "https://search.maven.org/solrsearch/select",
	"npm":       "https://registry.npmjs.org",
	"NuGet":     "https://api.nuget.org/v3-flatcontainer",
	"Packagist": "https://repo.packagist.org/p2",
	"Pub":       "https://pub.dev/api/packages",
	"PyPI":      "https://pypi.org/pypi",
	"RubyGems":  "https://rubygems.org/api/v1",
}

// Dispatcher for ecosystem-specific package existence checking.
func ExistsInEcosystem(pkg string, ecosystem string, suffix string) bool {
	switch ecosystem {
	case "CRAN":
		return existsInCran(pkg)
	case "crates.io":
		return existsInCrates(pkg)
	case "Go":
		return existsInGo(pkg)
	case "Hackage":
		return existsInHackage(pkg)
	case "Hex":
		return existsInHex(pkg)
	case "Julia":
		return existsInJulia(pkg)
	case "Maven":
		return existsInMaven(pkg)
	case "npm":
		return existsInNpm(pkg)
	case "NuGet":
		return existsInNuget(pkg)
	case "Packagist":
		return existsInPackagist(pkg, suffix)
	case "Pub":
		return existsInPub(pkg)
	case "PyPI":
		return existsInPyPI(pkg)
	case "RubyGems":
		return existsInRubyGems(pkg)
	default:
		if IsSchemaEcosystem != nil && IsSchemaEcosystem(ecosystem) {
			return true
		}
		return false
	}
}

// MissingVersionsError describes when specific versions of a package could not be found.
type MissingVersionsError struct {
	Package   string
	Ecosystem string
	Invalid   []string
	Missing   []string
	Known     []string
}

func (e MissingVersionsError) Error() string {
	msg := fmt.Sprintf("Failed to find %+q of %q in %q (have: %+q", e.Missing, e.Package, e.Ecosystem, e.Known)

	if len(e.Invalid) > 0 {
		msg += fmt.Sprintf(", invalid versions: %+q", e.Invalid)
	}

	msg += ")"

	return msg
}

// Dispatcher for ecosystem-specific package version existence checking.
func VersionsExistInEcosystem(pkg string, versions []string, ecosystem string, suffix string) error {
	switch ecosystem {
	case "CRAN":
		return versionsExistInCran(pkg, versions)
	case "crates.io":
		return versionsExistInCrates(pkg, versions)
	case "Go":
		return versionsExistInGo(pkg, versions)
	case "Hackage":
		return versionsExistInHackage(pkg, versions)
	case "Hex":
		return versionsExistInHex(pkg, versions)
	case "Julia":
		return versionsExistInJulia(pkg, versions)
	case "npm":
		return versionsExistInNpm(pkg, versions)
	case "NuGet":
		return versionsExistInNuGet(pkg, versions)
	case "Packagist":
		return versionsExistInPackagist(pkg, versions, suffix)
	case "Pub":
		return versionsExistInPub(pkg, versions)
	case "PyPI":
		return versionsExistInPyPI(pkg, versions)
	case "RubyGems":
		return versionsExistInRubyGems(pkg, versions)
	default:
		if IsSchemaEcosystem != nil && IsSchemaEcosystem(ecosystem) {
			return nil
		}
		return fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}
