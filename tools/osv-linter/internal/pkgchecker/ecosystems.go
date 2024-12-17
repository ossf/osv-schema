package pkgchecker

import (
	"fmt"
)

// Ecosystem support is a work in progress.
var SupportedEcosystems = []string{
	"Go",
	"PyPI",
	"crates.io",
	"npm",
	"NuGet",
	"RubyGems",
	"Packagist",
	"Pub",
	"Hackage",
	"Maven",
}

// EcosystemBaseURLs maps ecosystems to their base API URLs.
var EcosystemBaseURLs = map[string]string{
	"Go":        "https://proxy.golang.org",
	"PyPI":      "https://pypi.org/pypi",
	"crates.io": "https://crates.io/api/v1/crates",
	"npm":       "https://registry.npmjs.org",
	"NuGet":     "https://api.nuget.org/v3-flatcontainer",
	"RubyGems":  "https://rubygems.org/api/v1/gems",
	"Packagist": "https://repo.packagist.org/p2",
	"Pub":       "https://pub.dev/api/packages",
	"Hackage":   "https://hackage.haskell.org/package",
	"Maven":     "https://search.maven.org/solrsearch/select",
}

// Dispatcher for ecosystem-specific package existence checking.
func ExistsInEcosystem(pkg string, ecosystem string) bool {
	switch ecosystem {
	case "AlmaLinux":
		return true
	case "Alpine":
		return true
	case "Android":
		return true
	case "Bitnami":
		return true
	case "Chainguard":
		return true
	case "CRAN":
		return true
	case "crates.io":
		return existsInCrates(pkg)
	case "Debian":
		return true
	case "GIT":
		return true
	case "GitHub Actions":
		return true
	case "Go":
		return existsInGo(pkg)
	case "GSD":
		return true
	case "Hackage":
		return existsInHackage(pkg)
	case "Hex":
		return true
	case "Linux":
		return true
	case "Maven":
		return existsInMaven(pkg)
	case "npm":
		return existsInNpm(pkg)
	case "NuGet":
		return existsInNuget(pkg)
	case "openSUSE":
		return true
	case "OSS-Fuzz":
		return true
	case "Packagist":
		return existsInPackagist(pkg)
	case "Pub":
		return existsInPub(pkg)
	case "PyPI":
		return existsInPyPI(pkg)
	case "Red Hat":
		return true
	case "Rocky Linux":
		return true
	case "RubyGems":
		return existsInRubyGems(pkg)
	case "SUSE":
		return true
	case "SwiftURL":
		return true
	case "Ubuntu":
		return true
	case "UVI":
		return true
	case "Wolfi":
		return true
	}
	return false
}

// Missing VersionsError describes when specific versions of a package could not be found.
type MissingVersionsError struct {
	Package   string
	Ecosystem string
	Missing   []string
	Known     []string
}

func (e *MissingVersionsError) Error() string {
	return fmt.Sprintf("Failed to find %+q of %q in %q (have: %+q)", e.Missing, e.Package, e.Ecosystem, e.Known)
}

// Dispatcher for ecosystem-specific package version existence checking.
func VersionsExistInEcosystem(pkg string, versions []string, ecosystem string) error {
	switch ecosystem {
	case "AlmaLinux":
		return nil
	case "Alpine":
		return nil
	case "Android":
		return nil
	case "Bitnami":
		return nil
	case "Chainguard":
		return nil
	case "CRAN":
		return nil
	case "crates.io":
		return nil
	case "Debian":
		return nil
	case "GIT":
		return nil
	case "GitHub Actions":
		return nil
	case "Go":
		return versionsExistInGo(pkg, versions)
	case "GSD":
		return nil
	case "Hackage":
		return nil
	case "Hex":
		return nil
	case "Linux":
		return nil
	case "Maven":
		return nil
	case "npm":
		return nil
	case "NuGet":
		return nil
	case "openSUSE":
		return nil
	case "OSS-Fuzz":
		return nil
	case "Packagist":
		return nil
	case "Pub":
		return nil
	case "PyPI":
		return versionsExistInPyPI(pkg, versions)
	case "Red Hat":
		return nil
	case "Rocky Linux":
		return nil
	case "RubyGems":
		return nil
	case "SUSE":
		return nil
	case "SwiftURL":
		return nil
	case "Ubuntu":
		return nil
	case "UVI":
		return nil
	case "Wolfi":
		return nil
	}
	return fmt.Errorf("unsupported ecosystem: %s", ecosystem)
}
