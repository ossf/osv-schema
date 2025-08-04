package pkgchecker

import (
	"fmt"
)

// Ecosystem support is a work in progress.
var SupportedEcosystems = []string{
	"crates.io",
	"Go",
	"Hackage",
	"Hex",
	"Maven",
	"npm",
	"NuGet",
	"Packagist",
	"Pub",
	"PyPI",
	"RubyGems",
}

// EcosystemBaseURLs maps ecosystems to their base API URLs.
var EcosystemBaseURLs = map[string]string{
	"CRAN":      "https://crandb.r-pkg.org/",
	"crates.io": "https://crates.io/api/v1/crates",
	"Go":        "https://proxy.golang.org",
	"Hackage":   "https://hackage.haskell.org/package",
	"Hex":       "https://hex.pm/api/packages",
	"Maven":     "https://search.maven.org/solrsearch/select",
	"npm":       "https://registry.npmjs.org",
	"NuGet":     "https://api.nuget.org/v3-flatcontainer",
	"Packagist": "https://repo.packagist.org/p2",
	"Pub":       "https://pub.dev/api/packages",
	"PyPI":      "https://pypi.org/pypi",
	"RubyGems":  "https://rubygems.org/api/v1",
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
		return existsInCran(pkg)
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
		return existsInHex(pkg)
	case "Kubernetes":
		return true
	case "Linux":
		return true
	case "Maven":
		return existsInMaven(pkg)
	case "MinimOS":
		return true
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
		return versionsExistInCran(pkg, versions)
	case "crates.io":
		return versionsExistInCrates(pkg, versions)
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
		return versionsExistInHackage(pkg, versions)
	case "Hex":
		return versionsExistInHex(pkg, versions)
	case "Linux":
		return nil
	case "Maven":
		return nil
	case "MinimOS":
		return nil
	case "npm":
		return versionsExistInNpm(pkg, versions)
	case "NuGet":
		return versionsExistInNuGet(pkg, versions)
	case "openSUSE":
		return nil
	case "OSS-Fuzz":
		return nil
	case "Packagist":
		return versionsExistInPackagist(pkg, versions)
	case "Pub":
		return nil
	case "PyPI":
		return versionsExistInPyPI(pkg, versions)
	case "Red Hat":
		return nil
	case "Rocky Linux":
		return nil
	case "RubyGems":
		return versionsExistInRubyGems(pkg, versions)
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
