package pkgchecker

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ossf/osv-schema/linter/internal/faulttolerant"
)

// Validate the existence of a package in crates.io.
func existsInCrates(pkg string) bool {
	// Handle special case for rust standard library
	if pkg == "std" {
		return true
	}

	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["crates.io"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in npm.
func existsInNpm(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["npm"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in NuGet.
func existsInNuget(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s/index.json", EcosystemBaseURLs["NuGet"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in RubyGems.
func existsInRubyGems(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s.json", EcosystemBaseURLs["RubyGems"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Packagist.
func existsInPackagist(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s.json", EcosystemBaseURLs["Packagist"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Pub.
func existsInPub(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["Pub"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Hackage.
func existsInHackage(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["Hackage"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in PyPI.
// Note: for malicious packages, if the package has been removed, the verify will be fail
func existsInPyPI(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s/json", EcosystemBaseURLs["PyPI"], strings.ToLower(pkg))

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Go.
func existsInGo(pkg string) bool {
	// Of course the Go runtime exists :-)
	if pkg == "stdlib" || pkg == "toolchain" {
		return true
	}

	// The Go Module Proxy seems to require package names to be lowercase.
	// GitHub URLs are known to be case-insensitive.
	if strings.HasPrefix(pkg, "github.com/") {
		pkg = strings.ToLower(pkg)
	}

	packageInstanceURL := fmt.Sprintf("%s/%s/@v/list", EcosystemBaseURLs["Go"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Makes an HTTP GET request to check package existance, with fault tolerance.
func checkPackageExists(packageInstanceURL string) bool {
	// This 404's for non-existent packages.
	resp, err := faulttolerant.Head(packageInstanceURL)
	if err != nil {
		return false
	}

	return resp.StatusCode == http.StatusOK
}
