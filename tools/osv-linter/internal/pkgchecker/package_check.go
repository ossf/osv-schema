package pkgchecker

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ossf/osv-schema/linter/internal/faulttolerant"
)

// Validate the existence of a package in CRAN.
func existsInCran(pkg string) bool {
	ecosystem := "CRAN"
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs[ecosystem], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in crates.io.
func existsInCrates(pkg string) bool {
	// Handle special case for rust standard library
	if pkg == "std" {
		return true
	}

	ecosystem := "crates.io"
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs[ecosystem], pkg)

	if isPackageInDepsDev(ecosystem, pkg) {
		return true
	}

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

	ecosystem := "Go"
	packageInstanceURL := fmt.Sprintf("%s/%s/@v/list", EcosystemBaseURLs[ecosystem], pkg)

	if isPackageInDepsDev(ecosystem, pkg) {
		return true
	}

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Hackage.
func existsInHackage(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["Hackage"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Hex.
func existsInHex(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["Hex"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Julia.
func existsInJulia(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s/versions.json", EcosystemBaseURLs["Julia"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Maven.
func existsInMaven(pkg string) bool {
	if !strings.Contains(pkg, ":") {
		return false
	}
	group_id := strings.Split(pkg, ":")[0]
	artifact_id := strings.Split(pkg, ":")[1]

	ecosystem := "Maven"
	packageInstanceURL := fmt.Sprintf("%s/?q=g:%s%%20AND%%20a:%s", EcosystemBaseURLs[ecosystem], group_id, artifact_id)

	if isPackageInDepsDev(ecosystem, pkg) {
		return true
	}

	// Needs to use GET instead of HEAD for Maven
	resp, err := faulttolerant.Get(packageInstanceURL)
	if err != nil {
		return false
	}

	return resp.StatusCode == http.StatusOK
}

// Validate the existence of a package in npm.
func existsInNpm(pkg string) bool {
	ecosystem := "npm"
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs[ecosystem], pkg)

	if isPackageInDepsDev(ecosystem, pkg) {
		return true
	}

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in NuGet.
func existsInNuget(pkg string) bool {
	ecosystem := "NuGet"
	packageInstanceURL := fmt.Sprintf("%s/%s/index.json", EcosystemBaseURLs[ecosystem], pkg)

	if isPackageInDepsDev(ecosystem, pkg) {
		return true
	}

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Packagist.
func existsInPackagist(pkg string, repo string) bool {
	packageInstanceURL, err := resolvePackagistPackageInstanceURL(pkg, repo)

	if err != nil {
		return false
	}

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in Pub.
func existsInPub(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["Pub"], pkg)

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in PyPI.
func existsInPyPI(pkg string) bool {
	ecosystem := "PyPI"
	packageInstanceURL := fmt.Sprintf("%s/%s/json", EcosystemBaseURLs[ecosystem], strings.ToLower(pkg))

	if isPackageInDepsDev(ecosystem, pkg) {
		return true
	}

	return checkPackageExists(packageInstanceURL)
}

// Validate the existence of a package in RubyGems.
func existsInRubyGems(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("%s/gems/%s.json", EcosystemBaseURLs["RubyGems"], pkg)

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

func isPackageInDepsDev(ecosystem string, pkg string) bool {
	url := fmt.Sprintf("https://api.deps.dev/v3/systems/%s/packages/%s", ecosystem, pkg)
	return checkPackageExists(url)
}
