package pkgchecker

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/ossf/osv-schema/linter/internal/faulttolerant"

	pep440 "github.com/aquasecurity/go-pep440-version"

	"github.com/tidwall/gjson"
)

// Ecosystem support is a work in progress.
var SupportedEcosystems = []string{
	"Go",
	"PyPI",
}

// Dispatcher for ecosystem-specific package existence checking.
func ExistsInEcosystem(pkg string, ecosystem string) bool {
	switch ecosystem {
	case "Alpine":
		return true
	case "AlmaLinux":
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
		return true
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
		return true
	case "Hex":
		return true
	case "Linux":
		return true
	case "Maven":
		return true
	case "npm":
		return true
	case "NuGet":
		return true
	case "OSS-Fuzz":
		return true
	case "Packagist":
		return true
	case "Pub":
		return true
	case "PyPI":
		return existsInPyPI(pkg)
	case "Rocky Linux":
		return true
	case "RubyGems":
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
	case "Alpine":
		return nil
	case "AlmaLinux":
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
	case "OSS-Fuzz":
		return nil
	case "Packagist":
		return nil
	case "Pub":
		return nil
	case "PyPI":
		return versionsExistInPyPI(pkg, versions)
	case "Rocky Linux":
		return nil
	case "RubyGems":
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

// Validate the existence of a package in PyPI.
func existsInPyPI(pkg string) bool {
	packageInstanceURL := fmt.Sprintf("https://pypi.org/pypi/%s/json", strings.ToLower(pkg))

	// This 404's for non-existent packages.
	resp, err := faulttolerant.Head(packageInstanceURL)
	if err != nil {
		return false
	}

	return resp.StatusCode == http.StatusOK
}

// Confirm that all specified versions of a package exist in PyPI.
func versionsExistInPyPI(pkg string, versions []string) error {
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	pythonNormalizationRegex := regexp.MustCompile(`[-_.]+`)
	pkgNormalized := strings.ToLower(pythonNormalizationRegex.ReplaceAllString(pkg, "-"))
	packageInstanceURL := fmt.Sprintf("https://pypi.org/pypi/%s/json", pkgNormalized)

	// This 404's for non-existent packages.
	resp, err := faulttolerant.Get(packageInstanceURL)
	if err != nil {
		return fmt.Errorf("unable to validate package: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to validate package: %q for %s", resp.Status, packageInstanceURL)
	}

	// Parse the known versions from the JSON.
	respJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to retrieve JSON for %q: %v", pkg, err)
	}
	// Fetch all known versions of package.
	versionsInPyPy := []string{}
	releases := gjson.GetBytes(respJSON, "releases.@keys")
	releases.ForEach(func(key, value gjson.Result) bool {
		versionsInPyPy = append(versionsInPyPy, value.String())
		return true // keep iterating.
	})
	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		versionFound := false
		vc, err := pep440.Parse(versionToCheckFor)
		if err != nil {
			versionsMissing = append(versionsMissing, versionToCheckFor)
			continue
		}
		for _, pkgversion := range versionsInPyPy {
			pv, err := pep440.Parse(pkgversion)
			if err != nil {
				continue
			}
			if pv.Equal(vc) {
				versionFound = true
				break
			}
		}
		if versionFound {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return &MissingVersionsError{Package: pkg, Ecosystem: "PyPI", Missing: versionsMissing, Known: versionsInPyPy}
	}

	return nil
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

	packageInstanceURL := fmt.Sprintf("https://proxy.golang.org/%s/@v/list", pkg)

	// This 404's for non-existent packages.
	resp, err := faulttolerant.Head(packageInstanceURL)
	if err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK
}

// Confirm that all specified versions of a package exist in Go.
func versionsExistInGo(pkg string, versions []string) error {
	if pkg == "stdlib" || pkg == "toolchain" {
		return goVersionsExist(versions)
	}

	// The Go Module Proxy seems to require package names to be lowercase.
	// GitHub URLs are known to be case-insensitive.
	if strings.HasPrefix(pkg, "github.com/") {
		pkg = strings.ToLower(pkg)
	}

	packageInstanceURL := fmt.Sprintf("https://proxy.golang.org/%s/@v/list", pkg)

	// This 404's for non-existent packages.
	resp, err := faulttolerant.Get(packageInstanceURL)
	if err != nil {
		return fmt.Errorf("unable to validate package: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to validate package: %q for %s", resp.Status, packageInstanceURL)
	}

	// Load the known versions from the list provided.
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to retrieve versions for for %q: %v", pkg, err)
	}
	// Fetch all known versions of package.
	versionsInGo := strings.Split(strings.TrimSpace(string(respBytes)), "\n")
	// It seems that an empty version set is plausible. Unreleased?
	// e.g. github.com/nanobox-io/golang-nanoauth
	if len(versionsInGo[0]) == 0 {
		versionsInGo = []string{}
	}
	if len(versionsInGo) == 0 {
		// TODO: This is warning-level worthy if warnings were a thing...
		return nil
	}

	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		// First, detect pseudo-version and skip it.
		if module.IsPseudoVersion("v" + versionToCheckFor) {
			// TODO: Try mapping the pseudo-version to a base version and
			// checking for that instead of skipping.
			continue
		}
		if slices.Contains(versionsInGo, semver.Canonical("v"+versionToCheckFor)) {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return &MissingVersionsError{Package: pkg, Ecosystem: "Go", Missing: versionsMissing, Known: versionsInGo}
	}

	return nil
}

// Confirm that all specified versions of Go exist.
func goVersionsExist(versions []string) error {
	URL := "https://go.dev/dl/?mode=json&include=all"

	resp, err := faulttolerant.Get(URL)
	if err != nil {
		return fmt.Errorf("unable to validate Go versions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to validate package: %q for %s", resp.Status, URL)
	}

	// Fetch all known versions of Go.
	// Parse the known versions from the JSON.
	respJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to retrieve JSON for Go: %v", err)
	}
	// Fetch all known versions of package.
	goVersions := []string{}
	releases := gjson.GetBytes(respJSON, "#.version")
	releases.ForEach(func(key, value gjson.Result) bool {
		goVersions = append(goVersions, value.String())
		return true // keep iterating.
	})

	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		if slices.Contains(goVersions, "go"+versionToCheckFor) {
			continue
		}
		if semver.Prerelease("v"+versionToCheckFor) == "-0" {
			// Coerce "1.16.0-0" to "1.16".
			if slices.Contains(goVersions, "go"+strings.TrimPrefix(semver.MajorMinor("v"+versionToCheckFor), "v")) {
				continue
			}
			// Coerce "1.21.0-0" to "1.21.0".
			if slices.Contains(goVersions, "go"+strings.TrimPrefix(strings.TrimSuffix("v"+versionToCheckFor, semver.Prerelease("v"+versionToCheckFor)), "v")) {
				continue
			}
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return fmt.Errorf("failed to find %+v for Go in %+v", versionsMissing, goVersions)
	}

	return nil
}
