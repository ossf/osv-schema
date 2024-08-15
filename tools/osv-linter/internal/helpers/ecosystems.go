package helpers

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
)

// Dispatcher for ecosystem-specific package existence checking.
func PackageExistsInEcosystem(pkg string, ecosystem string) bool {
	switch ecosystem {
	case "PyPI":
		return PackageExistsInPyPI(pkg)
	case "Go":
		return PackageExistsInGo(pkg)
	}
	return false
}

// Dispatcher for ecosystem-specific package version existence checking.
func PackageVersionsExistInEcosystem(pkg string, versions []string, ecosystem string) error {
	switch ecosystem {
	case "PyPI":
		return PackageVersionsExistInPyPI(pkg, versions)
	case "Go":
		return PackageVersionsExistInGo(pkg, versions)
	}
	return fmt.Errorf("unsupported ecosystem: %s", ecosystem)
}

// Validate the existence of a package in PyPI.
func PackageExistsInPyPI(pkg string) bool {
	packageURL := "https://pypi.org/pypi/{package}/json"

	packageInstanceURL := strings.ReplaceAll(packageURL, "{package}", pkg)

	// This 404's for non-existent packages.
	resp, err := Head(packageInstanceURL)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusOK {
		return true
	}

	return false
}

// Confirm that all specified versions of a package exist in PyPI.
func PackageVersionsExistInPyPI(pkg string, versions []string) error {
	packageURL := "https://pypi.org/pypi/{package}/json"

	packageInstanceURL := strings.ReplaceAll(packageURL, "{package}", pkg)

	// This 404's for non-existent packages.
	resp, err := Get(packageInstanceURL)
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
		if slices.Contains(versionsInPyPy, versionToCheckFor) {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return fmt.Errorf("failed to find %#v for %q", versionsMissing, pkg)
	}

	return nil
}

// Validate the existence of a package in Go.
func PackageExistsInGo(pkg string) bool {
	packageURL := "https://proxy.golang.org/{package}/@v/list"

	// Of course the Go runtime exists :-)
	if pkg == "stdlib" || pkg == "toolchain" {
		return true
	}

	// The Go Module Proxy seems to require package names to be lowercase.
	// GitHub URLs are known to be case-insensitive.
	if strings.HasPrefix(pkg, "github.com/") {
		pkg = strings.ToLower(pkg)
	}

	packageInstanceURL := strings.ReplaceAll(packageURL, "{package}", pkg)

	// This 404's for non-existent packages.
	resp, err := Head(packageInstanceURL)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusOK {
		return true
	}

	return false
}

// isGoPseudoVersion checks if a given version string is a Go pseudo-version,
// including those with pre-release and build metadata segments,
// and handles cases where the pre-release identifier starts with '0.'.
func isGoPseudoVersion(version string) bool {
	// Seen in the wild:
	// 1.2.0.0
	// 0.5.0-alpha.5.0.20200423152442-f4b650b51dc4
	// 1.0.0-beta
	// 1.0.4-0.20180125103619-43913f2f4fbd
	// 1.1.10-0.20180427153919-f5cbcbc5cc6f
	// 1.16.0-0
	// 2.2.5-rc6.0.20190621200032-0ddffe484adc+incompatible

	// Regular expression to match pseudoversions.
	pseudoVersionRegex := regexp.MustCompile(`^(0\.|[0-9]+\.[0-9]+\.)(?:0+|(?:\d+(?:[.-](?:rc)?\d+){0,2})(?:\.(?:0+|(?:\d+(?:[.-]\d+){0,2}))){1,2})([-+].+)?$`)
	return pseudoVersionRegex.MatchString(version)
}

// Confirm that all specified versions of a package exist in Go.
func PackageVersionsExistInGo(pkg string, versions []string) error {
	packageURL := "https://proxy.golang.org/{package}/@v/list"

	if pkg == "stdlib" || pkg == "toolchain" {
		return GoVersionsExist(versions)
	}

	// The Go Module Proxy seems to require package names to be lowercase.
	// GitHub URLs are known to be case-insensitive.
	if strings.HasPrefix(pkg, "github.com/") {
		pkg = strings.ToLower(pkg)
	}

	packageInstanceURL := strings.ReplaceAll(packageURL, "{package}", pkg)

	// This 404's for non-existent packages.
	resp, err := Get(packageInstanceURL)
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
	versionsInGo := strings.Split(string(respBytes), "\n")
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
		// Add pseudo-version to base version mapping here.
		// First, detect pseudo-version and skip it.
		if isGoPseudoVersion(versionToCheckFor) {
			// TODO: Try mapping the pseudo-version to a base version and
			// checking for that instead of skipping.
			continue
		}
		// Check for both bare versions and "v"-prefixed versions.
		if slices.Contains(versionsInGo, versionToCheckFor) || slices.Contains(versionsInGo, "v"+versionToCheckFor) {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return fmt.Errorf("failed to find %+v for %q in %+v", versionsMissing, pkg, versionsInGo)
	}

	return nil
}

// Confirm that all specified versions of Go exist.
func GoVersionsExist(versions []string) error {
	URL := "https://go.dev/dl/?mode=json&include=all"

	resp, err := Get(URL)
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
	GoVersions := []string{}
	releases := gjson.GetBytes(respJSON, "#.version")
	releases.ForEach(func(key, value gjson.Result) bool {
		GoVersions = append(GoVersions, value.String())
		return true // keep iterating.
	})

	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		if isGoPseudoVersion(versionToCheckFor) {
			// TODO: Try mapping the pseudo-version to a base version instead of skipping.
			continue
		}
		if slices.Contains(GoVersions, "go"+versionToCheckFor) {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return fmt.Errorf("failed to find %+v for Go in %+v", versionsMissing, GoVersions)
	}

	return nil
}
