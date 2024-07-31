package helpers

import (
	"fmt"
	"io"
	"net/http"
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
	releases := gjson.GetBytes(respJSON, `releases.@keys`)
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
	if pkg == "stdlib" {
		return true
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

// Confirm that all specified versions of a package exist in Go.
func PackageVersionsExistInGo(pkg string, versions []string) error {
	packageURL := "https://proxy.golang.org/{package}/@v/list"

	if pkg == "stdlib" {
		return GoVersionsExist(versions)
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

	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		if slices.Contains(versionsInGo, versionToCheckFor) {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return fmt.Errorf("failed to find %#v for %q", versionsMissing, pkg)
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
	releases := gjson.GetBytes(respJSON, `#.version`)
	releases.ForEach(func(key, value gjson.Result) bool {
		GoVersions = append(GoVersions, value.String())
		return true // keep iterating.
	})

	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		if slices.Contains(GoVersions, "go"+versionToCheckFor) {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}
	if len(versionsMissing) > 0 {
		return fmt.Errorf("failed to find %#v for Go", versionsMissing)
	}

	return nil
}
