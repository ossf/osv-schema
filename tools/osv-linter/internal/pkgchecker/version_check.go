package pkgchecker

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/linter/internal/faulttolerant"
	"github.com/tidwall/gjson"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// Confirm that all specified versions of a package exist in RubyGems.
func versionsExistInRubyGems(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/versions/%s.json", EcosystemBaseURLs["RubyGems"], pkg)

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
	versionsInRepository := []string{}
	releases := gjson.GetBytes(respJSON, "@this")
	releases.ForEach(func(key, value gjson.Result) bool {
		versionsInRepository = append(versionsInRepository, value.Get("number").String())
		return true // keep iterating.
	})
	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		versionFound := false
		vc, err := semantic.Parse(versionToCheckFor, "RubyGems")
		if err != nil {
			versionsMissing = append(versionsMissing, versionToCheckFor)
			continue
		}
		for _, pkgversion := range versionsInRepository {
			if r, err := vc.CompareStr(pkgversion); r == 0 && err == nil {
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
		return &MissingVersionsError{Package: pkg, Ecosystem: "RubyGems", Missing: versionsMissing, Known: versionsInRepository}
	}

	return nil
}

// Confirm that all specified versions of a package exist in Packagist.
func versionsExistInPackagist(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s.json", EcosystemBaseURLs["Packagist"], pkg)

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
	versionsInRepository := []string{}
	releases := gjson.GetBytes(respJSON, fmt.Sprintf("packages.%s", pkg))
	releases.ForEach(func(key, value gjson.Result) bool {
		versionsInRepository = append(versionsInRepository, value.Get("version").String())
		return true // keep iterating.
	})
	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	for _, versionToCheckFor := range versions {
		versionFound := false
		vc, err := semantic.Parse(versionToCheckFor, "Packagist")
		if err != nil {
			versionsMissing = append(versionsMissing, versionToCheckFor)
			continue
		}
		for _, pkgversion := range versionsInRepository {
			if r, err := vc.CompareStr(pkgversion); r == 0 && err == nil {
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
		return &MissingVersionsError{Package: pkg, Ecosystem: "Packagist", Missing: versionsMissing, Known: versionsInRepository}
	}

	return nil
}

// Confirm that all specified versions of a package exist in PyPI.
func versionsExistInPyPI(pkg string, versions []string) error {
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	pythonNormalizationRegex := regexp.MustCompile(`[-_.]+`)
	pkgNormalized := strings.ToLower(pythonNormalizationRegex.ReplaceAllString(pkg, "-"))
	packageInstanceURL := fmt.Sprintf("%s/%s/json", EcosystemBaseURLs["PyPI"], pkgNormalized)

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
		vc, err := semantic.Parse(versionToCheckFor, "PyPI")
		if err != nil {
			versionsMissing = append(versionsMissing, versionToCheckFor)
			continue
		}
		for _, pkgversion := range versionsInPyPy {
			if r, err := vc.CompareStr(pkgversion); r == 0 && err == nil {
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

	packageInstanceURL := fmt.Sprintf("%s/%s/@v/list", EcosystemBaseURLs["Go"], pkg)

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
