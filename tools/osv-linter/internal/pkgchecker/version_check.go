package pkgchecker

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/tools/osv-linter/internal/faulttolerant"
	"github.com/tidwall/gjson"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

var errPathNotFound = errors.New("path not found")

// Identify a cached version list by its URL and JSON path.
type urlAndJSONPath struct {
	url      string
	jsonPath string
}

// Cache of parsed version lists by URL and JSON path.
var versionsByURLAndJSONPath sync.Map

// Cache of parsed version lists by URL.
var versionsByURL sync.Map

// Fetch the package data from the registry.
func fetchPackageData(packageInstanceURL string) ([]byte, error) {
	resp, err := faulttolerant.Get(packageInstanceURL)
	if err != nil {
		return nil, fmt.Errorf("unable to validate package: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to validate package: %q for %s", resp.Status, packageInstanceURL)
	}
	return io.ReadAll(resp.Body)
}

// Fetch and cache the versions at the specified JSON path.
func fetchJSONVersions(url, versionsPath string) ([]string, error) {
	key := urlAndJSONPath{url: url, jsonPath: versionsPath}
	if versions, ok := versionsByURLAndJSONPath.Load(key); ok {
		return versions.([]string), nil
	}
	data, err := fetchPackageData(url)
	if err != nil {
		return nil, err
	}

	r := gjson.GetBytes(data, versionsPath)
	if !r.Exists() {
		return nil, errPathNotFound
	}
	results := r.Array()
	versions := make([]string, 0, len(results))
	for _, result := range results {
		versions = append(versions, result.String())
	}
	versionsByURLAndJSONPath.Store(key, versions)
	return versions, nil
}

// Confirm that all specified versions of a package exist in a registry
func versionsExistInGeneric(
	pkg string,
	versions []string,
	eco string,
	packageInstanceURL string,
	versionsPath string,
) error {
	versionsInRepository, err := fetchJSONVersions(packageInstanceURL, versionsPath)
	if err == errPathNotFound {
		return err
	}
	if err != nil {
		return fmt.Errorf("unable to retrieve JSON for %q: %v", pkg, err)
	}

	// Determine which referenced versions are missing.
	versionsMissing := []string{}
	versionsInvalid := []string{}
	for _, versionToCheckFor := range versions {
		versionFound := false
		vc, err := semantic.Parse(versionToCheckFor, eco)
		if err != nil {
			// consider this "missing" since the version here comes from the advisory
			// so hopefully it's actually a malformed version rather than a bug
			versionsMissing = append(versionsMissing, versionToCheckFor)
			continue
		}
		for _, pkgversion := range versionsInRepository {
			r, err := vc.CompareStr(pkgversion)

			if err != nil {
				// note versions that semantic considered invalid, since that is most
				// likely a bug in our code given the version is from the ecosystem repo
				versionsInvalid = append(versionsInvalid, pkgversion)
			} else if r == 0 {
				versionFound = true
				break
			}
		}
		if versionFound {
			continue
		}
		versionsMissing = append(versionsMissing, versionToCheckFor)
	}

	if len(versionsMissing) > 0 || len(versionsInvalid) > 0 {
		return MissingVersionsError{
			Package:   pkg,
			Ecosystem: eco,
			Invalid:   versionsInvalid,
			Missing:   versionsMissing,
			Known:     slices.Clone(versionsInRepository),
		}
	}

	return nil
}

// Confirm that all specified versions of a package exist in CRAN.
func versionsExistInCran(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s/all", EcosystemBaseURLs["CRAN"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"CRAN",
		packageInstanceURL,
		"versions.@keys",
	)
}

// Confirm that all specified versions of a package exist in crates.io.
func versionsExistInCrates(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["crates.io"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"crates.io",
		packageInstanceURL,
		"versions.#.num",
	)
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

	versionsInGo, err := fetchGoModuleVersions(packageInstanceURL)
	if err != nil {
		return fmt.Errorf("unable to retrieve versions for for %q: %v", pkg, err)
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
		return MissingVersionsError{Package: pkg, Ecosystem: "Go", Missing: versionsMissing, Known: slices.Clone(versionsInGo)}
	}

	return nil
}

// Fetch and cache the Go module's version list.
func fetchGoModuleVersions(url string) ([]string, error) {
	if versions, ok := versionsByURL.Load(url); ok {
		return versions.([]string), nil
	}
	data, err := fetchPackageData(url)
	if err != nil {
		return nil, err
	}
	versions := []string{}
	// Unreleased modules may have an empty version list.
	if list := strings.TrimSpace(string(data)); list != "" {
		versions = strings.Split(list, "\n")
	}
	versionsByURL.Store(url, versions)
	return versions, nil
}

// Confirm that all specified versions of Go exist.
func goVersionsExist(versions []string) error {
	url := "https://go.dev/dl/?mode=json&include=all"
	goVersions, err := fetchJSONVersions(url, "#.version")
	if err != nil && err != errPathNotFound {
		return fmt.Errorf("unable to retrieve JSON for Go: %v", err)
	}

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

// Confirm that all specified versions of a package exist in Hackage.
func versionsExistInHackage(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s.json", EcosystemBaseURLs["Hackage"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"Hackage",
		packageInstanceURL,
		"@keys",
	)
}

// Confirm that all specified versions of a package exist in Hex.
func versionsExistInHex(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["Hex"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"Hex",
		packageInstanceURL,
		"releases.#.version",
	)
}

// Confirm that all specified versions of a package exist in npm.
func versionsExistInNpm(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["npm"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"npm",
		packageInstanceURL,
		"versions.@keys",
	)
}

// Confirm that all specified versions of a package exist in NuGet.
func versionsExistInNuGet(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s/index.json", EcosystemBaseURLs["NuGet"], strings.ToLower(pkg))

	return versionsExistInGeneric(
		pkg, versions,
		"NuGet",
		packageInstanceURL,
		"versions",
	)
}

// Confirm that all specified versions of a package exist in Julia.
func versionsExistInJulia(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s/versions.json", EcosystemBaseURLs["Julia"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"Julia",
		packageInstanceURL,
		"@keys",
	)
}

// Confirm that all specified versions of a package exist in Packagist.
func versionsExistInPackagist(pkg string, versions []string, repo string) error {
	packageInstanceURL, err := resolvePackagistPackageInstanceURL(pkg, repo)

	if err != nil {
		return err
	}

	return versionsExistInGeneric(
		pkg, versions,
		"Packagist",
		packageInstanceURL,
		fmt.Sprintf("packages.%s.#.version", pkg),
	)
}

// Confirm that all specified versions of a package exist in Pub.
func versionsExistInPub(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/%s", EcosystemBaseURLs["Pub"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"Pub",
		packageInstanceURL,
		"versions.#.version",
	)
}

// Confirm that all specified versions of a package exist in PyPI.
func versionsExistInPyPI(pkg string, versions []string) error {
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	pythonNormalizationRegex := regexp.MustCompile(`[-_.]+`)
	pkgNormalized := strings.ToLower(pythonNormalizationRegex.ReplaceAllString(pkg, "-"))
	packageInstanceURL := fmt.Sprintf("%s/%s/json", EcosystemBaseURLs["PyPI"], pkgNormalized)

	return versionsExistInGeneric(
		pkg, versions,
		"PyPI",
		packageInstanceURL,
		"releases.@keys",
	)
}

// Confirm that all specified versions of a package exist in RubyGems.
func versionsExistInRubyGems(pkg string, versions []string) error {
	packageInstanceURL := fmt.Sprintf("%s/versions/%s.json", EcosystemBaseURLs["RubyGems"], pkg)

	return versionsExistInGeneric(
		pkg, versions,
		"RubyGems",
		packageInstanceURL,
		"@this.#.number",
	)
}
