package pkgchecker

import (
	"errors"
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

var errPathNotFound = errors.New("path not found")

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

// Confirm that all specified versions of a package exist in a registry
func versionsExistInGeneric(
	pkg string,
	versions []string,
	eco string,
	packageInstanceURL string,
	versionsPath string,
) error {
	respJSON, err := fetchPackageData(packageInstanceURL)
	if err != nil {
		return fmt.Errorf("unable to retrieve JSON for %q: %v", pkg, err)
	}

	// Fetch all known versions of package.
	versionsInRepository := []string{}

	r := gjson.GetBytes(respJSON, versionsPath)

	if !r.Exists() {
		return errPathNotFound
	}

	for _, result := range r.Array() {
		versionsInRepository = append(versionsInRepository, result.String())
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
			Known:     versionsInRepository,
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

	respBytes, err := fetchPackageData(packageInstanceURL)
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
		return MissingVersionsError{Package: pkg, Ecosystem: "Go", Missing: versionsMissing, Known: versionsInGo}
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
func versionsExistInPackagist(pkg string, versions []string) error {
	// most drupal packages are published in a dedicated repository, so check there first
	if strings.HasPrefix(pkg, "drupal/") {
		drupalInstanceURL := fmt.Sprintf("%s/%s.json", "https://packages.drupal.org/files/packages/8/p2", pkg)

		err := versionsExistInGeneric(
			pkg, versions,
			"Packagist",
			drupalInstanceURL,
			fmt.Sprintf("packages.%s.#.version", pkg),
		)

		if err == nil {
			return err
		}

		// not all drupal packages are published on the drupal repository,
		// and some packages are only present with security advisories
		//
		// todo: ideally we should not be checking the error message itself
		if !strings.HasSuffix(err.Error(), "bad response: 404") && !errors.Is(err, errPathNotFound) {
			return err
		}
	}

	packageInstanceURL := fmt.Sprintf("%s/%s.json", EcosystemBaseURLs["Packagist"], pkg)

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
