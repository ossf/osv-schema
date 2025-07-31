package checks

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/linter/internal/pkgchecker"
	"github.com/package-url/packageurl-go"
	"github.com/tidwall/gjson"
)

var CheckPackageExists = &CheckDef{
	Code:        "PKG:001",
	Name:        "package-exists",
	Description: "package exists in ecosystem's registry",
	Check:       PackageExists,
}

type Package struct {
	Ecosystem string
	Name      string
}

// PackageExists checks the package exists in the registry for that ecosystem.
func PackageExists(json *gjson.Result, config *Config) (findings []CheckError) {
	affectedEntries := json.Get("affected")

	knownExistent := make(map[Package]bool)
	knownNonexistent := make(map[Package]bool)

	// Examine each entry:
	// for ones for packages, on a per-package basis
	affectedEntries.ForEach(func(key, value gjson.Result) bool {
		// If it has a package field, it's for a package, otherwise confirm the range is of type GIT.
		maybePackage := value.Get("package")
		if !maybePackage.Exists() {
			return true // keep iterating (over affected entries)
		}
		// Normalize ecosystems with a colon to their base.
		// e.g. "Alpine:v3.5" -> "Alpine"
		ecosystem := strings.Split(value.Get("package.ecosystem").String(), ":")[0]
		// Use config.Ecosystems as an allowlist, if it is set.
		if len(config.Ecosystems) > 0 && !slices.Contains(config.Ecosystems, ecosystem) {
			return true // keep iterating (over affected entries)
		}
		pkg := value.Get("package.name").String()

		// Avoid unnecessary network traffic for repeat packages.
		if _, ok := knownExistent[Package{Ecosystem: ecosystem, Name: pkg}]; ok {
			return true // keep iterating (over affected entries)
		}
		if _, ok := knownNonexistent[Package{Ecosystem: ecosystem, Name: pkg}]; ok {
			return true // keep iterating (over affected entries)
		}
		// Not cached, determine existence.
		if !pkgchecker.ExistsInEcosystem(pkg, ecosystem) {
			findings = append(findings, CheckError{Message: fmt.Sprintf("package %q not found in %q", pkg, ecosystem)})
			knownNonexistent[Package{Ecosystem: ecosystem, Name: pkg}] = true
		} else {
			knownExistent[Package{Ecosystem: ecosystem, Name: pkg}] = true
		}
		return true // keep iterating (over affected entries)
	})
	return findings
}

var CheckPackageVersionsExist = &CheckDef{
	Code:        "PKG:002",
	Name:        "package-versions-exist",
	Description: "package versions exist in ecosystem's registry",
	Check:       PackageVersionsExist,
}

// PackageVersionsExist checks the package versions exist in the registry for that ecosystem.
func PackageVersionsExist(json *gjson.Result, config *Config) (findings []CheckError) {
	affectedEntries := json.Get("affected")

	// Examine each affected entry:
	// for ones for packages, on a per-package basis
	affectedEntries.ForEach(func(key, value gjson.Result) bool {
		// If it has a package field, it's for a package, otherwise confirm the range is of type GIT.
		maybePackage := value.Get("package")
		if !maybePackage.Exists() {
			return true // keep iterating (over affected entries)
		}
		// Normalize ecosystems with a colon to their base.
		// e.g. "Alpine:v3.5" -> "Alpine"
		ecosystem := strings.Split(value.Get("package.ecosystem").String(), ":")[0]
		// Use config.Ecosystems as an allowlist, if it is set.
		if len(config.Ecosystems) != 0 && !slices.Contains(config.Ecosystems, ecosystem) {
			return true // keep iterating (over affected entries)
		}
		pkg := value.Get("package.name").String()
		versionsToCheck := []string{}
		// Examine versions in ranges.
		maybeRanges := value.Get("ranges")
		maybeRanges.ForEach(func(key, value gjson.Result) bool {
			rangeType := value.Get("type").String()
			if rangeType == "GIT" {
				return true // keep iterating (over ranges)
			}
			events := value.Get("events")
			events.ForEach(func(key, value gjson.Result) bool {
				// Collect all the introduced values.
				result := value.Get("introduced")
				if result.Exists() && result.String() != "0" {
					versionsToCheck = append(versionsToCheck, result.String())
				}
				// Collect all the fixed/last_affected values.
				result = value.Get("fixed")
				if result.Exists() {
					versionsToCheck = append(versionsToCheck, result.String())
				}
				result = value.Get("last_affected")
				if result.Exists() {
					versionsToCheck = append(versionsToCheck, result.String())
				}
				return true // keep iterating (over events)
			})
			return true // keep iterating (over ranges)
		})
		// Examine versions in versions array.
		maybeVersions := value.Get("versions")
		maybeVersions.ForEach(func(key, value gjson.Result) bool {
			versionsToCheck = append(versionsToCheck, value.String())
			return true // keep iterating (over versions)
		})
		err := pkgchecker.VersionsExistInEcosystem(pkg, versionsToCheck, ecosystem)
		if err != nil {
			findings = append(findings, CheckError{Message: err.Error()})
		}

		return true // keep iterating (over affected entries)
	})
	return findings
}

var CheckPackagePurlValid = &CheckDef{
	Code:        "PKG:003",
	Name:        "package-purl-valid",
	Description: "package purl validates",
	Check:       PackagePurlValid,
}

// PackagePurlValid checks the package purls validate.
func PackagePurlValid(json *gjson.Result, config *Config) (findings []CheckError) {
	affectedEntries := json.Get("affected")

	// Examine each affected entry:
	// for ones for packages, on a per-package basis
	affectedEntries.ForEach(func(key, value gjson.Result) bool {
		// If it has a package field, it's for a package, otherwise confirm the range is of type GIT.
		maybePackage := value.Get("package")
		if !maybePackage.Exists() {
			return true // keep iterating (over affected entries)
		}
		purl := value.Get("package.purl")
		if !purl.Exists() {
			return true // keep iterating (over affected entries)
		}

		_, err := packageurl.FromString(purl.String())
		if err != nil {
			// Add a version placeholder, as some ecosystem requires one.
			purlWithVersion := purl.String() + "@version"
			_, err = packageurl.FromString(purlWithVersion)
			if err != nil {
				findings = append(findings, CheckError{Message: fmt.Sprintf("Invalid Purl %q: %#v", purl.String(), err)})
			}
		}

		return true // keep iterating (over affected entries)
	})
	return findings
}
