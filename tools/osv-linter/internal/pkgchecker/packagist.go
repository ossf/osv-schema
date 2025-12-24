package pkgchecker

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/ossf/osv-schema/linter/internal/faulttolerant"
	"github.com/tidwall/gjson"
)

var packagistCache sync.Map

func fetchPackagistPackagesInfo(repo string) ([]byte, error) {
	resp, err := faulttolerant.Get(repo)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch packages.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to fetch packages.json: %q for %s", resp.Status, repo)
	}

	return io.ReadAll(resp.Body)
}

// fetchPackagistMetadataUrl returns the metadata-url that should be used
// for the given Packagist-based repository.
//
// The URL will include "%package%" to indicate where the package name goes,
// and be absolute.
//
// also see https://getcomposer.org/doc/05-repositories.md#metadata-url-available-packages-and-available-package-patterns
func fetchPackagistMetadataUrlActual(repo string) (string, error) {
	packagesInfo, err := fetchPackagistPackagesInfo(repo + "/packages.json")

	if err != nil {
		return "", err
	}

	// todo: this field is only supported by Composer v2, and technically
	//  not the only way to provide packages
	metadataURL := gjson.GetBytes(packagesInfo, "metadata-url").String()

	if strings.HasPrefix(metadataURL, "http") {
		return metadataURL, nil
	}

	parsed, err := url.Parse(repo)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, metadataURL), nil
}

func fetchPackagistMetadataUrl(repo string) (string, error) {
	cached, ok := packagistCache.Load(repo)

	if !ok {
		metadataURL, err := fetchPackagistMetadataUrlActual(repo)

		if err != nil {
			return "", err
		}

		cached, _ = packagistCache.LoadOrStore(repo, metadataURL)
	}

	return cached.(string), nil
}

func resolvePackagistPackageInstanceURL(pkg string, repo string) (string, error) {
	if repo == "" {
		repo = "https://packagist.org"
	}

	metadataURL, err := fetchPackagistMetadataUrl(repo)

	if err != nil {
		return "", err
	}

	return strings.ReplaceAll(metadataURL, "%package%", pkg), nil
}
