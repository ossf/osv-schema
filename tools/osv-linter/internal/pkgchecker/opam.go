package pkgchecker

import (
	"fmt"
	"net/url"
)

// Packages and versions removed from opam-repository are moved to
// opam-repository-archive, so both repositories need to be consulted.
const (
	opamRepositoryURL        = "https://raw.githubusercontent.com/ocaml/opam-repository/master/packages"
	opamRepositoryArchiveURL = "https://raw.githubusercontent.com/ocaml/opam-repository-archive/main/packages"
	opamArchiveContentsURL   = "https://api.github.com/repos/ocaml/opam-repository-archive/contents/packages"
)

// opamVersionExists checks if a version of a package exists in opam-repository
// or opam-repository-archive.
//
// Each version of an opam package is a "packages/<pkg>/<pkg>.<version>/opam"
// file, so versions are matched exactly rather than semantically.
func opamVersionExists(pkg string, version string) bool {
	pkg = url.PathEscape(pkg)
	version = url.PathEscape(version)

	for _, repo := range []string{opamRepositoryURL, opamRepositoryArchiveURL} {
		if checkPackageExists(fmt.Sprintf("%s/%s/%s.%s/opam", repo, pkg, pkg, version)) {
			return true
		}
	}

	return false
}
