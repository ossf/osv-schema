package osvschema

const SchemaVersion = "1.6.8"

type Ecosystem string

const (
	EcosystemAlmaLinux     Ecosystem = "AlmaLinux"
	EcosystemAlpine        Ecosystem = "Alpine"
	EcosystemAndroid       Ecosystem = "Android"
	EcosystemBioconductor  Ecosystem = "Bioconductor"
	EcosystemBitnami       Ecosystem = "Bitnami"
	EcosystemChainguard    Ecosystem = "Chainguard"
	EcosystemConanCenter   Ecosystem = "ConanCenter"
	EcosystemCRAN          Ecosystem = "CRAN"
	EcosystemCratesIO      Ecosystem = "crates.io"
	EcosystemDebian        Ecosystem = "Debian"
	EcosystemGHC           Ecosystem = "GHC"
	EcosystemGitHubActions Ecosystem = "GitHub Actions"
	EcosystemGo            Ecosystem = "Go"
	EcosystemHackage       Ecosystem = "Hackage"
	EcosystemHex           Ecosystem = "Hex"
	EcosystemKubernetes    Ecosystem = "Kubernetes"
	EcosystemLinux         Ecosystem = "Linux"
	EcosystemMageia        Ecosystem = "Mageia"
	EcosystemMaven         Ecosystem = "Maven"
	EcosystemNPM           Ecosystem = "npm"
	EcosystemNuGet         Ecosystem = "NuGet"
	EcosystemOpenSUSE      Ecosystem = "openSUSE"
	EcosystemOSSFuzz       Ecosystem = "OSS-Fuzz"
	EcosystemPackagist     Ecosystem = "Packagist"
	EcosystemPhotonOS      Ecosystem = "Photon OS"
	EcosystemPub           Ecosystem = "Pub"
	EcosystemPyPI          Ecosystem = "PyPI"
	EcosystemRedHat        Ecosystem = "Red Hat"
	EcosystemRockyLinux    Ecosystem = "Rocky Linux"
	EcosystemRubyGems      Ecosystem = "RubyGems"
	EcosystemSUSE          Ecosystem = "SUSE"
	EcosystemSwiftURL      Ecosystem = "SwiftURL"
	EcosystemUbuntu        Ecosystem = "Ubuntu"
	EcosystemWolfi         Ecosystem = "Wolfi"
)

type SeverityType string

const (
	SeverityCVSSV2 SeverityType = "CVSS_V2"
	SeverityCVSSV3 SeverityType = "CVSS_V3"
	SeverityCVSSV4 SeverityType = "CVSS_V4"
)

type RangeType string

const (
	RangeSemVer    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type ReferenceType string

const (
	ReferenceAdvisory   ReferenceType = "ADVISORY"
	ReferenceArticle    ReferenceType = "ARTICLE"
	ReferenceDetection  ReferenceType = "DETECTION"
	ReferenceDiscussion ReferenceType = "DISCUSSION"
	ReferenceReport     ReferenceType = "REPORT"
	ReferenceFix        ReferenceType = "FIX"
	ReferenceIntroduced ReferenceType = "INTRODUCED"
	ReferenceGit        ReferenceType = "GIT"
	ReferencePackage    ReferenceType = "PACKAGE"
	ReferenceEvidence   ReferenceType = "EVIDENCE"
	ReferenceWeb        ReferenceType = "WEB"
)

type CreditType string

const (
	CreditFinder               CreditType = "FINDER"
	CreditReporter             CreditType = "REPORTER"
	CreditAnalyst              CreditType = "ANALYST"
	CreditCoordinator          CreditType = "COORDINATOR"
	CreditRemediationDeveloper CreditType = "REMEDIATION_DEVELOPER" //nolint:gosec
	CreditRemediationReviewer  CreditType = "REMEDIATION_REVIEWER"  //nolint:gosec
	CreditRemediationVerifier  CreditType = "REMEDIATION_VERIFIER"  //nolint:gosec
	CreditTool                 CreditType = "TOOL"
	CreditSponsor              CreditType = "SPONSOR"
	CreditOther                CreditType = "OTHER"
)
