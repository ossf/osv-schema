package constants

type Ecosystem string

const (
	EcosystemAlmaLinux     Ecosystem = "AlmaLinux"
	EcosystemAlpine        Ecosystem = "Alpine"
	EcosystemAndroid       Ecosystem = "Android"
	EcosystemBioconductor  Ecosystem = "Bioconductor"
	EcosystemBitnami       Ecosystem = "Bitnami"
	EcosystemConanCenter   Ecosystem = "ConanCenter"
	EcosystemCRAN          Ecosystem = "CRAN"
	EcosystemCratesIO      Ecosystem = "crates.io"
	EcosystemDebian        Ecosystem = "Debian"
	EcosystemGitHubActions Ecosystem = "GitHub Actions"
	EcosystemGo            Ecosystem = "Go"
	EcosystemHex           Ecosystem = "Hex"
	EcosystemLinux         Ecosystem = "Linux"
	EcosystemMaven         Ecosystem = "Maven"
	EcosystemNPM           Ecosystem = "npm"
	EcosystemNuGet         Ecosystem = "NuGet"
	EcosystemOSSFuzz       Ecosystem = "OSS-Fuzz"
	EcosystemPackagist     Ecosystem = "Packagist"
	EcosystemPhotonOS      Ecosystem = "Photon OS"
	EcosystemPub           Ecosystem = "Pub"
	EcosystemPyPI          Ecosystem = "PyPI"
	EcosystemRedHat        Ecosystem = "Red Hat"
	EcosystemRockyLinux    Ecosystem = "Rocky Linux"
	EcosystemRubyGems      Ecosystem = "RubyGems"
	EcosystemSwiftURL      Ecosystem = "SwiftURL"
	EcosystemUbuntu        Ecosystem = "Ubuntu"
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
