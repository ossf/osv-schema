"""Module for parsing converting CSAF to OSV data"""
import re
from dataclasses import field, dataclass, InitVar
import json
from typing import Literal
import requests
from jsonschema import validate
from redhat_osv.csaf import CSAF

# Update this if verified against a later version
SCHEMA_VERSION = "1.7.0"
# This assumes the datetime being formatted is in UTC
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Go package advisory reference prefix
PKG_GO_DEV_VULN = "https://pkg.go.dev/vuln/"
REDHAT_ADVISORY_URL = "https://access.redhat.com/errata/"
# Other common advisory prefixes in Red Hat Advisories
ADVISORY_URL_PREFIXES = (
    PKG_GO_DEV_VULN,
    "https://www.cve.org/CVERecord",
    "https://nvd.nist.gov/vuln/detail/",
    "https://www.kb.cert.org/vuls/id/",
    "https://github.com/advisories/",
)


class OSVEncoder(json.JSONEncoder):
    """Encodes OSV objects into JSON format"""

    def default(self, o):
        if isinstance(o, Event):
            return o.encode_json()
        return o.__dict__


@dataclass
class Event:
    """
    Class to hold event information for a Range. Advisories for Red Hat RPM based products always
    assume all previous versions are affected.
    """

    event_type: Literal["introduced", "fixed"]
    version: str = "0"
    introduced: Literal["introduced"] = "introduced"
    fixed: Literal["fixed"] = "fixed"

    def __post_init__(self):
        if self.event_type not in (self.introduced, self.fixed):
            raise ValueError(
                f"Expected one of {(self.introduced, self.fixed)} for type. "
                f"Got {self.event_type}")

    def encode_json(self):
        """
        Custom JSON encoding for event type which changes attribute name depending on the type of
        event eg. introduced or fixed
        """
        if self.event_type == "introduced":
            return {"introduced": self.version}
        if self.event_type == "fixed":
            return {"fixed": self.version}
        raise ValueError("Unexpected event_type for Event")


@dataclass
class Range:
    """
    Class to hold range information for a Package. Ecosystem here refers to RPM versions as defined
    in https://github.com/rpm-software-management/rpm/blob/master/rpmio/rpmvercmp.c
    """

    fixed: InitVar[str]
    type: str = field(init=False)
    events: list[Event] = field(init=False)

    def __post_init__(self, fixed):
        self.events = [Event("introduced"), Event("fixed", fixed)]
        self.type = "ECOSYSTEM"


@dataclass
class Package:
    """
    Class to hold package data for an Affect.
    Expects an ecosystem string that starts with CPE_PATTERN.
    Replaces the CPE prefix 'redhat' part with 'Red Hat'
    to match more closely with other ecosystem identifiers in the OSV database.
    Also removes version and qualifiers from the CSAF remediation PURL
    """

    cpe_pattern: re.Pattern = field(init=False,
                                    default=re.compile(r"cpe:/[oa]:(redhat)"))
    name: str
    ecosystem: str
    purl: str

    def __post_init__(self):
        if not self.cpe_pattern.match(self.ecosystem):
            raise ValueError(f"Got unsupported ecosystem: {self.ecosystem}")
        self.ecosystem = f"Red Hat{self.cpe_pattern.split(self.ecosystem, maxsplit=1)[-1]}"
        if "@" in self.purl:
            version_index = self.purl.index("@")
            self.purl = self.purl[:version_index]


@dataclass
class Affected:
    """
    Class to hold affected data for a Vulnerability
    """

    package: Package
    ranges: list[Range]


# pylint: disable=too-many-instance-attributes
# This class is directly encoded into OSV json so has one instance attribute for each OSV property
class OSV:
    """
    Class to convert CSAF data to OSV
    """

    def __init__(self, csaf_data: CSAF, modified: str, published: str = ""):
        self.schema_version = SCHEMA_VERSION

        self.id = ""

        # This attribute is declared after id to make the resulting JSON human-readable. It can only
        # be populated after reading the csaf vulnerabilities and references sections.
        self.related: list[str] = []
        self.upstream: list[str] = []

        if published:
            self.published = published
        else:
            self.published = modified
        self.modified = modified

        self.summary = csaf_data.title

        # Set severity to the CVSS of the highest CVSSv3 base score
        vulnerability_scores: dict[str, str] = {}
        for vulnerability in csaf_data.vulnerabilities:
            if not vulnerability.cvss_v3_vector or not vulnerability.cvss_v3_base_score:
                continue
            vulnerability_scores[
                vulnerability.cvss_v3_base_score] = vulnerability.cvss_v3_vector
        if vulnerability_scores:
            highest_score = sorted(vulnerability_scores.keys())[-1]
            self.severity = [{
                "type": "CVSS_V3",
                "score": vulnerability_scores[highest_score]
            }]

        self.affected: list[Affected] = []

        # Deduplicate arch specific remediations
        unique_packages: dict[str:tuple[str:str]] = {}

        for vulnerability in csaf_data.vulnerabilities:
            self.upstream.append(vulnerability.cve_id)
            for remediation in vulnerability.remediations:
                # Safety check for when we start processing non-rpm content
                if not remediation.purl.startswith("pkg:rpm/"):
                    package = Package(remediation.component, remediation.cpe,
                                      remediation.purl)
                    ranges = [Range(remediation.fixed_version)]
                    self.affected.append(Affected(package, ranges))
                else:
                    # Architecture suffixes are now removed in the Remediation class,
                    # so we can use the fixed_version directly
                    # CPE's are URI percent encoded and '&' is a reserved character so it should
                    # never appear in a CPE without being percent encoded.
                    unique_packages[remediation.cpe + "&" +
                                    remediation.component] = (
                                        remediation.fixed_version,
                                        remediation.purl,
                                    )

        # Add all the RPM packages without arch suffixes
        for package_key, version_purl in unique_packages.items():
            package_key_parts = package_key.split("&", 1)
            cpe = package_key_parts[0]
            component = package_key_parts[1]
            package = Package(component, cpe, version_purl[1])
            ranges = [Range(version_purl[0])]
            self.affected.append(Affected(package, ranges))

        self.references = self._convert_references(csaf_data)

    def _convert_references(self, csaf) -> list[dict[str, str]]:
        """
        CSAF has references for an advisory and each vulnerability has references as well.
        Collect this into a single references list for OSV and deduplicate them.
        """
        references: dict[str, str] = {}
        for reference in csaf.references:
            # This will capture both the Advisory URL and the CSAF document for the advisory
            if reference["category"] == "self":
                if reference["summary"].startswith(REDHAT_ADVISORY_URL):
                    self.id = reference["summary"].removeprefix(
                        REDHAT_ADVISORY_URL)
                references[reference["url"]] = "ADVISORY"
            else:
                references[reference[
                    "url"]] = self._get_reference_type_and_add_go_related(
                        reference)
        for vulnerability in csaf.vulnerabilities:
            for reference in vulnerability.references:
                # This captures the CVE specific information
                if reference["category"] == "self":
                    references[reference["url"]] = "REPORT"
                else:
                    references[reference[
                        "url"]] = self._get_reference_type_and_add_go_related(
                            reference)
        return [{"type": t, "url": u} for u, t in references.items()]

    def _get_reference_type_and_add_go_related(
            self, reference: dict[str, str]) -> str:
        """
        Convert references from CSAF into typed referenced in OSV
        Also make sure to add a related entry for any GO advisory references found
        """
        reference_url = reference["url"]
        if reference_url.startswith(ADVISORY_URL_PREFIXES):
            if reference_url.startswith(PKG_GO_DEV_VULN):
                self.related.append(reference_url.removeprefix(PKG_GO_DEV_VULN))
            return "ADVISORY"
        if reference_url.startswith("https://bugzilla.redhat.com/show_bug.cgi"):
            return "REPORT"
        return "ARTICLE"


class RedHatConverter:
    """
    Class which converts and validates a CSAF string to an OSV string
    """
    SCHEMA = (
        f"https://raw.githubusercontent.com/ossf/osv-schema/v{SCHEMA_VERSION}"
        "/validation/schema.json")
    REQUEST_TIMEOUT = 60

    def __init__(self):
        schema_content = requests.get(self.SCHEMA, timeout=self.REQUEST_TIMEOUT)
        self.osv_schema = schema_content.json()

    def convert(self,
                csaf_content: str,
                modified: str,
                published: str = "") -> tuple[str, str]:
        """
        Converts csaf_content json string into an OSV json string
        returns an OSV ID and the json string content of the OSV file
        the json string content will be empty if no content is applicable
        throws a validation error in the schema doesn't validate correctly.
        The modified value for osv is passed in so it matches what's in all.json
        Raises ValueError is CSAF file can't be parsed
        """
        csaf = CSAF(csaf_content)
        osv = OSV(csaf, modified, published)

        # We convert from an OSV object to a JSON string here in order to use the OSVEncoder
        # Once we OSV json string data we validate it using the OSV schema
        osv_content = json.dumps(osv, cls=OSVEncoder, indent=2)
        osv_data = json.loads(osv_content)
        validate(osv_data, schema=self.osv_schema)

        return osv.id, osv_content
