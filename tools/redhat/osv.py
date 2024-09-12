"""Module for parsing converting CSAF to OSV data"""
import re
from dataclasses import field, dataclass, InitVar
from json import JSONEncoder
from typing import Literal

from csaf import Remediation, CSAF

# Update this if verified against a later version
SCHEMA_VERSION = "1.6.5"
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


class OSVEncoder(JSONEncoder):
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
    to match more closely with other ecosystem identifiers in the OSV database
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


@dataclass
class Affected:
    """
    Class to hold affected data for a Vulnerability
    """

    remediation: InitVar[Remediation]
    package: Package = field(init=False)
    ranges: list[Range] = field(init=False)

    def __post_init__(self, remediation: Remediation):
        self.package = Package(remediation.component, remediation.cpe,
                               remediation.purl)
        self.ranges = [Range(remediation.fixed_version)]


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
        for vulnerability in csaf_data.vulnerabilities:
            self.related.append(vulnerability.cve_id)
            for remediation in vulnerability.remediations:
                self.affected.append(Affected(remediation))

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
                references[reference["url"]] = self._get_reference_type_and_add_go_related(
                    reference)
        for vulnerability in csaf.vulnerabilities:
            for reference in vulnerability.references:
                # This captures the CVE specific information
                if reference["category"] == "self":
                    references[reference["url"]] = "REPORT"
                else:
                    references[reference["url"]] = self._get_reference_type_and_add_go_related(
                        reference)
        return [{"type": t, "url": u} for u, t in references.items()]

    def _get_reference_type_and_add_go_related(self, reference: dict[str, str]) -> str:
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

