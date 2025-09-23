"""Module for parsing CSAF v2 advisories"""
import json
from dataclasses import dataclass, InitVar, field
from typing import Any, Iterable
from packageurl import PackageURL


class RemediationParseError(ValueError):
    """Exception raised when parsing remediation data fails."""


def parse_purl_info(purl: str) -> tuple[str, str]:
    """
    Parse a PURL to extract component name and version.

    Args:
        purl: A PURL string like "pkg:rpm/redhat/package@version?arch=x86_64"

    Returns:
        tuple: (component_name, version) where version includes epoch if present
        Uses epoch=0 as default if no epoch is specified

    Raises:
        ValueError: If the PURL format is invalid or not an RPM PURL
    """
    try:
        parsed_purl = PackageURL.from_string(purl)
    except Exception as e:
        raise ValueError(f"Invalid PURL format: {purl}") from e

    # Check that this is an RPM PURL
    if parsed_purl.type != "rpm":
        raise ValueError(f"Only RPM PURLs are supported, got: {purl}")

    component = parsed_purl.name
    version = parsed_purl.version

    if not component:
        raise ValueError(f"PURL missing component name: {purl}")
    if not version:
        raise ValueError(f"PURL missing version: {purl}")

    # Check for epoch qualifier and include it in the version
    epoch = parsed_purl.qualifiers.get('epoch', '0')
    if ':' not in version:
        # Add epoch prefix if not already present in version
        version = f"{epoch}:{version}"

    return component, version


@dataclass
class Remediation:
    """
    class to handle remediation advice in CSAF data
    """

    csaf_product_id: InitVar[str]
    cpes: InitVar[dict[str, str]]
    purls: InitVar[dict[str, str]]
    product: str = field(init=False)
    product_version: str = field(init=False)
    component: str = field(init=False)
    fixed_version: str = field(init=False)
    purl: str = field(init=False)
    cpe: str = field(init=False)

    def __post_init__(self, csaf_product_id: str, cpes: dict[str, str],
                      purls: dict[str, str]):
        if ":" not in csaf_product_id:
            raise ValueError(
                f"Did not find ':' in product_id: {csaf_product_id}")
        (self.product, self.product_version) = csaf_product_id.split(":",
                                                                     maxsplit=1)

        # Find the PURL for this product_version
        # The purls dict maps different formats depending on the package type
        purl_key = None

        # Try the full product_version first (works for regular packages and some modular RPMs)
        if self.product_version in purls:
            purl_key = self.product_version
        else:
            # For modular RPMs with module prefix, extract just the NEVRA part
            # Pattern: module:stream:build:context:NEVRA
            # The NEVRA part starts after the 4th colon
            if self.product_version.count(":") >= 4:
                nevra_candidate = self.product_version.split(':', maxsplit=4)[-1]
                if nevra_candidate in purls:
                    purl_key = nevra_candidate

        if purl_key is None:
            # This happens for module-only product IDs that don't represent specific packages
            # These should be skipped as they don't have corresponding RPM packages
            raise RemediationParseError(
                f"No PURL found for product ID: {csaf_product_id}")
        try:
            self.purl = purls[purl_key]
            self.cpe = cpes[self.product]
        except KeyError as e:
            # pylint: disable=raise-missing-from
            raise RemediationParseError(
                f"Did not find {csaf_product_id} in product branches: {e}")

        # There are many pkg:oci/ remediations in Red Hat data. However there are no strict
        # rules enforced on versioning Red Hat containers, therefore we cant compare container
        # versions to each other with 100% accuracy at this time.
        if not self.purl.startswith("pkg:rpm/"):
            raise RemediationParseError(
                "Non RPM remediations are not supported in OSV at this time")

        # Extract component name and version from the PURL instead of parsing product_id
        # This is much more reliable than heuristic parsing
        try:
            self.component, self.fixed_version = parse_purl_info(self.purl)
        except ValueError as e:
            raise RemediationParseError(
                f"Failed to parse PURL {self.purl}: {e}") from e


@dataclass
class Vulnerability:
    """
    class to handle vulnerability information
    """

    csaf_vuln: InitVar[dict[str, Any]]
    cpes: InitVar[dict[str, str]]
    purls: InitVar[dict[str, str]]
    cve_id: str = field(init=False)
    cvss_v3_vector: str = field(init=False)
    cvss_v3_base_score: str = field(init=False, default=None)
    references: list[dict[str, str]] = field(init=False)
    remediations: list[Remediation] = field(init=False)

    def __post_init__(self, csaf_vuln: dict[str, Any], cpes: dict[str, str],
                      purls: dict[str, str]):
        self.cve_id = csaf_vuln["cve"]
        if not hasattr(csaf_vuln, "scores"):
            self.cvss_v3_vector = ""
            self.cvss_v3_base_score = ""
        for score in csaf_vuln.get("scores", []):
            if "cvss_v3" in score:
                self.cvss_v3_vector = score["cvss_v3"]["vectorString"]
                self.cvss_v3_base_score = score["cvss_v3"]["baseScore"]
            else:
                self.cvss_v3_base_score = ""
                self.cvss_v3_vector = ""
        self.references = csaf_vuln["references"]
        self.remediations = []
        for product_id in csaf_vuln["product_status"]["fixed"]:
            try:
                self.remediations.append(Remediation(product_id, cpes, purls))
            except RemediationParseError:
                continue
        if not self.remediations:
            raise ValueError(f"Did not find any remediations for {self.cve_id}")


def gen_dict_extract(key, var: Iterable):
    """
    Given a key value and dictionary or list, traverses that dictionary or list returning the value
    of the given key.
    From https://stackoverflow.com/questions/9807634/
        find-all-occurrences-of-a-key-in-nested-dictionaries-and-lists
    """
    if hasattr(var, "items"):
        for k, v in var.items():
            if k == key:
                yield v
            if isinstance(v, dict):
                yield from gen_dict_extract(key, v)
            elif isinstance(v, list):
                for d in v:
                    yield from gen_dict_extract(key, d)


def build_product_maps(
        product_tree_branches: dict) -> tuple[dict[str, str], dict[str, str]]:
    """
    Given a CSAF product tree branch dictionary returns a tuple of CPEs by product ID and PURLs by
    product ID.
    """
    cpe_map = {}
    purl_map = {}
    products = gen_dict_extract("product", product_tree_branches)
    for product in products:
        product_id = product["product_id"]
        if "product_identification_helper" in product:
            helper = product["product_identification_helper"]
            if "cpe" in helper:
                cpe_map[product_id] = helper["cpe"]
            elif "purl" in helper:
                purl_map[product_id] = helper["purl"]
    return cpe_map, purl_map


class CSAF:
    """
    class to handle CSAF data read from a local file path
    """

    def __init__(self, csaf_content: str):
        csaf_data = json.loads(csaf_content)

        if not csaf_data:
            raise ValueError("Unable to load CSAF JSON data.")

        self.doc = csaf_data["document"]

        self.csaf = {
            "type": self.doc["category"],
            "csaf_version": self.doc["csaf_version"]
        }

        # Only support csaf_vex 2.0
        if self.csaf != {
                "type": "csaf_security_advisory",
                "csaf_version": "2.0"
        }:
            raise ValueError(
                f"Can only handle csaf_security_advisory 2.0 documents. Got: {self.csaf}"
            )

        self.cpes, self.purls = build_product_maps(csaf_data["product_tree"])

        self.vulnerabilities = [
            Vulnerability(v, self.cpes, self.purls)
            for v in (csaf_data["vulnerabilities"])
        ]

    @property
    def title(self):
        """
        Document Title
        """
        return self.doc["title"]

    @property
    def references(self):
        """
        Document References
        """
        return self.doc["references"]
