"""Module for parsing CSAF v2 advisories"""
import json
from dataclasses import dataclass, InitVar, field
from typing import Any, Iterable

class RemediationParseError(ValueError):
    pass

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

        # NEVRA stands for Name Epoch Version Release and Architecture
        # We split the name from the rest of the 'version' data (EVRA). We store name as component.
        split_component_version = self.product_version.rsplit("-", maxsplit=2)
        if len(split_component_version) < 3:
            raise RemediationParseError(
                f"Could not convert component into NEVRA: {self.product_version}"
            )
        # RHEL Modules have 4 colons in the name part of the NEVRA. If we detect a modular RPM
        # product ID, discard the module part of the name and look for that in the purl dict.
        # Ideally we would keep the module information and use it when scanning a RHEL system,
        # however this is not done today by Clair:  https://github.com/quay/claircore/pull/901/files
        if split_component_version[0].count(":") == 4:
            self.component = split_component_version[0].rsplit(":")[-1]
        else:
            self.component = split_component_version[0]
        self.fixed_version = "-".join(
            (split_component_version[1], split_component_version[2]))

        try:
            nevra = f"{self.component}-{self.fixed_version}"
            self.purl = purls[nevra]
            self.cpe = cpes[self.product]
        except KeyError:
            # pylint: disable=raise-missing-from
            # Raising this as a ValueError instead of as a KeyError allows us to wrap
            # the entire call to init() in try/catch block with a single exception type
            raise ValueError(
                f"Did not find {csaf_product_id} in product branches")

        # There are many pkg:oci/ remediations in Red Hat data. However there are no strict
        # rules enforced on versioning Red Hat containers, therefore we cant compare container
        # versions to each other with 100% accuracy at this time.
        if not self.purl.startswith("pkg:rpm/"):
            raise ValueError(
                "Non RPM remediations are not supported in OSV at this time")


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
        if self.csaf != {"type": "csaf_vex", "csaf_version": "2.0"}:
            raise ValueError(
                f"Can only handle csaf_vex 2.0 documents. Got: {self.csaf}")

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
