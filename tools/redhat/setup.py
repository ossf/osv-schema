""" Convert a CSAF document to OSV format
    i.e. https://access.redhat.com/security/data/csaf/v2/advisories/2024/rhsa-2024_4546.json
"""

from setuptools import setup

REQUIRES = ["jsonschema", "requests", "packageurl-python"]

setup(
    name="redhat_osv",
    version="1.0.0",
    description="Convert Red Hat CSAF documents to OSV format",
    author_email="jshepher@redhat.com",
    url="",
    keywords=["OSV", "CSAF"],
    install_requires=REQUIRES,
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    packages=["redhat_osv"],
    entry_points={"console_scripts": ["convert_redhat=convert_redhat:main"]},
    long_description=
    "The purpose of this tool is to convert from Red Hat CSAF documents to OSV",
)
