#!/usr/bin/env python
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 1994-2024 The FreeBSD Project.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Copyright (c) 2024 The FreeBSD Foundation
#
# Portions of this software were developed by Pierre Pronchery
# <pierre@defora.net> at Defora Networks GmbH under sponsorship
# from the FreeBSD Foundation.
#
# Portions of this software were developed by Tuukka Pasanen
# <tuukka.pasanen@ilmi.fi> under sponsorship from the FreeBSD Foundation.

"""VuXML to OSV converter."""
import datetime
import getopt
import json
from lxml import etree, html
import os
from pathlib import Path
import re
import sys
import pypandoc

re_date = re.compile(r"^(19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}$")
re_invalid_package_name = re.compile("[@!#$%^&*()<>?/\\|}{~:]")

# warn if description has more than X characters
DESCRIPTION_LENGTH = 5000

namespace = "{http://www.vuxml.org/apps/vuxml-1}"

url_advisories = [
    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
    "https://nvd.nist.gov/vuln/detail/",
    "https://github.com/advisories/",
    "https://www.debian.org/security/",
]
url_bid = "https://www.securityfocus.com/bid/%s/info"
url_certsa = "https://www.cert.org/advisories/%s.html"
url_certvu = "https://www.kb.cert.org/vuls/id/%s"
url_cve = "https://cveawg.mitre.org/api/cve/%s"
url_freebsd_bugzilla = "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=%s"
url_freebsd_sa = "https://www.freebsd.org/security/advisories/FreeBSD-%s.asc"
url_reports = [
    "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=",
    "http://bugzilla.mozilla.org/show_bug.cgi?id=",
    "https://bugzilla.mozilla.org/show_bug.cgi?id=",
    "https://bugzilla.redhat.com/show_bug.cgi?id=",
    "https://bugzilla.suse.com/show_bug.cgi?id=",
]


class PrefixResolver(etree.Resolver):
    def __init__(self, prefix):
        self.prefix = prefix
        self.result_xml = (
            """\
              <xsl:stylesheet
                     xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                <test xmlns="testNS">%s-TEST</test>
              </xsl:stylesheet>
              """
            % prefix
        )

    def resolve(self, url, pubid, context):
        if url.startswith(self.prefix):
            print("Resolved url %s as prefix %s" % (url, self.prefix))
            return self.resolve_string(self.result_xml, context)


# dateof
def dateof(string):
    return datetime.datetime.strptime(string, "%Y-%m-%d")


def formatdate(date):
    # RFC 3339 ending with Z
    return date.strftime("%Y-%m-%dT%H:%M:%SZ")


# error
def error(string):
    print(f"{sys.argv[0]}: error: {string}", file=sys.stderr)
    return 2


# usage
def usage(e=None):
    if e is not None:
        print(e, file=sys.stderr)
    print(
        "Usage: %s [-e ecosystem][-o output_directory] vuln.xml" % sys.argv[0],
        file=sys.stderr,
    )
    return 1


# warn
def warn(string):
    print(f"{sys.argv[0]}: warning: {string}", file=sys.stderr)


# main
def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "e:o:n")
    except getopt.GetoptError as e:
        return usage(e)
    ecosystem = "FreeBSD:ports"
    output = None
    only_new = False
    is_kernel = False

    output_id = {}

    for name, optarg in opts:
        if name == "-e":
            ecosystem = optarg
        elif name == "-o":
            output = optarg
        elif name == "-n":
            only_new = True
        else:
            return usage("%s: Unsupported option" % name)

    if len(args) != 1:
        return usage()

    parser = etree.XMLParser(dtd_validation=False)
    tree = etree.parse(args[0], parser)
    root = tree.getroot()

    ret = 0

    entries = []
    for vuln in reversed(root):
        is_kernel = False

        if vuln.find(namespace + "cancelled") is not None:
            continue

        # id
        vid = vuln.get("vid")
        entry = {"schema_version": "1.7.0"}
        dates = {"modified": None, "published": None}
        # database_specific
        database_specific = {"vid": vid}

        # modified
        try:
            d = vuln.find(namespace + "dates").find(namespace + "entry").text
            if not re_date.match(d):
                ret = error("entry date not in YYYY-MM-DD format: {0}".format(d))
                raise
            else:
                dates_entry = dateof(d)
        except Exception as e:
            dates_entry = None
        try:
            d = vuln.find(namespace + "dates").find(namespace + "modified").text
            if not re_date.match(d):
                ret = error("modified date not in YYYY-MM-DD format: {0}".format(d))
                raise
            else:
                dates_modified = dateof(d)
        except Exception as e:
            dates_modified = None
        if dates_modified is not None:
            entry["modified"] = formatdate(dates_modified)
            dates["modified"] = dates_modified
        elif dates_entry is not None:
            entry["modified"] = formatdate(dates_entry)
            dates["modified"] = dates_entry
        if dates_entry is not None:
            entry["published"] = formatdate(dates_entry)
            dates["published"] = dates_entry

        # summary
        try:
            summary = vuln.find(namespace + "topic").text
        except Exception as e:
            ret = error(f"{vid} has no topic")
            summary = None
        if summary is not None:
            entry["summary"] = summary

        # details
        details = vuln.find(namespace + "description")
        if details is None:
            ret = error(f"{vid} has no description")
        else:
            try:
                details_html = etree.tostring(
                    details, encoding="unicode", method="html"
                )

                details = pypandoc.convert_text(details_html, "md", format="html")

                tree = html.fromstring(details_html)

                for elem in tree.iterchildren():
                    if elem.tag == "blockquote":
                        cite = elem.get("cite")
                        if cite:
                            if "cite" not in database_specific:
                                database_specific["cite"] = []
                            database_specific["cite"].append(cite)

                if len(details) > DESCRIPTION_LENGTH:
                    warn("%s: description truncated (> %s)" % (vid, DESCRIPTION_LENGTH))
                    details = details[0:DESCRIPTION_LENGTH]
            except Exception as e:
                ret = error(
                    "%s could not parse description: %s: %s"
                    % (vid, type(e).__name__, e)
                )
                details = None
        if details is not None:
            entry["details"] = details

        # references
        references = []

        if "cite" in database_specific:
            for cite in database_specific["cite"]:
                references.append({"type": "REPORT", "url": cite})

        refs = vuln.find(namespace + "references")
        for ref in refs:
            is_appendable = False
            if ref.text is None or len(ref.text) == 0 or type(ref) is etree._Comment:
                continue

            cur_tag = ref.tag.removeprefix(namespace)

            if ref.tag == namespace + "bid":
                reference = {"type": "ADVISORY", "url": url_bid % ref.text}
                is_appendable = True
            elif ref.tag == namespace + "certsa":
                reference = {"type": "ADVISORY", "url": url_certsa % ref.text}
                is_appendable = True
            elif ref.tag == namespace + "certvu":
                reference = {"type": "ADVISORY", "url": url_certvu % ref.text}
                is_appendable = True
            elif ref.tag == namespace + "cvename":
                reference = {"type": "ADVISORY", "url": url_cve % ref.text}
                is_appendable = True
            elif ref.tag == namespace + "freebsdpr" and len(ref.text.split("/")) == 2:
                id = ref.text.split("/")[1]
                reference = {"type": "REPORT", "url": url_freebsd_bugzilla % id}
                is_appendable = True
            elif ref.tag == namespace + "freebsdsa":
                reference = {"type": "ADVISORY", "url": url_freebsd_sa % ref.text}
                is_appendable = True
            elif ref.tag == namespace + "mlist":
                reference = {"type": "DISCUSSION", "url": ref.text}
            elif ref.tag == namespace + "url":
                if (
                    "cite" in database_specific
                    and ref.text in database_specific["cite"]
                ):
                    continue

                # As there can be also URL for this then do not add
                # double entries
                if (
                    "references" in database_specific
                    and "cvename" in database_specific["references"]
                ):
                    is_cvename = False
                    for cvename in database_specific["references"]["cvename"]:
                        if cvename in ref.text and "mitre.org" in ref.text:
                            is_cvename = True
                            break
                    if is_cvename:
                        continue

                reference = {"type": "WEB", "url": ref.text}
                for prefix in url_advisories:
                    if str(ref.text).startswith(prefix):
                        reference["type"] = "ADVISORY"
                        break
                if reference["type"] == "WEB":
                    for prefix in url_reports:
                        if str(ref.text).startswith(prefix):
                            reference["type"] = "REPORT"
                            break
            else:
                continue

            if is_appendable:
                if "references" not in database_specific:
                    database_specific["references"] = {}
                if cur_tag not in database_specific["references"]:
                    database_specific["references"][cur_tag] = []
                database_specific["references"][cur_tag].append(ref.text)

            references.append(reference)
        if len(references) > 0:
            entry["references"] = references

        # affected
        affected = []
        affects = vuln.find(namespace + "affects")
        for package in affects.findall(namespace + "package"):

            # affected: package
            for name in package.findall(namespace + "name"):
                a = {}
                if re_invalid_package_name.search(name.text) is not None:
                    ret = error("%s package with invalid name: %s" % (vid, name.text))
                    continue
                cur_ecosystem = ecosystem
                if name.text == "FreeBSD-kernel":
                    cur_ecosystem = "FreeBSD:kernel"
                    is_kernel = True

                p = {"ecosystem": cur_ecosystem, "name": name.text}
                a["package"] = p

                key_order = ["introduced", "fixed", "last_affected", "limit"]
                # affected: ranges
                try:
                    ranges = []
                    versions = []
                    for e in package.findall(namespace + "range"):
                        events = []
                        semver = {"type": "ECOSYSTEM"}

                        # affected: ranges
                        event = {}
                        ge = e.find(namespace + "ge")
                        if ge is not None and len(ge.text) > 0:
                            if ge.text != "*":
                                event["introduced"] = ge.text
                            else:
                                event["introduced"] = "0"
                        gt = e.find(namespace + "gt")
                        if gt is not None and len(gt.text) > 0:
                            if gt.text != "*":
                                # Not correct. Should be fixed
                                event["introduced"] = gt.text + ",1"
                            else:
                                event["introduced"] = "0"
                        le = e.find(namespace + "le")
                        if le is not None and len(le.text) > 0:
                            event["fixed"] = le.text
                            if le.text != "*":
                                event["fixed"] = le.text
                            else:
                                event["fixed"] = "0"
                        lt = e.find(namespace + "lt")
                        if lt is not None and len(lt.text) > 0:
                            if lt.text != "*":
                                event["fixed"] = lt.text
                            else:
                                event["fixed"] = "0"
                        if "fixed" in event or "introduced" in event:
                            if "introduced" not in event:
                                event["introduced"] = "0"

                        # Always introduced and fixed after that
                        # just for the sanity
                        for order_key in key_order:
                            if order_key in event:
                                events.append({order_key: event[order_key]})

                        eq = e.find(namespace + "eq")
                        if eq is not None and len(eq.text) > 0 and eq.text != "*":
                            events.append({"introduced": eq.text})
                            events.append({"fixed": eq.text})

                        if len(events) > 0:
                            semver["events"] = events
                            ranges.append(semver)
                except Exception as e:
                    warn(e, file=sys.stderr)
                    ranges = []
                if len(ranges) > 0:
                    a["ranges"] = ranges
                if len(versions) > 0:
                    a["versions"] = versions

                if len(a) > 0:
                    affected.append(a)
            if len(affected) > 0:
                entry["affected"] = affected

        try:
            d = vuln.find(namespace + "dates").find(namespace + "discovery").text
            if not re_date.match(d):
                ret = error("discovery date not in YYYY-MM-DD format: {0}".format(d))
                raise
            else:
                dates_discovery = dateof(d)
        except Exception as e:
            dates_discovery = None
        if dates_discovery is not None:
            database_specific["discovery"] = formatdate(dates_discovery)
        if len(database_specific) > 0:
            entry["database_specific"] = database_specific

        if output is not None:
            try:
                date_str = None
                date_obj = None
                year_str = None
                if dates["published"] is not None:
                    date_str = dates["published"].strftime("%Y-%m-%d")
                    year_str = dates["published"].strftime("%Y")
                    date_obj = dates["published"]
                elif dates["modified"] is not None:
                    date_str = dates["modified"].strftime("%Y-%m-%d")
                    year_str = dates["published"].strftime("%Y")
                    date_obj = dates["modified"]

                if date_str is None:
                    raise Exception(f"There is no date available")

                file_base_name = "FreeBSD"

                # File name can be with date of release:
                # FreeBSD-20250101.json
                # or just running number
                # FreeBSD-2025-0001.json
                # When using running id then there won't be yearly
                # subdirs
                if year_str not in output_id:
                    output_id[year_str] = 0
                output_id[year_str] += 1
                output_file = f"{file_base_name}-{year_str}-{output_id[year_str]:04}"

                # Make sure that is same as filename
                entry["id"] = output_file

                output_year_path = output + "/" + year_str

                if os.path.isdir(output_year_path) is False:
                    os.mkdir(output_year_path)
                    year_date = datetime.date(int(year_str), 1, 1)
                    year_time_ts = int(year_date.strftime("%s"))
                    os.utime(output_year_path, (year_time_ts, year_time_ts))

                affected_array = entry["affected"]

                # If output is not flat then output path will be like
                # 2025/somepackage/ with flat only 2025/
                # output_path_with_name = output_year_path + "/" + output_name
                output_path_with_name = output_year_path

                if os.path.isdir(output_path_with_name) is False:
                    os.mkdir(output_path_with_name)

                output_with_suffix = output_file + ".json"

                output_full_path = output_path_with_name + "/" + output_with_suffix

                if os.path.isfile(output_full_path) is True:
                    if only_new:
                        continue
                    print("OSVf file already created: " + output_full_path)

                # This one have to open file with binary to write
                # as bytes
                with open(output_full_path, "w") as f:
                    print(json.dumps(entry, indent=4, sort_keys=True), file=f)

                if os.path.isfile(output_full_path):
                    timeint = int(date_obj.strftime("%s"))
                    os.utime(output_full_path, (timeint, timeint))

            except Exception as e:
                print("There was an error: ", e)
                ret = error(e)
        else:
            entries.append(entry)

    if output is None:
        if len(entries) == 1:
            print(json.dumps(entries[0], indent=4))
        else:
            print(json.dumps(entries, indent=4))

    return ret


if __name__ == "__main__":
    sys.exit(main())
