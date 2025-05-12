#!/usr/bin/env python
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

"""VuXML to OSV converter."""
import getopt
import json
from lxml import etree
import sys

namespace_vuxml = "{http://www.vuxml.org/apps/vuxml-1}"
namespace_xhtml = "{http://www.w3.org/1999/xhtml}"

url_bid = "https://www.securityfocus.com/bid/"
url_certsa = "https://www.cert.org/advisories/"
url_certvu = "https://www.kb.cert.org/vuls/id/"
url_cve = "https://api.osv.dev/v1/vulns/"
url_freebsd_bugzilla = "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id="
url_freebsd_sa = "https://www.freebsd.org/security/advisories/FreeBSD-"


# convert
def convert(filename, vuxml):
    ret = 0

    try:
        with open(filename, "r") as f:
            j = json.load(f)
            vuln = etree.Element("vuln", vid=j["id"])
            vuxml.append(vuln)

            # topic
            topic = etree.Element("topic")
            if "summary" in j:
                topic.text = j["summary"]
            vuln.append(topic)

            # description
            if "details" in j:
                description = etree.Element("description")
                body = etree.Element(namespace_xhtml+"body")
                body.text = j["details"]
                description.append(body)
                vuln.append(description)

            # affects
            if "affected" in j:
                for affected in j["affected"]:
                    affects = None
                    package = None
                    if "package" in affected \
                            and "name" in affected["package"]:
                        affects = etree.Element("affects")
                        package = etree.Element("package")
                        name = etree.Element("name")
                        name.text = affected["package"]["name"]
                        package.append(name)
                        affects.append(package)
                    if affects is not None \
                            and "package" in affected \
                            and "name" in affected["package"] \
                            and "versions" in affected:
                        for version in affected["versions"]:
                            rnge = etree.Element("range")
                            eq = etree.Element("eq")
                            eq.text = version
                            rnge.append(eq)
                            package.append(rnge)
                    if affects is not None \
                            and "package" in affected \
                            and "name" in affected["package"] \
                            and "ranges" in affected:
                        for r in affected["ranges"]:
                            if "type" in r \
                                    and r["type"] == "SEMVER" \
                                    and "events" in r:
                                rnge = etree.Element("range")
                                for event in r["events"]:
                                    for k, v in event.items():
                                        if k == "introduced" and v != "0":
                                            ge = etree.Element("ge")
                                            ge.text = v
                                            rnge.append(ge)
                                        elif k == "fixed":
                                            lt = etree.Element("lt")
                                            lt.text = v
                                            rnge.append(lt)
                                        elif k == "last_affected":
                                            le = etree.Element("le")
                                            le.text = v
                                            rnge.append(le)
                                if len(rnge) >= 1:
                                    package.append(rnge)
                    if affects is not None:
                        vuln.append(affects)

            # references
            references = etree.Element("references")
            if "references" in j:
                for ref in j["references"]:
                    if ref["type"] == "ADVISORY":
                        if ref["url"].startswith(url_bid):
                            r = etree.Element("bid")
                            url = ref["url"][len(url_bid):]
                            if url.endswith("/info"):
                                url = url[:-5]
                            r.text = url
                            references.append(r)
                        elif ref["url"].startswith(url_freebsd_sa):
                            r = etree.Element("freebsdsa")
                            url = ref["url"][len(url_freebsd_sa):]
                            if url.endswith(".asc"):
                                url = url[:-4]
                            r.text = url
                            references.append(r)
                        elif ref["url"].startswith(url_certsa):
                            r = etree.Element("certsa")
                            url = ref["url"][len(url_certsa):]
                            if url.endswith(".html"):
                                url = url[:-5]
                            r.text = url
                            references.append(r)
                        elif ref["url"].startswith(url_certvu):
                            r = etree.Element("certvu")
                            r.text = ref["url"][len(url_certvu):]
                            references.append(r)
                        elif ref["url"].startswith(url_cve):
                            r = etree.Element("cvename")
                            r.text = ref["url"][len(url_cve):]
                            references.append(r)
                        else:
                            r = etree.Element("url")
                            r.text = ref["url"]
                            references.append(r)
                    elif ref["type"] == "REPORT":
                        if ref["url"].startswith(url_freebsd_bugzilla):
                            r = etree.Element("freebsdpr")
                            r.text = ref["url"][len(url_freebsd_bugzilla):]
                            references.append(r)
                        else:
                            r = etree.Element("url")
                            r.text = ref["url"]
                            references.append(r)
                    else:
                        r = etree.Element("url")
                        r.text = ref["url"]
                        references.append(r)
            if len(references):
                vuln.append(references)

            # dates
            dates = etree.Element("dates")
            entry = j["modified"][0:10]
            discovery = entry
            modified = None
            if "published" in j:
                modified = entry
                entry = j["published"][0:10]
            if "database_specific" in j \
                    and "discovery" in j["database_specific"]:
                discovery = j["database_specific"]["discovery"][0:10]
            date = etree.Element("discovery")
            date.text = discovery
            dates.append(date)
            date = etree.Element("entry")
            date.text = entry
            dates.append(date)
            if modified is not None:
                date = etree.Element("modified")
                date.text = modified
                dates.append(date)
            vuln.append(dates)

            # cancelled
            if "withdrawn" in dates:
                cancelled = etree.Element("cancelled")
                vuln.append(cancelled)
    except Exception as e:
        ret = error(e)
    return ret


# error
def error(string):
    print(f"{sys.argv[0]}: error: {string}", file=sys.stderr)
    return 2


# usage
def usage(e=None):
    if e is not None:
        print(e, file=sys.stderr)
    print("Usage: %s [-o output.xml] vuln.json..."
          % sys.argv[0], file=sys.stderr)
    return 1


# warn
def warn(string):
    print(f"{sys.argv[0]}: warning: {string}", file=sys.stderr)


# main
def main():
    ret = 0

    try:
        opts, args = getopt.getopt(sys.argv[1:], "o:")
    except getopt.GetoptError as e:
        return usage(e)
    output = None
    for name, optarg in opts:
        if name == "-o":
            output = optarg
        else:
            return usage("%s: Unsupported option" % name)

    if len(args) < 1:
        return usage()

    vuxml = etree.Element(namespace_vuxml+"vuxml")
    for arg in args:
        if convert(arg, vuxml) != 0:
            ret = 2
            break

    if ret == 0:
        try:
            xml = etree.tostring(vuxml, pretty_print=True)
            if output is not None:
                with open(output, "w") as f:
                    print("""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE vuxml PUBLIC "-//vuxml.org//DTD VuXML 1.1//EN" "http://www.vuxml.org/dtd/vuxml-1/vuxml-11.dtd">"""+xml.decode(), file=f)
            else:
                print("""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE vuxml PUBLIC "-//vuxml.org//DTD VuXML 1.1//EN" "http://www.vuxml.org/dtd/vuxml-1/vuxml-11.dtd">"""+xml.decode())
        except Exception as e:
            ret = error(e)

    return ret


if __name__ == "__main__":
    sys.exit(main())
