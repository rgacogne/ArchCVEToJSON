#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from datetime import date
import json
import os
import re
import sys

def getUpstreamVersion(version):
    return version.rsplit('-', 1)[0]

def printSubject(asa, issue, package, vulnType):
    print('[%s] %s: %s' % (asa, package, vulnType))

def printBody(asa, issue, package, vulnType):
    header = "Arch Linux Security Advisory %s" % (asa)
    cveStr = ''
    for cve in issue['cves']:
        if len(cveStr) > 0:
            cveStr = cveStr + ' ' + cve
        else:
            cveStr = cve

    oldUpstreamVersion = getUpstreamVersion(issue['vulnerableVersion'])
    upstreamFixedVersion = getUpstreamVersion(issue['fixedVersion'])
    if upstreamFixedVersion == oldUpstreamVersion:
        upstreamFixedVersion = None

    print(header)
    print('='*len(header))
    print()
    print('Severity: Low, Medium, High, Critical')
    print('Date    : %s' % (date.today().strftime("%Y-%m-%d")))
    print('CVE-ID  : %s' % (cveStr))
    print('Package : %s' % (package))
    print('Type    : %s' % (vulnType))
    print('Remote  : <Yes/No>')
    print('Link    : https://wiki.archlinux.org/index.php/CVE')
    print()
    print('Summary')
    print('=======')
    print()
    print('The package %s before version %s is vulnerable to %s.' % (package, issue['fixedVersion'], vulnType))
    print()
    print('Resolution')
    print('==========')
    print()
    print('Upgrade to %s.' % (issue['fixedVersion']))
    print()
    print('# pacman -Syu "%s>=%s"' % (package, issue['fixedVersion']))
    print()
    print('The problem has been fixed upstream in version %s.' % (upstreamFixedVersion))
    print()
    print('Workaround')
    print('==========')
    print()
    print('<Is there a way to mitigate this vulnerability without upgrading?>')
    print()
    print('Description')
    print('===========')
    print()
    print('<Long description, for example from original advisory>.')
    print()
    print('Impact')
    print('======')
    print()
    print('<What is it that an attacker can do? Does this need existing')
    print('pre-conditions to be exploited (valid credentials, physical access)?')
    print('Is this remotely exploitable?>.')
    print()
    print('References')
    print('==========')
    print()
    for entry in issue['btEntries']:
        print('https://bugs.archlinux.org/task/%s' % (entry))
    for link in issue['links']:
        if 'link' in link:
            print(link['link'])
    for cve in issue['cves']:
        print('https://access.redhat.com/security/cve/%s' % (cve))

def printASA(asa, issue, package, vulnType):
    if issue['status'] != 'Fixed':
        print('Warning, this issue is not marked Fixed but %s!' % (issue['status']), file=sys.stderr)
    if not issue['fixedVersion']:
        print('Warning, this issue does not have a fixed version!', file=sys.stderr)
    printSubject(asa, issue, package, vulnType)
    print()
    printBody(asa, issue, package, vulnType)

if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit('Usage: %s <JSON database> <package> <CVE number>|<fixed version> <ASA identifier> <vulnerabilty type>' % (sys.argv[0]))

    dbFile = sys.argv[1]
    package = sys.argv[2]
    asa = sys.argv[4]
    vulnType = sys.argv[5]
    versionRE = re.compile(r'^([<>]?=?)?\s*(\d+:)?[.a-zA-Z\d_-]+(-\d+)?$')
    cveRE = re.compile(r'cve\-\d{4}\-\d{4,}', re.IGNORECASE)

    if cveRE.match(sys.argv[3]):
        cve = sys.argv[3]
        version = None
    elif versionRE.match(sys.argv[3]):
        cve = None
        version = sys.argv[3]
    else:
        sys.exit('Third parameter (%s) does not look like a valid CVE identifier or version number, exiting.' % (sys.argv[3]))

    if not os.path.isfile(sys.argv[1]):
        sys.exit("JSON database %s does not exist!" % (sys.argv[1]))

    with open(sys.argv[1]) as db:
        issuesJSON = json.load(db)

    issues = []
    for issue in issuesJSON:
        if package in issue['packages']:
            if (version and version == issue['fixedVersion']) or (cve and cve in issue['cves']):
                printASA(asa, issue, package, vulnType)
                break
