#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import json
import os
import re
import sys
import requests

def getCurrentVersion(package):
    # https://wiki.archlinux.org/index.php/Official_repositories_web_interface
    url = "https://www.archlinux.org/packages/search/json/?name=%s" % package
    resp = requests.get(url)
    if resp.status_code != 200:
        return None
    payload = resp.json()
    if not payload or not 'results' in payload:
        return None
    for result in payload['results']:
        if not 'pkgname' in result or result['pkgname'] != package:
            continue
        if not 'pkgrel' in result or not 'pkgver' in result:
            continue
        if not 'epoch' in result or result['epoch'] == 0:
            return result['pkgver'] + '-' + result['pkgrel']
        else:
            return str(result['epoch']) + ':' + result['pkgver'] + '-' + result['pkgrel']
    return None

def checkVulnerableEntriesUpdated(dbFile):

    versionRE = re.compile(r'^([<>]?=?)?\s*((\d+:)?[.+a-zA-Z\d_-]+(-\d+)?)$')
    with open(dbFile) as db:
        issuesJSON = json.load(db)

    for issue in issuesJSON:
        if issue['status'] == 'Vulnerable':
            match = versionRE.match(issue['vulnerableVersion'])
            if not match:
                continue
            vulnerableVersion = match.group(2)
            currentVersion = getCurrentVersion(issue['packages'][0])

            if vulnerableVersion != currentVersion:
                print("Package %s is marked as vulnerable in version %s, but is currenly in version %s"
                      % (issue['packages'][0],
                         vulnerableVersion,
                         currentVersion))

if __name__ == "__main__":
    nbParams = len(sys.argv) - 1
    if nbParams != 1:
        sys.exit('Usage: %s <JSON database>' % (sys.argv[0]))

    if not os.path.isfile(sys.argv[1]):
        sys.exit("JSON database %s does not exist!" % (sys.argv[1]))

    checkVulnerableEntriesUpdated(sys.argv[1])
