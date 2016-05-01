#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import json
import os
import sys

def checkVulnerableEntries(dbFile):
    if not os.path.isfile(dbFile):
        sys.exit("JSON database %s does not exist!" % (dbFile))

    with open(dbFile) as db:
        issuesJSON = json.load(db)

    for issue in issuesJSON:
        if issue['status'] == 'Vulnerable':
            print("Package %s %s is vulnerable since %s" % (issue['packages'][0], issue['vulnerableVersion'], issue['disclosureDate']))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Usage: %s <JSON database>' % (sys.argv[0]))

    checkVulnerableEntries(sys.argv[1])
