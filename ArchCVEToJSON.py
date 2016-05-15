#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import json
import re
import sys
import time
import httplib2

class ArchIssueLink:
    def __init__(self, link, description=None):
        self.link = link
        self.description = description

    def to_JSON(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True,
                          indent=4)

class ArchSecurityAdvisoryLink:
    def __init__(self, asaId, link):
        self.asaId = asaId
        self.link = link

    def to_JSON(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True,
                          indent=4)

class ArchIssue:

    def __init__(self, packages, disclosureDate, vulnerableVersion, status, btEntries=None, cves=None, links=None, fixedVersion=None, responseTime=None, asas=None):
        self.status = status
        self.cves = cves or []
        self.links = links or []
        self.packages = packages
        self.vulnerableVersion = vulnerableVersion
        self.fixedVersion = fixedVersion
        self.disclosureDate = disclosureDate
        self.asas = asas or []
        self.responseTime = responseTime
        self.btEntries = btEntries or []

    def to_JSON(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True,
                          indent=4)

class ArchWikiCVEScrapper:
    _URL = 'https://wiki.archlinux.org/api.php?action=query&titles=CVE&prop=revisions&rvprop=content&rvsection=5&format=json&formatversion=2'

    def __init__(self):
        self.issues = []
        self._cveRE = re.compile(r'cve\-\d{4}\-\d{4,}', re.IGNORECASE)
        self._linksRE = re.compile(r'\[\s*(https?://[^\]\s]+)\s*([^\]]*)\]', re.IGNORECASE)
        self._packageRE = re.compile(r'\{\{pkg\|([a-z\d+_*-]+)\}\}', re.IGNORECASE)
        self._versionRE = re.compile(r'^([<>]?=?)?\s*(\d+:)?[.+a-zA-Z\d_-]+(-\d+)?$')
        self._responseTimeRE = re.compile(r'^[<~>]?\s*\d+[dmy]$', re.IGNORECASE)
        self._statusRE = re.compile(r'(?:\'\'\')?(Fixed|Rejected|Invalid|Vulnerable)(?:\'\'\')?')
        self._btEntryRE = re.compile(r'\{\{bug\|(\d+)\}\}')
        self._asaRE = re.compile(r'\[\s*(https://[^\]\s]+)\s*(ASA-\d{6}-\d{1,})\]')

    def _parseCVEs(self, value):
        cves = self._cveRE.findall(value)
        if cves:
            # remove duplicates
            cves = list(set(cves))
            cves.sort(key=lambda x: x.lower())
            return [str(x) for x in cves]
        return []

    def _parseLinks(self, value):
        result = []
        for link in self._linksRE.finditer(value):
            description = link.group(2)
            if description and description != 'templink' and description != 'temp link' and description != 'tmplink' and description != 'tmp link' and description != 'temp-link':
                result.append(ArchIssueLink(link.group(1), description))
            else:
                result.append(ArchIssueLink(link.group(1)))

        return result

    def _parsePackages(self, value):
        value = value.strip()
        entries = self._packageRE.findall(value)
        if entries:
            return entries
        return []

    @staticmethod
    def _parseDate(value):
        value = value.strip()
        try:
            return time.strftime("%Y-%m-%d", time.strptime(value, "%Y-%m-%d"))
        except ValueError:
            return None

    def _parseVersion(self, value):
        value = value.strip()
        if self._versionRE.match(value):
            return value

        if value and value != '?':
            print('Warning, invalid version "' + value + '"', file=sys.stderr)
        return None

    def _parseResponseTime(self, value):
        value = value.strip()
        if self._responseTimeRE.match(value):
            return value

        if value and value != '?' and value != '-':
            print('Warning, Invalid response time "' + value + '"', file=sys.stderr)
        return None

    def _parseStatus(self, value):
        value = value.strip()
        status = self._statusRE.match(value)
        if status:
            return status.group(1)

        if value and value != '?' and value != '-':
            print('Warning, invalid status "' + value + '"', file=sys.stderr)
        return None

    def _parseBTEntries(self, value):
        value = value.strip()
        entries = self._btEntryRE.findall(value)
        if entries:
            return [str(x) for x in entries]
        return []

    def _parseASAs(self, value):
        result = []
        value = value.strip()
        for asa in self._asaRE.finditer(value):
            result.append(ArchSecurityAdvisoryLink(asa.group(2), asa.group(1)))
        return result

    def _parseWikiLine(self, line):
        # remove the leading '|' and trim the following whitespaces
        line = line[1:].lstrip()
        parts = line.split('||')
        if len(parts) != 8:
            return

        cves = self._parseCVEs(parts[0])
        links = self._parseLinks(parts[0])
        packages = self._parsePackages(parts[1])
        disclosureDate = self._parseDate(parts[2])
        affectedVersion = self._parseVersion(parts[3])
        fixedVersion = self._parseVersion(parts[4])
        responseTime = self._parseResponseTime(parts[5])
        status = self._parseStatus(parts[6])
        bts = self._parseBTEntries(parts[6])
        asas = self._parseASAs(parts[7])

        if len(packages) == 0:
            print('An issue should concern at least one package, skipping!', file=sys.stderr)
            return

        self.issues.append(ArchIssue(packages, disclosureDate, affectedVersion, status, bts, cves, links, fixedVersion, responseTime, asas))

    def getIssues(self):
        return self.issues

    def scrapWiki(self, timeout=20):
        conn = httplib2.Http(timeout=timeout)
        response, content = conn.request(self._URL, 'GET')

        if response.status != 200:
            raise Exception('Error fetching URL %s, HTTP status was %d' % (self._URL, response.status))

        data = json.loads(content.decode('utf-8'))
        if not ('query' in data and 'pages' in data['query'] and len(data['query']['pages']) == 1):
            raise Exception('No page found')
        page = data['query']['pages'][0]
        if not ('revisions' in page and len(page['revisions']) == 1):
            raise Exception('No revision found')
        revision = page['revisions'][0]
        if not 'content' in revision:
            raise Exception('No content found')
        revisionContent = revision['content']

        for line in revisionContent.splitlines(True):
            line = line.strip()
            if not line.startswith('|-'):
                if line.startswith('|'):
                    self._parseWikiLine(line)

if __name__ == "__main__":
    scrapper = ArchWikiCVEScrapper()
    scrapper.scrapWiki()
    issues = scrapper.getIssues()
    print(json.dumps(issues,
                     default=lambda o: o.__dict__,
                     sort_keys=True,
                     indent=4))
