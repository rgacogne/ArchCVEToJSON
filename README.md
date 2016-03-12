Arch Linux CVE tools
====================

Arch Linux CVE Wiki Page Parser
-------------------------------

The tiny script named `ArchCVEToJSON.py` parses the Arch Linux Wiki CVE page
to a more usable JSON format.


Arch Linux Security Advisories Generator
----------------------------------------

Based on the JSON output of `ArchCVEToJSON.py`, `JSONToASA.py` generates the
template of the Security Advisory for a specific vulnerability.

Usage is JSONToASA.py <JSON database file> <package> <CVE number>|<fixed version> <ASA identifier> <vulnerabilty type>

For example, to generate the template for the ASA ASA-201603-15, for a denial
of service vulnerability fixed in the 2.0.2-1 version of the package named
wireshark-cli:

```
$ python ArchCVEToJSON.py > CVEs.json
$ python JSONToASA.py CVEs.json wireshark-cli 2.0.2-1 ASA-201603-15 "denial of service"
```
