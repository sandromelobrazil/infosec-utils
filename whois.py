#!/bin/python3.5

import urllib.request
import json
import sys

def sendGETRequest(url):
    response = urllib.request.urlopen(url).read().decode("utf-8")
    return response

def fetchAllDNSRecords(hostname):
    recordsToLookUp = [
        "A",
        "MX",
        "NS",
        "TXT",
        "SOA"
    ]

    for record in recordsToLookUp:
        dnsRecords = getDNSRecordsForHost(hostname, record)
        printDNSrecords(dnsRecords)

def getDNSRecordsForHost(hostname, recordType):
    baseUrl = "https://dns-api.org/"
    recordType += "/"
    url = baseUrl + recordType + hostname
    dnsRecordsRaw = sendGETRequest(url)

    return dnsRecordsRaw

def printDNSrecords(dnsRecordsRaw):
    dnsRecords = json.loads(dnsRecordsRaw)
    for dnsRecord in dnsRecords:
        print(dnsRecord["type"] + "\t" + dnsRecord["value"] + "\t" + dnsRecord["name"])

if (sys.argv[1]):
    hostname = sys.argv[1]
    fetchAllDNSRecords(hostname)
