#!/bin/python3.5
import urllib.request
import json
import sys

def sendGetRequest(url):
    response = urllib.request.urlopen(url).read().decode("utf-8")
    return response


def fetchAllDNSRecords(domain):
    recordsToLookUp = [
        "A",
        "MX",
        "NS",
        "TXT",
        "SOA"
    ]

    for record in recordsToLookUp:
        dnsRecords = lookupDNSRecordForHost(domain, record)
        printDNSRecords(dnsRecords)


def lookupDNSRecordForHost(hostname, recordType):
    baseUrl = "https://dns-api.org/"
    recordType += "/"
    url = baseUrl + recordType + hostname
    dnsRecordsRaw = sendGetRequest(url)

    return dnsRecordsRaw


def printDNSRecords(dnsRecordsRaw):
    dnsRecords = json.loads(dnsRecordsRaw)
    for dnsRecord in dnsRecords:
        try:
            print(dnsRecord["type"] + "\t" + dnsRecord["value"] + "\t" + dnsRecord["name"])
        except:
            print("Some DNS records may be missing..")


def whoisDomain(domain):
    url = "http://whoiz.herokuapp.com/lookup.json?url=" + domain
    whoisResponseRaw = sendGetRequest(url)
    return whoisResponseRaw

def printWhois(whoisRaw):
    whois = json.loads(whoisRaw)
    print("Created: " + str(whois["created_on"]))

if sys.argv.__len__() > 1:
    domain = sys.argv[1]
    fetchAllDNSRecords(domain)
    whoisDomainRaw = whoisDomain(domain)
    printWhois(whoisDomainRaw)

else:
    print("Supply a hostname like so whois.py [hostname]")
