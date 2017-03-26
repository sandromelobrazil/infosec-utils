#!/bin/python3.5
import urllib.request
import json
import sys

BASE_WHOIS_URL = "https://www.whois.com/whois/"

def sendGetRequest(url):
    response = urllib.request.urlopen(url).read().decode("utf-8")
    return response


def fetchAllDNSRecordsByDomain(domain):
    recordsToLookUp = [
        "A",
        "MX",
        "NS",
        "TXT",
        "SOA"
    ]

    for record in recordsToLookUp:
        dnsRecords = getDNSRecordsByDomain(domain, record)
        printDNSRecords(dnsRecords)


def getDNSRecordsByDomain(domain, recordType):
    baseUrl = "https://dns-api.org/"
    recordType += "/"
    url = baseUrl + recordType + domain
    dnsRecordsRaw = sendGetRequest(url)

    return dnsRecordsRaw


def printDNSRecords(dnsRecordsRaw):
    dnsRecords = json.loads(dnsRecordsRaw)
    for dnsRecord in dnsRecords:
        try:
            print(dnsRecord["type"] + "\t" + dnsRecord["value"] + "\t" + dnsRecord["name"])
        except:
            print("Some DNS records may be missing..")


def getWhoisRawByDomain(domain):
    url = BASE_WHOIS_URL + domain
    whoisResponseRaw = sendGetRequest(url)

    return whoisResponseRaw


def printRegistrantInfo(registrantInfo, domain):
    print("Created:\t" + registrantInfo["created"] + " | " + registrantInfo["organisation"] + "\n"
        "Location:\t" + registrantInfo["country"] + ", " + registrantInfo["state"] + ", " + registrantInfo["city"] + "\n"
        "More:\t\t" + BASE_WHOIS_URL + domain
          )


def getRegistrantInfo(whoisRawData):
    registrantAttributes = \
        "Creation Date: ", \
        "Registrant Organization: ", \
        "Registrant City: ", \
        "Registrant State/Province: ", \
        "Registrant Country: "

    registrantInfoKeys = ["created", "organisation", "city", "state", "country"]
    registrantInfoValues = []

    for index, attribute in enumerate(registrantAttributes):
        registrantInfoValues.append(getRegistrantDataByAttribute(whoisRawData, attribute))

    registrantInfoValues = replaceEmptyItemsWithPlaceholders(registrantInfoValues)
    registrantInfo = dict(zip(registrantInfoKeys, registrantInfoValues))

    return registrantInfo


def replaceEmptyItemsWithPlaceholders(registrantInfoValues):
    for index, info in enumerate(registrantInfoValues):
        if info is None:
            registrantInfoValues[index] = "-"

    return registrantInfoValues


def getRegistrantDataByAttribute(whoisRawData, attribute):
    if whoisRawData.find(attribute) > 0 :
        value = whoisRawData.split(attribute)[1].split("\n")[0]
        return str(value).strip()


def main():
    if sys.argv.__len__() > 1:
        domain = sys.argv[1]
        fetchAllDNSRecordsByDomain(domain)
        whoisDomainRaw = getWhoisRawByDomain(domain)
        registrantInfo = getRegistrantInfo(whoisDomainRaw)
        printRegistrantInfo(registrantInfo, domain)
    else:
        print("Supply a domain like so: whois.py [domain]")

main()