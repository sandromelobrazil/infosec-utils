#!/bin/python3.5
import urllib.request
import json
import sys

# todo: accept ip as an argument

BASE_WHOIS_URL = "https://www.whois.com/whois/"
BASE_CYMON_URL = "https://cymon.io/api/nexus/v1/ip/"

def sendGetRequest(url):
    headers = {"Authorization": "Token 9dd9bc3276b0c35f5d64624bb7901f296b0ff37a"}
    request = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(request).read().decode("utf-8")
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
        dnsRecordsDict = printDNSRecords(dnsRecords)
        getIPFromDNSRecord(dnsRecordsDict, record)


def getIPFromDNSRecord(dnsRecords, record):
    global DOMAIN_IP
    if record == "A" and  DOMAIN_IP == None:
        DOMAIN_IP = dnsRecords[0]["value"]
        print(DOMAIN_IP)


def getDNSRecordsByDomain(domain, recordType):
    baseUrl = "https://dns-api.org/"
    recordType += "/"
    url = baseUrl + recordType + domain
    dnsRecordsRaw = sendGetRequest(url)
    return dnsRecordsRaw


def printDNSRecords(dnsRecordsRaw):
    dnsRecords = convertStringToJSON(dnsRecordsRaw)
    for dnsRecord in dnsRecords:
        try:
            print(dnsRecord["type"] + "\t" + dnsRecord["value"] + "\t" + dnsRecord["name"])
        except:
            print("Some DNS records may be missing..")
    return dnsRecords


def convertStringToJSON(string):
    return json.loads(string)


def getWhoisRawByDomain(domain):
    url = BASE_WHOIS_URL + domain
    whoisResponseRaw = sendGetRequest(url)
    return whoisResponseRaw


def printRegistrantInfo(registrantInfo, domain):
    print("Created:\t" + registrantInfo["created"] + " | " + registrantInfo["organisation"] + "\n"
        "Location:\t" + registrantInfo["country"] + ", " + registrantInfo["state"] + ", " + registrantInfo["city"] + "\n"
        "More:\t\t" + BASE_WHOIS_URL + domain)


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


def getThreatReportsByIP(ip):
    url = BASE_CYMON_URL + ip + "/events"
    response = sendGetRequest(url)
    threatsReports = convertStringToJSON(response)
    return threatsReports


def printThreatReports(threatReports):
    if threatReports["count"] > 0:
        print("\n\n[*] Printing threat reports for the domain, based on the IP: " + DOMAIN_IP)

        for report in threatReports["results"]:
            print("[!] " + report["created"] + " " + report["title"] + " " + str(report["description"]).strip().replace(".","[.]"))
            containsDetailsUrl = (report["details_url"] != None)

            if containsDetailsUrl:
                    print("More: " + report["details_url"] + "\n")
    else:
        print("\n\n[*] No threat reports found for the domain, based on the IP: " + DOMAIN_IP)


def main():
    global DOMAIN_IP
    DOMAIN_IP = None
    if sys.argv.__len__() > 1:
        domain = sys.argv[1]
        fetchAllDNSRecordsByDomain(domain)
        whoisDomainRaw = getWhoisRawByDomain(domain)
        registrantInfo = getRegistrantInfo(whoisDomainRaw)
        printRegistrantInfo(registrantInfo, domain)
        threatReports = getThreatReportsByIP(DOMAIN_IP)
        printThreatReports(threatReports)
    else:
        print("Supply a domain like so: whois.py [domain]")


main()
