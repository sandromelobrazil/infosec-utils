#!/bin/python3.5
# todo: add the remote nslookup for the ip
import urllib.request
import json
import sys
import socket
from urllib.error import URLError
from urllib.error import HTTPError

BASE_WHOIS_URL = "https://www.whois.com/whois/"
BASE_CYMON_URL = "https://cymon.io/api/nexus/v1/ip/"

def sendHttpRequest(request):
    try:
        response = urllib.request.urlopen(request).read().decode("utf-8")
    except HTTPError as httperror:
        return httperror
    except URLError as urlerror:
         return urlerror
    except:
        print("Domain or IP you supplied may not be in correct format..")
        exit(1)
    return response

def buildHTTPRequest(url, headers={"Authorization": "Token 9dd9bc3276b0c35f5d64624bb7901f296b0ff37a", "Accept": "application/json"}, data=None):
    httpRequest = urllib.request.Request(url, data=data, headers=headers)
    return httpRequest


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
        dnsRecordsDict = printDNSRecords(dnsRecords, record)
        getIPFromDNSRecord(dnsRecordsDict, record)


def getIPFromDNSRecord(dnsRecords, record):
    global DOMAIN_IP
    try:
        if record == "A" and DOMAIN_IP == None:
            DOMAIN_IP = dnsRecords[0]["value"]
    except:
        print("Domain you entered could not be resolved, check spelling.")
        exit(1)


def getDomainsByIP(ip):
    url = BASE_CYMON_URL + ip + "/domains/"
    request = buildHTTPRequest(url)
    domainsRaw = sendHttpRequest(request)
    return domainsRaw


def printDomains(domains):
    domains = convertStringToJSON(domains)
    
    if domains["count"] > 0:
        print("\n[*] Some associated domains:")
        for domain in domains["results"]:
            print(domain["name"] + "\t\t(created: " + domain["created"] + ")")
    else:
        print("\n[*] No associated domains found...")


def getDNSRecordsByDomain(domain, recordType):
    baseUrl = "https://dns-api.org/"
    recordType += "/"
    url = baseUrl + recordType + domain
    request = buildHTTPRequest(url)
    dnsRecordsRaw = sendHttpRequest(request)
    return dnsRecordsRaw


def printDNSRecords(dnsRecordsRaw, record):
    dnsRecords = convertStringToJSON(dnsRecordsRaw)

    for dnsRecord in dnsRecords:
        try:
            print(dnsRecord["type"] + "\t" + dnsRecord["value"] + "\t" + dnsRecord["name"])
        except:
            print(record + "\tDNS record seems missing..")
    return dnsRecords


def convertStringToJSON(string):
    return json.loads(string)


def getWhoisRawByDomain(domain):
    url = BASE_WHOIS_URL + domain
    request = buildHTTPRequest(url)
    whoisResponseRaw = sendHttpRequest(request)
    return whoisResponseRaw


def printRegistrantInfo(registrantInfo, domain):
    print("Registered:\t" + registrantInfo["created"] + " | " + registrantInfo["organisation"] + "\n"
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
    request = buildHTTPRequest(url)
    response = sendHttpRequest(request)
    threatsReports = convertStringToJSON(response)
    return threatsReports


def printThreatReports(threatReports):
    if threatReports["count"] > 0:
        print("\n[*] Some historical threat reports for: " + DOMAIN_IP)

        for report in threatReports["results"]:
            print("[!] " + report["created"] + " " + report["title"] + " " + str(report["description"]).replace(".","[.]").strip())
            containsDetailsUrl = (report["details_url"] != None)

            if containsDetailsUrl:
                print("More: " + report["details_url"])
            print("\r")
    else:
        print("\n[*] No threat reports found for " + DOMAIN_IP)


def isValidIPAddress(string):
    try:
        socket.inet_aton(string)
        return True
    except:
        return False


def getHostNameByIp(IP):
    url = "http://network-tools.com/default.asp?prog=dnsrec&host=" + IP
    headers = {
        "Accept": "text/html",
        "Content-type": "application/json",
    }

    request = buildHTTPRequest(url, headers=headers)
    response = sendHttpRequest(request)
    hostname = extractCanonicalName(response)
    return hostname


def extractCanonicalName(string):
    anchor = "canonical name: "
    
    if anchor in string:
        hostname = string.split(anchor)[1]
        hostname = hostname.split("<br/>")[0]
    else:
        hostname = "[*] Could not resolve to hostname..."

    return hostname


def printHostName(hostname):
    print("[*] Resolving to hostname...\n" + hostname)


def main():
    global DOMAIN_IP
    DOMAIN_IP = None

    if sys.argv.__len__() > 1:
        domain = sys.argv[1]

        if not isValidIPAddress(domain):
            fetchAllDNSRecordsByDomain(domain)
            whoisDomainRaw = getWhoisRawByDomain(domain)
            registrantInfo = getRegistrantInfo(whoisDomainRaw)
            printRegistrantInfo(registrantInfo, domain)
        else:
            DOMAIN_IP = domain
            hostname = getHostNameByIp(DOMAIN_IP)
            printHostName(hostname)
            domainsRaw = getDomainsByIP(DOMAIN_IP)
            printDomains(domainsRaw)


        threatReports = getThreatReportsByIP(DOMAIN_IP)
        printThreatReports(threatReports)
    else:
        print("Supply a domain or IPv4 like so: whois.py [domain | IP]")


main()
