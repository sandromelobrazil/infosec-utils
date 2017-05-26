#!/bin/python3.5
import urllib.request
import json
import sys
import socket
from urllib.error import URLError
from urllib.error import HTTPError

BASE_WHOIS_URL = "https://www.whois.com/whois/"
BASE_CYMON_URL = "https://cymon.io/api/nexus/v1/ip/"
BASE_TALOS_URL = "https://talosintelligence.com/sb_api/"
BASE_ABUSEIP_URL = "https://www.abuseipdb.com/check/"

def sendHTTPRequest(request):
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


def buildHTTPRequest(url, headers={"Authorization": "Token 9dd9bc3276b0c35f5d64624bb7901f296b0ff37a", "User-Agent": "Mantvydas' cmd-line Whois", "Accept": "application/json", "Content-Type": "text/html; charset=utf-8"}, data=None):
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
    printSection("DNS Lookup")

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


def getDomainsByIP(ip):
    url = BASE_CYMON_URL + ip + "/domains/"
    request = buildHTTPRequest(url)
    domainsRaw = sendHTTPRequest(request)
    return domainsRaw


def printDomains(domains):
    domains = convertStringToJSON(domains)
    
    if domains["count"] > 0:
        printSection("Associated Domains")
        for domain in domains["results"]:
            print(domain["name"] + "\t\t(created: " + domain["created"] + ")")
    else:
        print("\n[*] No associated domains found...")


def getDNSRecordsByDomain(domain, recordType):
    baseUrl = "https://dns-api.org/"
    recordType += "/"
    url = baseUrl + recordType + domain
    request = buildHTTPRequest(url)
    dnsRecordsRaw = sendHTTPRequest(request)
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


def getRawWhois(domain):
    url = BASE_WHOIS_URL + domain
    request = buildHTTPRequest(url)
    whoisResponseRaw = sendHTTPRequest(request)
    return whoisResponseRaw


def printDoimainWhois(registrantInfo, domain):
    registrantInfo = registrantInfo.split('<pre class="df-raw"')
    
    if len(registrantInfo) > 1:
        registrantInfo = registrantInfo[1].split('</pre>')[0].replace("\n\n\n","\n")
        lines = registrantInfo.split("\n")
        registrantInfo = ""
        
        for line in lines[1:len(lines)-1]:
            registrantInfo += line + "\n"
        printSection("Domain Whois Info")
        print(registrantInfo)


def printSection(sectionName):
    separator = "########################################################################"
    print("\n\n\n" + separator + "\n    " + sectionName + "\n" + separator)


def getThreatReportsByIP(ip):
    if ip != None:
        url = BASE_CYMON_URL + ip + "/events"
        request = buildHTTPRequest(url)
        response = sendHTTPRequest(request)
        threatsReports = convertStringToJSON(response)
        return threatsReports
    else:
        print("[!] Cannot retrieve threat reports as IP is not specified...")
        exit(1)


def printThreatReports(threatReports):
    printSection("Associated Threat Reports")
    
    if threatReports["count"] > 0:
        for report in threatReports["results"]:
            print("[!] " + report["created"] + " " + report["title"])
    else:
        print("[*] No associated threat reports found")


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
    response = sendHTTPRequest(request)
    hostname = extractCanonicalName(response)
    return hostname


def extractCanonicalName(string):
    anchor = "canonical name: "
    if anchor in string:
        hostname = string.split(anchor)[1]
        hostname = hostname.split("<br/>")[0]
    else:
        hostname = None
    return hostname


def printHostName(hostname):
    printSection("IP to Hostname")
    if hostname != None:
        print(hostname)
    else:
        print("\n[*] Could not resolve IP to hostname...")


def getWBRS(host):
    url = BASE_TALOS_URL + "remote_lookup?hostname=SDS&query_string=%2Fscore%2Fwbrs%2Fjson%3Furl=" + host
    request = buildHTTPRequest(url)
    response = convertStringToJSON(sendHTTPRequest(request))
    wbrs = str(response[0]["response"]["wbrs"]["score"])
    return wbrs


def getTalosDetails(host):
    if isValidIPAddress(host):
        queryType = "ip"
    else:
        queryType = "domain"

    url = BASE_TALOS_URL + "query_lookup?query=%2Fapi%2Fv2%2Fdetails%2F" + queryType + "%2F&query_entry=" + host
    request = buildHTTPRequest(url)
    response = convertStringToJSON(sendHTTPRequest(request))
    return response


def getTalosIntelligenceReport(IP):
    report = ""
    printSection("Talos Intelligence + AbuseIPDB (based on IP)")
    talosDetails = getTalosDetails(IP)
    report = "[*] Web score: " + talosDetails["web_score_name"] + "\n"
    report += "[*] WBRS: " + getWBRS(IP)
    
    if "blacklists" in talosDetails:
        blacklists = talosDetails["blacklists"]
        blacklistReport = "None"
        for index, service in blacklists.items():
            if service["rules"]:
                blacklistReport += index + " "
        report += "\n[*] Blacklists: " + blacklistReport

    print(report)


def getAbuseIpReport(IP):
    days = "90"
    endpoint = BASE_ABUSEIP_URL + IP + "/json?key=J6uXCXZUfK9axKh3I1sGi1S467vSqgPR5CWNcUFp&days=" + days
    request = buildHTTPRequest(endpoint)
    response = convertStringToJSON(sendHTTPRequest(request))
    print("[*] Times IP reported as abusive in the last " + days + " days: " + str(len(response)) + ", http://www.abuseipdb.com/check/" + IP)


def main():
    global DOMAIN_IP
    DOMAIN_IP = None

    if sys.argv.__len__() > 1:
        host = sys.argv[1]

        if isValidIPAddress(host):
            DOMAIN_IP = host
            hostname = getHostNameByIp(DOMAIN_IP)
            printHostName(hostname)
            domainsRaw = getDomainsByIP(DOMAIN_IP)
            printDomains(domainsRaw)
        else:
            fetchAllDNSRecordsByDomain(host)

        whoisDomainRaw = getRawWhois(host)
        printDoimainWhois(whoisDomainRaw, host)
        threatReports = getThreatReportsByIP(DOMAIN_IP)
        printThreatReports(threatReports)
        getTalosIntelligenceReport(host)
        getAbuseIpReport(DOMAIN_IP)
    else:
        print("Supply a domain or IPv4 like so: whois.py [domain | IP]")


main()
