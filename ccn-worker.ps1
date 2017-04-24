Param(
    #source can be a URL or a path to folder where .txt files with CCN data is stored
    [string]$source
)

$Global:PATH_TO_CCN = "http://pastebin.com/raw/Zfwg4hww" 

if ($source.Length -gt 0) {
    $Global:PATH_TO_CCN = $source
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$Global:CCN_LIST = ""
[int] $Global:CCN_COUNTER = 0
[regex] $Global:CCN_REGEX = '([2-9][0-9]{12,15})|([2-9][0-9]{3})(-? ?[0-9]{3,4}){3}'

function main() {
    if ($Global:PATH_TO_CCN -like '*C:\*' -and $Global:PATH_TO_CCN -notlike '*.zip') {
        getCCNsFromFolder $Global:PATH_TO_CCN
    } elseif ($Global:PATH_TO_CCN -like '*.zip') {
        $extractedFolder = extractZipFile $Global:PATH_TO_CCN
        getCCNsFromFolder $extractedFolder
    } else {
        if ($Global:PATH_TO_CCN -ne $null) {
            $Global:PATH_TO_CCN = $Global:PATH_TO_CCN -replace("https","http")
            $rawCCNData = getRawDumpFromURL $Global:PATH_TO_CCN
            getCCNsFromRawDump $rawCCNData
        } else {
            printHelp
        }
    }
    
    Write-Host "[*] Looking for CCN-like numbers..."
    Write-Host $Global:CCN_LIST
    Write-Host "CCNs found:" $Global:CCN_COUNTER '(Source'$Global:PATH_TO_CCN')'
   
    saveExtractedCCNsToFile
    openCSIRTTools
}

function printHelp() {
    Write-Host "[*] Please supply a path to CCN data as an argument, i.e. ccn-worker.ps1 'PATH_TO_CCN_DATA'`n
    [!] PATH_TO_CCN_DATA could be one of the following:`r
    [1] URL, i.e. - http://pastebin.com/raw/Zfwg4hww`r
    [2] Path to a folder with CCN data (txt files) is stored, i.e - C:\CCNs`r
    [3] Path to a zip file containin CNN data, i.e - C:\Downloads\CCN.zip`n
    [i] Example: ccn-worker.ps1 http://pastebin.com/raw/Zfwg4hww"
    break
}

function saveExtractedCCNsToFile() {
    cd C:\Users\$env:USERNAME\Downloads
    $filePath = Get-Location
    $filePath = $filePath.Path + "\CCNs-Found-" + (Get-Date).ToString("dd-MM-yyyy_HHmm") + ".txt"
    $Global:CCN_LIST | Out-File $filePath
    Write-Host "CCNs saved:" $filePath
}

function getCCNsFromRawDump($rawCCNData) {
    $CCNMatches = $Global:CCN_REGEX.Matches($rawCCNData)
    $CCNMatches.ForEach({
        addCCNtoDeduplicatedList $_
    })
}

function containsCCN($string) {
    #returns CNN if true, false otherwise
    [regex] $regex = $Global:CCN_REGEX
    $isCCN = $string -match($regex)

    if ($isCCN -ne $false) {
        $CCN = $Matches[0]
        return $CCN
    } else {
        return $false        
    }
}

function addCCNtoDeduplicatedList($CCN) {
    if ($Global:CCN_LIST -notlike '*' + $CCN +'*') {
        $CCN = $CCN -replace(" ","")
        $Global:CCN_LIST += $CCN + "`r`n"
        $Global:CCN_COUNTER++
    }
}

function getCCNsFromFolder($Global:PATH_TO_CCN) {
    cd $Global:PATH_TO_CCN
    [array] $CCNFiles = Get-ChildItem $Global:PATH_TO_CCN -Recurse

    $CCNFiles.ForEach({
        Get-Content $_ | ForEach-Object {
            $CCN = containsCCN $_

            if ($CCN -ne $false) {
                addCCNtoDeduplicatedList $CCN
            }
        }
    })
}

function getRawDumpFromURL($URL) {
    $proxyHost = "proxyUrl"
    $response = Invoke-WebRequest -Uri $URL -Proxy $proxyHost -ProxyUseDefaultCredentials
    return $response.content
}

function extractZipFile($archive) {    
    Add-Type -AssemblyName System.IO.Compression.FileSystem    
    $outPath = $archive -replace (".zip","")
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $outPath)
    return $outPath
}

function grabFilesFromFoxIT() {
    # Get attachments GET /rest/api/content/{id}/child/attachment
    # Children GET /rest/api/content/{id}/child
    # Get content by id GET /rest/api/content/{id}

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $base_URL = "https://cybercrime-portal.fox-it.com/confluence/rest/api/"
    $parameters = @{
        os_destination = ""
        user_role = ""
        atl_token = ""
        login = "Log In"
    }

    $response = Invoke-WebRequest -Uri $URL -Method POST -Body $requestParameters
    return $response
}

main
