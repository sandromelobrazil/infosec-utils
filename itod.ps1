param (
    [string] $ip
)

function processArguments() {
    if ($ip -eq "") {
        Write-Host "[i] itod (IP to Domain) usage: itod.ps1 <IP>. Example: itod.ps1 127.0.0.1"
        break
    }
}

function main() {
    processArguments
    Set-Location $MyInvocation.PSScriptRoot
    [array] $dnsRecords = ConvertFrom-Csv (Get-Content zones.csv)
    getDomainByIp $ip $dnsRecords
}

function getDomainByIp($ip, $dnsRecords) {
    $isResolved = $false
    Write-Host "[*] Searching..."

    foreach ($record in $dnsRecords) {
        if ($record.ip -eq $ip) {
            Write-Host [>] $record.domain
            $isResolved = $true
        }
    }

    if (!$isResolved) {
        Write-Host "[!] No DNS records found for $ip"
    }
}

main
