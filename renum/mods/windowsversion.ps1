$osv1 = (Get-WmiObject -class Win32_OperatingSystem).Caption
$osv2 = [Environment]::OSVersion
$servicePack = $osv2.ServicePack
$version = $osv2.Version

if ($servicePack -eq "") {
    $servicePack = "No Service Pack."
}
$osVersion = "`n$osv1 ($version). $servicePack"

Write-Host $osVersion
