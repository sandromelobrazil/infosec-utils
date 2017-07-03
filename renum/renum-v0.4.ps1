param(
    [string]$Global:REMOTE_HOST,
    [string]$user,
    [switch]$shell,
    [switch]$arp,
    [switch]$ipcfg,
    [switch]$route,
    [switch]$conns,
    [switch]$procs,
    [switch]$users,
    [switch]$accounts,
    [switch]$usbenum,
    [switch]$regquery,
    [string]$key,
    [switch]$autoruns,
    [switch]$mount,
    [switch]$mountedd,
    [switch]$mounteds,
    [switch]$drivers,
    [switch]$prefetch,
    [switch]$recent,
    [switch]$downloads,
    [switch]$nbtcache,
    [switch]$desktop,
    [switch]$typedurls,
    [switch]$artefacts,
    [switch]$netstats,
    [switch]$sessions,
    [switch]$dnscache,
    [switch]$programs,
    [switch]$mft,
    [switch]$mailfile,
    [switch]$loggedon,
    [switch]$mailfileo,
    [switch]$winver,
    [switch]$sniffer,
    [string]$module,
    [string]$modargs,
    [switch]$h
)

# If these not set, you will be prompted for your service id credentials. Setting these is not encouraged.
$Global:SERVICE_ID = ""
$Global:PASSWORD = ''
$Global:SESSION = ""
$Global:COMMAND_SPECIFIED = $false
$Global:MODS_PATH = ".\mods\"
$Global:UTILS_PATH = ".\utils\"
$Global:ARTEFACTS_PATH = "C:\artefacts\"

function ConstructModuleObject([string] $_name, [string] $_helpText, $_shouldExecute, [string] $_arguments = $false, [bool] $_userIDRequired = $false) {
    $moduleObject = @{
        name = $_name
        helpText = $_helpText
        shouldExecute = $_shouldExecute
        isUserIDRequired = $_userIDRequired
        arguments = $_arguments
    }
    return $moduleObject
}

$Global:MODULES = [array] (
    (ConstructModuleObject "arp" "-arp`t`t Get ARP cache" $arp),
    (ConstructModuleObject "ipcfg" "-ipcfg`t`t Get IP configuration" $ipcfg),
    (ConstructModuleObject "routing" "-route`t`t Get routing tables" $route),
    (ConstructModuleObject "tasklist" "-procs`t`t Get running processes" $procs),
    (ConstructModuleObject "connections" "-conns`t`t Get established connections & ports listening" $conns),
    (ConstructModuleObject "users" "-users`t`t Get users who have used the machine" $users),
    (ConstructModuleObject "loggedon" "-loggedon`t Get currently logged on users" $loggedon),
    (ConstructModuleObject "regquery" "-regquery`t Get registry key info. Use -key to specify the 'key'. Mind the quotes." $regquery $key),
    (ConstructModuleObject "autoruns" "-autoruns`t Get autoruns from popular persistence locations. Requires -user <username>" $autoruns $user $true),
    (ConstructModuleObject "mounteddevices" "-mountedd`t Get currently mounted physical device letters" $mountedd),
    (ConstructModuleObject "mountedshares" "-mounteds`t Get currently mounted shares" $mounteds),
    (ConstructModuleObject "programs" "-programs`t Get currently installed programs" $programs),
    (ConstructModuleObject "shell" "-shell`t`t Get remote shell" $shell),
    (ConstructModuleObject "module" "-module`t Specify path of an external module to be executed. -modargs to supply arguments" $module $modargs),
    (ConstructModuleObject "drivers" "-drivers`t Get installed drivers" $drivers),
    (ConstructModuleObject "mailfile" "-mailfile`t Open domino mailfile. Requires -user <username>" $mailfile),
    # (ConstructModuleObject "mailfileo" "-mailfileo`t Open O365 mailfile. Requires -user <username>" $mailfileo),
    (ConstructModuleObject "usbenumeration" "-usbenum`t Get USB devices that had been plugged in" $usbenum),
    (ConstructModuleObject "sniffer" "-sniffer`t Sniff traffic. Currently dumps results to to CSV only." $sniffer),
    (ConstructModuleObject "netbioscache" "-nbtcache`t Get NetBios cache" $nbtcache),
    (ConstructModuleObject "accounts" "-accounts`t Get user accounts for machine" $accounts),
    (ConstructModuleObject "smbsessions" "-sessions`t Get a list of SMB sessions incoming to the remote machine" $sessions),
    (ConstructModuleObject "netstats" "-netstats`t Get uptime, permissions and password violations count" $netstats),
    (ConstructModuleObject "typedurls" "-typedurls`t Get URLs  typed in Internet Explorer address bar. Requires -user <username>" $typedurls $user $true),
    (ConstructModuleObject "downloads" "-downloads`t Get contents of the downloads folder. Requires -user <username>" $downloads $user $true),
    (ConstructModuleObject "desktop" "-desktop`t Get contents of the desktop. Requires -user <username>" $desktop $user $true),
    (ConstructModuleObject "mft" "-mft`t`t Get Master File Table" $mft),
    (ConstructModuleObject "dnscache" "-dnscache`t Get DNS cache" $dnscache),
    (ConstructModuleObject "windowsversion" "-winver`t Get Windows OS version, including Service Pack" $winver),
    (ConstructModuleObject "recent" "-recent`t Get recently accessed documents. Requires -user <username>" $recent $user $true)
)

function debugSession() {
    $Global:REMOTE_HOST = ""
    $module =  ".\utils\find-suspicious-traffic.ps1"
    $modargs = ""
    $Global:COMMAND_SPECIFIED = $true
    executeExternalModule $module $modargs
}

function main() {
    # debugSession
    changeWorkingDirectory
    processArguments
        
    if ($h) {
        printHelp
    } 
    
    establishRemoteSession
    setupEnvironment
    enumerateSystem
    closeRemoteSession
}

function setupEnvironment() {
    if (!(Test-Path -Path $Global:ARTEFACTS_PATH)) { New-Item -ItemType Directory -Path $Global:ARTEFACTS_PATH -Force | Out-Null }
}

function closeRemoteSession() {
    Get-PSSession | Remove-PSSession
    cmdkey.exe /delete:$Global:REMOTE_HOST | Out-Null
}

function printHelp() {


    Write-Host "
      ___           ___           ___           ___           ___     
     /\  \         /\  \         /\__\         /\__\         /\__\    
    /  \  \       /  \  \       /  |  |       / /  /        /  |  |   
   / /\ \  \     / /\ \  \     / | |  |      / /  /        / | |  |   
  /  \ \ \  \   /  \ \ \  \   / /| |  |__   / /  /  ___   / /| |__|__ 
 / /\ \ \ \__\ / /\ \ \ \__\ / / | | /\__\ / /__/  /\__\ / / |    \__\
 \/_|  \/ /  / \ \ \ \ \/__/ \/__| |/ /  / \ \  \ / /  / \/__/--/ /  /
    | |  /  /   \ \ \ \__\       | / /  /   \ \  / /  /        / /  / 
    | |\/__/     \ \ \/__/       |  /  /     \ \/ /  /        / /  /  
    | |  |        \ \__\         / /  /       \  /  /        / /  /   
     \|__|         \/__/         \/__/         \/__/         \/__/    
        
        " -ForegroundColor Yellow

        Write-Host "[*] REnum (RemoteEnumeration) is a collection of convenience functions to help during an investigtion." -ForegroundColor Cyan
        Write-Host [i] Specify remote host and -[command] you want to execute.`n[i] Example: to get remote machine IP configuration, type: renum-v0.1.ps1 127.0.0.1 -ipcfg
        Write-Host "`n[i] Available commands:`n
        Tip:`t`t Omit the command to open C$ share without mounting it... or use -mount to do it"
        
        foreach ($module in $Global:MODULES) {
            Write-Host "`t" $module.helpText
        }
        break
}

function processArguments() {
    if ($Global:REMOTE_HOST -eq "") {
        printHelp
    }
    processHost  
    processCredentials
}

function processHost() {
    try {
        if ([ipaddress] $Global:REMOTE_HOST) {
            $Global:REMOTE_HOST = [System.Net.Dns]::GetHostByAddress($Global:REMOTE_HOST).HostName
        }
    } catch { }
}

function processCredentials() {
    if ($Global:PASSWORD -eq '' -or $Global:SERVICE_ID -eq '') {
        $Global:CREDENTIALS = Get-Credential
    } else {
        $Global:PASSWORD2 = ConvertTo-SecureString $Global:PASSWORD -AsPlainText -Force
        $Global:CREDENTIALS = New-Object System.Management.Automation.PSCredential($Global:SERVICE_ID, $Global:PASSWORD2)
    }
}

function isUserSpecified() {
    if ($user -eq "" -or $user -eq $null) {
        $username = Read-Host -Prompt "[!] Enter username of the destination machine (Tip: switch -users shows users who had engaged with the remote machine)"
        Write-Host "[i] Tip: use -user <user> to avoid this prompt in the future..."
        return $username
    } else {
        return $user
    }
}

function sniffTraffic($module) {
    $packetCaptureFilename = "$Global:REMOTE_HOST-sniff.csv"
    $ignoreIP = (Test-Connection -ComputerName (hostname) -Count 1 | Select IPV4Address).IPV4Address.IPAddressToString

    executeRemoteCommand $module $ignoreIP
    waitForEscapeKey
    $artefact = downloadArtefact $packetCaptureFilename
    Write-Host "[*] Download complete."

    identifySuspiciousTraffic $packetCaptureFilename
    Remove-Item $artefact
}

function identifySuspiciousTraffic($packetCaptureFilename) {
    $location = $Global:ARTEFACTS_PATH + $packetCaptureFilename
    powershell $Global:UTILS_PATH\find-suspicious-traffic.ps1 $location
}

function waitForEscapeKey() {
    [int] $percent = 0
    [date] $sniffingStartTime = (Get-Date)
    $artefact = $null

    while ($true) {
        Write-Progress -Activity "Sniffing traffic $Global:REMOTE_HOST... Press ESC or Ctrl+C to stop and download the results..." -Status ((Get-Date) - $sniffingStartTime) -PercentComplete $percent

        if ($host.ui.RawUi.KeyAvailable) {
            $pressedKey = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            if ($pressedKey.VirtualKeyCode -eq 27 -or (3 -eq [int]$Host.UI.RawUI.ReadKey("AllowCtrlC,IncludeKeyUp,NoEcho").Character)) {
                Get-Job | Stop-Job 
                Get-Job | Remove-Job
                return 
            }
        } 

        if ($percent -eq 100) {
            $percent = 0
        } else {
            $percent++
        }

        Start-Sleep 0.1
    }

    write-host $artefact
}

function getMFT($module) {
    copyUtilsToRemoteHost
    executeRemoteCommand $module
    $remoteMFTpath = downloadArtefact "$Global:REMOTE_HOST.mft"
    Remove-Item $remoteMFTpath   
    parseMFT
}

function parseMFT() {
    $mftLocation = "$Global:ARTEFACTS_PATH\$Global:REMOTE_HOST.mft"
    $mftReport = "$Global:ARTEFACTS_PATH\$Global:REMOTE_HOST-mft.xls"

    Write-Host "[*] Parsing $Global:REMOTE_HOST.mft..."
    powershell $Global:UTILS_PATH\mftdump.exe $mftLocation /o $mftReport
    Write-Host "[*] Opening $Global:REMOTE_HOST MFT, please wait..."
    Invoke-Item $mftReport
}

function getShell() {
    $Global:COMMAND_SPECIFIED = $true
    Enter-PSSession -ComputerName $Global:REMOTE_HOST -Credential $Global:CREDENTIALS
}

function mountShare() {
    net use * \\$Global:REMOTE_HOST\c$ /user:$Global:SERVICE_ID $Global:PASSWORD
    Invoke-Item \\$Global:REMOTE_HOST\c$
}

function getMailFile() {
    $user = isUserSpecified
    $Global:COMMAND_SPECIFIED = $true
    $mailfile = "$user.nsf"
    $mailfileDestination = "C:\Users\$env:USERNAME\Downloads\$mailfile"
    $mailfileSource = "\\" + "$Global:REMOTE_HOST\d$\Lotus\Domino\data\mail\$mailfile"
    
    Write-Host "[*] Downloading mailfile to $mailfileDestination. Please wait, it will be opened automatically..."
    Copy-Item $mailfileSource -Destination $mailfileDestination -Force -Recurse
    Write-Host [*] Opening mailfile... Do not forget to delete it once done.
    Invoke-Item $mailfileDestination
}

function getOutlookMailFile() {
    $user = isUserSpecified
    $Global:COMMAND_SPECIFIED = $true
    $mailfile = "*.ost"
    $mailfileDestination = "C:\Users\$env:USERNAME\Downloads\"
    $mailfileSource = "\\" + "$Global:REMOTE_HOST\c$\users\$user\AppData\Local\Microsoft\Outlook\*.ost"
    
    Write-Host "[*] Downloading mailfile to $mailfileDestination. Please wait, it will be opened automatically..."
    Copy-Item $mailfileSource -Destination $mailfileDestination -Force -Recurse
    Write-Host [*] Opening mailfile... Do not forget to delete it once done.
    Invoke-Item $mailfileDestination
}

function getDrivers() {
    $Global:COMMAND_SPECIFIED = $true
    driverquery /s $Global:REMOTE_HOST /u $Global:SERVICE_ID /p $Global:PASSWORD
}

function enumerateSystem() {
    foreach ($module in $Global:MODULES) {
        if ($module.shouldExecute) {
            switch ($module.name) {
                "shell" { getShell }
                "mft" { getMFT $module }
                "drivers" { getDrivers }
                "mailfile" { getMailFile }
                "mailfileo" { getOutlookMailFile }
                "sniffer" { sniffTraffic $module }
                "module" { executeExternalModule $module $modargs }
                Default { executeRemoteCommand $module $module }
            }            
        }
    }
    
    isCommandNotSpecified
}

function isCommandNotSpecified() {
    if (!$Global:COMMAND_SPECIFIED) {
        if ($mount) {
            Write-Host "[*] Mounting share \\$Global:REMOTE_HOST\C$"
            mountShare
        }
        Write-Host "[*] Opening share \\$Global:REMOTE_HOST\C$"
        Invoke-Item \\$Global:REMOTE_HOST\c$
    }
}

function executeExternalModule($module, $modargs) {
    executeRemoteCommand $module $modargs $true
}

function changeWorkingDirectory() {
    Set-Location $MyInvocation.PSScriptRoot
}

function executeRemoteCommand($module, $arguments=$null, $isExternalModule=$false) {
    $Global:COMMAND_SPECIFIED = $true
    $command = $module.name

    if ($module.isUserIDRequired -and $user -eq "") {
        $module.arguments = isUserSpecified
    }
    $arguments = $module.arguments

    if (!$isExternalModule) {
        $module = "$Global:MODS_PATH\$command.ps1"
    } 
    
    if ($command -eq "sniffer") {
        Invoke-Command -Session $Global:SESSION -FilePath $module -ArgumentList $arguments -AsJob | Out-Null
    } else {
        Invoke-Command -Session $Global:SESSION -FilePath $module -ArgumentList $arguments
    }
}

function downloadArtefact($artefactName, $isLocked=$false) {
    $artefactsSaveLocation = "$Global:ARTEFACTS_PATH$artefactName"
    $artefactSourceLocation = "\\" + $Global:REMOTE_HOST + "\c$\temp\$artefactName"
    Write-Host "[*] Downloading $artefactName to $artefactsSaveLocation"
    
    Copy-Item $artefactSourceLocation -Destination $Global:ARTEFACTS_PATH -Force -Recurse   
    return $artefactSourceLocation
}

function copyUtilsToRemoteHost() {
    Copy-Item $Global:UTILS_PATH\copy.exe -Destination \\$Global:REMOTE_HOST\c$\TEMP\copy.exe -Recurse -Force
}

function notifyConnectionError() {
    Write-Host "[*] Not connected. Machine offline or misspelled..."
    break
}

function establishRemoteSession() {
    Write-Host "[*] Connecting to" $Global:REMOTE_HOST
    cmdkey.exe /add:$Global:REMOTE_HOST /user:$Global:SERVICE_ID /pass:$Global:PASSWORD | Out-Null

    if (!$mailfile -and $Global:REMOTE_HOST.Length -gt 7) {
        $Global:SESSION = New-PSSession -ComputerName $Global:REMOTE_HOST -Credential $Global:CREDENTIALS
        if ($Global:SESSION) {
            Write-Host "[*] Connected!"
        } else {
            notifyConnectionError
        }
    }
}

main
