param(
    [string]$remoteHost,
    [string]$user,
    [switch]$shell,
    [switch]$arp,
    [switch]$ipcfg,
    [switch]$route,
    [switch]$conns,
    [switch]$procs,
    [switch]$users,
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
    [switch]$dnscache,
    [switch]$mailfile,
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

# todo: order help menu

function main() {
    changeWorkingDirectory
    processArguments
    establishRemoteSession $remoteHost

    if ($h) {
        printHelp
    } 
    if ($shell) {
        getShell $remoteHost
    } 

    enumerateSystem $remoteHost   
    closeRemoteSession
}

function closeRemoteSession() {
    if (!$mailfile) {
        Remove-PSSession $Global:SESSION
    }
    cmdkey.exe /delete:$remoteHost | Out-Null
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
        Write-Host [i] Specify remote host and -[command] you want to execute.`n[i] Example: renum-v0.1.ps1 127.0.0.1 -ipcfg to get remote machine IP configuration.`n
        Write-Host "[i] Available commands:`n
        Tip:`t`t Omit the command to open C$ share without mounting it... or use -mount to do it
        -shell`t`t Get remote shell
        -arp`t`t Get ARP table
        -ipcfg`t`t Get IP configuration
        -route`t`t Get routing tables
        -procs`t`t Get running processes
        -conns`t`t Get established connections & ports listening
        -users`t`t Get users who have used the machine
        -regquery`t Get registry key info. Use -key to specify the 'key'. Mind the quotes.
        -autoruns`t Get autoruns from popular persistence locations
        -mountedd`t Get currently mounted physical device letters
        -mounteds`t Get currently mounted shares
        -module`t`t Specify path of an external module to be executed. -modargs to supply arguments
        -usbenum`t Get USB devices that had been plugged in
        -drivers`t Get installed drivers
        -nbtcache`t Get NetBios cached
        -typedurls`t Get URLs user typed in IE
        -mailfile`t Open user (-user <username>) domino mailfile
        -netstats`t Get uptime, permissions and password violations count
        -downloads`t Get contents of downloads folder (-user <username>)
        -desktop`t Get contents of desktop (-user <username>)
        -prefetch`t Get prefetches
        -recent`t`t Get recently accessed documents (-user <username>)
        -dnscache`t Get DNS cache`n"
        break
}

function processArguments() {
    if ($remoteHost -eq "") {
        printHelp
    }
    
    processCredentials
}

function processCredentials() {
    if ($Global:PASSWORD -eq '' -or $Global:SERVICE_ID -eq '') {
        $Global:CREDENTIALS = Get-Credential
    } else {
        $Global:PASSWORD2 = ConvertTo-SecureString $Global:PASSWORD -AsPlainText -Force
        $Global:CREDENTIALS = New-Object System.Management.Automation.PSCredential($Global:SERVICE_ID, $Global:PASSWORD2)
    }
}

function getIPConfig($remoteHost) {
    $command = "ipcfg"
    executeRemoteCommand $remoteHost $command
    return $true
}

function getRoutingTable($remoteHost) {
    $command = "routing"
    executeRemoteCommand $remoteHost $command
}

function getDNSCache($remoteHost) {
    $command = "dnscache"
    executeRemoteCommand $remoteHost $command
}

function getNetstats($remoteHost) {
    $command = "netstats"
    executeRemoteCommand $remoteHost $command
}

function getUsers($remoteHost) {
    $command = "users"
    executeRemoteCommand $remoteHost $command
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

function getRecentItems($remoteHost) {
    $user = isUserSpecified
    $command = "recent"
    executeRemoteCommand $remoteHost $command $user
}

function getConnections($remoteHost) {
    $command = "connections"
    executeRemoteCommand $remoteHost $command
}

function getNetbiosCache($remoteHost) {
    $command = "netbioscache"
    executeRemoteCommand $remoteHost $command $remoteHost
}

function getShell($remoteHost) {
    $Global:COMMAND_SPECIFIED = $true
    Enter-PSSession -ComputerName $remoteHost -Credential $Global:CREDENTIALS
}

function getProcessList($remoteHost) {
    $command = "tasklist"
    executeRemoteCommand $remoteHost $command
}

function getARPTable($remoteHost) {
    $command = "arp"
    executeRemoteCommand $remoteHost $command
}

function getPrefetches($remoteHost) {
    $command = "prefetches"
    executeRemoteCommand $remoteHost $command
}

function getDownloads($remoteHost) {
    $user = isUserSpecified
    $command = "downloads"
    executeRemoteCommand $remoteHost $command $user
}

function getDesktop($remoteHost) {
    $user = isUserSpecified
    $command = "desktop"
    executeRemoteCommand $remoteHost $command $user
}

function getUSBEnum($remoteHost) {
    $command = "usbenumeration"
    executeRemoteCommand $remoteHost $command
}

function getMountedShares($remoteHost) {
    $command = 'mountedshares'
    executeRemoteCommand $remoteHost $command
}

function getMountedDevices($remoteHost) {
    $command = "mounteddevices"
    executeRemoteCommand $remoteHost $command
}

function getAutoruns($remoteHost) {
    $user = isUserSpecified
    $command = "autoruns"
    executeRemoteCommand $remoteHost $command $user
}

function getTypedURLs($remoteHost) {
    $user = isUserSpecified
    $command = "typedurls"
    executeRemoteCommand $remoteHost $command $user
}

function mountShare($remoteHost) {
    net use * \\$remoteHost\c$ /user:$Global:SERVICE_ID $Global:PASSWORD
    Invoke-Item \\$remoteHost\c$
}

function getMailFile($remoteHost) {
    $user = isUserSpecified

    $Global:COMMAND_SPECIFIED = $true
    $mailfile = "$user.nsf"
    $mailfileDestination = "C:\Users\$env:USERNAME\Downloads\$mailfile"
    $mailfileSource = "\\" + "$remoteHost\d$\Lotus\Domino\data\mail\$mailfile"
    
    Write-Host [*] Saving mailfile to $mailfileDestination...
    Copy-Item $mailfileSource -Destination $mailfileDestination -Force -Recurse
    Write-Host [*] Opening mailfile... Do not forget to delete it once done.
    Invoke-Item $mailfileDestination
}

function getDrivers($remoteHost) {
    $Global:COMMAND_SPECIFIED = $true
    driverquery /s $remoteHost /u $Global:SERVICE_ID /p $Global:PASSWORD
}

function queryRegKey($remoteHost, $key) {
    $command = 'regquery'
    executeRemoteCommand $remoteHost $command $key
}

function enumerateSystem($remoteHost) {
    if ($arp) {
        getARPTable $remoteHost
    }
    if ($ipcfg) {
        getIPConfig $remoteHost
    }
    if ($route) {
        getRoutingTable $remoteHost
    }
    if ($conns) {
        getConnections $remoteHost
    }
    if ($procs) {
        getProcessList $remoteHost
    }
    if ($dnscache) {
        getDNSCache $remoteHost
    }
    if ($users) {
        getUsers $remoteHost
    }
    if ($usbenum) {
        getUSBEnum $remoteHost
    }
    if ($regquery) {
        queryRegKey $remoteHost $key
    }
    if ($typedurl) {
        getTypedURLs $remoteHost
    }
    if ($autoruns) {
        getAutoruns $remoteHost
    }
    if ($prefetch) {
        getPrefetches $remoteHost
    }
    if ($recent) {
        getRecentItems $remoteHost
    }
    if ($nbtcache) {
        getNetbiosCache $remoteHost
    }
    if ($downloads) {
        getDownloads $remoteHost
    }
    if ($desktop) {
        getDesktop $remoteHost
    }
    if ($netstats) {
        getNetstats $remoteHost
    }
    if ($mount) {
        mountShare $remoteHost
    }
    if ($mountedd) {
        getMountedDevices $remoteHost
    }
    if ($mounteds) {
        getMountedShares $remoteHost
    }
    if ($artefacts) {
        collectArtefacts $remoteHost
    }
    if ($drivers) {
        getDrivers $remoteHost
    }
    if ($typedurls) {
        getTypedURLs $remoteHost
    }
    if ($mailfile) {
        getMailFile $remoteHost
    }
    if ($module) {
        executeExternalModule $remoteHost $module $modargs
    }
    if (!$Global:COMMAND_SPECIFIED) {
        Write-Host "[i] Command not specified, opening share \\$remoteHost\C$"
        Invoke-Item \\$remoteHost\c$
    }
}

function executeExternalModule($remoteHost, $module, $modargs) {
    executeRemoteCommand $remoteHost $module $modargs $true
}

function changeWorkingDirectory() {
    Set-Location $MyInvocation.PSScriptRoot
}

function executeRemoteCommand($remoteHost, $module, $arguments=$null, $isExternalModule=$false) {
    $Global:COMMAND_SPECIFIED = $true
    if (!$isExternalModule) {
        $module = "mods\$command.ps1"
    }
    Invoke-Command -Session $Global:SESSION -FilePath $module -ArgumentList $arguments
}

function collectArtefacts($remoteHost, $user) {
    $Global:COMMAND_SPECIFIED = $true
    $lockedArtefacts = @("C:\Users\$user\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat")
    
    $unlockedArtefacts = @(
        "C:\ProgramData\McAfee\DesktopProtection", 
        "C:\Quarantine"
        # "C:\Users\$user\AppData\Local\Mozilla\Firefox\Profiles",
        # "C:\Users\$user\AppData\Local\Google\Chrome\User Data\Default\Cache"
    )

    # $lockedArtefacts | ForEach-Object {
    #     $artefactName = getFileName $_
    #     psexec.exe \\$remoteHost -u $Global:SERVICE_ID -p $Global:PASSWORD cmd /c C:\TEMP\copy.exe /FileNamePath:$_ /OutputPath:C:\TEMP
    #     downloadArtefact $remoteHost $artefactName $true
    # }

    $unlockedArtefacts | ForEach-Object {
        Write-Host "[*] Collecting $_..."
        downloadArtefact $remoteHost $_ $false
    }

    Write-Host "[*] Changing working directory.."
    cd C:\artefacts\$remoteHost
}

function getFileName($artefact) {
    return Split-Path $artefact -Leaf
}

function downloadArtefact($remoteHost, $artefactName, $isLocked) {
    # downloads artefacts from a remote machine host being investigated;
    $artefactsSaveLocation = "C:\artefacts\$remoteHost\"

    if ($isLocked) {
        $artefactSourceLocation = "\\$remoteHost\c$\TEMP\$artefactName"
    } else {
        $artefactLocation = Split-Path $artefactName -NoQualifier
        $artefactSourceLocation = "\\$remoteHost\c$" + $artefactLocation
    }

    Copy-Item $artefactSourceLocation -Destination $artefactsSaveLocation -Force -Recurse
}

function copyUtilsToRemoteHost($remoteHost) {
    Copy-Item ".\utils\copy.exe" -Destination \\$remoteHost\c$\TEMP\copy.exe -Force -Recurse
}

function establishRemoteSession($remoteHost) {
    Write-Host "[*] Connecting to" $remoteHost
    cmdkey.exe /add:$remoteHost /user:$Global:SERVICE_ID /pass:$Global:PASSWORD | Out-Null

    if (!$mailfile) {
        $Global:SESSION = New-PSSession -ComputerName $remoteHost -Credential $Global:CREDENTIALS
    }
    Write-Host "[*] Connected!"

}

main
