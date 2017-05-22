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
    [switch]$programs,
    [switch]$mft,
    [switch]$mailfile,
    [switch]$sniffer,
    [string]$module,
    [string]$modargs,
    [switch]$h
)

# todo accept IP as a remote host
# make sniffer save output to the File
# make snifffer save to PCAP
# fix arguments being passed into the external module
# check sheduled tasks in persistence module
# todo: order help menu

# If these not set, you will be prompted for your service id credentials. Setting these is not encouraged.
$Global:SERVICE_ID = ""
$Global:PASSWORD = ''
$Global:SESSION = ""
$Global:COMMAND_SPECIFIED = $false
$Global:MODS_PATH = ".\mods\"
$Global:UTILS_PATH = ".\utils\"

function main() {
    changeWorkingDirectory
    processArguments
        
    if ($h) {
        printHelp
    } 
    
    establishRemoteSession $Global:REMOTE_HOST
    
    if ($shell) {
        getShell $Global:REMOTE_HOST
    } 

    enumerateSystem $Global:REMOTE_HOST   
    closeRemoteSession
}

function closeRemoteSession() {
    if (!$mailfile) {
        Get-PSSession | Remove-PSSession
    }
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
        Write-Host [i] Specify remote host and -[command] you want to execute.`n[i] Example: renum-v0.1.ps1 127.0.0.1 -ipcfg to get remote machine IP configuration.`n
        Write-Host "[i] Available commands:`n
        Tip:`t`t Omit the command to open C$ share without mounting it... or use -mount to do it
        -shell`t`t Get remote shell
        -arp`t`t Get ARP cache
        -ipcfg`t`t Get IP configuration
        -route`t`t Get routing tables
        -procs`t`t Get running processes
        -conns`t`t Get established connections & ports listening
        -users`t`t Get users who have used the machine
        -regquery`t Get registry key info. Use -key to specify the 'key'. Mind the quotes.
        -autoruns`t Get autoruns from popular persistence locations
        -mountedd`t Get currently mounted physical device letters
        -mounteds`t Get currently mounted shares
        -programs`t Get currently installed programs
        -module`t`t Specify path of an external module to be executed. -modargs to supply arguments
        -usbenum`t Get USB devices that had been plugged in
        -drivers`t Get installed drivers
        -sniffer`t Sniff traffic
        -nbtcache`t Get NetBios cache
        -typedurls`t Get URLs  typed in Internet Explorer address bar. Requires -user <username>
        -mailfile`t Open domino mailfile. Requires -user <username>
        -netstats`t Get uptime, permissions and password violations count
        -downloads`t Get contents of the downloads folder. Requires -user <username>
        -desktop`t Get contents desktop contents. Requires -user <username>
        -prefetch`t Get prefetches
        -mft`t`t Get Master File Table
        -recent`t`t Get recently accessed documents. Requires -user <username>
        -dnscache`t Get DNS cache`n"
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
    }
    catch {
        
    }
}

function processCredentials() {
    if ($Global:PASSWORD -eq '' -or $Global:SERVICE_ID -eq '') {
        $Global:CREDENTIALS = Get-Credential
    } else {
        $Global:PASSWORD2 = ConvertTo-SecureString $Global:PASSWORD -AsPlainText -Force
        $Global:CREDENTIALS = New-Object System.Management.Automation.PSCredential($Global:SERVICE_ID, $Global:PASSWORD2)
    }
}

function getIPConfig($Global:REMOTE_HOST) {
    $command = "ipcfg"
    executeRemoteCommand $Global:REMOTE_HOST $command
    return $true
}

function getRoutingTable($Global:REMOTE_HOST) {
    $command = "routing"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getDNSCache($Global:REMOTE_HOST) {
    $command = "dnscache"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getNetstats($Global:REMOTE_HOST) {
    $command = "netstats"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getUsers($Global:REMOTE_HOST) {
    $command = "users"
    executeRemoteCommand $Global:REMOTE_HOST $command
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

function getRecentItems($Global:REMOTE_HOST) {
    $user = isUserSpecified
    $command = "recent"
    executeRemoteCommand $Global:REMOTE_HOST $command $user
}

function sniffTraffic($Global:REMOTE_HOST) {
    $command = "sniffer"
    $ignoreIP = (Test-Connection -ComputerName (hostname) -Count 1  | Select IPV4Address).IPV4Address.IPAddressToString
    executeRemoteCommand $Global:REMOTE_HOST $command $ignoreIP
}

function getMFT($Global:REMOTE_HOST) {
    $command = "mft"
    copyUtilsToRemoteHost $Global:REMOTE_HOST
    executeRemoteCommand $Global:REMOTE_HOST $command
    downloadArtefact $Global:REMOTE_HOST "$Global:REMOTE_HOST.mft"
    parseMFT $Global:REMOTE_HOST
}

function parseMFT($Global:REMOTE_HOST) {
    $mftLocation = "C:\artefacts\$Global:REMOTE_HOST.mft"
    $mftReport = "C:\artefacts\$Global:REMOTE_HOST-mft.xls"
    
    Write-Host "[*] Parsing $Global:REMOTE_HOST.mft..."
    .\utils\mftdump.exe $mftLocation /o $mftReport
    
    Write-Host "[*] Opening $Global:REMOTE_HOST MFT, please wait..."
    Invoke-Item $mftReport
}

function getConnections($Global:REMOTE_HOST) {
    $command = "connections"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getNetbiosCache($Global:REMOTE_HOST) {
    $command = "netbioscache"
    executeRemoteCommand $Global:REMOTE_HOST $command $Global:REMOTE_HOST
}

function getShell($Global:REMOTE_HOST) {
    $Global:COMMAND_SPECIFIED = $true
    Enter-PSSession -ComputerName $Global:REMOTE_HOST -Credential $Global:CREDENTIALS
}

function getProcessList($Global:REMOTE_HOST) {
    $command = "tasklist"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getARPTable($Global:REMOTE_HOST) {
    $command = "arp"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getPrefetches($Global:REMOTE_HOST) {
    $command = "prefetches"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getDownloads($Global:REMOTE_HOST) {
    $user = isUserSpecified
    $command = "downloads"
    executeRemoteCommand $Global:REMOTE_HOST $command $user
}

function getDesktop($Global:REMOTE_HOST) {
    $user = isUserSpecified
    $command = "desktop"
    executeRemoteCommand $Global:REMOTE_HOST $command $user
}

function getUSBEnum($Global:REMOTE_HOST) {
    $command = "usbenumeration"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getMountedShares($Global:REMOTE_HOST) {
    $command = 'mountedshares'
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getInstalledPrograms($Global:REMOTE_HOST) {
    $command = 'programs'
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getMountedDevices($Global:REMOTE_HOST) {
    $command = "mounteddevices"
    executeRemoteCommand $Global:REMOTE_HOST $command
}

function getAutoruns($Global:REMOTE_HOST) {
    $user = isUserSpecified
    $command = "autoruns"
    executeRemoteCommand $Global:REMOTE_HOST $command $user
}

function getTypedURLs($Global:REMOTE_HOST) {
    $user = isUserSpecified
    $command = "typedurls"
    executeRemoteCommand $Global:REMOTE_HOST $command $user
}

function mountShare($Global:REMOTE_HOST) {
    net use * \\$Global:REMOTE_HOST\c$ /user:$Global:SERVICE_ID $Global:PASSWORD
    Invoke-Item \\$Global:REMOTE_HOST\c$
}

function getMailFile($Global:REMOTE_HOST) {
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

function getDrivers($Global:REMOTE_HOST) {
    $Global:COMMAND_SPECIFIED = $true
    driverquery /s $Global:REMOTE_HOST /u $Global:SERVICE_ID /p $Global:PASSWORD
}

function queryRegKey($Global:REMOTE_HOST, $key) {
    $command = 'regquery'
    executeRemoteCommand $Global:REMOTE_HOST $command $key
}

function enumerateSystem($Global:REMOTE_HOST) {
    if ($arp) {
        getARPTable $Global:REMOTE_HOST
    }
    if ($ipcfg) {
        getIPConfig $Global:REMOTE_HOST
    }
    if ($route) {
        getRoutingTable $Global:REMOTE_HOST
    }
    if ($conns) {
        getConnections $Global:REMOTE_HOST
    }
    if ($procs) {
        getProcessList $Global:REMOTE_HOST
    }
    if ($dnscache) {
        getDNSCache $Global:REMOTE_HOST
    }
    if ($mft) {
        getMFT $Global:REMOTE_HOST
    }
    if ($users) {
        getUsers $Global:REMOTE_HOST
    }
    if ($usbenum) {
        getUSBEnum $Global:REMOTE_HOST
    }
    if ($regquery) {
        queryRegKey $Global:REMOTE_HOST $key
    }
    if ($typedurl) {
        getTypedURLs $Global:REMOTE_HOST
    }
    if ($autoruns) {
        getAutoruns $Global:REMOTE_HOST
    }
    if ($prefetch) {
        getPrefetches $Global:REMOTE_HOST
    }
    if ($recent) {
        getRecentItems $Global:REMOTE_HOST
    }
    if ($sniffer) {
        sniffTraffic $Global:REMOTE_HOST
    }
    if ($nbtcache) {
        getNetbiosCache $Global:REMOTE_HOST
    }
    if ($downloads) {
        getDownloads $Global:REMOTE_HOST
    }
    if ($desktop) {
        getDesktop $Global:REMOTE_HOST
    }
    if ($netstats) {
        getNetstats $Global:REMOTE_HOST
    }
    if ($mount) {
        mountShare $Global:REMOTE_HOST
    }
    if ($mountedd) {
        getMountedDevices $Global:REMOTE_HOST
    }
    if ($mounteds) {
        getMountedShares $Global:REMOTE_HOST
    }
    if ($artefacts) {
        collectArtefacts $Global:REMOTE_HOST
    }
    if ($drivers) {
        getDrivers $Global:REMOTE_HOST
    }
    if ($programs) {
        getInstalledPrograms $Global:REMOTE_HOST
    }
    if ($typedurls) {
        getTypedURLs $Global:REMOTE_HOST
    }
    if ($mailfile) {
        getMailFile $Global:REMOTE_HOST
    }
    if ($module) {
        executeExternalModule $Global:REMOTE_HOST $module $modargs
    }
    if (!$Global:COMMAND_SPECIFIED) {
        Write-Host "[i] Command not specified, opening share \\$Global:REMOTE_HOST\C$"
        Invoke-Item \\$Global:REMOTE_HOST\c$
    }
}

function executeExternalModule($Global:REMOTE_HOST, $module, $modargs) {
    executeRemoteCommand $Global:REMOTE_HOST $module $modargs $true
}

function changeWorkingDirectory() {
    Set-Location $MyInvocation.PSScriptRoot
}

function executeRemoteCommand($Global:REMOTE_HOST, $module, $arguments=$null, $isExternalModule=$false) {
    $Global:COMMAND_SPECIFIED = $true
    if (!$isExternalModule) {
        $module = "mods\$command.ps1"
    }
    Invoke-Command -Session $Global:SESSION -FilePath $module -ArgumentList $arguments
}

function downloadArtefact($Global:REMOTE_HOST, $artefactName, $isLocked=$false) {
    $artefactsSaveLocation = "C:\artefacts\" + $artefactName
    $artefactSourceLocation = "\\" + $Global:REMOTE_HOST + "\c$\temp\$artefactName"
    Write-Host "[*] Downloading $artefactName to $artefactsSaveLocation"
    Copy-Item $artefactSourceLocation -Destination $artefactsSaveLocation -Force -Recurse
}

function copyUtilsToRemoteHost($Global:REMOTE_HOST) {
    Copy-Item .\utils\copy.exe -Destination \\$Global:REMOTE_HOST\c$\TEMP\copy.exe -Recurse -Force
}

function notifyConnectionError() {
    Write-Host "[*] Not connected. Machine offline or misspelled..."
    break
}

function establishRemoteSession($Global:REMOTE_HOST) {
    Write-Host "[*] Connecting to" $Global:REMOTE_HOST
    cmdkey.exe /add:$Global:REMOTE_HOST /user:$Global:SERVICE_ID /pass:$Global:PASSWORD | Out-Null

    if (!$mailfile) {
        $Global:SESSION = New-PSSession -ComputerName $Global:REMOTE_HOST -Credential $Global:CREDENTIALS
        if ($Global:SESSION) {
            Write-Host "[*] Connected!"
        } else {
            notifyConnectionError
        }
    }
}

main
