param(
    [string]$remoteHost,
    [string]$user,
    [string]$password,
    [switch]$shell,
    [switch]$arp,
    [switch]$ipcfg,
    [switch]$route,
    [switch]$conns,
    [switch]$procs,
    [switch]$users,
    [switch]$usbenum,
    [switch]$devices,
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
    [switch]$nbtstat,
    [switch]$desktop,
    [switch]$typedurls,
    [switch]$artefacts,
    [switch]$netstats,
    [switch]$dnscache,
    [switch]$mailfile,
    [switch]$h
)

$Global:SERVICE_ID = "x"
$Global:PASSWORD = 'x'
$Global:COMMAND_SPECIFIED = $false
$Global:MODS_PATH = ".\mods\"
$Global:UTILS_PATH = ".\utils\"
$Global:MODULES = @{
    autoruns = "autoruns"
    typedurls = "typedurls"}

# TODO ///////////////////////
# make it even more modular with powershell mods

function main() {
    changeWorkingDirectory
    processArguments
    storeCredentialsForRemoteHost $remoteHost

    if ($h) {
        printHelp
    } 
    if ($shell) {
        getShell $remoteHost
    } 

    enumerateSystem $remoteHost   
    removeCredentials
}

function removeCredentials() {
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
        Tip:`t`t Omit the command to open C$ share without mounting it.. or use -mount to do it
        -shell`t`t Get remote shell
        -arp`t`t Get ARP table
        -ipcfg`t`t Get IP configuration
        -route`t`t Get routing tables
        -procs`t`t Get running processes
        -conns`t`t Get established connections & ports listening
        -users`t`t Get users who have used the machine / Last Accessed Time shown
        -regquery`t Get registry key info. Use -key to specify the key
        -autoruns`t Get autoruns from popular persistence locations
        -mountedd`t Get currently mounted physical device letters
        -mounteds`t Get currently mounted shares
        -usbenum`t Get USB devices that had been plugged in
        -drivers`t Get installed drivers
        -nbtstat`t Get NetBios cached names
        -typedurls`t Get URLs user typed in IE
        -mailfile`t Open user (-user <username>) domino mailfile.
        -netstats`t Get uptime, permission and password violations count
        -downloads`t Get contents of downloads folder (-user <username>) / Last Accessed Time shown
        -desktop`t Get contents of desktop (-user <username>) / Last Accessed Time shown
        -prefetch`t Get prefetches / Last Accessed Time shown
        -recent`t`t Get recently accessed documents (-user <username>) / Last Accessed Time shown
        -dnscache`t Get DNS cache entries`n"
        break
}

function processArguments() {
    if ($remoteHost -eq "") {
        printHelp
    }
}

function getIPConfig($remoteHost) {
    $command = "ipconfig /all"
    executeRemotePsExec $remoteHost $command
    return $true
}

function getRoutingTable($remoteHost) {
    $command = "netstat -r"
    executeRemotePsExec $remoteHost $command
}

function getDNSCache($remoteHost) {
    $command = "ipconfig /displaydns"
    executeRemotePsExec $remoteHost $command
}

function getNetstats($remoteHost) {
    $command = "net statistics server"
    executeRemotePsExec $remoteHost $command
}

function getUsers($remoteHost) {
    $command = "dir C:\Users /TA"
    executeRemotePsExec $remoteHost $command
}

function isUserSpecified() {
    if ($user -eq "" -or $user -eq $null) {
        $user = Read-Host -Prompt "[!] Enter username of the destination machine (Tip: switch -users shows users who had engaged with the remote machine)"
        Write-Host "[i] Tip: use -user <user> to avoid this prompt in the future..."
        return $user
    }
}

function getRecentItems($remoteHost) {
    $user = isUserSpecified
    $command = "dir /TA /A:-D C:\Users\$user\AppData\Roaming\Microsoft\Windows\Recent"
    executeRemotePsExec $remoteHost $command
}

function getConnections($remoteHost) {
    $command = "netstat -anb"
    executeRemotePsExec $remoteHost $command
}

function getNetbiosCache($remoteHost) {
    $command = "nbtstat -A $remoteHost -c"
    executeRemotePsExec $remoteHost $command
}

function getShell($remoteHost) {
    $command = "cmd"
    executeRemotePsExec $remoteHost $command
}

function getProcessList($remoteHost) {
    $command = "tasklist"
    executeRemotePsExec $remoteHost $command
}

function getARPTable($remoteHost) {
    $command = "arp -a"
    executeRemotePsExec $remoteHost $command
}

function getPrefetches($remoteHost) {
    $command = "dir C:\Windows\Prefetch /TA"
    executeRemotePsExec $remoteHost $command
}

function getDownloads($remoteHost) {
    $user = isUserSpecified
    $command = "dir C:\Users\$user\Downloads /TA"
    executeRemotePsExec $remoteHost $command
}

function getDesktop($remoteHost) {
    $user = isUserSpecified
    $command = "dir C:\Users\$user\Desktop /TA"
    executeRemotePsExec $remoteHost $command
}

function getUSBEnum($remoteHost) {
    $keys = @(
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR',    
    'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\USBSTOR', 
    'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\USBSTOR')

    $keys | ForEach-Object {
        $command = 'reg query ' + $_
        executeRemotePsExec $remoteHost $command
    }
}

function getMountedShares($remoteHost) {
    $command = 'net use'
    executeRemotePsExec $remoteHost $command
}

function getMountedDevices($remoteHost) {
    $keys = @(
    'HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices')

    $keys | ForEach-Object {
        $command = 'reg query ' + $_
        executeRemotePsExec $remoteHost $command
    }
}

function getAutoruns($remoteHost) {
    $user = isUserSpecified
    $arguments = $user
    executePSModule $Global:MODULES.autoruns $remoteHost $arguments
}

function getTypedURLs($remoteHost) {
    $user = isUserSpecified
    $arguments = $user
    executePSModule $Global:MODULES.typedurls $remoteHost $arguments
}

function getModuleInfo ($moduleName) {
    $moduleInfo = @{
        fileName = $moduleName + ".ps1"
        path = $Global:MODS_PATH + $moduleName + ".ps1"
    }
    return $moduleInfo
}

function executePSModule($moduleName, $remoteHost, $arguments) {
    $module = getModuleInfo $moduleName
    $moduleSourcePath = $module.path
    
    $destinationFolder = "temp\"
    $moduleDestinationFolder = "\\" + "$remoteHost\c$\$destinationFolder"
    $moduleDestinationPath = "$moduleDestinationFolder\" + $module.fileName   

    Copy-Item $moduleSourcePath -Destination $moduleDestinationFolder -Force -Recurse
    $command = "powershell " + "C:\" + "$destinationFolder\" + $module.fileName + " " + $arguments

    executeRemotePsExec $remoteHost $command
    Remove-Item $moduleDestinationPath
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
    if ($key -eq "" -or $key -eq $null) {
        Write-Host [!] Specify the key you want to query with -key
        break
    }
    $command = 'reg query "' + $key + '"'
    executeRemotePsExec $remoteHost $command
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
    if ($nbtstat) {
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

    if (!$Global:COMMAND_SPECIFIED) {
        Write-Host "[i] Command not specified, opening share \\$remoteHost\C$"
        Invoke-Item \\$remoteHost\c$
    }
}

function changeWorkingDirectory() {
    Set-Location $MyInvocation.PSScriptRoot
}

function executeRemotePsExec($remoteHost, $command) {
    $Global:COMMAND_SPECIFIED = $true
    .\utils\psexec.exe -accepteula \\$remoteHost -u $Global:SERVICE_ID -p $Global:PASSWORD -s cmd /c $command
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

function storeCredentialsForRemoteHost($remoteHost) {
    cmdkey.exe /add:$remoteHost /user:$Global:SERVICE_ID /pass:$Global:PASSWORD | Out-Null
    Write-Host "[*] Authenticated to" $remoteHost
}

main
