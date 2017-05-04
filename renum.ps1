param(
    [string]$remoteHost,
    [string]$user,
    [string]$serviceID,
    [string]$password,

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
    [switch]$prefech,
    [switch]$typedurl,
    [switch]$recent,
    [switch]$dnscache
)

$Global:SERVICE_ID = $serviceID
$Global:PASSWORD = $password

function main() {
    removeCredentials
    processArguments
    storeCredentialsForRemoteHost $remoteHost
    # copyUtilsToRemoteHost $remoteHost

    if ($shell) {
        getShell $remoteHost
    } 

    enumerateSystem $remoteHost   
    # collectArtefacts $remoteHost $user
    removeCredentials
}

function removeCredentials() {
    cmdkey.exe /delete:$remoteHost | Out-Null
}

function printHelp() {
        Write-Host [!] Specify remote host with -remoteHost [host]!
        Write-Host "[!] Available switches:`n
        -shell`t`t Get remote shell
        -arp`t`t Get ARP table
        -ipcfg`t`t Get IP configuration
        -route`t`t Get routing tables
        -procs`t`t Get running processes
        -conns`t`t Get established connections
        -users`t`t Get users who have used the machine / Last Accessed Time
        -regquery`t Query registry by a key. Use -key to specify the key
        -autoruns`t Get autoruns
        -prefetch`t Get prefetches / Last Accessed Time
        -recent`t`t Get recently accessed items / Last Accessed Time
        -typedurl`t`t Get Explorer typed URLs
        -dnscache`t Get DNS cache entries"
        break
}

function processArguments() {
    if ($remoteHost -eq "") {
        printHelp
    }
}

function getIPConfig($remoteHost) {
    $command = "C:\Windows\system32\ipconfig.exe /all"
    executeRemotePsExec $remoteHost $command
}

function getRoutingTable($remoteHost) {
    $command = "C:\Windows\system32\netstat.exe -r"
    executeRemotePsExec $remoteHost $command
}

function getDNSCache($remoteHost) {
    $command = "C:\Windows\system32\ipconfig.exe /displaydns"
    executeRemotePsExec $remoteHost $command
}

function getUsers($remoteHost) {
    $command = "dir C:\Users /TA"
    executeRemotePsExec $remoteHost $command
}

function getRecentItems($remoteHost) {
    if ($user -eq "" -or $user -eq $null) {
        Write-Host [!] Specify username with -user
        break
    }
    $command = "dir /TA /A:-D C:\Users\$user\AppData\Roaming\Microsoft\Windows\Recent"
    executeRemotePsExec $remoteHost $command
}

function getConnections($remoteHost) {
    $command = "C:\Windows\system32\netstat.exe -anb"
    executeRemotePsExec $remoteHost $command
}

function getShell($remoteHost) {
    $command = "C:\Windows\system32\cmd.exe"
    executeRemotePsExec $remoteHost $command
}

function getProcessList($remoteHost) {
    $command = "C:\Windows\system32\tasklist.exe"
    executeRemotePsExec $remoteHost $command
}

function getARPTable($remoteHost) {
    $command = "C:\Windows\system32\arp.exe -a"
    executeRemotePsExec $remoteHost $command
}

function getPrefetches($remoteHost) {
    $command = "dir C:\Windows\Prefetch /TA"
    executeRemotePsExec $remoteHost $command
}

function getUSBEnum($remoteHost) {
    $keys = @('HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\USBSTOR', 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\USBSTOR')
    $keys | ForEach-Object {
        $command = 'C:\Windows\system32\reg.exe query ' + $_
        executeRemotePsExec $remoteHost $command
    }
}

function getAutoruns($remoteHost) {
    $keys = @(
        'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $keys | ForEach-Object { queryRegKey $remoteHost $_ }           
}

function queryRegKey($remoteHost, $key) {
    if ($key -eq "" -or $key -eq $null) {
        Write-Host [!] Specify a key you want to query qith -regkey
        break
    }
    $command = 'C:\Windows\system32\reg.exe query "' + $key + '"'
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
    if ($prefech) {
        getPrefetches $remoteHost
    }
    if ($recent) {
        getRecentItems $remoteHost
    }
}

function executeRemotePsExec($remoteHost, $command) {
    psexec.exe \\$remoteHost -u $Global:SERVICE_ID -p $Global:PASSWORD -s cmd /c $command
}

function collectArtefacts($remoteHost, $user) {
    # $lockedArtefacts = @("C:\Users\$user\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat")
    
    $unlockedArtefacts = @(
        "C:\ProgramData\McAfee\DesktopProtection", 
        "C:\Quarantine", 
        "C:\Users\$user\AppData\Local\Mozilla\Firefox\Profiles",
        "C:\Users\$user\AppData\Local\Google\Chrome\User Data\Default\Cache"
    )

    # $lockedArtefacts | ForEach-Object {
    #     $artefactName = getFileName $_
    #     psexec.exe \\$remoteHost -u $Global:SERVICE_ID -p $Global:PASSWORD cmd /c C:\TEMP\RawCopy64.exe /FileNamePath:$_ /OutputPath:C:\TEMP
    #     downloadArtefact $remoteHost $artefactName $true
    # }

    $unlockedArtefacts | ForEach-Object {
        Write-Host "[*] Collecting..."
        downloadArtefact $remoteHost $_ $false
    }
}

function getFileName($artefact) {
    return Split-Path $artefact -Leaf
}

function downloadArtefact($remoteHost, $artefactName, $isLocked) {
    # downloads artefacts from a remote machine host being investigated;
    if ($isLocked) {
        $artefactSourceLocation = "\\$remoteHost\c$\TEMP\$artefactName"
    } else {
        $artefactLocation = Split-Path $artefactName -NoQualifier
        $artefactSourceLocation = "\\$remoteHost\c$" + $artefactLocation
    }
    Copy-Item $artefactSourceLocation -Destination C:\Users\Documents\Scripts\artefacts-worker\$remoteHost\ -Force -Recurse
}

function copyUtilsToRemoteHost($remoteHost) {
    Copy-Item ".\utils\RawCopy64.exe" -Destination \\$remoteHost\c$\TEMP\RawCopy64.exe -Force -Recurse
}

function storeCredentialsForRemoteHost($remoteHost) {
    cmdkey.exe /add:$remoteHost /user:$Global:SERVICE_ID /pass:$Global:PASSWORD | Out-Null
    Write-Host "[*] Authenticated to" $remoteHost
}

main
