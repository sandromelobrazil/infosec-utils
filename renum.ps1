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
    [switch]$regquery,
    [string]$key,
    [switch]$autoruns,
    [switch]$prefech,
    [switch]$typedurl,
    [switch]$recent,
    [switch]$downloads,
    [switch]$desktop,
    [switch]$dnscache
)

$Global:SERVICE_ID = "x"
$Global:PASSWORD = 'x'
$Global:COMMAND_SPECIFIED = $false

function main() {
    changeWorkingDirectory
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
        Write-Host "`r"
        Write-Host "[*] REnum (RemoteEnumeration) is a collection of convenience functions to speed-up an investigtion." -ForegroundColor Cyan
        Write-Host [!] Specify remote host with -remoteHost [host] and the -[command] you want to execute.`n[i] Example: renum-v0.1.ps1 -remoteHost 127.0.0.1 -ipcfg to get remote machine IP configuration.
        Write-Host "[!] Available commands:`n
        Tip:`t`t Omit the command to open C$ share
        -shell`t`t Get remote shell
        -arp`t`t Get ARP table
        -ipcfg`t`t Get IP configuration
        -route`t`t Get routing tables
        -procs`t`t Get running processes
        -conns`t`t Get established connections & ports listening
        -users`t`t Get users who have used the machine / Last Accessed Time shown
        -regquery`t Get registry key info. Use -key to specify the key
        -autoruns`t Get autoruns
        -usbenum`t Get USB devices that had been plugged
        -downloads`t Get contents of downloads folder / Last Accessed Time shown
        -desktop`t Get contents of desktop / Last Accessed Time shown
        -prefetch`t Get prefetches / Last Accessed Time shown.
        -recent`t`t Get recently accessed documents / Last Accessed Time shown
        -typedurl`t Get URLs that were typed in Explorer and IE
        -dnscache`t Get DNS cache entries`n"
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
    return $true
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

function isUserSpecified() {
    if ($user -eq "" -or $user -eq $null) {
        Write-Host "[!] Specify username with -user. Tip: you can run -users to get users who had engaged with this machine."
        break
    }
}

function getRecentItems($remoteHost) {
    isUserSpecified
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

function getDownloads($remoteHost) {
    isUserSpecified
    $command = "dir C:\Users\$user\Downloads /TA"
    executeRemotePsExec $remoteHost $command
}

function getDesktop($remoteHost) {
    isUserSpecified
    $command = "dir C:\Users\$user\Desktop /TA"
    executeRemotePsExec $remoteHost $command
}

function getUSBEnum($remoteHost) {
    $keys = @(
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR',    
    'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\USBSTOR', 
    'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\USBSTOR')

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
        Write-Host [!] Specify a key you want to query with -key
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
    if ($downloads) {
        getDownloads $remoteHost
    }
    if ($desktop) {
        getDesktop $remoteHost
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
    .\utils\psexec.exe \\$remoteHost -u $Global:SERVICE_ID -p $Global:PASSWORD -s cmd /c $command
}

function collectArtefacts($remoteHost, $user) {
    $lockedArtefacts = @("C:\Users\$user\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat")
    
    $unlockedArtefacts = @(
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
    # Copy-Item \\$workstation\c$\Quarantine\ -Destination $Dest -Force -Recurse
    Copy-Item $artefactSourceLocation -Destination C:\Users\artefacts\$remoteHost\ -Force -Recurse
}

function copyUtilsToRemoteHost($remoteHost) {
    Copy-Item ".\utils\RawCopy64.exe" -Destination \\$remoteHost\c$\TEMP\RawCopy64.exe -Force -Recurse
}

function storeCredentialsForRemoteHost($remoteHost) {
    cmdkey.exe /add:$remoteHost /user:$Global:SERVICE_ID /pass:$Global:PASSWORD | Out-Null
    Write-Host "[*] Authenticated to" $remoteHost
}

main
