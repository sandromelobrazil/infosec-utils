function printHelp() {
    Write-Host "
      ___           ___           ___           ___           ___     
     /\  \         /\  \         /\__\         /\__\         /\__\    
    /::\  \       /::\  \       /::|  |       /:/  /        /::|  |   
   /:/\:\  \     /:/\:\  \     /:|:|  |      /:/  /        /:|:|  |   
  /::\~\:\  \   /::\~\:\  \   /:/|:|  |__   /:/  /  ___   /:/|:|__|__ 
 /:/\:\ \:\__\ /:/\:\ \:\__\ /:/ |:| /\__\ /:/__/  /\__\ /:/ |::::\__\
 \/_|::\/:/  / \:\~\:\ \/__/ \/__|:|/:/  / \:\  \ /:/  / \/__/~~/:/  /
    |:|::/  /   \:\ \:\__\       |:/:/  /   \:\  /:/  /        /:/  / 
    |:|\/__/     \:\ \/__/       |::/  /     \:\/:/  /        /:/  /  
    |:|  |        \:\__\         /:/  /       \::/  /        /:/  /   
     \|__|         \/__/         \/__/         \/__/         \/__/    
        
        " -ForegroundColor Yellow

        Write-Host "[*] REnum (RemoteEnumeration) is a collection of convenience functions to speed-up an investigtion." -ForegroundColor Cyan
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
