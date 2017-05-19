$programs = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# this is specifially ignores patches and updates
foreach ($program in $programs) {
    if ($program.DisplayName -ne $null -and $program.DisplayName.length -gt 1 -and -not ($program.DisplayName -like "*security update*" -or $program.DisplayName -like "*update for*" -or $program.DisplayName -like "*hotfix*" -or $program.DisplayName -like "*service pack*")) {
        
        if ($program.InstallDate -eq $null) {
            $installDate = "No Install Date"
        } else {
           $installDate = $program.InstallDate
        }
        
        $installDate + "`t`t" + $program.DisplayName + " by " + $program.Publisher
    }
}