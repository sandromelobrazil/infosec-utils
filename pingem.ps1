[array] $MACHINES = 
"x1",
"x2"

$sleep = 60*60

function getIPs($string) {
    $IPMatched = $string -match '([\d]{1,}\.){3}([\d]{1,})'
    return $IPMatched -replace (':', "")
}   

function main(){
    while ($true) { 
    
        Get-Date
    
        $MACHINES.ForEach({
            #send 1 byte once
            $isHostUp = PING.EXE $_ -n 1 -l 1 

            if ($isHostUp -like '*Received = 1*') {
                $hostIP = getIPs $isHostUp
                Write-Host "$_ seems up! (" $hostIP[0] ")" -ForegroundColor Green
            } else {
                Write-Host "$_ seems down"
            }
        })
    
        Start-Sleep $sleep
        Write-Host `n`n
    }
}

main