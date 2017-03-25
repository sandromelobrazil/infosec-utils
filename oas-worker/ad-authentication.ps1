$Global:PASSWORD = ConvertTo-SecureString "" -AsPlainText -Force
$Global:CREDENTIALS = New-Object System.Management.Automation.PSCredential(“”, $Global:PASSWORD)
#$Global:CREDENTIALS = Get-Credential
# $Global:CREDENTIALS = $Global:CREDENTIALS

function getCredentials() {
    
    if ($Global:CREDENTIALS -ne $null) {
        return $Global:CREDENTIALS
    } else {
        return authenticate
    }
}

function authenticate(){
    $Global:CREDENTIALS = Get-Credential
    return $Global:CREDENTIALS
}
