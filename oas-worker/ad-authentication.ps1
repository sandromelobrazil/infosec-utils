$Global:PASSWORD = ConvertTo-SecureString "" -AsPlainText -Force
$Global:CREDENTIALS = New-Object System.Management.Automation.PSCredential(“”, $Global:PASSWORD)

function getCredentials() {
    if ($Global:CREDENTIALS -ne $null) {
        return $Global:CREDENTIALS
    } else {
        return authenticate
    }
}

function authenticate() {
    $Global:CREDENTIALS = Get-Credential
    return $Global:CREDENTIALS
}
