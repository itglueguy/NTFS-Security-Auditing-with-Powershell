cls
$ErrorActionPreference = "SilentlyContinue"

# Import the Powershell Script
. "Location of powershell functionNTFS_auditing.ps1"

#--------------------------------------------------------------------------


    $username = "username"
    $password = "password"
    $SecurePassword = ConvertTo-SecureString $password -asplaintext -force 
    $cred = New-Object System.Management.Automation.PSCredential $username,$SecurePassword


    # this direct attempts to filter out paths in which may possibly be user paths
    $ACLResults = Get-AclfromNetapp -controller "name of controller" -credential $cred -depth 2 | where {$_.Path -notlike "*ser*"}

    Report-ACLs -inputobject $ACLResults


    # users that have Evryone Permissions
    $paths = ($ACLResults  | where { $_.Identityreference -like "*S-1-5*" -and $_.path -notlike "*I$*" -and $_.isinherited -eq "True"} | select path).path
    <#
    foreach($path in $paths) {

    Remove-ExplcitPermissions -path $path
    }
    #>