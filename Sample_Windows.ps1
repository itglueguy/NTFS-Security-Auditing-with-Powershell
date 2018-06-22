cls
$ErrorActionPreference = "SilentlyContinue"

# Import the Powershell Script
. "Location of powershell functionNTFS_auditing.ps1"

#--------------------------------------------------------------------------



    # this direct attempts to filter out paths in which may possibly be user paths
    $ACLResults = Get-AclfromWindows -computer "name of computer" -depth "numeric Depth"

    Report-ACLs -inputobject $ACLResults


    # Explicit permissions to remove
    $paths = ($ACLResults  | where { $_.Identityreference -like "*S-1-5*" -and $_.path -notlike "*I$*" -and $_.isinherited -eq "True"} | select path).path
    
    <#
    foreach($path in $paths) {

    Remove-ExplcitPermissions -path $path
    }
    #>