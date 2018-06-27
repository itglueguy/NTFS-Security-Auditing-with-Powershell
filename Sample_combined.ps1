<#
Title:
Powershell NTFS Auditing

Purpose:
-Audit the ACL's of both Windows and Netapp Based Shares
-Audit Open Files on either Windows and Netapp shares to get recommendaitons on users to add to groups
-Report of particular Groups in which should perhaps be modified

Last Updated:
06/25/2018


#>

cls

# Import the Powershell Script
. "Location of your Powershell Script\NTFS_auditing.ps1"

# import the Computer / Keyword File
$computer_keywords = import-csv "C:\scripts\Current_dev\NTFS\Computer_keywordfilters.csv"

#---------------------------------------------------------

# Specify the computers you want to scan for

$computers = "computer or cifs server name"

#---------------------------------------------------------

# Credential Information Goes Here
$username = "username"
    $password = "password"
    $SecurePassword = ConvertTo-SecureString $password -asplaintext -force 
    $cred = New-Object System.Management.Automation.PSCredential $username,$SecurePassword

#---------------------------------------------------------

# Process the ACL permissions from the array of computers
$ACLResults = Get-AclfromWinNetapp -controller "controller" -computer $computers -credential $cred -depth 1

#---------------------------------------------------------

# take out users
$ACLResults2 = $ACLResults

$ACLResults2 | ft


$ACLResults2 | ft

# Report on interesting ACL Trends
Report-ACLs -inputobject $ACLResults2

#-------------------------- SEE open files
<#
$ACLResults = foreach($computer in $computers) {

    # extract the right keywords
    $format1 = ($computer_keywords | where {$_.Computer -eq $computer} | select Keyword).Keyword

    $volumefilter = ($computer_keywords | where {$_.Computer -eq $computer} | select Volume_filter1).Volume_filter1
    $keyword = $format1.split("|")

    Get-OpenAclbyKeyword


}
#>
