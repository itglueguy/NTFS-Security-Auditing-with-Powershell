# Import the Powershell Script
. "Location of your Powershell Script\NTFS_auditing.ps1"

cls

# import the Computer / Keyword File
$computer_keywords = import-csv "C:\scripts\Current_dev\NTFS\Computer_keywordfilters.csv"

#---------------------------------------------------------

# Specify the computers you want to scan for

$computers = "Your Computer"

#---------------------------------------------------------

$username = "Username"
    $password = "Password"
    $SecurePassword = ConvertTo-SecureString $password -asplaintext -force 
    $cred = New-Object System.Management.Automation.PSCredential $username,$SecurePassword

#---------------------------------------------------------

$ACLResults = foreach($computer in $computers) {

    # extract the right keywords
    $format1 = ($computer_keywords | where {$_.Computer -eq $computer} | select Keyword).Keyword

    $volumefilter = ($computer_keywords | where {$_.Computer -eq $computer} | select Volume_filter1).Volume_filter1
    $keyword = $format1.split("|")

   Get-AclfromWinNetapp -controller $controller -computer $computer -credential $cred -depth 1


}

# take out users
$ACLResults2 = $ACLResults | where {$_.path -notlike "*H$*"}

Report-ACLs -inputobject $ACLResults2


