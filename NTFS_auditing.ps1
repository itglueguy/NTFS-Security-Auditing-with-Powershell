
    # Checking if the NTFS Security Module has been installed

    if (!(Get-Module "NTFSSecurity")) {

        write-host "Prompting to install the NTFS Security Module"

        Install-Module -name "NTFSSecurity"
    }

    # checking if the ActiveDirectory Module has beem Loaded

    if (!(Get-Module "ActiveDirectory")) {

        write-host "Active Directory Module is not installed...Please load the RSAT Tools for your Operating System"

    }

    # checking if the DataOntap Module has beem Loaded

    if (!(Get-Module "DataOntap")) {

        write-host "Netapp DataOntp Module is not installed...Please load the Netapp Powershell Commandlets for your Operating System"

    }

#--------------------------------------------------------------------------------------------------------------------------------------------------

Function Remove-OSCSID
{   
<#
		.SYNOPSIS
		Function Remove-OSCSID is an advanced function which can reomve the orphaned SID from file/folders ACL.
		.DESCRIPTION
		Function Remove-OSCSID is an advanced function which can reomve the orphaned SID from file/folders ACL.
		.PARAMETER Path
		Indicates the path of the specified file or folder.
		.PARAMETER Recurse
		Indicates check the child items of the specified folder.
		.EXAMPLE
		Remove-OSCSID  -path C:\acls.txt
		
		Remove orphaned SIDs from C:\acls.txt
		.EXAMPLE
		Remove-OSCSID  -Path C:\test -Recurse
		
		Remove orphaned SIDs from all the files/folders ACL of C:\test
		.LINK
		Windows PowerShell Advanced Function
		http://technet.microsoft.com/en-us/library/dd315326.aspx
		.LINK
		Get-Acl
		http://technet.microsoft.com/en-us/library/hh849802.aspx
		.LINK
		Set-Acl
		http://technet.microsoft.com/en-us/library/hh849810.aspx
	#>

	[CmdletBinding()]
	Param
	(
		#Define parameters
		[Parameter(Mandatory=$true,Position=1)]
		[String]$Path,		
		[Parameter(Mandatory=$false,Position=2)]
		[Switch]$Recurse
	)
	#Try to get the object ,and define a flag to record the count of orphaned SIDs 
    Try
	{
		if(Test-Path -Path $Path)
		{ 
			$count = 0
			#If the object is a folder and the "-recurse" is chosen ,then get all of the folder childitem,meanwhile store the path into an array folders
			if ($Recurse) 
	    	{		
		 		$folders = Get-ChildItem -Path $path -Recurse 
		 		#For-Each loop to get the ACL in the folders and check the orphaned SIDs 
		 		ForEach ($folder in $folders)
				{
		   			$PSPath = $folder.fullname 
		   			DeleteSID($PSPath)	
				}
			}
			else
			#The object is a file or the "-recurse" is not chosen,check the orphaned SIDs .
			{
				$PSPath =$path
				DeleteSID($PSPath)	
			}	
		}
		else
		{
			Write-Error "The path is incorrect"
		}
	}	
	catch
	{
	 	Write-Error $Error
	}
}

Function DeleteSID([string]$path)
{  
  	try
  	{
   		#This function is used to delete the orphaned SID 
   		$acl = Get-Acl -Path $Path
   		foreach($acc in $acl.access )
   		{
   			$value = $acc.IdentityReference.Value
   			if($value -match "S-1-5-*")
   			{
   				$ACL.RemoveAccessRule($acc) | Out-Null
   				Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
   				Write-Host "Remove SID: $value  form  $Path "
   			}
   		}
  	}
   	catch
   	{
   		Write-Error $Error
   	}
}


#--------------------------------------------------------------------------------------------------------------------------------------------------

Function Get-AclfromWindows ($computer,$depth) {
    
    # get all the valid share letters from the computer
    $shares = (get-WmiObject -class Win32_Share -computer $computer | where {$_.Name -like "*$*" -and $_.Name -ne "C$" -and $_.Name -ne "ADMIN$" -and $_.Name -ne "IPC$" -and $_.Name -ne "Sys"} | select Name).Name

    # get all the ACLS from the shares of a computer
    $ACLResults = foreach($share in $shares) {

        # filter it to the base shares only and no user folders
        $full_share_path = -join("\\",$computer,"\",$share)

        $folders5 = Get-childitem $full_share_path -recurse -depth $depth -Directory | % { $path1 = $_.fullname; Get-Acl $_.Fullname | % { $_.access | Add-Member -MemberType NoteProperty 'Path' -Value $path1 -passthru }}

        # the $folders object will then report all the fields to the $all_results object
        $folders5
                    }
    # when done it will output the $ACL_Results object
    write-output $ACLResults

}

#--------------------------------------------------------------------------------------------------------------------------------------------------

Function Get-AclfromNetapp ($controller,$credential,$depth) {
    <#

    $username = "your username"
    $password = "your password"
    $SecurePassword = ConvertTo-SecureString $password -asplaintext -force 
    $cred = New-Object System.Management.Automation.PSCredential $username,$SecurePassword

    Requires the Netapp Powershell Commandlets to work properly
    Requires the NTFS Security Module to work properly

    #>

    # Check the connection to the Controller in Question
    Connect-NcController $controller -cred $credential | out-null

    # get all valid Vservers from the given controoler
    $vservers = (Get-Ncvserver | where {$_.VserverType -eq "data" -and $_.Vserver -notlike "*dr*" -and $_.State -eq "running"} | select Vserver).Vserver

    # Curse as it helps with getting the Bad ACL's out with Powershell
    $combined_results = foreach($vserver in $vservers) {

        # filter it to the base shares only and no user folders
        $shares = Get-NcCifsShare -VserverContext $vserver| where {$_.path -notlike "/*/*" -and $_.path -ne "/" -and $_.Sharename -notlike "*sers*" -and $_.Sharename -notlike "*pst*" -and $_.Sharename -notlike "*SER*"}

        $all_results = foreach($share in $shares) {
            # specif the subfields to a direct variable
            $cifs_name = $share.CifsServer
            $actual_share = $share.ShareName

            # create the full share path name
            $full_sharepath = -join("\\",$cifs_name,"\",$actual_share)

            # attempt to filter out users
            if ($full_sharepath -like "*ser*") {
                 write-output "" | out-null 
                 } else {

                        $folders = Get-childitem $full_sharepath -recurse -depth $depth -Directory | % { $path1 = $_.fullname; Get-Acl $_.Fullname | % { $_.access | Add-Member -MemberType NoteProperty 'Path' -Value $path1 -passthru }}

                        # the $folders object will then report all the fields to the $all_results object
                        $folders

                    }

        }
        # all results are than added on the $dang_results varilable
        $all_results

    }

    # when done it will output the $dang_results object
    $combined_results

}

#--------------------------------------------------------------------------------------------------------------------------------------------------


Function Get-ACLbyKeyword ($computer,$volumefilter,$keywords) {

    # Query all the open files from a certain computer
    $openfiles = openfiles /Query /S $computer /FO CSV /V | ConvertFrom-Csv

    # further Filter those files
    $filtered = $openfiles | where {$_."Open File (Path\executable)" -like "*$volumefilter*" -and $_."Open Mode" -notlike "*No Access*"} | Select "Accessed By","Open Mode","Open File (Path\executable)"


    foreach($keyword in $keywords) {

        write-host "=========I. showing list of paths for $keyword ====================================="

        $client_filtered = $filtered | where {$_."Open File (Path\executable)" -like "*$keyword*"} 


        # BEGIN SHOW PATHS

        $client_filtered | sort-object "Accessed By" -descending | ft

        $users = $client_filtered | where {$_."Accessed By" -notlike "*admin*" -or $_."Accessed By" -notlike "*service*"} | select "Accessed By" -Unique

        $results = $null
        
        # begin for lOOP
        foreach($user in $users."Accessed By") {

            $results = Get-ADPrincipalGroupMembership $user | where {$_.name -like "*$keyword*"} | SELECT NAME

            if ($results -eq $null) {
                write-host -ForegroundColor "Red" "===== II. Group Membership of $user";
                 write-host -ForegroundColor "Red" "$user is not part of group $keyword"

                 # Create the Temporary Folder if it does not exist
                 New-Item -ItemType Directory -Force -Path "C:\temp" | out-null

                 # Add them to a .txt file
                 Add-content -path "c:\temp\notingroup.txt" -Value "$user - not in group - $keyword"

                 $membership = (get-aduser $user | select Distinguishedname).Distinguishedname
                 #write-host $membership
     
                 } else {
                      write-host -ForegroundColor "Yellow" "== III. Group Membership of $user";
                         ($results).Name | ft
                         $membership = (get-aduser $user | select Distinguishedname).Distinguishedname
                 #write-host $membership
                          }

        }
        # END fOR LOOP
        # end shOW PATHS


    }
        write-host "The following users are not in the intended groups"
        $usernotingroup = get-content "c:\temp\notingroup.txt" | out-string
        write-host -foregroundcolor "red" $usernotingroup
        clear-content "c:\temp\notingroup.txt" -force

}

#--------------------------------------------------------------------------------------------------------------------------------------------------

 Function Get-ACLbyDepth ($paths,$depth) {
    
    $PathACLS = foreach($path in $paths) {
        # Get the path
        $folderACLS = Get-childitem $path -recurse -depth $depth -Directory | % { $path1 = $_.fullname; Get-Acl $_.Fullname | % { $_.access | Add-Member -MemberType NoteProperty 'Path' -Value $path1 -passthru }}

        # output the object
        $folderACL
    }

    # output the result of the path ACLS
    $PathACLS

 }
 
 #--------------------------------------------------------------------------------------------------------------------------------------------------

 Function Remove-ExplcitPermissions ($path) {

    $fullpath = ((get-childitem $path) | select FullName).FullName

    foreach($path in $fullpath) {

        Enable-NTFSAccessInheritance -path $path -RemoveExplicitAccessRules

    }

}

 #--------------------------------------------------------------------------------------------------------------------------------------------------

 Function Report-ACLs ($inputobject) {

    #filter out users $inputobject
    $format1 = $inputobject | where {$_.path -notlike "*ser*"}

    # users that have full control that are not admins
    write-host "Identifying Directories with Full Control that are not Admins or Service Accounts"
    $format1 | where {$_.FileSystemRights -eq "FullControl" -and $_.IdentityReference -notlike "*dmin*" -and $_.IdentityReference -notlike "*servic*" -and $_.IdentityReference -notlike "*system*" -and $_.IdentityReference -notlike "*owner*" -and $_.IdentityReference -notlike "*S-1-5*" -and $_.IdentityReference -notlike "*home*" -and $_.paht -notlike "*I$*"} | ft

    # All ou Groups ( a Whole OU is assigned to a particular Share
    write-host "========== 1. Identifying Directories with Default all OU Users Groups"
    $format1 | where {$_.IdentityReference -like "*defaul*"} | ft

    # Domain Users Group
    write-host "========== 2. Identifying Directories with Domain Users Permissions"
    $format1  | where {$_.IdentityReference -like "*Domain Users*"} | ft

    # users that have Everyone Permissions
    write-host "========== 3. Identifying Directories with Everyone Permission"
    $format1  | where { $_.Identityreference -like "*Everyone*"} | ft

    # users that have Creator Owner Permissions
    write-host "========== 4. Identifying Directories with Creator Owner Permission"
    $format1  | where { $_.Identityreference -like "*Creator Owner*"} | ft

    # users that have Creator Owner Permissions
    write-host "========== 5. Identifying Directories with Orphaned SID's"
    $format1  | where { $_.Identityreference -like "*S-1-5*"} | ft


 }

  #--------------------------------------------------------------------------------------------------------------------------------------------------

  Function Monitor-OpenFiles($computers,$iterations,$interval) {

    # Create the Temporary Folder if it does not exist
    New-Item -ItemType Directory -Force -Path C:\temp | out-null

    for ($i = 1; $i -lt $iterations; $i++)
    { 
        foreach($computer in $computers) {

            # create the Computer specific Folder if it does not exist
            New-Item -ItemType Directory -Force -Path "C:\temp\$computer" | out-null

            # Query all the open files from a certain computer
            $openfiles = openfiles /Query /S $computer /FO CSV /V | ConvertFrom-Csv

            # further Filter those files
            $filtered = $openfile | Select "Accessed By","Open Mode","Open File (Path\executable)"

            $date_base = get-date -format MM-HH-mm

            $date_base1 = "c:\temp\$computer\$computer"

            $fullpath = -join($date_base1,"_open_",$date_base,".csv")

            $filtered | export-csv $fullpath

        }
        # sleep for a certain interval until the next interation
        
        $interval_seconds = [int]$interval * 60  
        start-sleep -seconds $interval_seconds     
    }

    # when done, create a master file
    foreach($computer in $computers) {
        # create the done directory
        New-Item -ItemType Directory -Force -Path "C:\temp\$computer\done" | out-null

        # get all the CSV files of that directory
        $csvfiles = (get-childitem -path "c:\temp\$computer" -file | select Fullname).Fullname

        # enumerate all the CSV files together
        foreach($CSV in $CSVFiles) { 
            if(Test-Path $CSV) { 
         
                $FileName = [System.IO.Path]::GetFileName($CSV) 
                $temp = Import-CSV -Path $CSV | select *, @{Expression={$FileName};Label="FileName"} 
                $Output += $temp 
 
            } else { 
                Write-Warning "$CSV : No such file found" 
            } 
 
        } 
        $date_base = get-date -format MM-HH-mm
        $master_path = -join("c:\temp\",$computer,"\done\master_",$computer,$date_base,".csv")

        $Output | select "Accessed By","Open Mode","Open File (Path\executable)" -unique | Export-Csv -Path $master_path -NoTypeInformation 
        Write-Output "$OutputFile successfully created"
        
        #remove the old files
        Remove-item -path "c:\temp\$computer\*.csv" -force
         

    }

  }
