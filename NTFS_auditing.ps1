Function Get-AclfromWindows ($computer,$depth) {
    
    # get all the valid share letters from the computer
    $shares = (get-WmiObject -class Win32_Share -computer $computer | where {$_.Name -like "*$*" -and $_.Name -ne "C$" -and $_.Name -ne "ADMIN$" -and $_.Name -ne "IPC$"} | select Name).Name

    # Curse as it helps with getting the Bad ACL's out with Powershell
    $dang_results = foreach($share in $shares) {

        # filter it to the base shares only and no user folders
        $full_share_path = -join("\\",$computer,"\",$share)

        $folders = Get-childitem $full_share_path -recurse -depth $depth -Directory | % { $path1 = $_.fullname; Get-Acl $_.Fullname | % { $_.access | Add-Member -MemberType NoteProperty 'Path' -Value $path1 -passthru }}

                        # the $folders object will then report all the fields to the $all_results object
                        $folders

                    }
    # when done it will output the $dang_results object
    $dang_results

}

#--------------------------------------------------------------------------------------------------------------------------------------------------

Function Get-OrderedACLbyKeyword ($computer,$keywords) {

    # Query all the open files from a certain computer
    $openfiles = openfiles /Query /S $computer /FO CSV /V | ConvertFrom-Csv

    # further Filter those files
    $filtered = $openfiles | Select "Accessed By","Open Mode","Open File (Path\executable)"


    foreach($keyword in $keywords) {

        write-host "=========I. showing list of paths for $client ====================================="

        $client_filtered = $filtered | where {$_."Open File (Path\executable)" -like "*$keyword*"} 


        # BEGIN SHOW PATHS

        $client_filtered | ft

        $users = $client_filtered | select "Accessed By" -Unique

        $results = $null
        
        # begin for lOOP
        foreach($user in $users."Accessed By") {

            $results = Get-ADPrincipalGroupMembership $user | where {$_.name -like "*$keyword*"} | SELECT NAME

            if ($results -eq $null) {
                write-host -ForegroundColor "Red" "===== II. Group Membership of $user";
                 write-host -ForegroundColor "Red" "$user is not part of group $keyword"
                 $membership = (get-aduser $user | select Distinguishedname).Distinguishedname
                 #write-host $membership
     
                 } else {
                      <#write-host -ForegroundColor "Yellow" "== III. Group Membership of $user";#>
                         ($results).Name | ft
                         $membership = (get-aduser $user | select Distinguishedname).Distinguishedname
                 #write-host $membership
                          }

        }
        # END fOR LOOP
        # end shOW PATHS

    }


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
 