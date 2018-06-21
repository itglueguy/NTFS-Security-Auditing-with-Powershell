# NTFS-Security-Auditing-with-Powershell
Similar to tools like Netwrix File Auditor and Varonis, you can get a feel for what type of NTFS Permissions you have on your shares

Ex. Get-ACLbyDepth

The purpose of this function is to get all the ACL's of all the folders under a certain shared folder of a certain depth

ex. Get the ACL of the share \\computer\share1 for all funders under it ( depth of 1 )

Get-ACLbyDepth -paths "\\computer\share1" -depth 1

#------------------------------

Ex. Get-AclfromWindows

The purpose of this function is to get all the ACL's of all the Shares on a Windows Computer of a certain Depth

Ex. Get all the ACL's from all the shares for all the folders under it. computer name of Computer1 and share name of share1

ex. Get-AclfromWdinws -computer "Computer1" -depth 1

#------------------------------

Ex. Get-OrderedACLbyKeyword

ex. Assuming your Folders follow a Group Name / Folder Name naming convention, this allows you to see if certain Users actually belong to
certain Group from a certain share.

Get-OrderedACLbyKeyword -computer "Computer1" -Keywords "Micorosoft","Cisco"
