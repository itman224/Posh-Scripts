<#       
    ======================================
    |
    |    p.j.hartlieb
    |    powershell post-exploitation
    |    DomainEnum module v.0.1.0
    |    2015.06.24
    |    last verified 2015.06.24
    |
    ======================================
    
## [0] Reference: https://www.veil-framework.com/veil-powerview/
## [1] Reference: http://technet.microsoft.com/en-us/library/ff730967.aspx
## [2] Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directorysearcher(v=vs.110).aspx
## [3] Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx

#>


function Get-HomeBase ([switch] $noOutFile)
{
<#
.SYNOPSIS

This script is used to verify the presence of a DC and identify target domain based on environmental variables and wmi calls.

Function: Get-HomeBase
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: None
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate the target host (patient 0).
This script is used to identify domain and verify the presence of a DC.
Returns a hashtable with data.
	
.EXAMPLE

Get-HomeBase

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder #script output
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{}
    
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-Homebase command executed at : " + $currentTime)
    [void]$info.AppendLine("Command executed at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for target basic data ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")
        
# Identify Domain defined in environmental variable
    $TargetDomainEnv=$env:userdomain
    IF (($TargetDomainEnv -ne $NULL) -and ($TargetDomainEnv -ne "")) {
        $Key = "Domain (env)"
        $returnObject.Add($Key, $TargetDomainEnv)
        [void]$info.AppendLine("Target Domain (environment) : " + $TargetDomainEnv)
    } ELSE {
        $TargetDomainEnv = "undefined"
        $Key = "Domain (env)"
        $returnObject.Add($Key, $TargetDomainEnv)
        [void]$info.AppendLine("[!!] Target Domain is undefined")
    }

# Identify Domain reported by WMI
   $TargetDomainClip = Get-WMIObject -class "Win32_computersystem"
   $TargetDomainWMI = $TargetDomainClip.Domain
   IF (($TargetDomainWMI -ne $NULL) -and ($TargetDomainWMI -ne "")) {
        $Key = "Domain (wmi)"
        $returnObject.Add($Key, $TargetDomainWMI)
        [void]$info.AppendLine("Target Domain (WMI) : " + $TargetDomainEnv)
   } ELSE {
        $TargetDomainWMI = "undefined"
        $Key = "Domain (wmi)"
        $returnObject.Add($Key, $TargetDomainWMI)
        [void]$info.AppendLine("[!!] Target Domain is undefined")
   }
   
# Identify logonserver from environmental variables
    $logonserver=$env:logonserver
    IF (($logonserver -ne $NULL) -and ($logonserver -ne "")) {
         $logonserver=$logonserver -replace "\\",""
         $Key = "LogonServer"
         $returnObject.Add($Key, $logonserver)
         [void]$info.AppendLine("LogonServer : " + $logonserver)
    } ELSE {
         $logonserver = "undefined"
         $Key = "LogonServer"
         $returnObject.Add($Key, $logonserver)
         [void]$info.AppendLine("[!!] LogonServer is undefined")
    }
    
# Locate DC reported by WMI
   $DomainClipboard = Get-WMIObject -class "Win32_NTDomain" -filter "DomainName = '$TargetDomainWMI' "
   $DCName = $DomainClipboard.DomainControllerName                    
   IF ($DCName -ne $NULL) {
       $DCName=$DCName -replace "\\",""
       $Key = "DomainController"
       $returnObject.Add($Key, $DCName)
       [void]$info.AppendLine("Domain Controller : " + $DCName)
   } ELSE {
       $DCName = "undefined"
       $Key = "DomainController"
       $returnObject.Add($Key, $DCName)
       [void]$info.AppendLine("[!!] Domain Controller is undefined")
   }

# output
    IF ( -not $noOutFile) { 
        [void]$info.Appendline("`n")
        [void]$info.AppendLine("[*] OUTFILE(s)")
        [void]$info.Appendline("`n")
        [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetHomebase_info.txt")
        $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetHomebase_info.txt") #write output to file
        [void]$status.Appendline("[*] Success")
        Write-Host $status     
    }
    return $returnObject
}


function Get-Pedigree
{
<#
.SYNOPSIS

This script is used to enumerate the target host (patient 0).

Function: Get-Pedigree
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate the target host (patient 0).
A hash table is returned with the pedigree data.  
	
.EXAMPLE

Get-Pedigree

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder #script output
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{}
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-Pedigree command executed at : " + $currentTime)
    [void]$info.AppendLine("Command executed at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for target Pedigree ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Machine info
    $OSInfo = Get-WmiObject -class Win32_OperatingSystem
    IF (($OSInfo -ne $NULL) -and ($OSInfo -ne "")) {
        $machineInfo = ("Machine info : " + $OSInfo.Caption + " " + $OSInfo.OSArchitecture + " " + $OSInfo.Version)
        $Key = "Target machineInfo"
        $returnObject.Add($Key, $machineInfo)        
        [void]$info.AppendLine("Machine info : " + $OSInfo.Caption + " " + $OSInfo.OSArchitecture + " " + $OSInfo.Version)
    } ELSE {
        [void]$info.AppendLine("[!!] Machine info could not be retrieved")
    }

# hostname
    $myhostname = hostname
    IF (($myhostname -ne $NULL) -and ($myhostname -ne "")) {
        $Key = "Target hostname"
        $returnObject.Add($Key, $myhostname)
        [void]$info.AppendLine("The hostname for the target is : " + $myhostname)
    } ELSE {
        [void]$info.AppendLine("[!!] The hostname for the target could not be retrieved")
    }

# FQDN
    $myFQDN=(Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
    IF (($myFQDN -ne $NULL) -and ($myFQDN -ne "")) {
        $Key = "Target FQDN"
        $returnObject.Add($Key, $myFQDN)
        [void]$info.AppendLine("The FQDN for the target is : " + $myFQDN)
    } ELSE {
        [void]$info.AppendLine("[!!] The FQDN for the target could not be retrieved")
    }  

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
# Creating the DirectoryEntry and DirectorySearcher objects for target DN capture
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
        $strFilter = "Computer"
        
        $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
        $Serversearcher = New-Object System.DirectoryServices.DirectorySearcher

        ## specify the domain root as the starting point for the search 
            $Serversearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $Serversearcher.Filter = "(&(objectCategory=$strFilter)(Name=$myhostname))"
            #$Serversearcher.Filter = "(Name=$myhostname)"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $Serversearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $Serversearcher.PageSize = 1000 

        ## Execute the search and capture the target DN
            $ServerResults = $Serversearcher.FindOne() | ForEach-Object {$_.properties.distinguishedname}
            #$ServerResults = $Serversearcher.FindOne()
            IF ($ServerResults -ne $NULL) {           
                [void]$info.AppendLine("The DN for the target is: " + $ServerResults)
                $Key = "Target DN"
                $returnObject.Add($Key, $ServerResults)
            } ELSE {
            [void]$info.Appendline("[!!] The target DN could not be found")
            }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Host DN could not be resolved")
    }
    
# Creating the DirectoryEntry and DirectorySearcher objects for logonserver DN capture
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
        $strFilter = "Computer"

        $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
        $Serversearcher = New-Object System.DirectoryServices.DirectorySearcher

        ## specify the domain root as the starting point for the search 
            $Serversearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $Serversearcher.Filter = "(&(objectCategory=$strFilter)(Name=$LogonServerCheck))"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $Serversearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $Serversearcher.PageSize = 1000 

# Execute the search and capture the target DN
            $ServerResults = $Serversearcher.FindOne() | ForEach-Object {$_.properties.distinguishedname}
            
            IF ($ServerResults) {
                $Key = "Target logonserver DN"
                $returnObject.Add($Key, $ServerResults)           
                [void]$info.AppendLine("The DN for the logonserver is: " + $ServerResults)
            } ELSE {
                [void]$info.Appendline("[!!] The logonserver DN could not be found")
            }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. LogonServer DN could not be resolved")
    }
    
# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetPedigree_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetPedigree_info.txt") #write output to file
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    return $returnObject
}

function Get-Computer
{
<#
.SYNOPSIS
This script is used to enumerate all computers in a domain.

Function: Get-Computer
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION
This script is used to enumerate all computers in the current domain.
An array is returned with all computers in the domain.
	
.EXAMPLE
Get-Computer

.NOTES
## Reference: https://www.veil-framework.com/veil-powerview/
## Reference: http://technet.microsoft.com/en-us/library/ff730967.aspx
## Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directorysearcher(v=vs.110).aspx
## Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx
  
.LINK
Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @()
    
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-Computer command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for domain computers ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Creating the DirectoryEntry and DirectorySearcher objects.  Bail if the target is not in a domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
            $strFilter = "Computer" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry 
            $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher

            ## specify the domain root as the starting point for the search 
                $CompSearcher.SearchRoot = $TargetDomain

            ## construct the LDAP filter
                $CompSearcher.Filter = "(objectCategory=$strFilter)"

            ## the "Subtree" specification ensures that the search will be executed recursively
                $CompSearcher.SearchScope = "Subtree" 

            ## bypass the limits on the search (ie. get more than 100 results)
                $CompSearcher.PageSize = 1000 

# Execute the search

            ## Create an array with the DNs for each AD object
                $CompResults = $CompSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}
                IF (($CompResults.length -ne 0) -and ($CompResults -ne $NULL)) {           
                    foreach ($computer in $CompResults) {
                        $computer | Out-File -Append $("C:\Users\Public\" + $currentTime + "_computers.txt") #write output to file
                        $returnObject += $computer
                    }
                    [void]$info.AppendLine("This formatted computer list has been written to C:\Users\Public\" + $currentTime + "_computers.txt")
                } ELSE {
                   [void]$info.Appendline("[*] No computers enumerated")
                }
     } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Computers could not be enumerated")
     }

# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetComputer_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetComputer_info.txt") #write output to file
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    return $returnObject
}

function Get-DC
{
<#
.SYNOPSIS
This script is used to enumerate all domain controllers in a domain.

Function: Get-DC
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION
This script is used to enumerate all domain controllers in the current domain.
A hash table is returned with the domain controllers and the identified PDC in the current domain.
	
.EXAMPLE
Get-DC

.NOTES
## Reference: https://www.veil-framework.com/veil-powerview/
## Reference: http://technet.microsoft.com/en-us/library/ff730967.aspx
## Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directorysearcher(v=vs.110).aspx
## Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx

.LINK
Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{}
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-DC command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for domain DCs/PDC ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
# Querying for PDC and DCs.   Bail if the target is not in a domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain

## Retrieve and verify the current domain. 
                $Domain = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                [void]$info.AppendLine("The current domain is: " + $Domain )
                [void]$info.Appendline("`n")

                ## Enumerate all DCs
                    $DCs = ([Array]([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers))

                    IF (( $DCs.length -ne 0 ) -and ($DCs[0] -NotMatch '\s+') -and ($DCs -ne $NULL)) {
                
                        Foreach ($DC in $DCs) { #write DC names to file
                            $DC.name | Out-File -append $("C:\Users\Public\" + $currentTime + "_DCs.txt")
                            $DCs_names += $DC.name
                        }
                        
                        $index=0
                        Foreach ($name in $DCs_names) { #create hashtable for DCs as returnObject
                            $index++
                            $Key="DC " + $index
                            $returnObject.Add($Key, $name)
                        }
                    [void]$info.AppendLine("This formatted list of DCs has been written to C:\Users\Public\" + $currentTime + "_DCs.txt")
                    [void]$info.Appendline("`n")
                    } ELSE {
                        [void]$info.AppendLine("[!!] There were no DC(s) enumerated ")
                        [void]$info.Appendline("`n")
                    }

                ## Identify the PDC
                    $PDC = ([Array]([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers))[0].Name

                    IF (($PDC -ne $NULL ) -and ($PDC -ne "")) {
                        [void]$info.AppendLine("The Primary Domain Controller (PDC) is : " + $PDC)
                        $Key="PDC"
                        $returnObject.Add($Key, $PDC)
                    } ELSE {
                        [void]$info.AppendLine("[!!] The Primary Domain Controller (PDC) is UNDEFINED")
                    }
     } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Controllers could not be enumerated")
     }
             
# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetDC_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetDC_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-Group ([switch] $noOutFile)
{
<#
.SYNOPSIS
This script is used to enumerate all groups in a domain.

Function: Get-Group
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION
This script is used to enumerate all groups in the current domain.
An array is returned with all groups in the current domain.
	
.EXAMPLE
Get-Group

.NOTES
##Reference: https://www.veil-framework.com/veil-powerview/
##Reference: http://technet.microsoft.com/en-us/library/ff730967.aspx
##Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directorysearcher(v=vs.110).aspx
##Reference: http://msdn.microsoft.com/en-us/library/system.directoryservices.directoryentry(v=vs.110).aspx

.LINK
Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject=@()
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-Group command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for domain groups ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Creating the DirectoryEntry and DirectorySearcher objects.  Bail if the target is not in a domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain

        $strFilter = "group" 
        $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
        $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher

        ## specify the domain root as the starting point for the search 
            $GroupSearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $GroupSearcher.Filter = "(objectCategory=$strFilter)"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $GroupSearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $GroupSearcher.PageSize = 1000 

# Execute the search

        ## Create an array with the DNs for each AD object
            $GroupResults = $GroupSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}
            IF (($GroupResults.length -ne 0) -and ($GroupResults -ne $NULL)) {           
                foreach ($group in $GroupResults){
                    IF ( -not $noOutFile) {
                        $group | Out-File -Append $("C:\Users\Public\" + $currentTime + "_groups.txt") #write output to file
                    }
                    $returnObject += $group 
                }
                [void]$info.AppendLine("A formatted group list has been written to C:\Users\Public\" + $currentTime + "_groups.txt")
            } ELSE {
                [void]$info.Appendline("[!!] No groups enumerated")
            }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Groups could not be enumerated")
    }

# output
    IF ( -not $noOutFile) { 
        [void]$info.Appendline("`n")
        [void]$info.AppendLine("[*] OUTFILE(s)")
        [void]$info.Appendline("`n")
        [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetGroup_info.txt")
        $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetGroup_info.txt") #write output to file
        [void]$status.Appendline("[*] Success")
        Write-Host $status
    }
    
    return $returnObject
}


function Get-GroupUser
{
<#
.SYNOPSIS

This script is used to enumerate the users for each group in a domain.

Function: Get-GroupUser
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate group membership for all groups in the current domain.
An array of arrays is returned.  Each array is named after the group enumerated and includes all members. 

.EXAMPLE

Get-GroupUser

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object to contain output
$info = new-object system.text.stringbuilder
$status = new-object system.text.stringbuilder #status message
$returnObject = @{} # A hashtable of arrays. The keys are group names. The values are arrays of group members.
 
# Time when script is executing
$currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-GroupUser command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for group membership ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
#Query for groups in the domain.  Bail if the target is not part of a Domain.
     IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
        
        ##Creating the DirectoryEntry and DirectorySearcher objects
            $strFilter = "group" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $GroupSearcher = New-Object System.DirectoryServices.DirectorySearcher

        ##specify the domain root as the starting point for the search 
            $GroupSearcher.SearchRoot = $TargetDomain

        ##construct the LDAP filter
            $GroupSearcher.Filter = "(objectCategory=$strFilter)"

        ##the "Subtree" specification ensures that the search will be executed recursively
            $GroupSearcher.SearchScope = "Subtree" 

        ##bypass the limits on the search (ie. get more than 100 results)
            $GroupSearcher.PageSize = 1000 

#Execute the search
        ## Create an array with the DNs for each AD object
            $GroupResults = $GroupSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}

        ## Loop through each group and capture users for each 
            $group_name #init
            
            IF (($GroupResults.length -ne 0) -and ($GroupResults -ne $NULL)) {           
                foreach ($group in $GroupResults) {
                    $group_name = $group -replace ",","_" -replace "=","_"
                    $group | Out-File -Append $("C:\Users\Public\" + $currentTime + "_groups.txt") #write group names to file
                    $returnObject.Add("$group_name",@()) #creates a hash table containing a set of dynamically named arrays. Group Name=key User array=value.
                
                    ## Query for all members of each group, write users to array in hastable and write users to a file 
                    $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $UserSearcher.SearchRoot = $TargetDomain
                    $UserSearcher.Filter = "(&(objectCategory=user)(memberof=$group))"
                    $UserSearcher.PageSize=1000
                    $Users = $UserSearcher.FindAll() #creates array of users for the group
                
                    IF (($Users.length -ne 0) -and ($Users -ne $NULL)) {
                        foreach ($User in $Users) {
                            $target = $User.Properties.distinguishedname
                            $target | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $group_name + "_group_users.txt") #write outout to file
                            $returnObject."$group_name" += $target #append target(user) to my dynamically named user array that's contained in the larger hash table
                        } # close inner for-loop (users)
                    } # close if/then
                            
                } # close outer for-loop (groups)
                [void]$info.AppendLine("A formatted group list has been written to C:\Users\Public\" + $currentTime + "_groups.txt")
                [void]$info.Appendline("`n")
                [void]$info.AppendLine("Formatted lists of group membership have been written to " + $currentTime + "_<groupname>_group_user.txt")
            } ELSE {
                [void]$info.Appendline("[!!] No groups enumerated")
            }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Group Users could not be enumerated")
    }

#output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_Get-GroupUser_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_Get-GroupUser_info.txt") #write output to file
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-Server
{
<#
.SYNOPSIS

This script is used to enumerate all servers in a domain.

Function: Get-Server
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all servers in the current domain.
An array is returned that contains all the servers in the current domain.
	
.EXAMPLE

Get-Server

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @()
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-Server command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for domain servers ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Creating the DirectoryEntry and DirectorySearcher objects.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
            $strFilter = "Server" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Serversearcher = New-Object System.DirectoryServices.DirectorySearcher

            ## specify the domain root as the starting point for the search 
                $Serversearcher.SearchRoot = $TargetDomain

            ## construct the LDAP filter
                $Serversearcher.Filter = "(objectCategory=$strFilter)"

            ## the "Subtree" specification ensures that the search will be executed recursively
                $Serversearcher.SearchScope = "Subtree" 

            ## bypass the limits on the search (ie. get more than 100 results)
                $Serversearcher.PageSize = 1000 

# Execute the search
            ## Create an array with the DNs for each AD object
                $ServerResults = $Serversearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}
                IF (($ServerResults.length -ne 0) -and ($ServerResults -ne $NULL)) {           
                    foreach ($Server in $ServerResults) {
                        $Server | Out-File -Append $("C:\Users\Public\" + $currentTime + "_Servers.txt") #write output to file
                        $returnObject += $Server #append server to returned array
                    }
                    [void]$info.AppendLine("A formatted server list has been written to C:\Users\Public\" + $currentTime + "_servers.txt")
                } ELSE {
                    [void]$info.Appendline("[!!] No Servers enumerated")
                }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Servers could not be enumerated")
    }
    
# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetServer_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetServer_info.txt") #write output to file
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    return $returnObject
}

function Get-User
{
<#
.SYNOPSIS

This script is used to enumerate all users in a domain.

Function: Get-User
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all users in the current domain.
An array is returned that contains all the users in the current domain.
	
.EXAMPLE

Get-User

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @()
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-User command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for domain users ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")
    
# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
# Creating the DirectoryEntry and DirectorySearcher objects.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
            $strFilter = "User" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Usersearcher = New-Object System.DirectoryServices.DirectorySearcher

            ## specify the domain root as the starting point for the search 
                $Usersearcher.SearchRoot = $TargetDomain

            ## construct the LDAP filter
                $Usersearcher.Filter = "(objectCategory=$strFilter)"

            ## the "Subtree" specification ensures that the search will be executed recursively
                $Usersearcher.SearchScope = "Subtree" 

            ## bypass the limits on the search (ie. get more than 100 results)
                $Usersearcher.PageSize = 1000 

# Execute the search
            ## Create an array with the DNs for each AD object
                $UserResults = $Usersearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}
                IF (($UserResults.length -ne 0) -and ($UserResults -ne $NULL)) {           
                    foreach ($User in $UserResults) {
                        $User | Out-File -Append $("C:\Users\Public\" + $currentTime + "_Users.txt") #write output to file
                        $returnObject += $User #append user to an returned array
                    }
                    [void]$info.AppendLine("A formatted user list has been written to C:\Users\Public\" + $currentTime + "_users.txt")
                } ELSE {
                    [void]$info.Appendline("[!!] No Users enumerated")
                }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Users could not be enumerated")
    }
    
# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetUser_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetUser_info.txt") #write output to file
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    return $returnObject
}

function Get-Email
{

<#
.SYNOPSIS

This script is used to enumerate all email for all users in a domain.

Function: Get-Email
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all email for all users in the current domain.
An array is returned that contains all the email in the current domain.
	
.EXAMPLE

Get-Email

Get-Email -emailcount 3000

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Parameters
    Param
      (
        [parameter()]
        [Int]
        $emailcount  #number of harvested email addresses
      )
            
# Object(s) to contain output
    $info = new-object system.text.stringbuilder   #metadata written to file
    $status = new-object system.text.stringbuilder #status messages for screen
    $destinationfolder="C:\Users\Public\"
    $emailfilename="_Email.txt"
    $returnObject = @()
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-Email command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for domain users ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
# Creating the DirectoryEntry and DirectorySearcher objects.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
            $strFilter = "User" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Usersearcher = New-Object System.DirectoryServices.DirectorySearcher

            ## specify the domain root as the starting point for the search 
                $Usersearcher.SearchRoot = $TargetDomain

            ## construct the LDAP filter
                $Usersearcher.Filter = "(objectCategory=$strFilter)"

            ## the "Subtree" specification ensures that the search will be executed recursively
                $Usersearcher.SearchScope = "Subtree" 

            ## bypass the limits on the search (ie. get more than 100 results)
                $Usersearcher.PageSize = 500 
                
            ## bypass the limits on the search (ie. get more than 100 results)
                #$Usersearcher.SizeLimit = 6 

# Execute the search
           ## Create an array with the DNs for each AD object
           $EmailResults = $Usersearcher.FindAll() | ForEach-Object {$_.properties.mail} #harvest email from AD
           $topLimit=$EmailResults.Length #total number of emails harvested from AD
           $email_file = New-Object System.IO.StreamWriter($destinationfolder + $currentTime + $emailfilename)
           
           IF (($topLimit -ne 0) -and ($EmailResults -ne $NULL)) { #check for results

                IF ($emailcount -eq 0) { #indicates that all email is to be harvested
                    [void]$status.Appendline("[*] Preparing to write all " + $topLimit + " addresses to file.")   #screenmessage
                    [void]$info.Appendline("[*] Preparing to write all " + $topLimit + " addresses to file.")     #filemessage     
                    foreach ($Email in $EmailResults) {
                        IF ($Email -ne $NULL) {
                            $email_file.Writeline($Email)  
                            $returnObject += $Email
                        }
                    }
                   $email_file.close() 
                   [void]$info.AppendLine("`n")
                   [void]$info.AppendLine("[*] A formatted email list has been written to C:\Users\Public\" + $currentTime + "_Email.txt")  
                                    
                } ELSEIF (($emailcount -ne 0) -and ($emailcount -le $topLimit)) { #indicates that a specific email count is to be harvested
                    [void]$status.Appendline("[*] Preparing to write " + $emailcount + " addresses to file.")  #screenmessage
                    [void]$info.AppendLine("[*] Preparing to write " + $emailcount + " addresses to file.")    #filemessage
                    [void]$info.AppendLine("`n")
                    $counter=0           
                    foreach ($Email in $EmailResults) {
                        IF (($Email -ne $NULL) -and ($counter -lt $emailcount)) {
                            $counter++	        
                            $email_file.Writeline($Email) 
                            $returnObject += $Email
                        }
                    }
                    $email_file.close()
                    [void]$info.AppendLine("[*] A formatted email list has been written to C:\Users\Public\" + $currentTime + "_Email.txt")
               
                } ELSE {
                    [void]$status.Appendline("[!!] There are only " + $topLimit + " email addresses available.")   #screenmessage
                    [void]$info.AppendLine("[!!] There are only " + $topLimit + " email addresses available.")    #filemessage
                }
            }  ELSE {
                [void]$info.AppendLine("[!!] No Email enumerated")
            }
    } ELSE {
        [void]$info.AppendLine("[!!] The target domain is either WORKGROUP or undefined. Domain Emails could not be enumerated")
    }
        
# output
    [void]$info.AppendLine("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetEmail_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetEmail_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-OU
{
<#
.SYNOPSIS

This script is used to enumerate all OUs in a domain.

Function: Get-OU
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all OUs in the current domain.
An array is returned that contains all the OUs in the current domain.
	
.EXAMPLE

Get-OU

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @()
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-OU command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for domain OUs ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Query for OUs in the domain.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain

        ## Creating the DirectoryEntry and DirectorySearcher objects
            $strFilter = "organizationalUnit" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher

        ## specify the domain root as the starting point for the search 
            $OUSearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $OUSearcher.Filter = "(objectCategory=$strFilter)"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $OUSearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $OUSearcher.PageSize = 1000 

# Execute the search
        ## Create an array with the DNs for each AD object
                $OUResults = $OUSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}

        ## Loop through and list each OU 
            IF (($OUResults.length -ne 0) -and ($OUResults -ne $NULL)) {           
                foreach ($OU in $OUResults) {
                    $OU | Out-File -Append $("C:\Users\Public\" + $currentTime + "_OUs.txt") #write output to file
                    $returnObject += $OU
                }
                [void]$info.AppendLine("A formatted list of OUs has been written to C:\Users\Public\" + $currentTime + "_OUs.txt")
            } ELSE {
                [void]$info.Appendline("[!!] No OUs enumerated")
            }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain OUs could not be enumerated")
    }

# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetOU_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetOU_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-OUUser
{
<#
.SYNOPSIS

This script is used to enumerate all users in each OU in the current domain.

Function: Get-OUUser
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all users in each OU in the current domain.
An hashtable of arrays is returned.  Keys are OU names.  Values are arrays of users in the OU.

.EXAMPLE

Get-OUUser

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{} # A hashtable of arrays Keys are OU names.
    
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-OUUser command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for users per OU ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")
    
# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Query for OUs in the domain.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain

        ## Creating the DirectoryEntry and DirectorySearcher objects
            $strFilter = "organizationalUnit" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher

        ## specify the domain root as the starting point for the search 
            $OUSearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $OUSearcher.Filter = "(objectCategory=$strFilter)"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $OUSearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $OUSearcher.PageSize = 1000 

# Execute the search
        ## Create an array with the DNs for each AD object
            $OUResults = $OUSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}

        ## Loop through and list Users for each OU 
            $OU_name #init
            
            IF (($OUResults.length -ne 0) -and ($OUResults -ne $NULL)) {           
                foreach ($OU in $OUResults) {
                    $strFilter = "user" 
                    $OU | Out-File -Append $("C:\Users\Public\" + $currentTime + "_OUs.txt") #write OUs out to file
					$OU_name = $OU -replace ",","_" -replace "=","_"
                    $returnObject.Add("$OU_name",@()) #creates a hash table containing a set of dynamically named arrays. OU_Name=key array_of_OU_users=value.
                    
            ### Query for all Users in each OU and write them to a file
            ### scope search to each OU
                    $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$OU")
                    $OUUsersearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $OUUsersearcher.SearchRoot = $TargetDomain
                    $OUUsersearcher.Filter = "(objectCategory=$strFilter)"
                    $OUUsersearcher.PageSize=1000
                    $OUUsers = $OUUsersearcher.FindAll()
            
                    IF (($OUUsers.length -ne 0) -and ($OUUsers -ne $NULL)) {
                        foreach ($User in $OUUsers) {
                            $target = $User.Properties.distinguishedname
                            $target | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_Users.txt") #write user list out to file
                            $returnObject."$OU_name" += $target #append user DN to my dynamically named array that's contained in the larger hash table whose key is $OU_name
                        } #close inner for-loop (
                        [void]$info.AppendLine("Formatted list of users written to C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_Users.txt")
                        [void]$info.Appendline("`n")
                    } #close if then else
                } #close for loop
                [void]$info.AppendLine("Formatted OUs have been written to C:\Users\Public\" + $currentTime + "_OUs.txt")
            } ELSE {
                [void]$info.Appendline("[!!] No OUs enumerated")
            } #close if-then-else
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain OU users could not be enumerated")
    } #close if-then-else

#output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetOUs_users_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetOUs_users_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-OUServer
{
<#
.SYNOPSIS

This script is used to enumerate all servers in each OU in the current domain.

Function: Get-OUServer
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all servers in each OU in the current domain.
An hashtable of arrays is returned. Keys are OU names.  Values are arrays of servers in the OU. 

.EXAMPLE

Get-OUServer

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{}
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-OUServer command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for servers per OU ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Query for OUs in the domain.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
    
        ## Creating the DirectoryEntry and DirectorySearcher objects
            $strFilter = "organizationalUnit" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher

        ## specify the domain root as the starting point for the search 
            $OUSearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $OUSearcher.Filter = "(objectCategory=$strFilter)"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $OUSearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $OUSearcher.PageSize = 1000 

# Execute the search
        ## Create an array with the DNs for each AD object
            $OUResults = $OUSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}
            $OU_name #init
            $returnObject = @{"$OU_name" = @()} #creates a hash table containing a set of dynamically named arrays. OU_Name=key Array_of_servers=value.
        
        ## Loop through and list Servers for each OU 
            IF (($OUResults.length -ne 0) -and ($OUResults -ne $NULL)) {           
                foreach ($OU in $OUResults) {
                    $strFilter = "server" 
                    $OU | Out-File -Append $("C:\Users\Public\" + $currentTime + "_OUs.txt") # write OU names out to file
                    $OU_name = $OU -replace ",","_" -replace "=","_"
                    $returnObject.Add("$OU_name",@()) #creates a hash table containing a set of dynamically named arrays. Name=key array=value.
           
            ### Query for all servers in each OU and write them to a file
            ### scope search to OU
                    $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$OU")
                    $OUServersearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $OUServersearcher.SearchRoot = $TargetDomain
                    $OUServersearcher.Filter = "(objectCategory=$strFilter)"
                    $OUServersearcher.PageSize=1000
                    $OUServers = $OUServersearcher.FindAll()
                    $OUServers.length
                
                    IF (($OUServers.length -ne 0) -and ($OUServers -ne $NULL)) {
                        foreach ($Server in $OUServers) {
                            $target = $Server.Properties.distinguishedname
                            $target | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_Servers.txt")
                            $returnObject."$OU_name" += $target #append target to my dynamically named array that's contained in the larger hash table
                            [void]$info.Appendline($target)
                        } #close inner for loop
                        [void]$info.AppendLine("Formatted list of servers written to C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_Servers.txt") #close if-then-else
                        [void]$info.Appendline("`n")
                    } #close if then else
                } #close outer for loop
               [void]$info.AppendLine("Formatted OUs have been written to C:\Users\Public\" + $currentTime + "_OUs.txt")  
            } ELSE {
                [void]$info.Appendline("[!!] No OUs enumerated")
            } #close if-then-else
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain OU servers could not be enumerated")
    } #close if-then-else

# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_GetOUs_servers_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_GetOUs_servers_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-OUGroup
{
<#
.SYNOPSIS

This script is used to enumerate all groups in each OU in the current domain.

Function: Get-OUGroup
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all groups in each OU in the current domain.
An hashtable of arrays is returned. Keys are OU names. Values are arrays of groups in the OU. 
	
.EXAMPLE

Get-OUGroup

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{}
    
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-OUGroup command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for groups per OU ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Query for OUs in the domain.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain

        ## Creating the DirectoryEntry and DirectorySearcher objects
            $strFilter = "organizationalUnit" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher

        ## specify the domain root as the starting point for the search 
            $OUSearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $OUSearcher.Filter = "(objectCategory=$strFilter)"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $OUSearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $OUSearcher.PageSize = 1000 

# Execute the search
        ## Create an array with the DNs for each AD object
            $OUResults = $OUSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}

        ## Loop through and list groups for each OU 
            IF (($OUResults.length -ne 0) -and ($OUResults -ne $NULL)) {
            
            $OU_name #init
            $returnObject.Add("$OU_name",@()) #add hashtable entry OU_name=key array_of_groups=value.
                     
                foreach ($OU in $OUResults) {
                    $strFilter = "group" 
                    $OU | Out-File -Append $("C:\Users\Public\" + $currentTime + "_OUs.txt")
                    $OU_name = $OU -replace ",","_" -replace "=","_"
           
             ### Query for all groups in each OU and write them to a file
             ### scope search to OU
                    $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$OU")
                    $OUGroupSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $OUGroupSearcher.SearchRoot = $TargetDomain
                    $OUGroupSearcher.Filter = "(objectCategory=$strfilter)"
                    $OUGroupSearcher.PageSize=1000
                    $OUGroups = $OUGroupSearcher.FindAll()
            
                    IF (($OUGroups.length -ne 0) -and ($OUGroups -ne $NULL)) {
                        foreach ($Group in $OUGroups) {
                            $target = $Group.Properties.distinguishedname
                            $target | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_groups.txt")
                            $returnObject."$OU_name" += $target #append target to my dynamically named array that's contained in the larger hash table
                        }
                        [void]$info.AppendLine("Formatted list of groups written to C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_groups.txt")
                    } #close if-then-else 
                } #close for loop
            } ELSE { 
                [void]$info.Appendline("[!!] No OUs enumerated")
            } #close if-then-else
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain OU groups could not be enumerated")
    } #close if-then-else

# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_Get_OUGroups_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_Get_OUGroups_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-OUComputer
{
<#
.SYNOPSIS

This script is used to enumerate all computers in each OU in the current domain.

Function: Get-OUComputer
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all computers in each OU in the current domain.
An hashtable of arrays is returned. Keys are OU names. Values are arrays of computers in the OU.
	
.EXAMPLE

Get-OUComputer

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{}
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-OUComputer command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for computers per OU ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")
    
# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Query for OUs in the domain.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain

        ## Creating the DirectoryEntry and DirectorySearcher objects
            $strFilter = "organizationalUnit" 
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $OUSearcher = New-Object System.DirectoryServices.DirectorySearcher
     
        ## specify the domain root as the starting point for the search 
            $OUSearcher.SearchRoot = $TargetDomain

        ## construct the LDAP filter
            $OUSearcher.Filter = "(objectCategory=$strFilter)"

        ## the "Subtree" specification ensures that the search will be executed recursively
            $OUSearcher.SearchScope = "Subtree" 

        ## bypass the limits on the search (ie. get more than 100 results)
            $OUSearcher.PageSize = 1000 

# Execute the search
        ## Create an array with the DNs for each AD object
            $OUResults = $OUSearcher.FindAll() | ForEach-Object {$_.properties.distinguishedname}

        ## Loop through and list computers for each OU 
            IF (($OUResults.length -ne 0) -and ($OUResults -ne $NULL)) {
            $OU_name #init
            $returnObject = @{"$OU_name" = @()} #creates a hash table containing a set of dynamically named arrays. OU_name=key array_of_computers=value.           
                foreach ($OU in $OUResults) {
                    $strFilter = "computer" 
                    $OU | Out-File -Append $("C:\Users\Public\" + $currentTime + "_OUs.txt") #write out to file
                    $OU_name = $OU -replace ",","_" -replace "=","_"
                    $returnObject.Add("$OU_name",@()) # Adds to a hash table containing a set of dynamically named arrays. OU_Name=key array_of_computers=value.
           
        ## Query for all computers in each OU and write them to a file
            ### scope search to OU
                    $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$OU")
                    $OUComputerSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $OUComputerSearcher.SearchRoot = $TargetDomain
                    $OUComputerSearcher.Filter = "(objectCategory=$strFilter)"
                    $OUComputerSearcher.PageSize=1000
                    $OUComputers = $OUComputerSearcher.FindAll()
            
                        IF (($OUComputers.length -ne 0) -and ($OUComputers -ne $NULL)) {
                            foreach ($Computer in $OUComputers) {
                                $target = $Computer.Properties.distinguishedname
                                $target | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_computers.txt")
                                $returnObject."$OU_name" += $target #append target to my dynamically named array that's contained in the larger hash table
                            } #close for loop
                            [void]$info.AppendLine("Formatted list of computers written to C:\Users\Public\" + $currentTime + "_" + $OU_name + "_OU_Computers.txt")
                        } #close if-then-else
                } #close for loop
            } ELSE {
                [void]$info.Appendline("[!!] No OUs enumerated")
            } #close if-then-else
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain OU computers could not be enumerated")
    } #close if-then-else
    
# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_Get_OUComputer_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_Get_OUComputer_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-SiteServer
{
<#
.SYNOPSIS

This script is used to enumerate the servers per site in a domain.

Function: Get-SiteServer
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate the servers per site in the current domain.
A hash table is returned.  The Key = site name and the Value = array of servers for the site.
	
.EXAMPLE

Get-SiteServer

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object to contain output
$info = new-object system.text.stringbuilder
$status = new-object system.text.stringbuilder #status message
$returnObject = @{}
 
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-SiteServer command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for servers per site ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")

# Capture the current domain.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
            
            $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
            $TargetDomain.site

# Capture the Sites and Servers 
            $Sites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
                     IF (($Sites.length -ne 0) -and ($Sites -ne $NULL)) {
                         $site_name #init
                         #$returnObject = @{"$OU_name" = @()} #creates a hash table containing a set of dynamically named arrays. site_name=key servers_array=value.
                            foreach ($site in $Sites) {
                                $site_name = $site.name
                                $site_name | Out-File -Append $("C:\Users\Public\" + $currentTime + "_sites.txt") #write site out to a file
                                $site_servers = $site.servers
                                $returnObject.Add("$site_name",@()) #creates a hash table containing a set of dynamically named arrays. site_name=key servers_array=value.
                                
                                IF (($site_servers.length -ne 0) -and ($site_servers -ne $NULL)) {
                                    foreach ($server in $site_servers) {
                                        $name = $server.name
                                        $returnObject."$site_name" += $name #append server to my dynamically named array which is entry in hashtable with site_name=key
                                        $name | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $site_name + "_servers.txt")
                                    }
                                    [void]$info.Appendline("Formatted list(s) of server(s) per site have been written to C:\Users\Public\" + $currentTime + "_" + $sitename + "_servers.txt") 
                                } #close if-then-else
                            } #close for loop
                            [void]$info.AppendLine("Formatted site list has been written to C:\Users\Public\" + $currentTime + "_sites.txt")
                    } ELSE {
                            [void]$info.Appendline("[!!] No sites enumerated")
                    } #close if-then-else
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Site servers could not be enumerated")
    }
    
# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_Get-Sites-Server_info.txt")
    [void]$info.Appendline("`n")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_Get-Sites-Server_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status

    return $returnObject
}


function Get-SiteSubnet
{
<#
.SYNOPSIS

This script is used to enumerate all subnets for each site in a domain.

Function: Get-SiteSubnet
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all subnets for each site in the current domain.
A hash table is returned.  The Key = site name and the Value = array of subnets for the site.
	
.EXAMPLE

Get-SiteSubnet

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object(s) to contain output
    $info = new-object system.text.stringbuilder
    $status = new-object system.text.stringbuilder #status message
    $returnObject = @{}
    
# Time when script is executing
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-SiteSubnet command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for subnets per site ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
# Capture the current domain.  Bail if the target is not part of a Domain.
    IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
     
        $TargetDomain = New-Object System.DirectoryServices.DirectoryEntry
        $TargetDomain.site

# Capture the Sites and Subnets
        $Sites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
                 IF (($Sites.length -ne 0) -and ($Sites -ne $NULL)) {
                     $site_name #init
                    foreach ($site in $Sites) {
                        $site_name = $site.name
                        $returnObject.Add("$site_name",@()) #creates a hash table containing a set of dynamically named arrays. site_name=key subnet_array=value.
                        $site_name | Out-File -Append $("C:\Users\Public\" + $currentTime + "_sites.txt")
                        $site_subnets = $site.subnets
                        
                        IF (($site_subnets.length -ne 0) -and ($site_subnets -ne $NULL)) {
                            foreach ($subnet in $site_subnets) {
                                $name = $subnet.name
                                $returnObject."$site_name" += $name #append subnet to my dynamically named array that's contained in the larger hash table. site_name=key subnet_array=value.
                                $name | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $site_name + "_subnets.txt")
                            } #close for loop
                            [void]$info.AppendLine("Formatted subnet list(s) have been written to C:\Users\Public\" + $currentTime + "_" + $site_name + "_subnets.txt")
                        } #close if-then-else
                    } #close for loop
                    [void]$info.AppendLine("Formatted site list has been written to C:\Users\Public\" + $currentTime + "_sites.txt") 
                } ELSE {
                        [void]$info.Appendline("[!!] No sites enumerated")
                } #close if-then-else
            
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Site subnets could not be enumerated")
    } #close if-then-else
    
# output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_Get-SitesSubnet_info.txt")
    [void]$info.Appendline("`n")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_Get-SitesSubnet_info.txt")
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-GroupMember
{
<#
.SYNOPSIS

This script is used to enumerate all users in a specific group in the current domain.

Function: Get-GroupMember
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script is used to enumerate all users in a group in the current domain.
	
.EXAMPLE

Get-GroupMember "<DN>"

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Input parameter = Group DN
	Param(
				[Parameter(Mandatory=$true,
				HelpMessage="Please enter a valid DN")]
				
			    [ValidatePattern("^(CN=.+)+(,OU=.+)+(,DC=.+)+")]
				
				$DescName
			)

# Object(s) to contain output
$info = new-object system.text.stringbuilder
$status = new-object system.text.stringbuilder #status message
$returnObject = @{} # A hashtable of arrays with a single entry.  The key is the group name.  The value is an array containing the users for that group.
$group_name #init

# Time when script is executing
$currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-GroupMember command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying for group membership ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
# Query for groups in the domain.  Bail if the target is not part of a Domain.
     IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain

         $group_name = $DescName -replace ",","_" -replace "=","_"
         $returnObject.Add("$group_name",@()) #creates a hash table containing a set of dynamically named arrays. Name=key array=value.
                
    ## Query for all members of a group and write them to a file  
         $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher
         $UserSearcher.SearchRoot = $TargetDomain
         $UserSearcher.Filter = "(&(objectCategory=user)(memberof=$DescName))"
         $UserSearcher.PageSize=1000
         $Users = $UserSearcher.FindAll() #creates array of users for group
                
        IF (($Users.length -ne 0) -and ($Users -ne $NULL)) {
            foreach ($User in $Users) {
                $target = $User.Properties.distinguishedname
                $target | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $group_name + "_group_users.txt") #write outout to file
                $returnObject."$group_name" += $target #The key is the group name.  The value will be an array containing the users for that group.
            }
        }
        [void]$info.AppendLine("A formatted list of group membership has been written to " + $currentTime + "_" + $group_name + "_group_users.txt")
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Group Users could not be enumerated")
    }

#output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_" + "_Get-GroupMember_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_Get-GroupMember_info.txt") #write output to file
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-HighValueGroup
{
<#
.SYNOPSIS

This script will retrive high value group(s) based on a keyword file, enumerate group users, and collect email addresses.

Function: Get-HighValueGroup
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: Get-Homebase, Get-Group
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script will retrieve high value groups based on keywords, enumerate the users in each group returned, and collect corresponding email addresses.

.PARAMETER keywords
This is the keyword file that will be used to identify high value target groups.
	
.EXAMPLE

Get-HighValueGroup "<full path to file>"

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Input parameter = keyword file ( eg. keywords.txt)
	Param(
				[Parameter(Mandatory=$true,
				HelpMessage="Please provide the FULLPATH to a properly formatted keyword text file; one keyword per line.")]
				
                [ValidateScript({Test-Path $_})]
                
				$keywords
			)

# Object to contain output
$info = new-object system.text.stringbuilder
$status = new-object system.text.stringbuilder #status message
$tagwords=@() #holds keywords passed in with use file
$groupsHigh=@()
$groupsHighEmail=@()
$groupsHighMember=@{}
$returnObject = @{} # Keys are the high value group names.  Values are hashtables with key=username and value=user email
$userEmailPair = @{} # Username and email hashtable

# Time when script is executing
$currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$info.Appendline("`n")
    [void]$status.Appendline("`n")
    [void]$status.Appendline("[*] Get-HighValueGroup command executed at : " + $currentTime)
    [void]$info.AppendLine("Script ran at : " + $currentTime)
    [void]$info.Appendline("`n")
    [void]$info.Appendline("Querying groups ...")
    [void]$info.Appendline("`n")
    [void]$info.Appendline("[*] Results")
    [void]$info.Appendline("`n")

# Call Get-Homebase and verify Domain and Domain Controller
    $Pedigree = Get-Homebase -noOutFile
    $DomainCheck = $Pedigree.Get_Item("Domain (wmi)")
    $DCCheck = $Pedigree.Get_Item("DomainController")
    $LogonServerCheck = $Pedigree.Get_Item("LogonServer")
    
# Query for groups in the domain.  Bail if the target is not part of a Domain.
     IF (($DomainCheck -ne $NULL) -and ($DomainCheck -ne "WORKGROUP")) { #check to see if the target is in a domain
    
    ## Call Get-Group
        $groups = Get-Group -noOutFile 
         
    ## Write input file contents to array
        $tagwords = Get-Content $keywords
        
    ## Execute comparison and create file with high value groups
        foreach ($tag in $tagwords) {
            foreach ($gp in $groups) {
                IF ($gp -match $tag) {
                    $gp | Out-File -Append $("C:\Users\Public\" + $currentTime + "_HighValueGroups.txt")
                    $groupsHigh+=$gp #write the group out to an array
                 }
            }
        }
                
    ## Check to see if high vaklue groups were returned
        IF (($groupsHigh.length -ne 0) -and ($groupsHigh -ne $NULL)) { 
    
    ## Enumerate users and harvest email for each high value group
               foreach ($groupHigh in $groupsHigh) {
                 $HGroup_Name = $groupHigh -replace ",","_" -replace "=","_" #making naming cleaner
                 
    ## Query for all members of a group, harvtest the email and write both to a file  
                     $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher
                     $UserSearcher.SearchRoot = $TargetDomain
                     $UserSearcher.Filter = "(&(objectCategory=user)(memberof=$groupHigh))"
                     $UserSearcher.PageSize=1000
                     $groupsHighMember = $UserSearcher.FindAll() #creates array of users for group
                            
                    IF (($groupsHighMember.length -ne 0) -and ($groupsHighMember -ne $NULL)) {
                        foreach ($User in $groupsHighMember) {
                            $email = $User.properties.mail
                            $email | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $HGroup_Name + "_HighValue_user_email.txt") #write outout to file
                            $target = $User.Properties.distinguishedname
                            $target | Out-File -Append $("C:\Users\Public\" + $currentTime + "_" + $HGroup_Name + "_HighValue_user.txt") #write outout to fill
                            $userEmailPair.Add($target,$email)
                        }
                    $returnObject.Add($HGroup_Name,$userEmailPair) #The key is the group name.  The value will be a hashtable containing the usernames and emails.
                    [void]$info.AppendLine("A formatted list of group membership has been written to " + $currentTime + "_" + $HGroup_Name + "_HighValue_group_user.txt")
                    [void]$info.AppendLine("A formatted list of user emails has been written to " + $currentTime + "_" + $HGroup_Name + "_HighValue_user_email.txt")
                    }  
               }
        } ELSE {
            [void]$info.Appendline("[!!] No results.")
        }
    } ELSE {
        [void]$info.Appendline("[!!] The target domain is either WORKGROUP or undefined. Domain Group Users could not be enumerated")
    }

#output
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("[*] OUTFILE(s)")
    [void]$info.Appendline("`n")
    [void]$info.AppendLine("Output has been written to C:\Users\Public\" + $currentTime + "_" + "_Get-HighValueGroup_info.txt")
    $info.ToString() | Out-File $("C:\Users\Public\" + $currentTime + "_Get-HighValueGroup_info.txt") #write output to file
    [void]$status.Appendline("[*] Success")
    Write-Host $status
    
    return $returnObject
}

function Get-DomainDump
{
<#
.SYNOPSIS

This script will call all previous functions

Function: Get-DomainDump
Author: p.j. hartlieb, Twitter: @pjhartlieb
Required Dependencies: All other functions, except Get-HighValueGroup and Get-GroupMember
Optional Dependencies: None
Version: 0.0.9

.DESCRIPTION

This script does all the things.
	
.EXAMPLE

Get-DomainDump

.NOTES

.LINK

Blog: http://pjhartlieb.blogspot.com/
Github repo: https://github.com/pjhartlieb/post-exploitation.git

#>

# Object to contain output
    $kickoff = new-object system.text.stringbuilder #status message
    $end = new-object system.text.stringbuilder #status message
    $currentTime = get-date -uformat '%Y.%m.%d_%H_%M_%S'
    [void]$kickoff.Appendline("`n")
    [void]$kickoff.Appendline("[*] Get-DomainDump command executing at : " + $currentTime)
    $kickoff.ToString()
    
    #1
    Get-Homebase
    #2
    Get-Pedigree
    #3
    Get-Computer
    #4
    Get-DC
    #5
    Get-Group
    #6
    Get-GroupUser
    #7
    Get-Server
    #8
    Get-User
    #9
    Get-Email
    #10
    Get-OU
    #11
    Get-OUUser
    #12
    Get-OUServer
    #13
    Get-OUGroup
    #14
    Get-OUComputer
    #14
    Get-SiteServer
    #15
    Get-SiteSubnet
    
	[void]$end.Appendline("`n")
    [void]$end.Appendline("[*] Successful dump!  Have a nice day.")
    Write-Host $end
}
