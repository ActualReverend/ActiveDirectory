<#PSScriptInfo

.VERSION 0.2

.GUID bbd3d8d6-97c2-4feb-929b-998111cc0808

.AUTHOR Bryan Loveless (Bryan.Loveless@gmail.com)

.COMPANYNAME 

.COPYRIGHT 

.TAGS selective authentication Active Directory Trust

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

<# 

.DESCRIPTION 
 Sets the "allowed to authenticate" attribute on a machine object.  One use is to configure a local group (that has an external group from an external trust) to log into a selection of workstations. 
  

#> 


# modify "allowed to auth to" field of machine objects in an OU
# https://docs.microsoft.com/en-us/windows/desktop/ADSchema/r-allowed-to-authenticate
# Add the Security Group to All Computer Accounts That Need Access -https://www.anexinet.com/blog/what-ms-doesnt-tell-you-how-to-properly-create-a-two-way-external-domain-selective-trust-between-two-seperate-forests/
# https://www.petri.com/restrict-privileged-accounts-with-authentication-silos-in-windows-server-2012-r2
# https://stackoverflow.com/questions/47642698/dsacls-invalid-dn-syntax-in-powershell

$OUToModify = "OU=ChildDomain1Guest, DC=ChildDomain2, DC=local"
$JustTheWorkstation = "CN= Workstation1, OU=ChildDomain1Guest, DC=ChildDomain2, DC=local"
$ExternalDomainUserGroup
$InternalDomainName
$ExternalDomainName
$LocalDomainGroup = "ExternalDomainUsers"
$escapeparser = '--%'

#Get the list of machines in that OU:
$ComputersToModify = Get-ADComputer -Filter * -SearchBase $OUToModify


#must set AD as the location
Set-Location ad:

#for each object in that group, modify the security
Foreach ($ComputerToModify in $computersToModify) {
#(get-acl ($computertomodify).distinguishedname).access
#$commandtorun = (Write-Host "dsacls" "`"$computertomodify`"" "/g" `"$LocalDomainGroup":ca;allowed to authenticate`"")
#$commandtorun = ("dsacls " + $computertomodify + " /g " "$LocalDomainGroup:ca;allowed to authenticate").tostring()


$CommandToRun = '& c:\windows\system32\dsacls.exe ' + $computertomodify.DistinguishedName + ' /g ' + $LocalDomainGroup + ':ca`;allowed to authenticate'
$return = Invoke-Expression -Command $CommandToRun

#need above to say "dsacls "CN=Workstation1,OU=ChildDomain1Guest,DC=ChildDomain2,DC=local" /g ExternalDomainUsers:ca;allowed to authenticate"
} 



#dsacls "[DN of object]" /g "[groupname]:ca;allowed to authenticate"
dsacls "[DN of object]" /g "[groupname]:ca;allowed to authenticate"

(get-acl (Get-ADOrganizationalUnit -Filter 'name -eq "workstation1"').distinguishedname).access

(get-acl (Get-ADOrganizationalUnit -Filter 'name -eq "workstation1"').distinguishedname).access