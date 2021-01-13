<#
.SYNOPSIS
Discover privileged accounts in a IDrac system.

.DESCRIPTION
This cmdlet may be used to discover privileged accounts in a IDrac system.  When
called without arguments, the default behavior is to find all local accounts.  The caller can
override this behavior by specifying the exact list of roles to look for. 

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an account name and password to use.

.PARAMETER NetworkAddress
IP address or hostname of a IDrac database.

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the database server to
execute the discovery job.

.PARAMETER Roles
A list of roles to search for to identify privileged accounts, or set to @() to turn off role search.
https://downloads.dell.com/manuals/common/dell_rolebasedauthorizationprofile_1.0.pdf

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscIDracAccount IDrac.test.env

.EXAMPLE
Get-SgDiscIDracAccount IDrac.test.env -Credential (Get-Credential)

.EXAMPLE
Get-SgDiscIDracAccount IDrac.test.env -Roles "DCIM Local Role 16","DCIM Local Role 17"
#>
function Get-SgDiscIDracAccount
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$Roles = $null
    )
    
    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    
    if (-not $Credential)
    {
        # doing this here allows error action and verbose parameters to propagate
        $Credential = (Get-SgDiscConnectionCredential $NetworkAddress)
    }
    
    # https://www.dell.com/support/kbdoc/en-us/000178033/agentless-management-with-powershell-3-0-cim-cmdlets-and-idrac-lifecycle-controller
    $local:cimop=New-CimSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -Encoding Utf8 -UseSsl
    $local:session=New-CimSession -Authentication Basic -Credential $Credential -ComputerName $NetworkAddress -Port 443 -SessionOption $local:cimop
    
    # handle IDrac roles
    $local:PrivilegedAccountsFromRoles = @()
    if ($Roles)
    {
        # query to find matching role memberships (this is filtered to local accounts)  
        $local:foundRoles = Get-CimInstance -CimSession $session -Namespace root\dcim -ClassName DCIM_Role 
        foreach ($local:role in $local:foundRoles){
            if ($local:role.ElementName -in $Roles)
            {
                $local:identities = Get-CimAssociatedInstance -CimSession $session -ResultClassName DCIM_LocalUserIdentity $local:role
                foreach ($local:identity in $local:identities)
                {
                    $local:account = Get-CimAssociatedInstance -CimSession $session -ResultClassName DCIM_Account $local:identity
                    if ($local:account -and ($null -ne $local:account.UserID))
                    {
                        $local:PrivilegedAccountsFromRoles += New-Object PSObject -Property ([ordered]@{
                            AccountName = $local:account.UserID;
                            RoleName = $local:role.ElementName;
                        })
                    }
                }
            }
        }
    }
    else
    {        
        Get-CimInstance -CimSession $session -Namespace root\dcim -ClassName DCIM_Account | Where-Object UserID -ne $null | ForEach-Object {
            $local:PrivilegedAccountsFromRoles += New-Object PSObject -Property ([ordered]@{
                AccountName = $_.UserID;
                RoleName = "";
            })
        }
    }

    #  process results
    $local:Results = @{}
    $local:PrivilegedAccountsFromRoles | ForEach-Object {
        if ($local:Results[$_.AccountName])
        {            
            if (-not $_.RoleName -in $local:Results[$_.AccountName].Roles)
            {
                $local:Results[$_.AccountName].Roles += ($_.RoleName)
            }
        }
        else
        {
            $local:Results[$_.AccountName] = New-Object PSObject -Property ([ordered]@{
                AccountName = $_.AccountName;
                Roles = @($_.RoleName);
                Permissions = @();
                Description = "";
            })
        }
    }

    # convert results to an array and add the description
    $local:Results.Values | ForEach-Object {
        $_.Description = "safeguard-discovery --"
        if ($_.Roles)
        {
            $_.Description += " roles:" + ($_.Roles -join ",")
        }
        $_
    }
}
