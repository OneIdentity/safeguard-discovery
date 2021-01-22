$script:SqlServerPermissionsMap = @{
    "iLOConfigPrivilege" = "ALTER ANY EVENT SESSION"
    "RemoteConsolePrivilege" = "ADMINISTER BULK OPERATIONS"
    "UserConfigPrivilege"   = "ALTER"
    "VirtualPowerAndResetPrivilege" = "ALTER ANY SERVER AUDIT"
    "VirtualMediaPrivilege" = "ALTER ANY AVAILABILITY GROUP"
}
$script:SqlServerPermissionsString = ($script:SqlServerPermissionsMap | Out-String)

function Invoke-ThrowPermissionsException
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Host -ForegroundColor Yellow $script:SqlServerPermissionsString
    Write-Host -ForegroundColor Yellow "Example Usage:"
    Write-Host -ForegroundColor Yellow "  -IncludePermissions @(`"UserConfigPrivilege`",`"iLOConfigPrivilege`")"
    Write-Host -ForegroundColor Yellow "    or"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @(`"UserConfigPrivilege`",`"iLOConfigPrivilege`",`"VirtualMediaPrivilege`")"
    Write-Host -ForegroundColor Yellow "    or (to turn it off)"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @()"
    throw $Message
}

<#
.SYNOPSIS
Discover privileged accounts in a HP iLO.

.DESCRIPTION
This cmdlet may be used to discover privileged accounts in a HP iLO.  When
called without arguments, the default behavior is to find local accounts that have been
granted any permissions.  The caller can override this behavior by specifying the exact 
list of roles to look for.  The caller can also specify which directly granted permissions 
to exclude or include.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an account name and password to use.

.PARAMETER NetworkAddress
IP address or hostname of a HP iLO.

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the system to
execute the discovery job.

.PARAMETER ExcludePermissions
A list of permissions to exclude when searching for privileged accounts, or set to @() to turn off permission search.
See https://support.hpe.com/hpesc/public/docDisplay?docId=a00045108en_us&docLocale=en_US

.PARAMETER IncludePermissions
A list of permissions to include when searching for privileged accounts.
See https://support.hpe.com/hpesc/public/docDisplay?docId=a00045108en_us&docLocale=en_US

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscSqlServerAccount mssql.test.env

.EXAMPLE
Get-SgDiscSqlServerAccount mssql.test.env -Credential (Get-Credential)

.EXAMPLE
Get-SgDiscSqlServerAccount mssql.test.env -IncludePermissions UserConfigPrivilege,iLOConfigPrivilege,VirtualMediaPrivilege
#>
function Get-SgDiscHpiLOAccount
{
    [CmdletBinding(DefaultParameterSetName="ExcludePerms")]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory=$false,ParameterSetName="ExcludePerms")]
        [string[]]$ExcludePermissions = @(),
        [Parameter(Mandatory=$false,ParameterSetName="IncludePerms")]
        [string[]]$IncludePermissions = $null
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Credential)
    {
        # doing this here allows error action and verbose parameters to propagate
        $Credential = (Get-SgDiscConnectionCredential $NetworkAddress)
    }

    # make sure HPEiLOCmdlets is installed
    if (-not (Get-Module HPEiLOCmdlets)) 
    { 
        try 
        {
            Import-Module HPEiLOCmdlets
        }
        catch 
        {
            throw "HP ILO account discovery in safeguard-discovery requires HPEiLOCmdlets.  Please run: Install-Module HPEiLOCmdlets."
        }
    }

    $session = Connect-HPEiLO $NetworkAddress -Credential $Credential -DisableCertificateAuthentication

    # handle explicit permissions
    if (($PSCmdlet.ParameterSetName -eq "IncludePerms" -and $IncludePermissions) -or ($PSCmdlet.ParameterSetName -eq "ExcludePerms" -and $ExcludePermissions))
    {
        if ($PSCmdlet.ParameterSetName -eq "IncludePerms" -and $IncludePermissions)
        {
            $local:PermInclusions = ""
            foreach ($local:Perm in $IncludePermissions)
            {
                if (-not $script:SqlServerPermissionsMap.ContainsKey($local:Perm))
                {
                    Invoke-ThrowPermissionsException "Invalid permission inclusion '$($local:Perm)'"
                }
                if ($local:PermInclusions -ne "")
                {
                    $local:PermInclusions += " -or ";
                }
                $local:PermInclusions += "(`$_.$($local:Perm) -eq 'Yes')";
            }
            $filterScript = [scriptblock]::Create($local:PermInclusions)
        }
        elseif ($PSCmdlet.ParameterSetName -eq "ExcludePerms" -and $ExcludePermissions)
        {
            $local:PermExclusions = @()
            foreach ($local:Perm in $ExcludePermissions)
            {
                if (-not $script:SqlServerPermissionsMap.ContainsKey($local:Perm))
                {
                    Invoke-ThrowPermissionsException "Invalid permission exclusion '$($local:Perm)'"
                }
                if ($local:PermExclusions -ne "")
                {
                    $local:PermExclusions += " -and ";
                }
                $local:PermExclusions += "(`$_.$($local:Perm) -eq 'No')";
            }
            $filterScript = [scriptblock]::Create($local:PermExclusions)
        }

        # query to find matching permissions (this is filtered to local accounts)        
        $local:PrivilegedAccountsFromPermissions = (Get-HPEiLOUser $session).UserInformation | Where-Object -FilterScript $filterScript | ForEach-Object {
            New-Object PSObject -Property ([ordered]@{
                AccountName = $_.LoginName
            })
        }
    }
    else
    {               
        $local:PrivilegedAccountsFromPermissions = (Get-HPEiLOUser $session).UserInformation | ForEach-Object {
            New-Object PSObject -Property ([ordered]@{
                AccountName = $_.LoginName
            })
        }
    }

    #  process results
    $local:Results = @{}
    $local:PrivilegedAccountsFromPermissions | ForEach-Object {
        $local:Results[$_.AccountName] = New-Object PSObject -Property ([ordered]@{
            AccountName = $_.AccountName;
            Description = ""
        })
    }

    # convert results to an array and add the description
    $local:Results.Values | ForEach-Object {
        $_.Description = "safeguard-discovery"
        $_
    }
}
