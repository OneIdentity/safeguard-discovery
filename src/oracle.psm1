$script:SqlExplicitRoleMembersWithInclusions = "
SELECT 
       rp.Granted_Role AS RoleName,
       rp.Grantee AS AccountName
FROM dba_role_privs rp
WHERE rp.Granted_Role IN ({0})"

$script:AllSqlExplicitGrants = "
SELECT sp.Grantee AS AccountName,
       sp.Privilege AS PermissionName
FROM dba_sys_privs sp
WHERE "

$script:SqlExplicitGrantsWithInclusions = $script:AllSqlExplicitGrants + "sp.Privilege IN ({0})"
$script:SqlExplicitGrantsWithExclusions = $script:AllSqlExplicitGrants + "sp.Privilege NOT IN ({0})"

$script:OraclePermissionsMap = @{
    "DEQUEUE ANY QUEUE" = "DEQUEUE ANY QUEUE"
    "MANAGE ANY QUEUE" = "MANAGE ANY QUEUE"
    "CREATE ANY EVALUATION CONTEXT" = "CREATE ANY EVALUATION CONTEXT"
    "CREATE ANY RULE" = "CREATE ANY RULE"
    "CREATE ANY JOB" = "CREATE ANY JOB"
    "CREATE INDEXTYPE" = "CREATE INDEXTYPE"
    "SELECT ANY TABLE" = "SELECT ANY TABLE"
    "INSERT ANY TABLE" = "INSERT ANY TABLE"
    "EXECUTE ANY EVALUATION CONTEXT" = "EXECUTE ANY EVALUATION CONTEXT"
    "CREATE RULE SET" = "CREATE RULE SET"
    "ALTER ANY RULE" = "ALTER ANY RULE"
    "EXECUTE ANY PROGRAM" = "EXECUTE ANY PROGRAM"
    "EXECUTE ANY CLASS" = "EXECUTE ANY CLASS"
    "CREATE ANY CREDENTIAL" = "CREATE ANY CREDENTIAL"
    "CREATE EVALUATION CONTEXT" = "CREATE EVALUATION CONTEXT"
    "UPDATE ANY TABLE" = "UPDATE ANY TABLE"
    "ENQUEUE ANY QUEUE" = "ENQUEUE ANY QUEUE"    
    "CREATE DIMENSION" = "CREATE DIMENSION"
    "CREATE SEQUENCE" = "CREATE SEQUENCE"
    "CREATE SESSION"   = "CREATE SESSION"
    "CREATE TABLE" = "CREATE TABLE"
    "CREATE TYPE" = "CREATE TYPE"
    "DROP ANY RULE SET" = "DROP ANY RULE SET"
    "READ ANY TABLE" = "READ ANY TABLE"
    "CREATE RULE" = "CREATE RULE"
    "CREATE CLUSTER" = "CREATE CLUSTER"
    "CREATE PROCEDURE" = "CREATE PROCEDURE"
    "CREATE VIEW" = "CREATE VIEW"
    "ALTER ANY EVALUATION CONTEXT" = "ALTER ANY EVALUATION CONTEXT"
    "CREATE OPERATOR" = "CREATE OPERATOR"
    "CREATE SYNONYM"   = "CREATE SYNONYM"
    "DROP ANY EVALUATION CONTEXT"   = "DROP ANY EVALUATION CONTEXT"
    "EXECUTE ANY RULE" = "EXECUTE ANY RULE"
    "MANAGE SCHEDULER" = "MANAGE SCHEDULER"
    "CREATE EXTERNAL JOB" = "CREATE EXTERNAL JOB"
    "DELETE ANY TABLE" = "DELETE ANY TABLE"
    "ALTER ANY RULE SET"  = "ALTER ANY RULE SET"
    "EXECUTE ANY RULE SET"   = "EXECUTE ANY RULE SET"
    "ADMINISTER KEY MANAGEMENT" = "ADMINISTER KEY MANAGEMENT"
    "CREATE TRIGGER"  = "CREATE TRIGGER"
    "CREATE JOB"   = "CREATE JOB"
    "CREATE ANY RULE SET" = "CREATE ANY RULE SET"
    "DROP ANY RULE" = "DROP ANY RULE"
    "CREATE MATERIALIZED VIEW" = "CREATE MATERIALIZED VIEW"
}
$script:OraclePermissionsString = ($script:OraclePermissionsMap | Out-String)

function Invoke-ThrowPermissionsException
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Host -ForegroundColor Yellow $script:OraclePermissionsString
    Write-Host -ForegroundColor Yellow "Example Usage:"
    Write-Host -ForegroundColor Yellow "  -IncludePermissions @(`"INSERT ANY TABLE`",`"DROP ANY RULE`")"
    Write-Host -ForegroundColor Yellow "    or"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @(`"INSERT ANY TABLE`",`"DROP ANY RULE`",`"EXECUTE ANY RULE SET`")"
    Write-Host -ForegroundColor Yellow "    or (to turn it off)"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @()"
    throw $Message
}

<#
.SYNOPSIS
Discover privileged accounts in a Oracle database.

.DESCRIPTION
This cmdlet may be used to discover privileged accounts in a Oracle database.  When
called without arguments, the default behavior is to find local accounts that have been
added to the built-in role (AQ_ADMINISTRATOR_ROLE,DBA) and any local accounts that have been
granted any permissions other than SELECT ANY TABLE, READ ANY TABLE.  The caller can
override this behavior by specifying the exact list of roles to look for.  The caller
can also specify which directly granted permissions to exclude or include.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an account name and password to use.

.PARAMETER NetworkAddress
IP address or hostname of a Oracle database.

.PARAMETER Instance
Name of the postgres instance to connect to

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the database server to
execute the discovery job.

.PARAMETER Roles
A list of roles to search for to identify privileged accounts, or set to @() to turn off role search.
See https://docs.oracle.com/cd/A97630_01/server.920/a96521/privs.htm#:~:text=A%20user%20privilege%20is%20a,together%20privileges%20or%20other%20roles.

.PARAMETER ExcludePermissions
A list of permissions to exclude when searching for privileged accounts, or set to @() to turn off permission search.
See https://docs.oracle.com/cd/A97630_01/server.920/a96521/privs.htm#:~:text=A%20user%20privilege%20is%20a,together%20privileges%20or%20other%20roles.

.PARAMETER IncludePermissions
A list of permissions to include when searching for privileged accounts.
See https://docs.oracle.com/cd/A97630_01/server.920/a96521/privs.htm#:~:text=A%20user%20privilege%20is%20a,together%20privileges%20or%20other%20roles.

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscOracleAccount oracle.test.env

.EXAMPLE
Get-SgDiscOracleAccount oracle.test.env -Credential (Get-Credential)

.EXAMPLE
Get-SgDiscOracleAccount oracle.test.env -Roles DBA,CAPTURE_ADMIN,DV_SECANALYST -IncludePermissions CREATE TABLE,MANAGE ANY QUEUE,DEQUEUE ANY QUEUE
#>
function Get-SgDiscOracleAccount
{
    [CmdletBinding(DefaultParameterSetName="ExcludePerms")]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Instance,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$Roles = @("AQ_ADMINISTRATOR_ROLE","DBA"),
        [Parameter(Mandatory=$false,ParameterSetName="ExcludePerms")]
        [string[]]$ExcludePermissions = @("SELECT ANY TABLE","READ ANY TABLE"),
        [Parameter(Mandatory=$false,ParameterSetName="IncludePerms")]
        [string[]]$IncludePermissions
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Credential)
    {
        # doing this here allows error action and verbose parameters to propagate
        $Credential = (Get-SgDiscConnectionCredential $NetworkAddress)
    }

    $local:NetworkCredential = $Credential.GetNetworkCredential()
    $ConnectionString = "Data Source=$NetworkAddress/$Instance;User Id=$($local:NetworkCredential.UserName);Password=$($local:NetworkCredential.Password)"

    # make sure InvokeQuery is installed
    if (-not (Get-Module InvokeQuery)) 
    { 
        try 
        {
            Import-Module InvokeQuery
        }
        catch 
        {
            throw "SQL account discovery in safeguard-discovery requires InvokeQuery.  Please run: Install-Module InvokeQuery."
        }
    }

    # handle explicit permissions
    if (($PSCmdlet.ParameterSetName -eq "IncludePerms" -and $IncludePermissions) -or ($PSCmdlet.ParameterSetName -eq "ExcludePerms" -and $ExcludePermissions))
    {
        if ($PSCmdlet.ParameterSetName -eq "IncludePerms" -and $IncludePermissions)
        {
            $local:PermInclusions = @()
            foreach ($local:Perm in $IncludePermissions)
            {
                $local:PermInclusions += "'$($local:Perm)'"
            }
            $local:Sql = ($script:SqlExplicitGrantsWithInclusions -f ($local:PermInclusions -join ","))
        }
        elseif ($PSCmdlet.ParameterSetName -eq "ExcludePerms" -and $ExcludePermissions)
        {
            $local:PermExclusions = @()
            foreach ($local:Perm in $ExcludePermissions)
            {
                $local:PermExclusions += "'$($local:Perm)'"
            }
            $local:Sql = ($script:SqlExplicitGrantsWithExclusions -f ($local:PermExclusions -join ","))
        }

        # query to find matching permissions (this is filtered to local accounts)
        $local:PrivilegedAccountsFromPermissions = (Invoke-OracleQuery -Sql $local:Sql -ConnectionString $ConnectionString)
    }
    else
    {
        $local:PrivilegedAccountsFromPermissions = @()
    }

    # handle Oracle roles
    if ($Roles)
    {
        $local:RoleInclusions = @()
        foreach ($local:Role in $Roles)
        {
            $local:RoleInclusions += "'$($local:Role)'"
        }
        $local:Sql = ($script:SqlExplicitRoleMembersWithInclusions -f ($local:RoleInclusions -join ","))

        # query to find matching role memberships (this is filtered to local accounts)
        $local:PrivilegedAccountsFromRoles = (Invoke-OracleQuery -Sql $local:Sql -ConnectionString $ConnectionString)
    }
    else
    {
        $local:PrivilegedAccountsFromRoles = @()
    }

    #  process results
    $local:Results = @{}
    $local:PrivilegedAccountsFromPermissions | ForEach-Object {
        if ($local:Results[$_.AccountName])
        {
            $local:Results[$_.AccountName].Permissions += (New-Object PSObject -Property ([ordered]@{
                PermissionName = $_.PermissionName;
            }))
        }
        else
        {
            $local:Results[$_.AccountName] = New-Object PSObject -Property ([ordered]@{
                AccountName = $_.AccountName;
                Roles = @();
                Permissions = @(New-Object PSObject -Property ([ordered]@{
                    PermissionName = $_.PermissionName;
                }));
                Description = "";
            })
        }
    }
    $local:PrivilegedAccountsFromRoles | ForEach-Object {
        if ($local:Results[$_.AccountName])
        {
            $local:Results[$_.AccountName].Roles += ($_.RoleName)
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
        if ($_.Permissions)
        {
            $_.Description += " permissions:" + ($_.Permissions.PermissionName -join ",")
        }
        $_
    }
}
