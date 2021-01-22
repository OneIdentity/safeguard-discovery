$script:SqlExplicitRoleMembersWithInclusions = "
    SELECT 
        m.rolname AccountName
        r.rolname RoleName
    FROM     pg_auth_members am 
        JOIN pg_roles m on am.member = m.oid 
        JOIN pg_roles r on r.oid = am.roleid 
    WHERE m.rolcanlogin and (r.rolesuper or r.rolinherit or r.rolcreaterole or r.rolreplication or r.rolbypassrls) and r.rolname in ({0})"

$script:SqlExplicitGrantsWithInclusions = "
    SELECT 
        u.usesysid AS Id, 
        u.usename AS AccountName 
    FROM pg_catalog.pg_user u 
    where {0}
"
$script:SqlExplicitGrantsWithExclusions = "
    SELECT 
    u.usesysid AS Id, 
    u.usename AS AccountName 
    FROM pg_catalog.pg_user u 
    where not {0}"

$script:SqlServerPermissionsMap = @{
    "createdb" = "Create database"
    "super" = "All permissions"
    "repl" = "Manage Replication"
    "bypassrls" = "Bypass row level security"
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
    Write-Host -ForegroundColor Yellow "  -IncludePermissions @(`"createdb`",`"super`")"
    Write-Host -ForegroundColor Yellow "    or"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @(`"repl`",`"bypassrls`")"
    Write-Host -ForegroundColor Yellow "    or (to turn it off)"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @()"
    throw $Message
}

<#
.SYNOPSIS
Discover privileged accounts in a SQL Server database.

.DESCRIPTION
This cmdlet may be used to discover privileged accounts in a Postgres database.  When
called without arguments, the default behavior is to find local accounts that have added to any 
admin roles or that have been granted global permissions except usecreatedb, usesuper, userepl.  
The caller can override this behavior by specifying which directly granted permissions to exclude 
or include.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an account name and password to use.

.PARAMETER NetworkAddress
IP address or hostname of a SQL Server database.

.PARAMETER Instance
Name of the postgres instance to connect to

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the database server to
execute the discovery job.

.PARAMETER Roles
A list of roles to search for to identify privileged accounts, or set to @() to turn off role search.
See https://www.postgresql.org/docs/9.0/database-roles.html

.PARAMETER ExcludePermissions
A list of permissions to exclude when searching for privileged accounts, or set to @() to turn off permission search.
See https://www.postgresql.org/docs/9.0/user-manag.html

.PARAMETER IncludePermissions
A list of permissions to include when searching for privileged accounts.
See https://www.postgresql.org/docs/9.0/user-manag.html

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscPostgresAccount Postgres.test.env

.EXAMPLE
Get-SgDiscPostgresAccount Postgres.test.env -Credential (Get-Credential)

.EXAMPLE
Get-SgDiscPostgresAccount Postgres.test.env -IncludePermissions Create_priv,Drop_priv
#>
function Get-SgDiscPostgresAccount
{
    [CmdletBinding(DefaultParameterSetName="IncludePerms")]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Instance,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$Roles = @(),
        [Parameter(Mandatory=$false,ParameterSetName="ExcludePerms")]
        [string[]]$ExcludePermissions = @(),
        [Parameter(Mandatory=$false,ParameterSetName="IncludePerms")]
        [string[]]$IncludePermissions = @("createdb", "super", "repl", "bypassrls")
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Credential)
    {
        # doing this here allows error action and verbose parameters to propagate
        $Credential = (Get-SgDiscConnectionCredential $NetworkAddress)
    }
    
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

    $local:NetworkCredential = $Credential.GetNetworkCredential()
    $ConnectionString = "User ID=$($local:NetworkCredential.UserName);password=$($local:NetworkCredential.Password);host=$NetworkAddress;Database=$Instance"

    # handle explicit permissions
    if (($PSCmdlet.ParameterSetName -eq "IncludePerms" -and $IncludePermissions) -or ($PSCmdlet.ParameterSetName -eq "ExcludePerms" -and $ExcludePermissions))
    {
        if ($PSCmdlet.ParameterSetName -eq "IncludePerms" -and $IncludePermissions)
        {
            $local:PermInclusions = @()
            foreach ($local:Perm in $IncludePermissions)
            {
                if (-not $script:SqlServerPermissionsMap.ContainsKey($local:Perm))
                {
                    Invoke-ThrowPermissionsException "Invalid permission inclusion '$($local:Perm)'"
                }
                $local:PermInclusions += "use$($local:Perm)"
            }
            $local:Sql = ($script:SqlExplicitGrantsWithInclusions -f ($local:PermInclusions -join " or "))
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
                $local:PermExclusions += "use$($local:Perm)"
            }
            $local:Sql = ($script:SqlExplicitGrantsWithExclusions -f ($local:PermExclusions -join " and not "))
        }

        # query to find matching permissions (this is filtered to local accounts)
        $local:PrivilegedAccountsFromPermissions = (Invoke-PostgreSqlQuery -Sql $local:Sql -ConnectionString $ConnectionString)
    }
    else
    {
        $local:PrivilegedAccountsFromPermissions = @()
    }

    # handle sql server roles
    if ($Roles)
    {
        $local:RoleInclusions = @()
        foreach ($local:Role in $Roles)
        {
            $local:RoleInclusions += "'$($local:Role)'"
        }
        $local:Sql = ($script:SqlExplicitRoleMembersWithInclusions -f ($local:RoleInclusions -join ","))

        # query to find matching role memberships (this is filtered to local accounts)
        $local:PrivilegedAccountsFromRoles = (Invoke-PostgreSqlQuery -Sql $local:Sql -ConnectionString $ConnectionString)
    }
    else
    {
        $local:PrivilegedAccountsFromRoles = @()
    }

    #  process results
    $local:Results = @{}
    $local:PrivilegedAccountsFromPermissions | ForEach-Object {
            $local:Results[$_.AccountName] = New-Object PSObject -Property ([ordered]@{
                AccountName = $_.AccountName;
                Roles = @();
                Description = "safeguard-discovery"
            })
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
                Description = "safeguard-discovery --"
            })
        }
    }

    # convert results to an array and add the description
    $local:Results.Values | ForEach-Object {
        if ($_.Roles)
        {
            $_.Description += " roles:" + ($_.Roles -join ",")
        }
        $_
    }
}
