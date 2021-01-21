$script:SqlExplicitRoleMembersWithInclusions = "
SELECT srm.role_principal_id AS RoleId,rp.name AS RoleName,
       srm.member_principal_id AS Id,sp.name AS AccountName,
       sp.default_database_name AS DefaultDatabaseName
FROM (sys.server_principals sp
   INNER JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id)
INNER JOIN sys.server_principals rp ON rp.principal_id = srm.role_principal_id
WHERE sp.type = 'S' AND sp.name NOT LIKE '##%' AND rp.name IN ({0})"

$script:AllSqlExplicitGrants = "
SELECT sp.principal_id AS Id,
       sp.name AS AccountName,
       sp.default_database_name AS DefaultDatabaseName,
       p.class_desc AS PermissionClass,
       p.type AS PermissionName,
       p.permission_name PermissionDescription,
       p.state_desc AS PermissionState
FROM sys.server_principals sp
     INNER JOIN sys.server_permissions p ON sp.principal_id = p.grantee_principal_id
WHERE sp.type = 'S' AND sp.name NOT LIKE '##%' AND (p.state = 'G' OR p.state = 'W')"

$script:SqlExplicitGrantsWithInclusions = $script:AllSqlExplicitGrants + " AND p.type IN ({0})"
$script:SqlExplicitGrantsWithExclusions = $script:AllSqlExplicitGrants + " AND p.type NOT IN ({0})"

$script:SqlServerPermissionsMap = @{
    "AAES" = "ALTER ANY EVENT SESSION"
    "ADBO" = "ADMINISTER BULK OPERATIONS"
    "AL"   = "ALTER"
    "ALAA" = "ALTER ANY SERVER AUDIT"
    "ALAG" = "ALTER ANY AVAILABILITY GROUP"
    "ALCD" = "ALTER ANY CREDENTIAL"
    "ALCO" = "ALTER ANY CONNECTION"
    "ALDB" = "ALTER ANY DATABASE"
    "ALES" = "ALTER ANY EVENT NOTIFICATION"
    "ALHE" = "ALTER ANY ENDPOINT"
    "ALLG" = "ALTER ANY LOGIN"
    "ALLS" = "ALTER ANY LINKED SERVER"
    "ALRS" = "ALTER RESOURCES"
    "ALSR" = "ALTER ANY SERVER ROLE"
    "ALSS" = "ALTER SERVER STATE"
    "ALST" = "ALTER SETTINGS"
    "ALTR" = "ALTER TRACE"
    "AUTH" = "AUTHENTICATE SERVER"
    "CADB" = "CONNECT ANY DATABASE"
    "CL"   = "CONTROL"
    "CO"   = "CONNECT"
    "COSQ" = "CONNECT SQL"
    "CRAC" = "CREATE AVAILABILITY GROUP"
    "CRDB" = "CREATE ANY DATABASE"
    "CRDE" = "CREATE DDL EVENT NOTIFICATION"
    "CRHE" = "CREATE ENDPOINT"
    "CRSR" = "CREATE SERVER ROLE"
    "CRTE" = "CREATE TRACE EVENT NOTIFICATION"
    "IAL"  = "IMPERSONATE ANY LOGIN"
    "IM"   = "IMPERSONATE"
    "SHDN" = "SHUTDOWN"
    "SUS"  = "SELECT ALL USER SECURABLES"
    "TO"   = "TAKE OWNERSHIP"
    "VW"   = "VIEW DEFINITION"
    "VWAD" = "VIEW ANY DEFINITION"
    "VWDB" = "VIEW ANY DATABASE"
    "VWSS" = "VIEW SERVER STATE"
    "XA"   = "EXTERNAL ACCESS"
    "XU"   = "UNSAFE ASSEMBLY"
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
    Write-Host -ForegroundColor Yellow "  -IncludePermissions @(`"ALDB`",`"ALSS`")"
    Write-Host -ForegroundColor Yellow "    or"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @(`"CO`",`"COSQ`",`"VW`")"
    Write-Host -ForegroundColor Yellow "    or (to turn it off)"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @()"
    throw $Message
}

<#
.SYNOPSIS
Discover privileged accounts in a SQL Server database.

.DESCRIPTION
This cmdlet may be used to discover privileged accounts in a SQL Server database.  When
called without arguments, the default behavior is to find local accounts that have been
added to any of the built-in roles (sysadmin, securityadmin, serveradmin, setupadmin,
processadmin, diskadmin, dbcreator, bulkadmin) and any local accounts that have been
granted any permissions other than CO, COSQ, VW, VWAD, VWDB, VWSS.  The caller can
override this behavior by specifying the exact list of roles to look for.  The caller
can also specify which directly granted permissions to exclude or include.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an account name and password to use.

.PARAMETER NetworkAddress
IP address or hostname of a SQL Server database.

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the database server to
execute the discovery job.

.PARAMETER Roles
A list of roles to search for to identify privileged accounts, or set to @() to turn off role search.
See https://docs.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver15

.PARAMETER ExcludePermissions
A list of permissions to exclude when searching for privileged accounts, or set to @() to turn off permission search.
See https://docs.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-permissions-transact-sql?view=sql-server-ver15

.PARAMETER IncludePermissions
A list of permissions to include when searching for privileged accounts.
See https://docs.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-permissions-transact-sql?view=sql-server-ver15

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscSqlServerAccount mssql.test.env

.EXAMPLE
Get-SgDiscSqlServerAccount mssql.test.env -Credential (Get-Credential)

.EXAMPLE
Get-SgDiscSqlServerAccount mssql.test.env -Roles sysadmin,securityadmin,serveradmin -IncludePermissions AL,TO,SHDN
#>
function Get-SgDiscSqlServerAccount
{
    [CmdletBinding(DefaultParameterSetName="ExcludePerms")]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$Roles = @("sysadmin","securityadmin","serveradmin","setupadmin","processadmin","diskadmin","dbcreator","bulkadmin"),
        [Parameter(Mandatory=$false,ParameterSetName="ExcludePerms")]
        [string[]]$ExcludePermissions = @("CO","COSQ","VW","VWAD","VWDB","VWSS"),
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
                if (-not $script:SqlServerPermissionsMap.ContainsKey($local:Perm))
                {
                    Invoke-ThrowPermissionsException "Invalid permission inclusion '$($local:Perm)'"
                }
                $local:PermInclusions += "'$($local:Perm)'"
            }
            $local:Sql = ($script:SqlExplicitGrantsWithInclusions -f ($local:PermInclusions -join ","))
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
                $local:PermExclusions += "'$($local:Perm)'"
            }
            $local:Sql = ($script:SqlExplicitGrantsWithExclusions -f ($local:PermExclusions -join ","))
        }

        # query to find matching permissions (this is filtered to local accounts)
        $local:PrivilegedAccountsFromPermissions = (Invoke-SqlServerQuery -Sql $local:Sql -Credential $Credential -Server $NetworkAddress)
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
        $local:PrivilegedAccountsFromRoles = (Invoke-SqlServerQuery -Sql $local:Sql -Credential $Credential -Server $NetworkAddress)
    }
    else
    {
        $local:PrivilegedAccountsFromRoles = @()
    }

    #  process results
    $local:Results = @{}
    $local:PrivilegedAccountsFromPermissions | ForEach-Object {
        if ($local:Results[$_.Id])
        {
            $local:Results[$_.Id].Permissions += (New-Object PSObject -Property ([ordered]@{
                PermissionName = $_.PermissionName;
                PermissionDescription = $_.PermissionDescription;
                PermissionClass = $_.PermissionClass;
                PermissionState = $_.PermissionState
            }))
        }
        else
        {
            $local:Results[$_.Id] = New-Object PSObject -Property ([ordered]@{
                AccountName = $_.AccountName;
                DefaultDatabaseName = $_.DefaultDatabaseName;
                Roles = @();
                Permissions = @(New-Object PSObject -Property ([ordered]@{
                    PermissionName = $_.PermissionName;
                    PermissionDescription = $_.PermissionDescription;
                    PermissionClass = $_.PermissionClass;
                    PermissionState = $_.PermissionState
                }));
                Description = ""
            })
        }
    }
    $local:PrivilegedAccountsFromRoles | ForEach-Object {
        if ($local:Results[$_.Id])
        {
            $local:Results[$_.Id].Roles += ($_.RoleName)
        }
        else
        {
            $local:Results[$_.Id] = New-Object PSObject -Property ([ordered]@{
                AccountName = $_.AccountName;
                DefaultDatabaseName = $_.DefaultDatabaseName;
                Roles = @($_.RoleName);
                Permissions = @();
                Description = ""
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
