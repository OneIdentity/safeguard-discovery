$script:SqlExplicitGrantsWithInclusions = "SELECT u.User AS AccountName FROM mysql.user u where {0}"
$script:SqlExplicitGrantsWithExclusions = "SELECT u.User AS AccountName FROM mysql.user u where not {0}"


$script:SqlServerPermissionsMap = @{
    "Select_priv" = "Select rows"
    "Insert_priv" = "Insert rows"
    "Update_priv" = "Update rows"
    "Delete_priv" = "Delete rows"
    "Create_priv" = "Create databases, tables, or indexes"
    "Drop_priv" = "Drop databases, tables, or indexes"
    "Reload_priv" = "Flush or reset replication"
    "Shutdown_priv"   = "Shutdown or restart"
    "Process_priv" = "Show processes"
    "File_priv" = "Reading and writing files from server"
    "Grant_priv" = "Grant privileges"
    "References_priv" = "Create foreign key restraints"
    "Index_priv" = "Create and drop indexes"
    "Alter_priv" = "Alter tables"
    "Show_db_priv" = "Show database names"
    "Super_priv" = "Access to everything"
    "Create_tmp_table_priv" = "Create temporary tables"
    "Lock_tables_priv" = "Lock tables"
    "Execute_priv" = "Execute stored procedures"
    "Repl_slave_priv" = "Show replication settings on slave"
    "Repl_client_priv" = "Show replication settings on master"
    "Show_view_priv" = "Show views"
    "Create_view_priv" = "Create views"
    "Event_priv" = "Manage server events"
    "Trigger_priv" = "Create triggers"
    "Create_tablespace_priv" = "Create tablespaces"
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
    Write-Host -ForegroundColor Yellow "  -IncludePermissions @(`"Create_priv`",`"Drop_priv`")"
    Write-Host -ForegroundColor Yellow "    or"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @(`"Shutdown_priv`",`"Process_priv`",`"Super_priv`")"
    Write-Host -ForegroundColor Yellow "    or (to turn it off)"
    Write-Host -ForegroundColor Yellow "  -ExcludePermissions @()"
    throw $Message
}
<#
.SYNOPSIS
Discover privileged accounts in a SQL Server database.

.DESCRIPTION
This cmdlet may be used to discover privileged accounts in a Mysql database.  When
called without arguments, the default behavior is to find local accounts that have that have been
granted global permissions except Select_priv, Show_db_priv, Show_view_priv.  The caller can
override this behavior by specifying which directly granted permissions to exclude or include.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an account name and password to use.

.PARAMETER NetworkAddress
IP address or hostname of a SQL Server database.

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the database server to
execute the discovery job.

.PARAMETER ExcludePermissions
A list of permissions to exclude when searching for privileged accounts, or set to @() to turn off permission search.
See https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html

.PARAMETER IncludePermissions
A list of permissions to include when searching for privileged accounts.
See https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscMysqlAccount mysql.test.env

.EXAMPLE
Get-SgDiscMysqlAccount mysql.test.env -Credential (Get-Credential)

.EXAMPLE
Get-SgDiscMysqlAccount mysql.test.env -IncludePermissions Create_priv,Drop_priv
#>
function Get-SgDiscMysqlAccount
{
    [CmdletBinding(DefaultParameterSetName="ExcludePerms")]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = $null,
        [Parameter(Mandatory=$false,ParameterSetName="ExcludePerms")]
        [string[]]$ExcludePermissions,
        [Parameter(Mandatory=$false,ParameterSetName="IncludePerms")]
        [string[]]$IncludePermissions = @("Super_priv", "Grant_priv")
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Credential)
    {
        # doing this here allows error action and verbose parameters to propagate
        $Credential = (Get-SgDiscConnectionCredential $NetworkAddress)
    }

    # make sure InvokeQuery is installed
    if (-not (Get-Module InvokeQuery)) { Import-Module InvokeQuery }
    if (-not (Get-Module InvokeQuery))
    {
        throw "SQL account discovery in safeguard-discovery requires InvokeQuery.  Please run: Install-Module InvokeQuery."
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
                $local:PermExclusions += "'$($local:Perm)'"
            }
            $local:Sql = ($script:SqlExplicitGrantsWithExclusions -f ($local:PermExclusions -join " or not "))
        }

        # query to find matching permissions (this is filtered to local accounts)
        $local:PrivilegedAccountsFromPermissions = (Invoke-MysqlQuery -Sql $local:Sql -Credential $Credential -Server $NetworkAddress)
    }
    else
    {
        $local:PrivilegedAccountsFromPermissions = @()
    }

    #  process results
    $local:Results = @{}
    $local:PrivilegedAccountsFromPermissions | ForEach-Object {
            $local:Results[$_.AccountName] = New-Object PSObject -Property ([ordered]@{
                AccountName = $_.AccountName;
                DefaultDatabaseName = "";
                Roles = @();
                Permissions = @();
                Description = "safeguard-discovery --"
            })
        }

    # convert results to an array and add the description
    $local:Results.Values | ForEach-Object {
        $_
    }
}
