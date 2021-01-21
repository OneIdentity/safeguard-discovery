<#
.SYNOPSIS
Discover privileged Assets on an ServiceNow server.

.DESCRIPTION
This cmdlet may be used to discover privileged Assets on an ServiceNow server.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an Asset name and password to use.

.PARAMETER NetworkAddress
IP address or hostname of a ServiceNow database.

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the database server to
execute the discovery job.

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscServiceNowAsset servicenow.test.env

.EXAMPLE
Get-SgDiscServiceNowAsset servicenow.test.env -Credential (Get-Credential)
#>
function Get-SgDiscServiceNowAsset
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = $null
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Credential)
    {
        # doing this here allows error action and verbose parameters to propagate
        $Credential = (Get-SgDiscConnectionCredential $NetworkAddress)
    }

    # make sure ServiceNow is installed
    if (-not (Get-Module InvokeQuery)) 
    { 
        try 
        {
            Import-Module ServiceNow
        }
        catch 
        {
            throw "ServiceNow Asset discovery in safeguard-discovery requires ServiceNow.  Please run: Install-Module ServiceNow."
        }
    }

    if (-not (Set-ServiceNowAuth -url $NetworkAddress  -Credential $Credential))
    {
        throw "Could not connect to ServiceNow"
    }

    $local:Results = @()

    # computers
    $limit = 100
    do 
    {
        $skip = 0
        $local:computers = Get-ServiceNowTableEntry -Table 'cmdb_ci_computer' -Skip $skip -First $limit
        foreach ($local:computer in $local:computers)
        { 
            $local:Results += New-Object PSObject -Property ([ordered]@{
                AssetName = $local:computer.name;
                State = "$($local:computer.operational_status)";
                OperatingSystem = "$($local:computer.os) $($local:computer.os_version)";
                HostName = $null;
                IpAddress = $local:computer.ip_address;
                Description = "safeguard-discovery"
            })
        }
        $skip = 0 + $limit
    } while ($local:computers.Count > 0)

    # assets
    do 
    {
        $skip = 0
        $local:assets = Get-ServiceNowTableEntry -Table 'alm_asset' -Skip $skip -First $limit 
        $local:computers = $local:assets | Where-Object{ $_.sys_class_name -eq 'Hardware' }
        foreach ($local:computer in $local:computers)
        { 
            $local:Results += New-Object PSObject -Property ([ordered]@{
                AssetName = $local:computer.display_name;
                State = "$($local:computer.install_status)";
                OperatingSystem = $local:computer.model.display_value;
                HostName = $null;
                IpAddress = $null;
                Description = "safeguard-discovery"
            })
        }
        $skip = 0 + $limit
    } while ($local:assets.Count > 0)

    $local:Results
}
