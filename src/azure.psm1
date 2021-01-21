<#
.SYNOPSIS
Discover privileged Assets on an Azure server.

.DESCRIPTION
This cmdlet may be used to discover privileged Assets on an Azure server.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an Asset name and password to use.

.PARAMETER SubscriptionId
Azure subscription to search

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscAzureAsset Azure.test.env

.EXAMPLE
Get-SgDiscAzureAsset Azure.test.env -SubscriptionId 30184975-ef2c-43ac-9884-e8ebdb3b5548
#>
function Get-SgDiscAzureAsset
{
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SubscriptionId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # make sure Az is installed
    if (-not (Get-Module Az)) 
    { 
        try 
        {
            Import-Module Az
        }
        catch 
        {
            throw "Azure Asset discovery in safeguard-discovery requires Az.  Please run: Install-Module Az."
        }
    }

    (Connect-AzAccount -Subscription $SubscriptionId) 2> $null
    
    $local:Results = @()
    $local:systems = Get-AzVM 
    foreach ($local:system in $local:systems)
    {  
        $local:os = $null;
        $local:ipAddress = $null

        if ($local:system.OSProfile.WindowsConfiguration)
        {
            $local:OS = "Windows"
        }
        else 
        {
            if ($local:system.OSProfile.LinuxConfiguration)
            {
                $local:OS = "Linux"
            }
        }

        try 
        {
            $local:network = Get-AzNetworkInterface -ResourceId $local:system.NetworkProfile.Id
            $local:ipAddress = $local:network.IpConfigurations.PublicIpAddress.IpAddress
        }
        catch 
        { 
            # no public IP address
        }

        $local:Results += New-Object PSObject -Property ([ordered]@{
            AssetName = $local:system.Name;
            State = $local:system.StatusCode
            OperatingSystem = $local:OS;
            HostName = $local:system.OSProfile.ComputerName;
            IpAddress = $local:ipAddress;
            Description = "safeguard-discovery"
        })
    }

    $local:Results
}
