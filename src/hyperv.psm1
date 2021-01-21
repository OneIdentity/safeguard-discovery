<#
.SYNOPSIS
Discover privileged Assets on an Hyperv server.

.DESCRIPTION
This cmdlet may be used to discover privileged Assets on an Hyperv server.

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
Get-SgDiscHypervAsset Hyperv.test.env

.EXAMPLE
Get-SgDiscHypervAsset Hyperv.test.env -SubscriptionId 30184975-ef2c-43ac-9884-e8ebdb3b5548
#>
function Get-SgDiscHypervAsset
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

    # make sure Hyper-v is installed
    if (-not (Get-Module Hyper-v)) { Import-Module Hyper-v }
    if (-not (Get-Module Hyper-v))
    {
        throw "Hyper-v Asset discovery in safeguard-discovery requires Hyper-v.  Please turn on hyper-v powershell cmdlets using Windows feature settings."
    }
    
    $local:Results = @()
    $local:systems = Hyper-v\Get-VM -ComputerName $NetworkAddress -Credential $Credential
    foreach ($local:system in $local:systems)
    {  
        $local:ipAddress = $null

        try 
        {
            $local:network = Hyper-v\Get-VmNetworkAdapter $local:system.Name -ComputerName $NetworkAddress -Credential $Credential
            $local:ipAddress = $local:network.IpAddresses
        }
        catch 
        { 
            # no public IP address
        }

        $local:Results += New-Object PSObject -Property ([ordered]@{
            AssetName = $local:system.Name;
            State = $local:system.State;
            OperatingSystem = $null;
            HostName = $null;
            IpAddress = $local:ipAddress;
            Description = "safeguard-discovery"
        })
    }

    $local:Results
}
