<#
.SYNOPSIS
Discover privileged Assets on an Aws server.

.DESCRIPTION
This cmdlet may be used to discover privileged Assets on an Aws server.

When a credential is not supplied to this cmdlet, it will automatically look for an open
access request with a matching asset name or network address and use that access request
to get the password to run the discovery.  If no access request is found, the cmdlet
will prompt for an Asset name and password to use.

.PARAMETER Region
The AWS region to query for instances

.PARAMETER NetworkAddress
NeworkAddress used to look up credentials from Safeguard if desired

.PARAMETER Credential
A PowerShell credential object that can be used to connect to the AWS server to
execute the discovery job where UserName = AccessKey and Password = SecretKey

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscAwsAsset Aws.test.env

.EXAMPLE
Get-SgDiscAwsAsset Aws.test.env us-west-2 -NetworkAddress SafeguardAWS
#>
function Get-SgDiscAwsAsset
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Region,
        [Parameter(Mandatory=$false)]
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

    # make sure Awspowershell is installed
    if (-not (Get-Module Awspowershell)) { Import-Module Awspowershell }
    if (-not (Get-Module Awspowershell))
    {
        throw "AWS Asset discovery in safeguard-discovery requires Awspowershell.  Please run: Install-Module Awspowershell."
    }
    
    $local:NetworkCredential = $Credential.GetNetworkCredential()
    Initialize-AWSDefaults -AccessKey $local:NetworkCredential.UserName -SecretKey $local:NetworkCredential.Password -Region $Region

    $local:Results = @()
    $local:systems = Get-EC2Instance | ForEach-Object { $_.Instances }
    foreach ($local:system in $local:systems)
    {  
        $local:Results += New-Object PSObject -Property ([ordered]@{
            AssetName = $local:system.KeyName;
            State = $local:system.State.Name;
            OperatingSystem = $local:system.Platform;
            HostName = $local:system.PublicDnsName;
            IpAddress = $local:system.PublicIpAddress;
            Description = "safeguard-discovery"
        })
    }

    $local:Results
}
