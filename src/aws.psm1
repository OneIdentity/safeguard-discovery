<#
.SYNOPSIS
Discover privileged Assets on an Aws server.

.DESCRIPTION
This cmdlet may be used to discover privileged Assets on an Aws server.

.PARAMETER Region
The AWS region to query for instances

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
        [PSCredential]$Credential = $null
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Credential) 
    {
        $Credential = Get-Credential
    }

    # make sure Awspowershell is installed
    if (-not (Get-Module Awspowershell)) 
    { 
        try 
        {
            Import-Module Awspowershell
        }
        catch 
        {
            throw "AWS Asset discovery in safeguard-discovery requires Awspowershell.  Please run: Install-Module Awspowershell."
        }
    }
    
    $local:NetworkCredential = $Credential.GetNetworkCredential()
    Initialize-AWSDefaults -AccessKey $local:NetworkCredential.UserName -SecretKey $local:NetworkCredential.Password -Region $Region

    $local:Results = @()
    $local:systems = Get-EC2Instance | ForEach-Object { $_.Instances }
    foreach ($local:system in $local:systems)
    {  
        $local:name = $local:system.Tag | Where-Object { $_.Key -eq 'Name'} | Select-Object -ExpandProperty Value
        if (-not $local:name)
        {
            $local:name = $local:system.InstanceId
        }

        $local:Results += New-Object PSObject -Property ([ordered]@{
            AssetName = $local:name;
            State = $local:system.State.Name;
            OperatingSystem = $local:system.Platform;
            HostName = $local:system.PublicDnsName;
            IpAddress = $local:system.PublicIpAddress;
            Description = "safeguard-discovery"
        })
    }

    $local:Results
}
