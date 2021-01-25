# Helper
function Test-SafeguardSession
{
    [CmdletBinding()]
    param (
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not (Get-Module safeguard-ps)) { Import-Module safeguard-ps }
    if (Get-Module safeguard-ps)
    {
        if ($SafeguardSession)
        {
            $true
        }
        else
        {
            Write-Verbose "safeguard-ps is installed, but it is not connected to Safeguard"
            $false
        }
    }
    else
    {
        Write-Verbose "safeguard-ps is not installed"
        $false
    }
}


<#
.SYNOPSIS
Get login credentials from Safeguard or locally if not available.

.DESCRIPTION
If connected to Safeguard (using Connect-Safeguard) this cmdlet will look for an open access request that 
matches the provided network address. If found it will check-out the password and use that for login
credentials. If not found then it will prompt the user for the credentials at the console.

.PARAMETER NetworkAddress
Name or network address of an existing asset in Safeguard for which there is an open access request.

.PARAMETER AccountName
Name of the account to match against open access requests in case there are more than one for the asset.

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSCredential.

.EXAMPLE
Get-SgDiscConnectionCredential Hyperv.test.env

#>
function Get-SgDiscConnectionCredential
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [string]$AccountName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    
    $local:Credential = $null
    if (Test-SafeguardSession)
    {
        if (-Not $NetworkAddress)
        {
            $NetworkAddress = (Read-Host "NetworkAddress")
        }

        $local:Requests = Get-SafeguardMyRequest
        if ($AccountName)
        {
            $local:Requests = $local:Requests | Where-Object {
                ($_.AssetNetworkAddress -eq $NetworkAddress -or $_.AssetName -eq $NetworkAddress) -and $_.AccountName -eq $AccountName }
        }
        else
        {
            $local:Requests = $local:Requests | Where-Object {
                $_.AssetNetworkAddress -eq $NetworkAddress -or $_.AssetName -eq $NetworkAddress }
        }
        
        $local:count = $local:Requests | Measure-Object
        if ($local:count.Count -lt 1)
        {
            Write-Verbose "Unable to find an open access request with name or network address equal to '$NetworkAddress'"
            if ($AccountName) { Write-Verbose "Where account name also equals '$AccountName" }
        }
        elseif ($local:count.Count -gt 1)
        {
            Write-Verbose "Found $($local:count.Count) open access requests with name or network address equal to '$NetworkAddress'"
            if ($AccountName) { Write-Verbose "Where account name also equals '$AccountName" }
        }
        else
        {
            if ($local:Requests[0].State -ne "RequestAvailable" -and $local:Requests[0].State -ne "PasswordCheckedOut")
            {
                Write-Verbose "Access request state is '$($local:Requests[0].State)', not 'RequestAvailable' or 'PasswordCheckedOut'"
            }
            else
            {
                $local:Credential = (New-Object PSCredential -ArgumentList $local:Requests[0].AccountName,(ConvertTo-SecureString -AsPlainText -Force `
                                        (Get-SafeguardAccessRequestPassword $local:Requests[0].Id)))
            }
        }
    }
    else
    {
        Write-Verbose "No safeguard-ps connection, cannot use it for credentials"
    }

    if (-not $local:Credential)
    {
        Write-Host "Credentials for ${NetworkAddress}"
        if (-not $AccountName)
        {
            $AccountName = (Read-Host "AccountName")
        }
        $local:Password = (Read-Host "Password" -AsSecureString)
        $local:Credential = (New-Object PSCredential -ArgumentList $AccountName,$local:Password)
    }

    $local:Credential
}

<#
.SYNOPSIS
Import discovered accounts to an asset in Safeguard.

.DESCRIPTION
This cmdlet may be used to add accounts to an asset in Safeguard that were discovered using other cmdlets in this module.

You must be connected to Safeguard using the Connect-Safeguard cmdlet before using this function. 

.PARAMETER NetworkAddress
Network address or name of an existing asset in Safeguard to add accounts to

.PARAMETER DiscoveredAccounts
Array of discovered accounts containing an AccountName and a Description to be imported to Safeguard.

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscOracleAccount | Import-SgDiscDiscoveredAccount oracle.test.env

.EXAMPLE
Import-SgDiscDiscoveredAccount oracle.test.env $DiscoveredAccounts
#>
function Import-SgDiscDiscoveredAccount
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [PSObject[]]$DiscoveredAccounts
    )

    begin {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

        if (Test-SafeguardSession)
        {
            $local:Assets = @(Get-SafeguardAsset $NetworkAddress -Fields AssetPartitionName,Id,Name,NetworkAddress)
            if ($local:Assets.Count -lt 1)
            {
                throw "Unable to find an asset matching '$NetworkAddress'"
            }
            elseif ($local:Assets.Count -gt 1)
            {
                throw "Found $($local:Assets.Count) assets matching '$NetworkAddress"
            }
        }
        else
        {
            throw "You must connect to Safeguard using safeguard-ps to use this cmdlet, run Connect-Safeguard"
        }
    }
    process {
        $DiscoveredAccounts | ForEach-Object {
            if (-not $_.AccountName)
            {
                Write-Host -ForegroundColor Yellow ($_ | Out-String)
                throw "Discovered account has no AccountName field"
            }
            try
            {
                Write-Verbose "Checking for existence of '$($_.AccountName)' on '$NetworkAddress'"
                $local:Account = (Get-SafeguardAssetAccount $NetworkAddress $_.AccountName)
            }
            catch {}
            if ($local:Account)
            {
                Write-Host -ForegroundColor Green "Discovered account '$($_.AccountName)' already exists"
            }
            else
            {
                if ($_.Description)
                {
                    $local:Description = $_.Description
                }
                else
                {
                    $local:Description = "safeguard-discovery -- no additional information"
                }
                if ($_.DomainName)
                {
                    $local:Account = (New-SafeguardAssetAccount $local:Assets[0].Id -NewAccountName $_.AccountName -DomainName $_.DomainName `
                                        -Description $local:Description)
                }
                elseif ($_.DistinguishedName)
                {
                    $local:Account = (New-SafeguardAssetAccount $local:Assets[0].Id -NewAccountName $_.AccountName -DistinguishedName $_.DistinguishedName `
                                        -Description $local:Description)
                }
                else
                {
                    $local:Account = (New-SafeguardAssetAccount $local:Assets[0].Id -NewAccountName $_.AccountName `
                                        -Description $local:Description)
                }
                New-Object PSObject -Property ([ordered]@{
                    AssetId = $local:Account.AssetId;
                    AssetName = $local:Account.AssetName;
                    Id = $local:Account.Id
                    Name = $local:Account.Name;
                    DomainName = $local:Account.DomainName;
                    DistinguishedName = $local:Account.DistinguishedName;
                    PlatformDisplayName = $local:Account.PlatformDisplayName;
                })
            }
            $local:Account = $null
        }
    }
    end {}
}


<#
.SYNOPSIS
Import discovered assets to an asset partition in Safeguard.

.DESCRIPTION
This cmdlet may be used to add assets to an asset partition in Safeguard that were discovered using other cmdlets in this module.

You must be connected to Safeguard using the Connect-Safeguard cmdlet before using this function. 

.PARAMETER AssetPartition
Name of an existing asset partition in Safeguard

.PARAMETER DiscoveredAssets
Array of discovered accounts containing an AccountName and a Description to be imported to Safeguard.

.INPUTS
None.

.OUTPUTS
System.Management.Automation.PSObject.

.EXAMPLE
Get-SgDiscHypervAsset Hyperv.test.env | Import-SgDiscDiscoveredAsset Macrocosm

.EXAMPLE
Import-SgDiscDiscoveredAsset Macrocosm $DiscoveredAssets
#>
function Import-SgDiscDiscoveredAsset
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$AssetPartition,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [PSObject[]]$DiscoveredAssets
    )

    begin {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

        if (Test-SafeguardSession)
        {
            $local:AssetPartitions = @(Get-SafeguardAssetPartition $AssetPartition)
            if ($local:AssetPartitions.Count -lt 1)
            {
                throw "Unable to find an asset partition matching '$AssetPartition'"
            }
            elseif ($local:AssetPartitions.Count -gt 1)
            {
                throw "Found $($local:AssetPartitions.Count) assets matching '$AssetPartition"
            }
        }
        else
        {
            throw "You must connect to Safeguard using safeguard-ps to use this cmdlet, run Connect-Safeguard"
        }
    }
    process {
        $DiscoveredAssets | ForEach-Object {

            if (-not $_.AssetName)
            {
                Write-Host -ForegroundColor Yellow ($_ | Out-String)
                throw "Discovered asset has no AssetName field"
            }
            try
            {
                $local:AssetName = $_.AssetName.Replace("`"","")
                Write-Verbose "Checking for existence of '$local:AssetName'"
                $local:Asset = (Get-SafeguardAsset $local:AssetName)
            }
            catch {}
            if ($local:Asset)
            {
                Write-Host -ForegroundColor Green "Discovered asset '$local:AssetName' already exists"
            }
            else
            {
                if ($_.Description)
                {
                    $local:Description = $_.Description
                }
                else
                {
                    $local:Description = "safeguard-discovery -- no additional information"
                }

                if ($_.IpAddress)
                {
                    $count = $_.IpAddress | Measure-Object

                    if ($count.Count -eq 1)
                    {
                        $local:NetworkAddress = $_.IpAddress
                    }
                    elseif ($count.Count -gt 1)
                    {
                
                    }
                }
                else
                {
                    $local:NetworkAddress = $local:AssetName
                }

                if (-not $_.OperatingSystem)
                {
                    $local:Platform = 500 # Other
                }
                elseif ($_.OperatingSystem -like "*Windows*")
                {
                    $local:Platform = 548 # Windows
                }
                elseif ($_.OperatingSystem -like "*Mac*")
                {
                    $local:Platform = 525 # Mac
                }
                else
                {
                    $local:Platform = 521 # Linux
                }

                $CredentialType = "None" # No service account
                
                try
                {
                    $local:Asset = (New-SafeguardAsset -AssetPartitionId $local:AssetPartitions[0].Id -DisplayName $local:AssetName -NetworkAddress $local:NetworkAddress -Description $local:Description -Platform $local:Platform -ServiceAccountCredentialType $CredentialType -NoSshHostKeyDiscovery)
                    New-Object PSObject -Property ([ordered]@{
                        Id = $local:Asset.Id
                        Name = $local:Asset.Name;
                        Description = $local:Asset.Description;
                        NetworkAddress = $local:Asset.NetworkAddress;
                        AssetPartitionId = $local:Asset.AssetPartitionId;
                        AssetPartitionName = $local:Asset.AssetPartitionName;
                        PlatformId = $local:Asset.PlatformId;
                        PlatformDisplayName = $local:Asset.PlatformDisplayName;
                    })
                } 
                catch 
                {
                    throw "Failed to add discovered asset '$local:AssetName' to Safeguard. Reason: $_.Message"
                }
            }
            $local:Asset = $null
        }
    }
    end {}
}