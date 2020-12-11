function Get-SgDiscConnectionCredential
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [string]$AccountName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Credential = $null
    if (-not (Get-Module safeguard-ps)) { Import-Module safeguard-ps }
    if (Get-Module safeguard-ps)
    {
        if ($SafeguardSession)
        {
            if ($AccountName)
            {
                $local:Requests = (Get-SafeguardMyRequest | Where-Object {
                    ($_.AssetNetworkAddress -eq $NetworkAddress -or $_.AssetName -eq $NetworkAddress) -and $_.AccountName -eq $AccountName })
            }
            else
            {
                $local:Requests = (Get-SafeguardMyRequest | Where-Object {
                    $_.AssetNetworkAddress -eq $NetworkAddress -or $_.AssetName -eq $NetworkAddress })
            }
            if ($local:Requests.Count -lt 1)
            {
                Write-Verbose "Unable to find an open access request with name or network address equal to '$NetworkAddress'"
                if ($AccountName) { Write-Verbose "Where account name also equals '$AccountName" }
            }
            elseif ($local:Requests.Count -gt 1)
            {
                Write-Verbose "Found $($local:Requests.Count) open access requests with name or network address equal to '$NetworkAddress'"
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
            Write-Verbose "Not connected to Safeguard, cannot use it for credentials"
        }
    }
    else
    {
        Write-Verbose "safeguard-ps is not installed, cannot use it for credentials"
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