$script:Dependencies = @( "safeguard-ps", "Awspowershell", "Az", "VMware.VimAutomation.Core", "HPEiLOCmdlets", "ServiceNow", "InvokeQuery" )

function Invoke-ThrowDependencyException
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Host -ForegroundColor Yellow $script:Dependencies
    Write-Host -ForegroundColor Yellow "Example Usage:"
    Write-Host -ForegroundColor Yellow "  -Modules @(`"safeguard-ps`",`"Az`")"
    Write-Host -ForegroundColor Yellow "  -Modules @()"
    throw $Message
}
<#
.SYNOPSIS
Install dependencies needed for account/asset discovery cmdlets

.DESCRIPTION
This cmdlet may be used to install the powershell modules needed for the account and asset discovery cmdlets in this module.
Administrator permission is required in order to install these modules. By default all dependent modules will be installed.

These modules include: safeguard-ps, Awspowershell, Az, VMware.VimAutomation.Core, HPEiLOCmdlets, ServiceNow, and InvokeQuery.

.PARAMETER Modules
A list of modules to install.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Install-SgDiscDependencies

.EXAMPLE
Install-SgDiscDependencies  safeguard-ps,Az

#>
function Install-SgDiscDependencies
{
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$false)]
        [string[]]$Modules = @("safeguard-ps", "Awspowershell", "Az", "VMware.VimAutomation.Core", "HPEiLOCmdlets", "ServiceNow", "InvokeQuery")
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    if (($IsAdmin -eq $false)) 
    { 
        Write-Warning -Message "Uninstall aborted. PowerShell must be run elevated as an admin to remove it."
    }

    foreach ($local:module in $Modules)
    {
        if (-not $script:Dependencies.Contains($local:module))
        {
            Invoke-ThrowDependencyException "Invalid module '$($local:module)'"
        }

        if (Get-InstalledModule $local:module -ErrorAction silentlycontinue)
        {
            "Module $local:module is already installed"
            continue
        }

        "Installing module $local:module"
        Install-Module $local:module -AllowClobber -Confirm:$False
    }
}

<#
.SYNOPSIS
Uninstall dependencies needed for account/asset discovery cmdlets

.DESCRIPTION
This cmdlet may be used to uninstall the powershell modules needed for the account and asset discovery cmdlets in this module.
Administrator permission is required in order to uninstall these modules. By default all dependent modules will be uninstalled.

These modules include: safeguard-ps, Awspowershell, Az, VMware.VimAutomation.Core, HPEiLOCmdlets, ServiceNow, and InvokeQuery.

.PARAMETER Modules
A list of modules to install.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Uninstall-SgDiscDependencies

.EXAMPLE
Uninstall-SgDiscDependencies  safeguard-ps,Az

#>
function Uninstall-SgDiscDependencies
{
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$false)]
        [string[]]$Modules = @("safeguard-ps", "Awspowershell", "Az", "VMware.VimAutomation.Core", "HPEiLOCmdlets", "ServiceNow", "InvokeQuery")
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    if (($IsAdmin -eq $false)) 
    { 
        Write-Warning -Message "Uninstall aborted. PowerShell must be run elevated as an admin to remove it."
    }
    if ((Get-Process -Name powershell, pwsh -OutVariable Sessions -ErrorAction SilentlyContinue).Count -gt 1) 
    {
        Write-Warning -Message "Uninstall aborted. Please close all other PowerShell sessions before continuing. There are currently $($Sessions.Count) PowerShell sessions running."
    }

    foreach ($local:module in $Modules)
    {
        if (-not $script:Dependencies.Contains($local:module))
        {
            Invoke-ThrowDependencyException "Invalid module '$($local:module)'"
        }

        if (-not (Get-InstalledModule $local:module -ErrorAction SilentlyContinue))
        {
            "Module $local:module is not installed"
            continue
        }

		"Gathering dependencies for $local:module..."
		$local:dependentModules = (Get-DependentModule $local:module) | Select-Object -unique
		
		$local:dependentModules
		foreach ($local:dependentModule in $local:dependentModules)
		{
			"Uninstalling module $local:dependentModule"
			Remove-Module $local:dependentModule -ErrorAction SilentlyContinue
			Uninstall-Module $local:dependentModule -Force
		}
    }
}

# Recursively find dependent modules
function Get-DependentModule
{
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string[]]$ModuleName
    )

	$local:rootModule = Find-Module $ModuleName
	if (-not $local:rootModule) { return }
	
	$local:moduleNames = @( $ModuleName )
	foreach ($local:dependentModule in $local:rootModule.Dependencies)
	{
		$local:moduleNames += Get-DependentModule $local:dependentModule.Name
	}
	
	$local:moduleNames
}