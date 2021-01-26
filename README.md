[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/safeguard-discovery.svg)](https://www.powershellgallery.com/packages/safeguard-discovery)
[![GitHub](https://img.shields.io/github/license/OneIdentity/safeguard-discovery.svg)](https://github.com/OneIdentity/safeguard-discovery/blob/master/LICENSE)

# safeguard-discovery

One Identity Safeguard Discovery Powershell module and scripting resources.

-----------

## Support

One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/safeguard-discovery/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/safeguard-discovery/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

## Installation

This Powershell module is published to the
[PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-discovery)
to make it as easy as possible to install using the built-in `Import-Module` cmdlet.
It can also be updated using the `Update-Module` to get the latest functionality.

By default Powershell modules are installed for all users, and you need to be
running Powershell as an Administrator to install for all users.

```Powershell
> Install-Module safeguard-discovery
```

Or, you can install them just for you using the `-Scope` parameter which will
never require Administrator permission:

```Powershell
> Install-Module safeguard-discovery -Scope CurrentUser
```

## Upgrading

If you want to upgrade from the
[PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-discovery)
you should use:

```Powershell
> Update-Module safeguard-discovery
```

Or, for a specific user:


```Powershell
> Update-Module safeguard-discovery -Scope CurrentUser
```

If you run into errors while upgrading make sure that you upgrade for all users
if the module was originally installed for all users.  If the module was originally
installed for just the current user, be sure to use the `-Scope` parameter to again
specify `CurrentUser` when running the `Update-Module` cmdlet.

## Prerelease Versions

To install a prerelease version of safeguard-discovery you need to use the latest version
of PowerShellGet. Windows comes with one installed, but you
want the newest and it requires the `-Force` parameter to get it.

If you don't have PowerShellGet, run:

```Powershell
> Install-Module PowerShellGet -Force
```

Then, you can install a prerelease version of safeguard-discovery by running:

```Powershell
> Install-Module -Name safeguard-discovery -AllowPrerelease
```

## Prerequisites

These cmdlets are integrated into Safeguard using the safeguard-ps module
[PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-discovery)

The safeguard-ps module is not required if you just want to discover assets or accounts but not import them into Safeguard.

Other PowerShell modules are required depending on which platforms you wish to discover assets or accounts on.

- AWS: Awspowershell [PowerShell Gallery](https://www.powershellgallery.com/packages/Awspowershell)
- Azure: Az [PowerShell Gallery](https://www.powershellgallery.com/packages/Az)
- ESX: VMware.VimAutomation.Core [PowerShell Gallery](https://www.powershellgallery.com/packages/VMware.VimAutomation.Core)
- HP ILO: HPEiLOCmdlets [PowerShell Gallery](https://www.powershellgallery.com/packages/HPEiLOCmdlets)
- Hyper-v: Enable Hyper-v powershell module using windows feature manager
- ServiceNow: ServiceNow [PowerShell Gallery](https://www.powershellgallery.com/packages/ServiceNow)
- Databases: InvokeQuery [PowerShell Gallery](https://www.powershellgallery.com/packages/InvokeQuery)

## Safeguard Integration

Once you have loaded the module, you must first connect to Safeguard using the
`Connect-Safeguard` cmdlet.  See [safeguard-ps](https://github.com/OneIdentity/safeguard-ps) for more information.

If the login credentials for the target machine are stored in Safeguard then first create an access request for those credentials from the Safeguard console.
Once the access request is approved then you can use the `Get-SgDiscConnectionCredential` cmdlet to automatically check-out the password.

For example:

```Powershell
> $Credential = Get-SgDiscConnectionCredential <AssetName>
```

If an approved access request is discovered for an account belonging to the specified asset than the username/password will be returned as a PSCredential object.
If an approved access request is not found then the user will be prompted to enter the credentials manually.

Accounts and assets discovered using the provided cmdlets can be imported into Safeguard. Use `Import-SgDiscDiscoveredAccount` to import accounts into an existing
asset in Safeguard. Use `Import-SgDiscDiscoveredAsset` to import assets into an existing asset partition in Safeguard. Discovered accounts are PSObjects that have
at least an AccountName and Description. Discovered assets are PSObjects that have at least an AssetName, Description, IpAddress, and OperationSystem.

For example:

```Powershell
> Import-SgDiscDiscoveredAccount <AssetName> $DiscoveredAccounts
```

```Powershell
> Import-SgDiscDiscoveredAsset <AssetPartitionName> $DiscoveredAssets
```

## Discover Available cmdlets

Use the `Get-Command -Module safeguard-discovery` to see what is available from the module.

Since there are so many cmdlets in safeguard-discovery you can use filters to find
exactly the cmdlet you are looking for.

For example:

```Powershell
> Get-Command -Module safeguard-discovery

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Get-SgDiscAwsAsset                                 1.0.99999  safeguard-discovery

```

## Module Versioning

The version of safeguard-discovery mirrors the version of Safeguard that it was
developed and tested against.  However, the build numbers (fourth number)
should not be expected to match.

For Example:

safeguard-discovery 2.2.152 would correspond to Safeguard 2.2.0.6958.

This does not mean that safeguard-discovery 2.2.152 won't work at all with
Safeguard 2.4.0.7846.  For the most part the cmdlets will still work, but
you may occasionally come across things that are broken.

For the best results, please try to match the first two version numbers of
the safeguard-discovery module to the first two numbers of the Safeguard appliance
you are communicating with.  The most important thing for safeguard-discovery is
the version of the Safeguard Web API, which will never change between
where only the third and fourth numbers differ.

### Prerelease Builds

safeguard-discovery supports prerelease builds.  This is so the next version of
safeguard-discovery can be developed in lock step with the Safeguard product.

## Powershell cmdlets

The following cmdlets are currently supported.  More will be added to this
list over time.  Every cmdlet in the list supports `Get-Help` to provide
additional information as to how it can be called.

Please file GitHub Issues for cmdlets that are not working and to request
cmdlets for functionality that is missing.

The following list of cmdlets might not be complete.  To see everything that
safeguard-discovery can do run:

```Powershell
> Get-Command -Module safeguard-discovery
```

Please report anything you see from the output that is missing, and we will
update this list.

### Account Discovery

- Get-SgDiscHpiLOAccount
- Get-SgDiscIDracAccount
- Get-SgDiscMysqlAccount
- Get-SgDiscOracleAccount
- Get-SgDiscOracleAccount
- Get-SgDiscPostgresAccount
- Get-SgDiscSqlServerAccount

### Asset Discovery

- Get-SgDiscAwsAsset
- Get-SgDiscAzureAsset
- Get-SgDiscEsxAsset
- Get-SgDiscHypervAsset
- Get-SgDiscServiceNowAsset

### Safeguard Integration

- Get-SgDiscConnectionCredential
- Import-SgDiscDiscoveredAccount
- Import-SgDiscDiscoveredAsset
