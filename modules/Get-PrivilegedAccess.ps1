<#
.SYNOPSIS
    Inventories privileged group membership in Active Directory.

.DESCRIPTION
    Enumerates a defined set of high-privilege AD groups and reports their
    members, including nested (transitive) membership, so that "who holds
    privileged access" can be answered and reviewed. This is the foundational
    control of identity governance — every access review starts from an accurate
    inventory of privileged access.

    The privileged-group list is defined in one place (the $PrivilegedGroups
    parameter) so it can be tuned per environment. Membership is resolved
    transitively (Get-ADGroupMember -Recursive) to catch users who are
    privileged via nested groups, not just direct members — a common blind spot.

.PARAMETER PrivilegedGroups
    The groups to inventory. Defaults to the well-known Tier 0 / high-privilege
    AD groups. Extend per environment (e.g. custom admin roles).

.PARAMETER OutputPath
    Optional. If supplied, writes the inventory to a timestamped CSV.

.NOTES
    Directory-agnostic by design: this function resolves privileged access from
    Active Directory. The same report shape (Principal, PrivilegedRole, Type,
    Enabled, LastLogon) maps directly onto Entra ID directory roles via Microsoft
    Graph — see the "Hybrid Identity Extension" section of the project README for
    how a Graph-backed provider would slot in alongside this AD provider.

    Requires the ActiveDirectory module (RSAT-AD-PowerShell). Read-only; queries
    only.
#>
[CmdletBinding()]
param(
    [string[]] $PrivilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "Group Policy Creator Owners",
        "DnsAdmins"
    ),
    [string] $OutputPath
)

Import-Module ActiveDirectory -ErrorAction Stop

$results = [System.Collections.Generic.List[object]]::new()

foreach ($groupName in $PrivilegedGroups) {

    # Skip groups that don't exist in this domain rather than erroring out —
    # some well-known groups (e.g. DnsAdmins) may not be present everywhere.
    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
    if (-not $group) {
        Write-Verbose "Group '$groupName' not found in this domain; skipping."
        continue
    }

    # Resolve membership transitively to catch nested (indirect) privilege.
    $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue

    if (-not $members) {
        # Record empty privileged groups too — an empty Schema Admins is itself
        # a finding worth confirming, not a blank to omit.
        $results.Add([pscustomobject]@{
            PrivilegedRole = $groupName
            Principal      = "(no members)"
            SamAccountName = ""
            Type           = ""
            Enabled        = ""
            LastLogonDate  = ""
            DistinguishedName = ""
        })
        continue
    }

    foreach ($m in $members) {
        # Enrich user objects with status/last-logon; leave non-users as-is.
        $enabled = ""
        $lastLogon = ""
        if ($m.objectClass -eq "user") {
            $u = Get-ADUser -Identity $m.SID -Properties Enabled, LastLogonDate -ErrorAction SilentlyContinue
            if ($u) {
                $enabled   = $u.Enabled
                $lastLogon = $u.LastLogonDate
            }
        }

        $results.Add([pscustomobject]@{
            PrivilegedRole    = $groupName
            Principal         = $m.Name
            SamAccountName    = $m.SamAccountName
            Type              = $m.objectClass
            Enabled           = $enabled
            LastLogonDate     = $lastLogon
            DistinguishedName = $m.distinguishedName
        })
    }
}

# Sort so the most sensitive roles surface first and disabled/privileged
# accounts are easy to spot.
$sorted = $results | Sort-Object PrivilegedRole, Principal

if ($OutputPath) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $file  = Join-Path $OutputPath "privileged-access-inventory-$stamp.csv"
    $sorted | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host "Privileged access inventory written to: $file"
}

# Always return objects to the pipeline so the caller can format/inspect.
$sorted
