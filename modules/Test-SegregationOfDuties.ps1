<#
.SYNOPSIS
    Detects Segregation of Duties (SoD) violations in Active Directory.

.DESCRIPTION
    Segregation of Duties requires that no single identity hold a *combination*
    of privileges that together enable end-to-end abuse of a process. This tool
    defines SoD rules as pairs of conflicting AD groups and reports any principal
    who is an (effective, nested-inclusive) member of both groups in a pair.

    Rules here are modelled on the lab's tiered administration design plus a
    classic act-vs-audit conflict:

      - Tier 0 admin AND Tier 2 admin  (spans the highest and lowest admin tiers)
      - Domain Admins AND Auditors     (can act AND audit own actions)
      - A managed service-account role AND an interactive admin group

    Membership is resolved transitively, so a violation via nested groups is
    still caught.

.PARAMETER OutputPath
    Optional. If supplied, writes violations to a timestamped CSV.

.NOTES
    Report shape (Principal, RuleName, GroupA, GroupB) is directory-agnostic;
    the same conflict model applies to Entra ID role assignments via Microsoft
    Graph. See README "Hybrid Identity Extension".

    Read-only. Requires the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [string] $OutputPath
)

Import-Module ActiveDirectory -ErrorAction Stop

# --- SoD rule definitions: holding BOTH groups in a pair is a violation ------
# GroupA / GroupB are AD group names; RuleName / Rationale document intent.
$sodRules = @(
    [pscustomobject]@{
        RuleName  = 'Tier0-Tier2 span'
        GroupA    = 'T0-Admins'
        GroupB    = 'T2-Admins'
        Rationale = 'No account should hold both Tier 0 and Tier 2 admin rights; breaks tier isolation.'
    },
    [pscustomobject]@{
        RuleName  = 'Act vs Audit'
        GroupA    = 'Domain Admins'
        GroupB    = 'Auditors'
        Rationale = 'An account that can administer the domain must not also audit it (could conceal actions).'
    },
    [pscustomobject]@{
        RuleName  = 'Service account with interactive admin'
        GroupA    = 'ServiceAccountsRole'
        GroupB    = 'Domain Admins'
        Rationale = 'A non-human service identity should not also hold interactive domain admin rights.'
    }
)

# Resolve a group's effective (nested-inclusive) member SIDs once, cached.
$memberCache = @{}
function Get-EffectiveMemberSids {
    param([string] $GroupName)
    if ($memberCache.ContainsKey($GroupName)) { return $memberCache[$GroupName] }

    $grp = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if (-not $grp) {
        Write-Verbose "SoD: group '$GroupName' not found; rule involving it cannot fire."
        $memberCache[$GroupName] = @{}
        return @{}
    }
    $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue
    $map = @{}
    foreach ($m in $members) { $map[$m.SID.Value] = $m }
    $memberCache[$GroupName] = $map
    return $map
}

$violations = [System.Collections.Generic.List[object]]::new()

foreach ($rule in $sodRules) {
    $aMembers = Get-EffectiveMemberSids -GroupName $rule.GroupA
    $bMembers = Get-EffectiveMemberSids -GroupName $rule.GroupB

    # Intersection of the two membership sets = principals in violation.
    foreach ($sid in $aMembers.Keys) {
        if ($bMembers.ContainsKey($sid)) {
            $p = $aMembers[$sid]
            $violations.Add([pscustomobject]@{
                Principal      = $p.Name
                SamAccountName = $p.SamAccountName
                RuleName       = $rule.RuleName
                GroupA         = $rule.GroupA
                GroupB         = $rule.GroupB
                Rationale      = $rule.Rationale
            })
        }
    }
}

if ($violations.Count -eq 0) {
    Write-Host "No Segregation of Duties violations found against the defined rules."
}

$sorted = $violations | Sort-Object RuleName, Principal

if ($OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $file  = Join-Path $OutputPath "sod-violations-$stamp.csv"
    $sorted | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host "SoD analysis written to: $file"
}

$sorted
