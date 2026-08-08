<#
.SYNOPSIS
    Generates a consolidated access review (certification) report for privileged
    accounts in Active Directory.

.DESCRIPTION
    Access reviews (a.k.a. access certification / attestation) are the periodic
    governance control where a reviewer confirms that each identity's privileged
    access is still appropriate. This tool produces the reviewer-facing artifact:
    one row per privileged principal, consolidating

      - the privileged roles/groups they hold (nested-inclusive),
      - hygiene findings (dormant, password-never-expires, disabled),
      - any Segregation of Duties violations they are involved in,

    and an empty ReviewDecision / Reviewer / ReviewDate set of columns for the
    reviewer to complete (Approve / Revoke / Investigate). This is the format an
    IGA certification campaign runs on.

    This report composes the other toolkit modules' logic. In a fuller build the
    three collectors would be dot-sourced/imported; here the relevant queries are
    inlined so the report is self-contained and easy to run.

.PARAMETER PrivilegedGroups
    Privileged groups whose members are subject to review. Defaults to the
    well-known high-privilege groups.

.PARAMETER DormantDays
    Dormancy threshold for the hygiene flag. Default 30.

.PARAMETER OutputPath
    Optional. If supplied, writes the review report to a timestamped CSV.

.NOTES
    Directory-agnostic report contract (Principal, PrivilegedRoles,
    HygieneFindings, SoDViolations, ReviewDecision...) maps onto Entra ID role
    assignments + sign-in activity via Microsoft Graph. See README
    "Hybrid Identity Extension".

    Read-only. Requires the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [string[]] $PrivilegedGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Backup Operators', 'Server Operators',
        'Print Operators', 'Group Policy Creator Owners', 'DnsAdmins',
        'T0-Admins', 'T1-Admins', 'T2-Admins'
    ),
    [int]    $DormantDays = 30,
    [string] $OutputPath
)

Import-Module ActiveDirectory -ErrorAction Stop

$now           = Get-Date
$dormantCutoff = $now.AddDays(-$DormantDays)

# --- SoD rules (kept in sync with Test-SegregationOfDuties.ps1) --------------
$sodRules = @(
    @{ RuleName = 'Tier0-Tier2 span'; GroupA = 'T0-Admins'; GroupB = 'T2-Admins' },
    @{ RuleName = 'Act vs Audit'; GroupA = 'Domain Admins'; GroupB = 'Auditors' },
    @{ RuleName = 'Service account with interactive admin'; GroupA = 'ServiceAccountsRole'; GroupB = 'Domain Admins' }
)

# Cache of group -> effective member map (SID -> member object)
$memberCache = @{}
function Get-EffectiveMembers {
    param([string] $GroupName)
    if ($memberCache.ContainsKey($GroupName)) { return $memberCache[$GroupName] }
    $grp = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    $map = @{}
    if ($grp) {
        foreach ($m in (Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue)) {
            $map[$m.SID.Value] = $m
        }
    }
    $memberCache[$GroupName] = $map
    return $map
}

# --- Build the set of privileged principals and the roles each holds ---------
# principalRoles: SID -> ordered set of role names
$principalRoles = @{}
$principalObj   = @{}   # SID -> member object (for name/sam)

foreach ($groupName in $PrivilegedGroups) {
    $members = Get-EffectiveMembers -GroupName $groupName
    foreach ($sid in $members.Keys) {
        if (-not $principalRoles.ContainsKey($sid)) {
            $principalRoles[$sid] = [System.Collections.Generic.List[string]]::new()
            $principalObj[$sid]   = $members[$sid]
        }
        if (-not $principalRoles[$sid].Contains($groupName)) {
            $principalRoles[$sid].Add($groupName)
        }
    }
}

# --- Precompute SoD violations per principal SID -----------------------------
$sodBySid = @{}
foreach ($rule in $sodRules) {
    $a = Get-EffectiveMembers -GroupName $rule.GroupA
    $b = Get-EffectiveMembers -GroupName $rule.GroupB
    foreach ($sid in $a.Keys) {
        if ($b.ContainsKey($sid)) {
            if (-not $sodBySid.ContainsKey($sid)) {
                $sodBySid[$sid] = [System.Collections.Generic.List[string]]::new()
            }
            $sodBySid[$sid].Add($rule.RuleName)
        }
    }
}

# --- Assemble one review row per privileged principal ------------------------
$report = [System.Collections.Generic.List[object]]::new()

foreach ($sid in $principalRoles.Keys) {
    $obj = $principalObj[$sid]

    # Enrich with account status/hygiene where the principal is a user.
    $hygiene = [System.Collections.Generic.List[string]]::new()
    $enabled = ''
    $lastLogon = ''
    if ($obj.objectClass -eq 'user') {
        $u = Get-ADUser -Identity $sid -Properties Enabled, LastLogonDate, PasswordNeverExpires -ErrorAction SilentlyContinue
        if ($u) {
            $enabled   = $u.Enabled
            $lastLogon = $u.LastLogonDate
            if (-not $u.Enabled) { $hygiene.Add('DisabledButPrivileged') }
            if ($u.Enabled -and ((-not $u.LastLogonDate) -or ($u.LastLogonDate -lt $dormantCutoff))) {
                $hygiene.Add('Dormant')
            }
            if ($u.PasswordNeverExpires) { $hygiene.Add('PasswordNeverExpires') }
        }
    }

    $sodList = if ($sodBySid.ContainsKey($sid)) { $sodBySid[$sid] -join '; ' } else { '' }

    $report.Add([pscustomobject]@{
        Principal        = $obj.Name
        SamAccountName   = $obj.SamAccountName
        Type             = $obj.objectClass
        Enabled          = $enabled
        LastLogonDate    = $lastLogon
        PrivilegedRoles  = ($principalRoles[$sid] -join '; ')
        HygieneFindings  = ($hygiene -join '; ')
        SoDViolations    = $sodList
        # Reviewer completes these during the certification:
        ReviewDecision   = ''      # Approve / Revoke / Investigate
        Reviewer         = ''
        ReviewDate       = ''
    })
}

# Surface the riskiest rows first: SoD violations, then hygiene findings.
$sorted = $report | Sort-Object `
    @{ Expression = { [bool]$_.SoDViolations }; Descending = $true }, `
    @{ Expression = { [bool]$_.HygieneFindings }; Descending = $true }, `
    Principal

if ($OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $file  = Join-Path $OutputPath "access-review-$stamp.csv"
    $sorted | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host "Access review report written to: $file"
    Write-Host "Reviewer to complete ReviewDecision/Reviewer/ReviewDate for each row."
}

$sorted
