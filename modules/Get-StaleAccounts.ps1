<#
.SYNOPSIS
    Detects stale and risky Active Directory user accounts.

.DESCRIPTION
    Flags accounts that represent identity-hygiene risk or audit findings:
      - Dormant: enabled but no logon within the dormancy threshold
      - PasswordNeverExpires: password set to never expire (risk, esp. on users)
      - DisabledNotRemoved: disabled accounts left in the directory
      - StalePassword: password not changed within the password-age threshold

    Each finding is a *review item*, not an automatic action — the point of an
    access review is human judgement (e.g. a service account with
    PasswordNeverExpires may be intentionally exempt). The tool surfaces; the
    reviewer decides.

.PARAMETER DormantDays
    Days without logon before an enabled account is flagged dormant. Default 30
    for lab visibility; 90 is a common production default. Tune per environment.

.PARAMETER StalePasswordDays
    Days since last password change before flagging. Default 180.

.PARAMETER SearchBase
    Optional OU distinguished name to scope the scan. Defaults to the whole
    domain.

.PARAMETER OutputPath
    Optional. If supplied, writes findings to a timestamped CSV.

.NOTES
    Directory-agnostic report shape (SamAccountName, Finding, Detail, Enabled,
    LastLogonDate) maps onto Entra ID via Microsoft Graph sign-in activity and
    account properties — see the README "Hybrid Identity Extension" section.

    Read-only. Requires the ActiveDirectory module.
#>
[CmdletBinding()]
param(
    [int]    $DormantDays = 30,
    [int]    $StalePasswordDays = 180,
    [string] $SearchBase,
    [string] $OutputPath
)

Import-Module ActiveDirectory -ErrorAction Stop

$now              = Get-Date
$dormantCutoff    = $now.AddDays(-$DormantDays)
$passwordCutoff   = $now.AddDays(-$StalePasswordDays)

$adParams = @{
    Filter     = '*'
    Properties = @(
        'Enabled', 'LastLogonDate', 'PasswordLastSet',
        'PasswordNeverExpires', 'whenCreated', 'Description'
    )
}
if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }

$users    = Get-ADUser @adParams
$findings = [System.Collections.Generic.List[object]]::new()

foreach ($u in $users) {

    # --- Dormant: enabled, and either never logged on or past the cutoff ---
    if ($u.Enabled) {
        $lastLogon = $u.LastLogonDate
        $isDormant = (-not $lastLogon) -or ($lastLogon -lt $dormantCutoff)
        if ($isDormant) {
            $detail = if ($lastLogon) {
                "Last logon $([int]($now - $lastLogon).TotalDays) days ago ($($lastLogon.ToString('yyyy-MM-dd')))"
            } else {
                "No recorded logon (created $($u.whenCreated.ToString('yyyy-MM-dd')))"
            }
            $findings.Add([pscustomobject]@{
                SamAccountName = $u.SamAccountName
                Name           = $u.Name
                Finding        = 'Dormant'
                Detail         = $detail
                Enabled        = $u.Enabled
                LastLogonDate  = $lastLogon
                Description    = $u.Description
            })
        }
    }

    # --- Password never expires ---
    if ($u.PasswordNeverExpires) {
        $findings.Add([pscustomobject]@{
            SamAccountName = $u.SamAccountName
            Name           = $u.Name
            Finding        = 'PasswordNeverExpires'
            Detail         = 'Password set to never expire — confirm if intentional (e.g. service account)'
            Enabled        = $u.Enabled
            LastLogonDate  = $u.LastLogonDate
            Description    = $u.Description
        })
    }

    # --- Disabled but not removed ---
    if (-not $u.Enabled) {
        $findings.Add([pscustomobject]@{
            SamAccountName = $u.SamAccountName
            Name           = $u.Name
            Finding        = 'DisabledNotRemoved'
            Detail         = "Disabled account still present (created $($u.whenCreated.ToString('yyyy-MM-dd')))"
            Enabled        = $u.Enabled
            LastLogonDate  = $u.LastLogonDate
            Description    = $u.Description
        })
    }

    # --- Stale password ---
    if ($u.PasswordLastSet -and $u.PasswordLastSet -lt $passwordCutoff) {
        $findings.Add([pscustomobject]@{
            SamAccountName = $u.SamAccountName
            Name           = $u.Name
            Finding        = 'StalePassword'
            Detail         = "Password last set $([int]($now - $u.PasswordLastSet).TotalDays) days ago ($($u.PasswordLastSet.ToString('yyyy-MM-dd')))"
            Enabled        = $u.Enabled
            LastLogonDate  = $u.LastLogonDate
            Description    = $u.Description
        })
    }
}

$sorted = $findings | Sort-Object Finding, SamAccountName

if ($OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $file  = Join-Path $OutputPath "stale-account-findings-$stamp.csv"
    $sorted | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host "Stale account findings written to: $file"
    Write-Host "Thresholds: dormant > $DormantDays days, stale password > $StalePasswordDays days"
}

$sorted
