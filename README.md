# Active Directory Identity Governance Toolkit

A PowerShell toolkit that implements the core controls of an enterprise Identity
Governance and Administration (IGA) program against Active Directory: privileged
access inventory, stale-account detection, Segregation of Duties analysis, and
consolidated access-review (certification) reporting — with a Pester test suite
validating the detection logic.

> **Why this exists.** Commercial IGA platforms (SailPoint, Saviynt) answer a
> specific set of questions: who holds privileged access, is it still
> appropriate, is it stale, does any identity hold a toxic *combination* of
> access, and can we produce an auditable certification of all of it. This
> toolkit reproduces those controls with native PowerShell against Active
> Directory, so the governance concepts are demonstrable and repeatable without
> a licensed platform.

This is the **identity governance** companion to the
[Tiered Privileged Access Lab](https://github.com/trenton-carter/tiered-pam-lab)
(privileged access management). Together they cover two of the three IAM pillars
— governance and privileged access.

Every capability is **built and verified** against a live domain, including a
deliberately seeded Segregation of Duties violation that the tooling detects.

---

## Capabilities

| # | Tool | What it answers | Script |
|---|------|-----------------|--------|
| 1 | Privileged Access Inventory | *Who holds privileged access* (nested-inclusive)? | [`modules/Get-PrivilegedAccess.ps1`](modules/Get-PrivilegedAccess.ps1) |
| 2 | Stale Account Detection | *Which accounts are dormant, never-expiring, disabled, or stale?* | [`modules/Get-StaleAccounts.ps1`](modules/Get-StaleAccounts.ps1) |
| 3 | Segregation of Duties Analysis | *Does any identity hold a toxic combination of access?* | [`modules/Test-SegregationOfDuties.ps1`](modules/Test-SegregationOfDuties.ps1) |
| 4 | Access Review Report | *Consolidated, reviewer-facing certification of all privileged access* | [`modules/New-AccessReviewReport.ps1`](modules/New-AccessReviewReport.ps1) |
| — | Pester test suite | *Do the detections actually fire on known conditions?* | [`tests/Toolkit.Tests.ps1`](tests/Toolkit.Tests.ps1) |

All tools are **read-only** against Active Directory, parameterized, and emit
both pipeline objects and timestamped CSV reports.

---

## Design principles

- **Nested-inclusive resolution.** Membership is resolved transitively, so an
  identity that is privileged via a *nested* group is still caught — a common
  privilege-escalation blind spot that direct-membership checks miss. (The
  seeded test account surfaces as an effective Domain Admin through a nested
  Tier 0 role group.)
- **Findings are review items, not verdicts.** The tools *surface* candidates
  (e.g. a service account with `PasswordNeverExpires`, or a disabled built-in
  like `krbtgt`); a human reviewer applies judgement and dispositions each. That
  is how real access reviews work — the tool finds, the reviewer attests.
- **Correctness is a security property.** For a governance tool, a false
  negative (missing a real violation) is a security failure, so the detection
  logic is covered by Pester tests that assert each control fires on a known
  condition.
- **Directory-agnostic report contracts.** Each report's shape is deliberately
  generic so the same logic extends to cloud identity — see *Hybrid Identity
  Extension* below.

---

## Requirements this toolkit demonstrates

Phrases drawn from real IAM/IGA job descriptions.

| Requirement | Implemented by |
|-------------|----------------|
| Identity governance / IGA | The full toolkit (inventory, hygiene, SoD, certification) |
| Access reviews / certification / attestation | Access Review Report (Tool 4) |
| Segregation of Duties (SoD) | SoD Analysis (Tool 3) |
| Privileged access review | Privileged Access Inventory (Tool 1) |
| Account lifecycle / joiner-mover-leaver hygiene | Stale Account Detection (Tool 2) |
| PowerShell automation | Entire toolkit |
| Active Directory administration | All tools query AD |
| Testing / engineering discipline | Pester test suite (11 tests) |
| Hybrid identity (AD + Entra) | Documented Graph extension (below) |

---

## Usage

```powershell
# From the toolkit root, on a management host with RSAT-AD-PowerShell:
Import-Module ActiveDirectory

# 1. Who holds privileged access?
.\modules\Get-PrivilegedAccess.ps1 -OutputPath .\reports

# 2. Which accounts are stale or risky? (30-day dormancy default)
.\modules\Get-StaleAccounts.ps1 -DormantDays 30 -OutputPath .\reports

# 3. Any Segregation of Duties violations?
.\modules\Test-SegregationOfDuties.ps1 -OutputPath .\reports

# 4. Generate the consolidated access-review report
.\modules\New-AccessReviewReport.ps1 -OutputPath .\reports

# Validate the detection logic
Invoke-Pester -Path .\tests\Toolkit.Tests.ps1 -Output Detailed
```

Sample outputs are in [`reports/`](reports/).

---

## Hybrid Identity Extension (Microsoft Graph / Entra ID)

This toolkit targets on-premises Active Directory. It is **designed for
extension to Entra ID** via Microsoft Graph, and that extension is documented
here as forward-looking architecture rather than implemented, because a suitable
Entra tenant requires qualifying Microsoft licensing that was not available for
this build (the free Microsoft 365 Developer sandbox now requires a Visual
Studio Enterprise/Professional subscription or partner-program membership).

The design anticipates the extension deliberately:

- Each tool's **report contract is directory-agnostic** — `Principal`,
  `PrivilegedRole`/`PrivilegedRoles`, `Enabled`, `LastLogonDate`, `Finding`,
  `SoDViolations`. These fields map directly onto Entra objects.
- A **Graph-backed provider** would slot in alongside the AD provider per tool:
  - *Privileged inventory* → Entra **directory role** assignments
    (`Get-MgDirectoryRole` / `Get-MgRoleManagementDirectoryRoleAssignment`).
  - *Stale accounts* → Entra **sign-in activity**
    (`Get-MgUser -Property signInActivity`) and account/credential properties.
  - *SoD* → the same conflict-pair model over Entra role assignments.
  - *Access review* → the same consolidation over combined AD + Entra principals,
    for a single hybrid certification.

In a hybrid environment the toolkit would produce **one consolidated access
review spanning on-prem and cloud identities** — which is exactly the picture a
real access certification needs. (Hybrid-identity experience — AD provisioning,
Entra Connect synchronization, and MFA rollout across a multi-site network —
informs this design.)

---

## Seeded test data (transparency)

To demonstrate detection against known conditions, the following fixtures were
created in the lab domain and are referenced by the Pester tests:

- `sod-testuser` — deliberately placed in **both** `T0-Admins` and `T2-Admins`
  to create a Segregation of Duties violation for Tool 3 / the tests to catch.
- `T1-Admins`, `T2-Admins`, `Auditors`, `ServiceAccountsRole` — role/marker
  groups supporting the SoD rules (completing the tiered RBAC model).

These are demonstration fixtures, not findings — they exist so the controls can
be shown firing on a known-true condition.

---

## Skills demonstrated

PowerShell automation · Active Directory administration · identity governance
(IGA) · access certification / attestation · Segregation of Duties analysis ·
privileged access review · account lifecycle hygiene · Pester testing /
engineering discipline · hybrid-identity architecture (Microsoft Graph / Entra
extension design).

---

## Companion projects

This toolkit is the **governance** pillar of a three-part IAM portfolio:

- **[Tiered Privileged Access Lab](https://github.com/trenton-carter/tiered-pam-lab)** — privileged access management: credential vaulting and rotation, session recording, and tiered least-privilege administration.
- **[Keycloak SSO & AD Federation](https://github.com/trenton-carter/keycloak-ad-federation)** — identity federation and SSO: Keycloak federated to Active Directory over LDAPS, demonstrating OIDC and SAML.
